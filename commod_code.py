import time
import requests
import hashlib
import logging
import sys
import os
import re
import json
import urllib.parse
import difflib
import random
import string
from urllib.parse import quote, unquote, urlparse, parse_qs, urljoin, urlunparse, urlencode
from bs4 import BeautifulSoup
from collections import defaultdict

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
        
        # 初始化智能基准学习器
        self.baseline_learner = BaselineLearner()
        
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
            max_requests_per_second=self.config.get("max_requests_per_second", 15),  # 降低频率
            max_requests_per_minute=self.config.get("max_requests_per_minute", 300)
        )
        
        # 初始化请求队列（降低并发避免堆积）
        self.request_queue = RequestQueueManager(
            max_concurrent=self.config.get("max_concurrent_requests", 2),  # 进一步降低并发
            max_queue_size=self.config.get("max_queue_size", 30),  # 减小队列大小
            rate_limiter=self.rate_limiter
        )
        
        # 初始化请求发送器
        self.request_sender = RequestSender(
            timeout=self.config.get("request_timeout", 25),
            verify_ssl=self.config.get("verify_ssl", False),
            user_agent=self.config.get("user_agent"),
            proxies=None,  # 禁用代理，直接连接目标网站
            max_retries=self.config.get("max_retries", 1)  # 减少重试次数
        )

        # 初始化请求构造器和响应解析器
        self.request_builder = RequestBuilder()
        self.response_parser = ResponseParse()

        # 构建payload集合（使用更安全的payload）
        self.command_payloads = self._build_command_payloads()
        self.code_payloads = self._build_code_payloads()
        
        # 检测指示器
        self.command_indicators = self._get_command_indicators()
        self.code_indicators = self._get_code_indicators()
        
        # 时间延迟阈值
        self.time_delay_threshold = self.config.get("time_delay_threshold", 5.0)  # 增加阈值
        
        # 误报过滤器
        self.false_positive_filter = FalsePositiveFilter()
        
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
        
        # 上下文分析器
        self.context_analyzer = ContextAnalyzer()
        
        print("🔧 扫描器初始化完成，误报率已优化")

    def _get_default_cmd_config(self):
        """默认命令执行配置 - 使用更安全的payload"""
        return {
            "time_delay_threshold": 5.0,
            "payloads": {
                "unix_generic": {
                    "echo_based": ["; echo TEST_SAFE_CMD", "| echo TEST_SAFE_CMD", "& echo TEST_SAFE_CMD"],
                    "time_based": ["; sleep 5", "| sleep 5", "& sleep 5"],  # 增加延迟时间
                    "reverse_shell": [],
                    "file_operations": []
                },
                "windows_generic": {
                    "echo_based": ["& echo TEST_SAFE_CMD", "| echo TEST_SAFE_CMD", "&& echo TEST_SAFE_CMD"],
                    "time_based": ["& timeout 5", "| ping -n 5 127.0.0.1"],  # 增加延迟
                    "reverse_shell": [],
                    "file_operations": []
                }
            },
            "indicators": {
                "unix_output": ["TEST_SAFE_CMD", "root:", "bin/bash"],
                "windows_output": ["TEST_SAFE_CMD", "Windows"],
                "error_indicators": ["command not found", "is not recognized", "syntax error"],
                "time_based_confirm": ["sleep:", "timeout:", "ping statistics"]
            }
        }

    def _get_default_code_config(self):
        """默认代码执行配置 - 使用更安全的payload"""
        return {
            "payloads": {
                "php_generic": {
                    "eval_based": ["; echo 'TEST_SAFE_CODE';", "'; echo 'TEST_SAFE_CODE'; //"],
                    "system_based": [],
                    "file_include": [],
                    "assert_based": []
                },
                "python_generic": {
                    "eval_based": ["'; print('TEST_SAFE_CODE') #", "\"; print('TEST_SAFE_CODE') #"],
                    "os_system": [],
                    "pickle_rce": [],
                    "template_injection": ["${7*7}", "<%= 7*7 %>"]
                },
                "java_generic": {
                    "runtime_exec": [],
                    "process_builder": [],
                    "el_injection": ["${7*7}", "#{7*7}"]
                },
                "nodejs_generic": {
                    "eval_based": ["'; console.log('TEST_SAFE_CODE') //"],
                    "child_process": [],
                    "template_injection": ["${7*7}", "<%= 7*7 %>"]
                }
            },
            "indicators": {
                "php_output": ["TEST_SAFE_CODE", "PHP Version"],
                "python_output": ["TEST_SAFE_CODE", "Python"],
                "java_output": ["TEST_SAFE_CODE", "java."],
                "nodejs_output": ["TEST_SAFE_CODE", "console.log"],
                "error_indicators": ["PHP Parse error", "SyntaxError", "NameError"],
                "template_indicators": ["49"]
            }
        }

    def _build_command_payloads(self):
        """构建命令执行payload集合 - 优化选择"""
        payloads = {
            "unix_echo": [],
            "windows_echo": [],
            "unix_time": [],
            "windows_time": [],
            "conditional": []
        }
        
        config_payloads = self.cmd_config.get("payloads", {})
        
        # Unix payloads - 限制数量
        if "unix_generic" in config_payloads:
            unix = config_payloads["unix_generic"]
            
            if "echo_based" in unix:
                for payload in unix["echo_based"][:3]:  # 只取前3个
                    payloads["unix_echo"].append({
                        "payload": payload,
                        "os": "unix",
                        "type": "echo",
                        "separator": self._detect_separator(payload)
                    })
            
            if "time_based" in unix:
                for payload in unix["time_based"][:2]:  # 只取前2个
                    payloads["unix_time"].append({
                        "payload": payload,
                        "os": "unix",
                        "type": "time",
                        "separator": self._detect_separator(payload)
                    })
        
        # Windows payloads - 限制数量
        if "windows_generic" in config_payloads:
            windows = config_payloads["windows_generic"]
            
            if "echo_based" in windows:
                for payload in windows["echo_based"][:3]:  # 只取前3个
                    payloads["windows_echo"].append({
                        "payload": payload,
                        "os": "windows",
                        "type": "echo",
                        "separator": self._detect_separator(payload)
                    })
            
            if "time_based" in windows:
                for payload in windows["time_based"][:2]:  # 只取前2个
                    payloads["windows_time"].append({
                        "payload": payload,
                        "os": "windows",
                        "type": "time",
                        "separator": self._detect_separator(payload)
                    })
        
        # 条件payloads（用于验证）- 使用更安全的payload
        conditional_payloads = [
            {"payload": "; echo 'TEST_SAFE_CMD_1' && echo 'TEST_SAFE_CMD_2'", "os": "unix", "type": "conditional", "separator": ";"},
            {"payload": "& echo TEST_SAFE_CMD_1 && echo TEST_SAFE_CMD_2", "os": "windows", "type": "conditional", "separator": "&"}
        ]
        payloads["conditional"].extend(conditional_payloads)
        
        # 输出统计信息
        print(f"📦 加载命令执行payload: {sum(len(p) for p in payloads.values())} 个")
        
        return payloads

    def _build_code_payloads(self):
        """构建代码执行payload集合 - 优化选择"""
        payloads = {
            "php_direct": [],
            "python_eval": [],
            "nodejs_eval": [],
            "generic_template": []
        }
        
        config_payloads = self.code_config.get("payloads", {})
        
        # PHP payloads - 限制数量
        if "php_generic" in config_payloads:
            php = config_payloads["php_generic"]
            
            if "eval_based" in php:
                for payload in php["eval_based"][:3]:  # 只取前3个
                    payloads["php_direct"].append({
                        "payload": payload,
                        "language": "php",
                        "type": "eval",
                        "context": self._detect_context(payload)
                    })
        
        # Python payloads - 限制数量
        if "python_generic" in config_payloads:
            python = config_payloads["python_generic"]
            
            if "eval_based" in python:
                for payload in python["eval_based"][:3]:  # 只取前3个
                    payloads["python_eval"].append({
                        "payload": payload,
                        "language": "python",
                        "type": "eval",
                        "context": self._detect_context(payload)
                    })
        
        # Node.js payloads - 限制数量
        if "nodejs_generic" in config_payloads:
            nodejs = config_payloads["nodejs_generic"]
            
            if "eval_based" in nodejs:
                for payload in nodejs["eval_based"][:3]:  # 只取前3个
                    payloads["nodejs_eval"].append({
                        "payload": payload,
                        "language": "nodejs",
                        "type": "eval",
                        "context": self._detect_context(payload)
                    })
        
        # 通用模板注入payloads - 使用更安全的测试
        generic_template = [
            {"payload": "${7*7}", "language": "generic", "type": "template", "context": "injection"},
            {"payload": "#{7*7}", "language": "generic", "type": "template", "context": "injection"},
            {"payload": "{{7*7}}", "language": "generic", "type": "template", "context": "injection"},
            {"payload": "<%= 7*7 %>", "language": "generic", "type": "template", "context": "injection"}
        ]
        payloads["generic_template"].extend(generic_template)
        
        # 输出统计信息
        print(f"📦 加载代码执行payload: {sum(len(p) for p in payloads.values())} 个")
        
        return payloads

    def _get_command_indicators(self):
        """获取命令执行检测指示器"""
        indicators = self.cmd_config.get("indicators", {})
        
        # 添加默认指示器 - 更严格
        default_indicators = {
            "unix_output": ["TEST_SAFE_CMD", "root:", "bin/bash"],
            "windows_output": ["TEST_SAFE_CMD", "Windows"],
            "error_indicators": ["command not found", "is not recognized", "syntax error"],
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
        
        # 添加默认指示器 - 更严格
        default_indicators = {
            "php_output": ["TEST_SAFE_CODE", "PHP Version"],
            "python_output": ["TEST_SAFE_CODE", "Python"],
            "java_output": ["TEST_SAFE_CODE", "java."],
            "nodejs_output": ["TEST_SAFE_CODE", "console.log"],
            "error_indicators": ["PHP Parse error", "SyntaxError", "NameError"],
            "template_indicators": ["49"]
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
            result = self.request_queue.get_result(task_id, timeout=45)  # 合理超时
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
        """获取基准响应 - 改进版"""
        baseline_key = f"{url}_{param_name}_{method}"

        if baseline_key in self.baseline_responses:
            return self.baseline_responses[baseline_key]

        try:
            # 获取3次基准响应，取最稳定的
            responses = []
            for i in range(3):
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
                    responses.append(response)
                time.sleep(0.5)  # 短暂延迟

            if not responses:
                return None

            # 使用最长的响应作为基准（通常最完整）
            baseline_response = max(responses, key=lambda r: len(r['response'].get('content', '')))
            
            response_data = baseline_response['response']
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
                'hash': hashlib.md5(content.encode()).hexdigest() if content else '',
                'signature': self._calculate_content_signature(content)
            }

            self.baseline_responses[baseline_key] = baseline
            return baseline

        except Exception as e:
            print(f"获取基准响应失败: {e}")
            return None

    def _calculate_content_signature(self, content):
        """计算内容签名，用于快速比较"""
        if not content:
            return ""
        
        # 提取关键特征：行数、单词数、常见模式
        lines = content.split('\n')
        words = content.split()
        
        signature = {
            'line_count': len(lines),
            'word_count': len(words),
            'avg_line_length': sum(len(line) for line in lines) / max(len(lines), 1),
            'common_patterns': self._extract_common_patterns(content)
        }
        return signature

    def _extract_common_patterns(self, content):
        """提取常见模式"""
        patterns = []
        
        # 检测HTML标签
        html_tags = re.findall(r'<(div|span|p|a|img|form|input|button)[^>]*>', content, re.I)
        if html_tags:
            patterns.append(f"html_tags:{len(set(html_tags))}")
        
        # 检测数字
        numbers = re.findall(r'\b\d{3,}\b', content)
        if numbers:
            patterns.append(f"large_numbers:{len(numbers)}")
        
        # 检测错误模式
        error_patterns = ['error', 'exception', 'warning', 'notice', 'failed']
        for pattern in error_patterns:
            if pattern in content.lower():
                patterns.append(f"contains_{pattern}")
        
        return patterns

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
        """增强的基于回显的命令执行检测：多层验证 + 精准指示器识别"""
        vulnerabilities = []
        
        # 获取基准响应（用于对比）
        baseline = self.get_baseline_response(url, param_name, param_value, method, post_data)
        if not baseline:
            return vulnerabilities
            
        baseline_content = baseline.get('content', '')
        baseline_signature = baseline.get('signature', {})
        
        # ==================== Unix 命令执行测试 ====================
        for payload_info in self.command_payloads.get("unix_echo", [])[:3]:  # 减少测试数量
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
                
                # 第1层：基础相似度检查
                similarity = self._calculate_similarity(baseline_content, content)
                if similarity > 0.98:  # 非常高相似度，可能是误报
                    continue
                
                # 第2层：响应签名检查
                response_signature = self._calculate_content_signature(content)
                signature_diff = self._compare_signatures(baseline_signature, response_signature)
                
                # 第3层：精准指示器匹配（排除基准中已有的）
                unix_indicators = self.command_indicators.get("unix_output", [])
                matched_indicators = []
                
                for indicator in unix_indicators:
                    # 检查指示器是否在基准中已存在
                    if indicator in baseline_content:
                        continue
                    
                    # 检查指示器是否在新响应中出现
                    if indicator in content:
                        # 验证上下文 - 确保不是巧合
                        context = self._get_indicator_context(content, indicator)
                        if self._is_valid_command_context(context):
                            matched_indicators.append({
                                'indicator': indicator,
                                'context': context[:100],
                                'confidence': 0.9
                            })
                
                # 第4层：需要多重证据
                if matched_indicators and signature_diff > 0.3:
                    # 进一步验证：发送确认payload
                    confirm_payload = f"{param_value}; echo 'CONFIRM_TEST_{random.randint(1000,9999)}'"
                    confirm_response = self._send_command_test(url, param_name, confirm_payload, method, post_data)
                    
                    if confirm_response:
                        confirm_content = confirm_response['response'].get('content', '')
                        if 'CONFIRM_TEST_' in confirm_content:
                            vulnerabilities.append({
                                'type': 'Command Injection (Echo-Based)',
                                'payload': payload,
                                'os': 'Unix/Linux',
                                'confidence': '高',
                                'evidence': {
                                    'matched_indicators': [m['indicator'] for m in matched_indicators],
                                    'similarity': similarity,
                                    'signature_diff': signature_diff,
                                    'confirmed': True
                                },
                                'technique': 'Command output reflection',
                                'separator': separator,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break  # 找到一个有效漏洞即停止
            
            except Exception as e:
                print(f"[DEBUG] Unix echo 测试异常: {e}")
                continue
        
        # ==================== Windows 命令执行测试 ====================
        for payload_info in self.command_payloads.get("windows_echo", [])[:3]:  # 减少测试数量
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
                
                # 第1层：基础相似度检查
                similarity = self._calculate_similarity(baseline_content, content)
                if similarity > 0.98:
                    continue
                
                # 第2层：Windows 指示器匹配
                windows_indicators = self.command_indicators.get("windows_output", [])
                matched_indicators = []
                
                for indicator in windows_indicators:
                    if indicator in baseline_content:
                        continue
                    
                    if indicator in content:
                        context = self._get_indicator_context(content, indicator)
                        if self._is_valid_windows_context(context):
                            matched_indicators.append({
                                'indicator': indicator,
                                'context': context[:100],
                                'confidence': 0.9
                            })
                
                if matched_indicators:
                    # 确认测试
                    confirm_payload = f"{param_value}& echo CONFIRM_TEST_{random.randint(1000,9999)}"
                    confirm_response = self._send_command_test(url, param_name, confirm_payload, method, post_data)
                    
                    if confirm_response:
                        confirm_content = confirm_response['response'].get('content', '')
                        if 'CONFIRM_TEST_' in confirm_content:
                            vulnerabilities.append({
                                'type': 'Command Injection (Echo-Based)',
                                'payload': payload,
                                'os': 'Windows',
                                'confidence': '高',
                                'evidence': {
                                    'matched_indicators': [m['indicator'] for m in matched_indicators],
                                    'similarity': similarity,
                                    'confirmed': True
                                },
                                'technique': 'Command output reflection',
                                'separator': separator,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception as e:
                print(f"[DEBUG] Windows echo 测试异常: {e}")
                continue
        
        return vulnerabilities

    def detect_command_time_based(self, url, param_name, param_value, method, post_data):
        """增强的基于时间的命令执行检测：自适应阈值 + 多次验证"""
        vulnerabilities = []
        
        # ==================== 动态阈值计算 ====================
        # 获取多次基准响应时间（提高准确性）
        baseline_times = []
        for _ in range(5):  # 增加测量次数
            t = self._measure_response_time(url, param_name, param_value, method, post_data)
            if t != float('inf'):
                baseline_times.append(t)
            time.sleep(0.5)  # 测量间隔
        
        if len(baseline_times) < 3:
            return vulnerabilities
        
        # 计算统计信息
        baseline_times.sort()
        median_time = baseline_times[len(baseline_times)//2]  # 中位数
        avg_time = sum(baseline_times) / len(baseline_times)
        
        # 移除异常值
        filtered_times = [t for t in baseline_times if abs(t - median_time) / median_time < 0.5]
        if not filtered_times:
            filtered_times = baseline_times
        
        normal_time = sum(filtered_times) / len(filtered_times)
        std_dev = (sum((t - normal_time) ** 2 for t in filtered_times) / len(filtered_times)) ** 0.5
        
        # 动态阈值：考虑网络波动
        adaptive_threshold = normal_time + max(5.0, normal_time * 0.5 + std_dev * 3)
        
        print(f"[DEBUG] 时间基准: {normal_time:.2f}s ±{std_dev:.2f}s, 阈值: {adaptive_threshold:.2f}s")
        
        # ==================== Unix 时间盲注测试 ====================
        for payload_info in self.command_payloads.get("unix_time", [])[:2]:  # 减少测试数量
            payload = payload_info.get("payload", "")
            separator = payload_info.get("separator", "")
            
            try:
                test_value = f"{param_value}{payload}"
                
                # 第1次测试
                start_time1 = time.time()
                response1 = self._send_command_test(url, param_name, test_value, method, post_data, 
                                                   timeout=int(adaptive_threshold) + 10)
                elapsed_time1 = time.time() - start_time1
                
                if elapsed_time1 > adaptive_threshold:
                    # 第2次验证：不同延迟
                    alt_payload = payload.replace("5", "6")  # 稍微不同的延迟
                    alt_value = f"{param_value}{alt_payload}"
                    start_time2 = time.time()
                    response2 = self._send_command_test(url, param_name, alt_value, method, post_data,
                                                       timeout=int(adaptive_threshold) + 10)
                    elapsed_time2 = time.time() - start_time2
                    
                    # 第3次验证：正常请求对比
                    start_time3 = time.time()
                    response3 = self._send_command_test(url, param_name, param_value, method, post_data,
                                                       timeout=int(adaptive_threshold) + 10)
                    elapsed_time3 = time.time() - start_time3
                    
                    # 验证逻辑：延迟请求应明显慢于正常请求
                    if (elapsed_time1 > adaptive_threshold and 
                        elapsed_time2 > adaptive_threshold and
                        elapsed_time1 > elapsed_time3 * 2 and
                        elapsed_time2 > elapsed_time3 * 2):
                        
                        vulnerabilities.append({
                            'type': 'Command Injection (Time-Based)',
                            'payload': payload,
                            'os': 'Unix/Linux',
                            'confidence': '高',
                            'evidence': {
                                'baseline_time': round(normal_time, 2),
                                'test1_time': round(elapsed_time1, 2),
                                'test2_time': round(elapsed_time2, 2),
                                'normal_time': round(elapsed_time3, 2),
                                'threshold': round(adaptive_threshold, 2),
                                'std_dev': round(std_dev, 2)
                            },
                            'technique': 'Time-based blind injection',
                            'separator': separator
                        })
                        break
            
            except Exception as e:
                if "timeout" in str(e).lower():
                    # 验证超时是否真的由payload引起
                    try:
                        normal_response = self._send_command_test(url, param_name, param_value, method, post_data,
                                                                 timeout=10)
                        if normal_response:  # 正常请求应该不超时
                            vulnerabilities.append({
                                'type': 'Command Injection (Time-Based - Timeout)',
                                'payload': payload,
                                'os': 'Unix/Linux',
                                'confidence': '中',
                                'evidence': 'Payload请求超时，正常请求成功',
                                'technique': 'Time-based blind injection (timeout)',
                                'separator': separator
                            })
                    except:
                        pass
                continue
        
        # ==================== Windows 时间盲注测试 ====================
        for payload_info in self.command_payloads.get("windows_time", [])[:2]:  # 减少测试数量
            payload = payload_info.get("payload", "")
            separator = payload_info.get("separator", "")
            
            try:
                test_value = f"{param_value}{payload}"
                
                # 第1次测试
                start_time1 = time.time()
                response1 = self._send_command_test(url, param_name, test_value, method, post_data,
                                                   timeout=int(adaptive_threshold) + 10)
                elapsed_time1 = time.time() - start_time1
                
                if elapsed_time1 > adaptive_threshold:
                    # 第2次验证
                    alt_payload = payload.replace("5", "6")
                    alt_value = f"{param_value}{alt_payload}"
                    start_time2 = time.time()
                    response2 = self._send_command_test(url, param_name, alt_value, method, post_data,
                                                       timeout=int(adaptive_threshold) + 10)
                    elapsed_time2 = time.time() - start_time2
                    
                    # 正常请求
                    start_time3 = time.time()
                    response3 = self._send_command_test(url, param_name, param_value, method, post_data,
                                                       timeout=int(adaptive_threshold) + 10)
                    elapsed_time3 = time.time() - start_time3
                    
                    if (elapsed_time1 > adaptive_threshold and 
                        elapsed_time2 > adaptive_threshold and
                        elapsed_time1 > elapsed_time3 * 2 and
                        elapsed_time2 > elapsed_time3 * 2):
                        
                        vulnerabilities.append({
                            'type': 'Command Injection (Time-Based)',
                            'payload': payload,
                            'os': 'Windows',
                            'confidence': '高',
                            'evidence': {
                                'baseline_time': round(normal_time, 2),
                                'test1_time': round(elapsed_time1, 2),
                                'test2_time': round(elapsed_time2, 2),
                                'normal_time': round(elapsed_time3, 2),
                                'threshold': round(adaptive_threshold, 2)
                            },
                            'technique': 'Time-based blind injection',
                            'separator': separator
                        })
                        break
            
            except Exception as e:
                if "timeout" in str(e).lower():
                    try:
                        normal_response = self._send_command_test(url, param_name, param_value, method, post_data,
                                                                 timeout=10)
                        if normal_response:
                            vulnerabilities.append({
                                'type': 'Command Injection (Time-Based - Timeout)',
                                'payload': payload,
                                'os': 'Windows',
                                'confidence': '中',
                                'evidence': 'Payload请求超时，正常请求成功',
                                'technique': 'Time-based blind injection (timeout)',
                                'separator': separator
                            })
                    except:
                        pass
        
        return vulnerabilities

    def detect_command_conditional(self, url, param_name, param_value, method, post_data):
        """条件命令执行检测"""
        vulnerabilities = []
        
        for payload_info in self.command_payloads.get("conditional", [])[:2]:
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
                    
                    # 检查两个测试字符串是否都出现
                    if "TEST_SAFE_CMD_1" in content and "TEST_SAFE_CMD_2" in content:
                        # 进一步验证顺序
                        idx1 = content.find("TEST_SAFE_CMD_1")
                        idx2 = content.find("TEST_SAFE_CMD_2")
                        if idx1 < idx2:  # 确保顺序正确
                            vulnerabilities.append({
                                'type': 'Command Injection (Conditional)',
                                'payload': payload,
                                'os': os_type,
                                'confidence': '高',
                                'evidence': '条件命令执行验证成功',
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
        """
        vulnerabilities = []
        
        # 获取基准响应
        baseline = self.get_baseline_response(url, param_name, param_value, method, post_data)
        if not baseline:
            return vulnerabilities
            
        baseline_content = baseline.get('content', '')
        
        # 测试PHP eval payloads
        for payload_info in self.code_payloads.get("php_direct", [])[:2]:
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
                    
                    # 多层验证
                    evidence_points = 0
                    evidence_list = []
                    
                    # 1. 相似度检查（排除高度相似的响应）
                    similarity = self._calculate_similarity(baseline_content, content)
                    if similarity > 0.99:
                        continue  # 响应几乎相同，可能是误报
                    
                    # 2. 检查特定输出（排除基准中已有的）
                    php_indicators = self.code_indicators.get("php_output", [])
                    for indicator in php_indicators:
                        if indicator in baseline_content:
                            continue  # 基准中已有，跳过
                        
                        if indicator in content:
                            # 验证上下文
                            ctx = self._get_indicator_context(content, indicator)
                            if self._is_valid_php_context(ctx):
                                evidence_points += 2
                                evidence_list.append(f"PHP输出: {indicator}")
                                break
                    
                    # 3. 检查错误堆栈（必须是新的错误）
                    php_errors = ["PHP Parse error", "PHP Warning", "PHP Notice", "PHP Fatal error"]
                    for error in php_errors:
                        if error in content and error not in baseline_content:
                            # 验证错误上下文
                            error_context = self._extract_error_context(content, error)
                            if error_context and len(error_context) > 20:  # 确保有足够上下文
                                evidence_points += 3
                                evidence_list.append(f"PHP错误: {error}")
                                break
                    
                    # 4. 响应长度变化检查（排除微小变化）
                    length_diff = abs(len(content) - len(baseline_content))
                    if length_diff > 100:  # 显著变化
                        evidence_points += 1
                        evidence_list.append(f"响应长度变化: {length_diff}字符")
                    
                    # 5. 确认测试
                    if evidence_points >= 3:  # 需要足够证据
                        confirm_id = random.randint(10000, 99999)
                        confirm_payload = f"{param_value}; echo 'PHP_CONFIRM_{confirm_id}';"
                        confirm_response = self._send_code_test(url, param_name, confirm_payload, method, post_data)
                        
                        if confirm_response:
                            confirm_content = confirm_response['response'].get('content', '')
                            if f'PHP_CONFIRM_{confirm_id}' in confirm_content:
                                evidence_points += 2
                                evidence_list.append(f"确认测试成功: PHP_CONFIRM_{confirm_id}")
                    
                    # 最终判断
                    if evidence_points >= 4:  # 高阈值
                        confidence = '高' if evidence_points >= 5 else '中'
                        vulnerabilities.append({
                            'type': 'Code Injection (Eval-Based)',
                            'payload': payload,
                            'language': language,
                            'confidence': confidence,
                            'evidence': " | ".join(evidence_list),
                            'technique': 'PHP eval() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'evidence_points': evidence_points
                        })
            
            except Exception as e:
                print(f"[DEBUG] PHP检测异常: {e}")
                continue
        
        # 测试Python eval payloads
        for payload_info in self.code_payloads.get("python_eval", [])[:2]:
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
                    
                    evidence_points = 0
                    evidence_list = []
                    
                    # 相似度检查
                    similarity = self._calculate_similarity(baseline_content, content)
                    if similarity > 0.99:
                        continue
                    
                    # Python特定检查
                    python_indicators = ["Python", "Traceback", "NameError", "SyntaxError", "TypeError"]
                    for indicator in python_indicators:
                        if indicator in content and indicator not in baseline_content:
                            evidence_points += 2
                            evidence_list.append(f"Python特征: {indicator}")
                            break
                    
                    # 确认测试
                    if evidence_points >= 2:
                        confirm_id = random.randint(10000, 99999)
                        confirm_payload = f"{param_value}'; print('PY_CONFIRM_{confirm_id}') #"
                        confirm_response = self._send_code_test(url, param_name, confirm_payload, method, post_data)
                        
                        if confirm_response:
                            confirm_content = confirm_response['response'].get('content', '')
                            if f'PY_CONFIRM_{confirm_id}' in confirm_content:
                                evidence_points += 2
                                evidence_list.append(f"确认测试成功: PY_CONFIRM_{confirm_id}")
                    
                    if evidence_points >= 3:
                        confidence = '高' if evidence_points >= 4 else '中'
                        vulnerabilities.append({
                            'type': 'Code Injection (Eval-Based)',
                            'payload': payload,
                            'language': language,
                            'confidence': confidence,
                            'evidence': " | ".join(evidence_list),
                            'technique': 'Python eval()/exec() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'evidence_points': evidence_points
                        })
            
            except Exception:
                continue
        
        # 测试Node.js eval payloads
        for payload_info in self.code_payloads.get("nodejs_eval", [])[:2]:
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
                    
                    evidence_points = 0
                    evidence_list = []
                    
                    similarity = self._calculate_similarity(baseline_content, content)
                    if similarity > 0.99:
                        continue
                    
                    nodejs_indicators = ["ReferenceError", "TypeError", "console.log", "at Object."]
                    for indicator in nodejs_indicators:
                        if indicator in content and indicator not in baseline_content:
                            evidence_points += 2
                            evidence_list.append(f"Node.js特征: {indicator}")
                            break
                    
                    if evidence_points >= 2:
                        confirm_id = random.randint(10000, 99999)
                        confirm_payload = f"{param_value}'; console.log('NODE_CONFIRM_{confirm_id}') //"
                        confirm_response = self._send_code_test(url, param_name, confirm_payload, method, post_data)
                        
                        if confirm_response:
                            confirm_content = confirm_response['response'].get('content', '')
                            if f'NODE_CONFIRM_{confirm_id}' in confirm_content:
                                evidence_points += 2
                                evidence_list.append(f"确认测试成功: NODE_CONFIRM_{confirm_id}")
                    
                    if evidence_points >= 3:
                        confidence = '高' if evidence_points >= 4 else '中'
                        vulnerabilities.append({
                            'type': 'Code Injection (Eval-Based)',
                            'payload': payload,
                            'language': language,
                            'confidence': confidence,
                            'evidence': " | ".join(evidence_list),
                            'technique': 'Node.js eval() execution',
                            'context': context,
                            'response_code': response['response'].get('status_code', 0),
                            'evidence_points': evidence_points
                        })
            
            except Exception:
                continue
        
        return vulnerabilities

    def detect_code_template_injection(self, url, param_name, param_value, method, post_data):
        """
        模板注入检测 - 多验证层和计算表达式验证
        """
        vulnerabilities = []
        
        baseline = self.get_baseline_response(url, param_name, param_value, method, post_data)
        if not baseline:
            return vulnerabilities
            
        baseline_content = baseline.get('content', '')
        
        # 使用随机数避免固定模式误报
        test_number = random.randint(100, 999)
        expected_result = test_number * test_number
        
        # 测试各种模板语法
        template_payloads = [
            {"template": f"${{{test_number}*{test_number}}}", "engine": "通用表达式", "type": "dollar_brace"},
            {"template": f"#{{{test_number}*{test_number}}}", "engine": "通用表达式", "type": "hash_brace"},
            {"template": f"{{{test_number}*{test_number}}}", "engine": "Jinja2/Handlebars", "type": "double_brace"},
            {"template": f"<%= {test_number}*{test_number} %>", "engine": "ERB/EJS", "type": "percent_equal"},
        ]
        
        for payload_config in template_payloads:
            template_payload = payload_config["template"]
            engine = payload_config["engine"]
            
            try:
                test_value = f"{param_value}{template_payload}"
                response = self._send_code_test(url, param_name, test_value, method, post_data)
                
                if response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content)
                    
                    # 关键验证：是否返回计算结果
                    result_str = str(expected_result)
                    if result_str in content and result_str not in baseline_content:
                        # 进一步验证：使用不同计算
                        test_number2 = random.randint(50, 150)
                        expected_result2 = test_number2 + test_number2
                        confirm_payload = f"{param_value}${{{test_number2}+{test_number2}}}"
                        confirm_response = self._send_code_test(url, param_name, confirm_payload, method, post_data)
                        
                        if confirm_response:
                            confirm_content = confirm_response['response'].get('content', '')
                            confirm_result = str(expected_result2)
                            if confirm_result in confirm_content:
                                vulnerabilities.append({
                                    'type': 'Template Injection',
                                    'payload': template_payload,
                                    'language': 'generic',
                                    'template_engine': engine,
                                    'confidence': '高',
                                    'evidence': f"模板计算验证成功: {template_payload} = {result_str} (二次确认成功)",
                                    'technique': 'Template expression evaluation',
                                    'verified': True,
                                    'response_code': response['response'].get('status_code', 0)
                                })
                                break  # 找到一个即可
                    
                    # 如果没有直接计算结果，检查模板错误
                    template_errors = ["TemplateSyntaxError", "TemplateNotFound", "template error", "render error"]
                    for error in template_errors:
                        if error in content.lower() and error not in baseline_content.lower():
                            vulnerabilities.append({
                                'type': 'Template Injection',
                                'payload': template_payload,
                                'language': 'generic',
                                'template_engine': engine,
                                'confidence': '中',
                                'evidence': f"检测到模板引擎错误: {error}",
                                'technique': 'Template engine interaction',
                                'verified': False,
                                'response_code': response['response'].get('status_code', 0)
                            })
                            break
            
            except Exception:
                continue
        
        return vulnerabilities

    def _calculate_similarity(self, text1, text2):
        """计算两个文本的相似度（使用改进算法）"""
        if not text1 or not text2:
            return 0.0
        
        if text1 == text2:
            return 1.0
        
        # 使用difflib的SequenceMatcher（更准确）
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return matcher.ratio()

    def _compare_signatures(self, sig1, sig2):
        """比较两个签名"""
        if not sig1 or not sig2:
            return 0.0
        
        diff = 0
        total = 0
        
        for key in sig1:
            if key in sig2:
                if isinstance(sig1[key], (int, float)) and isinstance(sig2[key], (int, float)):
                    diff += abs(sig1[key] - sig2[key]) / max(sig1[key], sig2[key], 1)
                    total += 1
        
        return diff / max(total, 1)

    def _get_indicator_context(self, text, indicator, window=100):
        """获取指示器上下文"""
        if indicator not in text:
            return ""
        
        idx = text.find(indicator)
        start = max(0, idx - window)
        end = min(len(text), idx + len(indicator) + window)
        
        return text[start:end]

    def _is_valid_command_context(self, context):
        """验证命令执行的上下文是否有效"""
        # 排除常见的误报模式
        false_positives = [
            "<!--",  # HTML注释
            "function",  # JavaScript函数
            "var ",  # JavaScript变量
            "const ",  # JavaScript常量
            "let ",  # JavaScript变量
            "<script",  # 脚本标签
            "echo",  # 可能是页面文本
            "print",  # 可能是页面文本
        ]
        
        for fp in false_positives:
            if fp in context:
                return False
        
        return True

    def _is_valid_windows_context(self, context):
        """验证Windows命令执行的上下文是否有效"""
        # Windows特定的误报检查
        false_positives = [
            "Windows",  # 可能是页面关于Windows的内容
            "Microsoft",  # 可能是页面文本
            "C:\\",  # 可能是路径文本
            "cmd.exe",  # 可能是文档内容
        ]
        
        for fp in false_positives:
            if fp in context and context.count(fp) < 2:  # 如果只出现一次，可能是误报
                return False
        
        return True

    def _is_valid_php_context(self, context):
        """验证PHP执行的上下文是否有效"""
        false_positives = [
            "<?php",  # 可能是页面源码
            "PHP Version",  # 可能是页面信息
            "phpinfo()",  # 可能是文档
        ]
        
        for fp in false_positives:
            if fp in context:
                # 检查是否是代码执行（应该有输出）
                if "()" in fp and "echo" not in context and "print" not in context:
                    return True
                return False
        
        return True

    def _extract_error_context(self, text, error_pattern):
        """提取错误上下文"""
        import re
        pattern = re.escape(error_pattern) + r'.*?(?:\n\n|\r\n\r\n|$)'
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(0)
        return ""

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
            if not baseline:
                print("⚠️  无法获取基准响应，跳过命令注入检测")
                return [], self.results

            print("\n[1/3] 基于回显的命令执行检测...")
            echo_results = self.detect_command_echo_based(url, param_name or "cmd", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_command_vulnerability(vuln, url, param_name, method) for vuln in echo_results])

            print("[2/3] 基于时间的命令执行检测...")
            time_results = self.detect_command_time_based(url, param_name or "cmd", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_command_vulnerability(vuln, url, param_name, method) for vuln in time_results])

            print("[3/3] 条件命令执行检测...")
            conditional_results = self.detect_command_conditional(url, param_name or "cmd", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_command_vulnerability(vuln, url, param_name, method) for vuln in conditional_results])

            # 过滤误报
            vulnerabilities = self.false_positive_filter.filter_command_vulnerabilities(vulnerabilities)

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
                            evidence_str = ', '.join([f'{k}: {v}' for k, v in vuln['evidence'].items()][:3])
                            print(f"   证据: {evidence_str}")
                        else:
                            print(f"   证据: {vuln['evidence'][:100]}...")

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
            if not baseline:
                print("⚠️  无法获取基准响应，跳过代码注入检测")
                return [], self.results

            print("\n[1/2] 基于eval的代码执行检测...")
            eval_results = self.detect_code_eval_based(url, param_name or "code", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_code_vulnerability(vuln, url, param_name, method) for vuln in eval_results])

            print("[2/2] 模板注入检测...")
            template_results = self.detect_code_template_injection(url, param_name or "code", param_value or "test", method, post_data)
            vulnerabilities.extend([self._format_code_vulnerability(vuln, url, param_name, method) for vuln in template_results])

            # 过滤误报
            vulnerabilities = self.false_positive_filter.filter_code_vulnerabilities(vulnerabilities)

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
                            evidence_str = ', '.join([f'{k}: {v}' for k, v in vuln['evidence'].items()][:3])
                            print(f"   证据: {evidence_str}")
                        else:
                            print(f"   证据: {vuln['evidence'][:100]}...")

            # 更新全局结果
            self.results['vulnerabilities'].extend(vulnerabilities)

            return vulnerabilities, self.results

        except Exception as e:
            print(f"❌ 代码注入检测过程中发生错误: {e}")
            import traceback
            traceback.print_exc()
            return [], self.results

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
                        evidence_keys = list(vuln['evidence'].keys())[:3]
                        print(f"   证据: {evidence_keys}")
                    else:
                        print(f"   证据: {vuln['evidence'][:100]}...")
                print()
        
        return all_vulnerabilities, self.results


# ==================== 辅助类 ====================

class BaselineLearner:
    """智能基准学习器"""
    
    def __init__(self):
        self.baselines = {}
        self.pattern_cache = {}
    
    def learn_baseline(self, url, responses):
        """学习正常响应模式"""
        if not responses:
            return None
        
        # 分析响应特征
        features = {
            'common_content': self._extract_common_content(responses),
            'response_codes': [r.get('status_code', 0) for r in responses],
            'content_lengths': [len(r.get('content', '')) for r in responses],
            'patterns': self._extract_common_patterns(responses)
        }
        
        self.baselines[url] = features
        return features
    
    def _extract_common_content(self, responses):
        """提取共同内容"""
        if len(responses) < 2:
            return responses[0].get('content', '') if responses else ''
        
        # 使用最长公共子序列算法
        contents = [r.get('content', '') for r in responses]
        return self._find_common_substring(contents)
    
    def _find_common_substring(self, strings):
        """查找共同子字符串"""
        if not strings:
            return ""
        
        # 使用最短字符串作为基准
        shortest = min(strings, key=len)
        max_len = len(shortest)
        
        for length in range(max_len, 0, -1):
            for start in range(max_len - length + 1):
                substring = shortest[start:start+length]
                if all(substring in s for s in strings):
                    return substring
        
        return ""
    
    def _extract_common_patterns(self, responses):
        """提取常见模式"""
        patterns = []
        contents = [r.get('content', '') for r in responses]
        
        # 检测HTML结构
        html_tags = set()
        for content in contents:
            tags = re.findall(r'<([a-zA-Z][a-zA-Z0-9]*)[^>]*>', content)
            html_tags.update(tags)
        
        if html_tags:
            patterns.append(f"html_tags:{len(html_tags)}")
        
        # 检测常见模式
        common_patterns = [
            (r'\b\d{3,}\b', 'large_numbers'),
            (r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', 'email'),
            (r'https?://[^\s]+', 'url'),
        ]
        
        for pattern, name in common_patterns:
            count = sum(len(re.findall(pattern, c)) for c in contents) / len(contents)
            if count > 0:
                patterns.append(f"{name}:{int(count)}")
        
        return patterns


class FalsePositiveFilter:
    """误报过滤器"""
    
    def __init__(self):
        self.false_positive_patterns = [
            # HTML/JS 相关
            (r'<script[^>]*>.*?</script>', 'javascript_code'),
            (r'function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(', 'javascript_function'),
            (r'var\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=', 'javascript_var'),
            (r'console\.log\(', 'console_log'),
            
            # 常见页面内容
            (r'error\s+page', 'error_page'),
            (r'404\s+not\s+found', '404_page'),
            (r'page\s+not\s+found', 'not_found'),
            (r'internal\s+server\s+error', '500_error'),
            
            # 文档/帮助文本
            (r'usage:', 'usage_text'),
            (r'example:', 'example_text'),
            (r'syntax:', 'syntax_text'),
            
            # 代码示例（非执行）
            (r'```[a-zA-Z]*\n.*?\n```', 'code_block'),
            (r'<code>.*?</code>', 'html_code_tag'),
            (r'<pre>.*?</pre>', 'html_pre_tag'),
        ]
    
    def filter_command_vulnerabilities(self, vulnerabilities):
        """过滤命令注入误报"""
        filtered = []
        
        for vuln in vulnerabilities:
            if not self._is_false_positive(vuln, 'command'):
                filtered.append(vuln)
        
        return filtered
    
    def filter_code_vulnerabilities(self, vulnerabilities):
        """过滤代码注入误报"""
        filtered = []
        
        for vuln in vulnerabilities:
            if not self._is_false_positive(vuln, 'code'):
                filtered.append(vuln)
        
        return filtered
    
    def _is_false_positive(self, vulnerability, vuln_type):
        """检查是否是误报"""
        # 检查证据
        evidence = vulnerability.get('evidence', '')
        evidence_str = str(evidence)
        
        # 应用误报模式
        for pattern, pattern_name in self.false_positive_patterns:
            if re.search(pattern, evidence_str, re.IGNORECASE | re.DOTALL):
                print(f"[误报过滤] 排除 {vulnerability['type']}: 匹配模式 {pattern_name}")
                return True
        
        # 类型特定检查
        if vuln_type == 'command':
            return self._check_command_false_positive(vulnerability)
        elif vuln_type == 'code':
            return self._check_code_false_positive(vulnerability)
        
        return False
    
    def _check_command_false_positive(self, vulnerability):
        """检查命令注入误报"""
        # 检查是否为常见的管理页面输出
        evidence = vulnerability.get('evidence', '')
        evidence_str = str(evidence).lower()
        
        false_positives = [
            'server status', 'system info', 'server information',
            'uptime', 'load average', 'memory usage',
            'disk usage', 'process list', 'who is online'
        ]
        
        for fp in false_positives:
            if fp in evidence_str:
                print(f"[命令误报过滤] 排除: 可能是管理页面信息")
                return True
        
        return False
    
    def _check_code_false_positive(self, vulnerability):
        """检查代码注入误报"""
        # 检查是否为代码文档或示例
        evidence = vulnerability.get('evidence', '')
        evidence_str = str(evidence).lower()
        
        false_positives = [
            'code example', 'sample code', 'tutorial',
            'documentation', 'api reference', 'developer guide',
            'php manual', 'python docs', 'java documentation'
        ]
        
        for fp in false_positives:
            if fp in evidence_str:
                print(f"[代码误报过滤] 排除: 可能是文档内容")
                return True
        
        return False


class ContextAnalyzer:
    """上下文分析器"""
    
    def __init__(self):
        pass
    
    def analyze_response_context(self, content):
        """分析响应上下文"""
        analysis = {
            'is_html': self._is_html(content),
            'is_json': self._is_json(content),
            'is_xml': self._is_xml(content),
            'is_plain_text': self._is_plain_text(content),
            'contains_code': self._contains_code(content),
            'contains_errors': self._contains_errors(content),
            'structure_type': self._detect_structure_type(content)
        }
        
        return analysis
    
    def _is_html(self, content):
        """检查是否为HTML"""
        html_indicators = ['<!DOCTYPE', '<html', '<head', '<body', '<div', '<span', '<p>']
        return any(indicator in content[:1000].lower() for indicator in html_indicators)
    
    def _is_json(self, content):
        """检查是否为JSON"""
        content = content.strip()
        return (content.startswith('{') and content.endswith('}')) or \
               (content.startswith('[') and content.endswith(']'))
    
    def _is_xml(self, content):
        """检查是否为XML"""
        xml_indicators = ['<?xml', '<root>', '<response>', '<error>']
        return any(indicator in content[:500].lower() for indicator in xml_indicators)
    
    def _is_plain_text(self, content):
        """检查是否为纯文本"""
        # 如果没有HTML/XML/JSON特征，且长度合理，可能是纯文本
        return not (self._is_html(content) or self._is_json(content) or self._is_xml(content))
    
    def _contains_code(self, content):
        """检查是否包含代码"""
        code_indicators = [
            'function(', 'var ', 'const ', 'let ', 'class ', 'def ',
            'import ', 'require(', 'include(', 'echo ', 'print ',
            'System.out.', 'console.log', 'printf('
        ]
        
        content_lower = content.lower()
        for indicator in code_indicators:
            if indicator in content_lower:
                return True
        return False
    
    def _contains_errors(self, content):
        """检查是否包含错误信息"""
        error_indicators = [
            'error', 'exception', 'warning', 'notice', 'failed',
            'invalid', 'not found', 'undefined', 'null pointer',
            'syntax error', 'parse error', 'fatal error'
        ]
        
        content_lower = content.lower()
        return any(error in content_lower for error in error_indicators)
    
    def _detect_structure_type(self, content):
        """检测结构类型"""
        if self._is_html(content):
            return 'html'
        elif self._is_json(content):
            return 'json'
        elif self._is_xml(content):
            return 'xml'
        elif self._contains_code(content):
            return 'code'
        elif self._contains_errors(content):
            return 'error'
        else:
            return 'text'


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