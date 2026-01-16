import requests
import logging
import sys
import os
import time
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse,parse_qs,urljoin

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from modules.request_manager import RateLimiter
    from modules.request_queue import RequestQueueManager
    from modules.request_sender import RequestSender
    from modules.request_builder import RequestBuilder
    from modules.response_parse import ResponseParse
    from utils import load_config,load_sqli_payload,load_xss_payload
except ImportError as e:
    print(f"导入模块失败: {e}")
    sys.exit(1)

class sampilescanner:
    def __init__(self,config=None):
        self.config=config or load_config()
        self.session=requests.Session()
        self.session.headers.update({
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; rv:109.0) Gecko/20100101 Firefox/115.0"
        })
        #获取日志记录器
        self.logger=logging.getLogger('vuln_scanner.scan.port')

        # 初始化速率限制器
        self.rate_limiter=RateLimiter(
            max_requests_per_second=self.config.get("max_requests_pre_second",10),
            max_requests_per_minute=self.config.get("max_requests_per_minute",60)
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

        #xss检测配置
        self.xss_payloads=load_xss_payload()
        self.xss_indicators=[
            "<script>alert",
            "<script>confirm",
            "<script>prompt",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "<svg/onload=",
            "<img src=x onerror=",
            "<body onload=",
            "<iframe src="
        ]

        # 结果存储
        self.results = {
            "requests": [],
            "responses": [],
            "statistics":[],
            'vulnerabilities': [],
        }

    def _collect_statistics(self):
        """收集统计信息"""
        self.results['statistics'] = {
            'request_stats': self.request_sender.get_statistics(),
            'queue_stats': self.request_queue.get_statistics(),
            'rate_limit_stats': self.rate_limiter.get_stats(),
            'scan_duration': f"{time.time():.2f}s"
        }

    def send_controlled_request(self, request_info):
        """发送受控制的请求"""
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
                cookies=request_info.get('cookies'),
                allow_redirects=request_info.get('allow_redirects', True)
            )
            
            # 解析响应
            parsed_response = self.response_parser.parse_response(
                response,
                extract_links=True,
                extract_forms=True,
                base_url=url
            )
            
            return {
                'request': request_info,
                'response': {
                    'status_code': response.status_code,
                    'url': str(response.url),
                    'headers': dict(response.headers),
                    'content_length': len(response.content)
                },
                'parsed': parsed_response
            }
        
        # 提交到队列
        task_id = f"req_{int(time.time() * 1000)}_{hash(str(request_info)) % 10000}"
        
        self.request_queue.submit(task_id, _make_request)
        
        # 等待结果
        try:
            result = self.request_queue.get_result(task_id, timeout=30)
            
            # 记录结果
            self._record_request_result(result)
            
            return result
            
        except Exception as e:
            # self.logger.error_logger.error(f"请求失败: {request_info.get('url')} - {e}")
            return None

    def _record_request_result(self, result):
        """记录请求结果"""
        if not result:
            return
        
        self.results['requests'].append(result['request']) 
        self.results['responses'].append(result['response'])
        self._collect_statistics()

    def check_sql_injection(self, url_input):
        """
        SQL注入扫描
    支持单个URL字符串或URL列表
    
    Args:
        url_input: 单个URL字符串 或 URL列表
    
    Returns:
        list: 发现的漏洞列表
        """ 
    # SQL注入测试载荷
        testpayloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
        ]

        # SQL错误指示器（全部小写以便比较）
        error_indicators = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "sql syntax",
            "mysql_fetch",
            "syntax error",
            "mysql_num_rows",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "welcome",
            "dhakkan"
        ]

        vulnerabilities = []

        # 统一处理输入：将单个URL转换为列表
        if isinstance(url_input, str):
            urls = [url_input]
        elif isinstance(url_input, list):
            urls = url_input
        else:
            raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")

        # 对每个URL进行测试
        for url in urls:
            # 确保URL是字符串
            if not isinstance(url, str):
                print(f"跳过非字符串URL: {url}")
                continue
            
            print(f"\n开始测试URL: {url}")

            # 对当前URL测试所有payload
            for payload in testpayloads:
                try:
                    # 构建测试 URL（保证 base 有结尾斜杠再 join）
                    base = url if url.endswith('/') else url + '/'
                    test_url = urljoin(base, 'sqli-labs-master/Less-5/')
                    params = {'id': f"1{payload}"}

                    print(f"  测试payload: {payload}")
                    print(f"  请求URL: {test_url}")
                    print(f"  参数: {params}")

                    if test_url:
                        request_info={
                            'method' : 'GET',
                            'url':test_url,
                            'headers':{},
                            'params' : params
                        }
                    response=self.send_controlled_request(request_info)
                    
                    if response is None:
                    # 修复logger调用 - 根据你的实际logger结构调整
                        if hasattr(self.logger, 'error'):
                            self.logger.error(f"请求失败，响应为None: {url}")                        
                        else:
                            print(f"请求失败，响应为None: {url}")
                        continue
                
                    # 检查解析的内容是否存在
                    if 'parsed' not in response:
                        error_msg = f"响应中没有parsed字段: {url}"
                        if hasattr(self.logger, 'error'):
                            self.logger.error(error_msg)
                        else:
                            print(error_msg)
                        continue
                    body=str(response['parsed']['parsed_content'])
                    #print(body)

                    # response = self.session.get(test_url, params=params, timeout=5)#修改成包，利用受控制的请求发包
                    # body = response.text.lower()
                    # print(str(body))
                    # print("---------------------------------")
                    # print(body)
                    # 检查是否有SQL错误指示器
                    found_error = False
                    for error in error_indicators:
                        if error in str(body).lower():
                            vulnerabilities.append({
                                "url": url,  # 原始URL
                                "type": "SQL Injection",
                                "payload": payload,
                                "confidence": "低",
                                "tested_url": test_url,
                                "params": params,
                                "error_indicator": error,
                                "response_code": response['response']['status_code']
                            })
                            found_error = True
                            print(f"  发现SQL注入漏洞！错误指示: {error}")
                            break
                        
                    if not found_error:
                        print(f"  未发现漏洞")

                except requests.exceptions.Timeout:
                    print(f"  请求超时: {url}")
                    continue
                except requests.exceptions.RequestException as e:
                    print(f"  请求错误: {e}")
                    continue
                except Exception as e:
                    print(f"  其他错误: {e}")
                    continue
                
        # 统计结果
        print(f"\n扫描完成！共发现 {len(vulnerabilities)} 个SQL注入漏洞")
        scan_results=self.results
        return vulnerabilities,scan_results

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
        """检测响应中是否存在XSS漏洞
        
        Args:
            response_text: 响应文本
            payload: 使用的payload
            original_value: 参数原始值（用于对比）
            
        Returns:
            tuple: (是否发现漏洞, 置信度, 详细信息)
        """
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
            
            print(f"\n[+] 开始XSS扫描URL: {url}")
            
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
        print(f"\n{'='*60}")
        print(f"扫描完成！共发现 {len(vulnerabilities)} 个XSS漏洞")
        
        # 按置信度排序
        vulnerabilities.sort(key=lambda x: {"高": 0, "中": 1, "低": 2}[x.get("confidence", "低")])
        
        # 输出详细结果
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n漏洞 #{i}:")
            print(f"  类型: {vuln['type']}")
            print(f"  URL: {vuln['url']}")
            print(f"  参数: {vuln.get('parameter', 'N/A')}")
            print(f"  方法: {vuln.get('method', 'GET')}")
            print(f"  置信度: {vuln['confidence']}")
            print(f"  详情: {vuln['details']}")
        
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
        
        return vulnerabilities,self.results

    # def save_results(self, filename=None):
    #     """保存扫描结果到文件"""
    #     if not filename:
    #         timestamp = time.strftime("%Y%m%d_%H%M%S")
    #         filename = f"xss_scan_results_{timestamp}.json"
        
    #     try:
    #         with open(filename, 'w', encoding='utf-8') as f:
    #             # 转换结果以便序列化
    #             serializable_results = self.results.copy()
                
    #             # 确保所有数据可序列化
    #             def make_serializable(obj):
    #                 if isinstance(obj, dict):
    #                     return {k: make_serializable(v) for k, v in obj.items()}
    #                 elif isinstance(obj, list):
    #                     return [make_serializable(item) for item in obj]
    #                 elif hasattr(obj, '__dict__'):
    #                     return str(obj)
    #                 else:
    #                     return obj
                
    #             serializable_results = make_serializable(serializable_results)
                
    #             json.dump(serializable_results, f, indent=2, ensure_ascii=False)
            
    #         print(f"[+] 结果已保存到: {filename}")
    #         return filename
        
    #     except Exception as e:
    #         print(f"[-] 保存结果失败: {e}")
    #         return None
    
    # def check_xss(self, url_input):
    #     """ XSS扫描"""
    #     # testpayloads=[
    #     #     "<script>alert('XSS')</script>",
    #     #     "\"><script>alert('XSS')</script>",
    #     #     "'><script>alert('XSS')</script>",
    #     # ]
    #     testpayloads=load_xss_payload()

    #     vulnerabilities=[]

    #      # 统一处理输入：将单个URL转换为列表
    #     if isinstance(url_input, str):
    #         urls = [url_input]
    #     elif isinstance(url_input, list):
    #         urls = url_input
    #     else:
    #         raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")
        
    #     for url in urls:
    #          # 确保URL是字符串
    #         if not isinstance(url, str):
    #             print(f"跳过非字符串URL: {url}")
    #             continue
            
    #         print(f"\n开始测试URL: {url}")

    #         for payload in testpayloads:
    #             try:
    #                 test_url=f"{url}?test={payload}"
    #                 print(test_url)
    #                 if test_url:
    #                     request_info={
    #                         'method' : 'GET',
    #                         'url':test_url,
    #                         'headers':{}
    #                     }
    #                 response=self.send_controlled_request(request_info)
    #                 if response is None:
    #                 # 修复logger调用 - 根据你的实际logger结构调整
    #                     if hasattr(self.logger, 'error'):
    #                         self.logger.error(f"请求失败，响应为None: {url}")
    #                     elif isinstance(self.logger, dict) and 'error_logger' in self.logger:
    #                         self.logger['error_logger'].error(f"请求失败，响应为None: {url}")
    #                     else:
    #                         print(f"请求失败，响应为None: {url}")
    #                     continue
                
    #                 # 检查解析的内容是否存在
    #                 if 'parsed' not in response:
    #                     error_msg = f"响应中没有parsed字段: {url}"
    #                     if hasattr(self.logger, 'error'):
    #                         self.logger.error(error_msg)
    #                     else:
    #                         print(error_msg)
    #                     continue
    #                 body=response['parsed']

    #                 # response=self.session.get(test_url,timeout=5)#修改成包，利用受控制的请求发包
    #                 if payload in str(body).lower():
    #                     vulnerabilities.append({
    #                         "type":"反射型XSS",
    #                         "payload":payload,
    #                         "confidence":"低"
    #                     })
                        
    #             except requests.exceptions.RequestException as e:
    #                 print(f"请求错误: {e}")
    #                 continue
    #     scan_results=self.results
    #     return vulnerabilities,scan_results

    def crawl_links(self, url_input):
        """爬取页面中的链接"""

         # 统一处理输入：将单个URL转换为列表
        if isinstance(url_input, str):
            urls = [url_input]
        elif isinstance(url_input, list):
            urls = url_input
        else:
            raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")

        for url in urls:
            # 确保URL是字符串
            if not isinstance(url, str):
                print(f"跳过非字符串URL: {url}")
                continue
            
            print(f"\n开始测试URL: {url}")
            try:
                if url:
                    request_info={
                        'method' : 'GET',
                        'url':url,
                        'headers':{}
                    }
                response=self.send_controlled_request(request_info)
                # 检查响应是否为None（请求失败）
                if response is None:
                    # 修复logger调用 - 根据你的实际logger结构调整
                    if hasattr(self.logger, 'error'):
                        self.logger.error(f"请求失败，响应为None: {url}")
                    elif isinstance(self.logger, dict) and 'error_logger' in self.logger:
                        self.logger['error_logger'].error(f"请求失败，响应为None: {url}")
                    else:
                        print(f"请求失败，响应为None: {url}")
                    continue
                
                # 检查解析的内容是否存在
                if 'parsed' not in response:
                    error_msg = f"响应中没有parsed字段: {url}"
                    if hasattr(self.logger, 'error'):
                        self.logger.error(error_msg)
                    elif isinstance(self.logger, dict) and 'error_logger' in self.logger:
                        self.logger['error_logger'].error(error_msg)
                    else:
                        print(error_msg)
                    continue
                # response=self.session.get(url,timeout=10)#修改成包，利用受控制的请求发包
                body=response['parsed']['parsed_content']
                #print(body)
                soup=BeautifulSoup(str(body),"html.parser")
                #print(soup)

                # 解析基础URL的域名
                base_domain = urlparse(url).netloc
                links=[]
                try:
                    if soup:
                        for link in soup.find_all("a",href=True):
                            href=link['href']
                            # 解析链接的域名
                            absolute_url=urljoin(url,href)
                            link_domain = urlparse(absolute_url).netloc                
                            # 只爬取同域名链接（忽略协议差异）
                            if link_domain == base_domain:
                                links.append(absolute_url)
                    return list(set(links)) #去重
                except Exception as e:
                    self.logger.error(f"解析页面失败: {url}, 错误: {e}")
            except Exception as e:
                if self.logger is None:
                    print("日志对象未初始化！")
                else:
                    self.logger.error(f"爬取链接失败: {url}, 错误: {e}")
        return []
    # def get_result(result):
    #     if result is not None:
    #         return result
            
        
