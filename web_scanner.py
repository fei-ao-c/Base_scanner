import requests
import logging
import sys
import os
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from modules.request_manager import RateLimiter
    from modules.request_queue import RequestQueueManager
    from modules.request_sender import RequestSender
    from modules.request_builder import RequestBuilder
    from modules.response_parse import ResponseParse
    from utils import load_config
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

        # 结果存储
        self.results = {
            "requests": [],
            "responses": [],
            "statistics":[],
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
        

        
        # 分析响应中的敏感信息
        # self._analyze_response_for_sensitive_info(result)
        
        # 检查常见漏洞
        # self._check_response_for_vulnerabilities(result)

    # def check_sql_injection(self, url):
    #     # SQL注入扫描
                 
    #     testpayloads=[
    #             "'",
    #             "\"",
    #             "' OR '1'='1",
    #             "\" OR \"1\"=\"1",
    #     ]

    #     vulnerabilities=[]
    #     #下面漏洞识别能力未完成
    #     for payload in testpayloads:
    #         # 构建测试 URL（保证 base 有结尾斜杠再 join）
    #         base = url if url.endswith('/') else url + '/'
    #         test_url = urljoin(base, 'sqli-labs-master/Less-5/')
    #         params = {'id': f"1{payload}"}
    #         print(f"Testing: {test_url} params={params}")
    #         try:
    #             response = self.session.get(test_url, params=params, timeout=5)
    #             body = response.text.lower()
    #             # 常见的 SQL 错误指示器（全部小写以便比较）
    #             error_indicators = [
    #                 "you have an error in your sql syntax",
    #                 "warning: mysql",
    #                 "sql syntax",
    #                 "mysql_fetch",
    #                 "syntax error",
    #                 "mysql_num_rows",
    #                 "unclosed quotation mark after the character string",
    #                 "quoted string not properly terminated",
    #                 "welcome",
    #                 "dhakkan"
    #             ]
    #             # 只打印响应摘要，避免大量输出
    #             #print(body[:400])
    #             for error in error_indicators:
    #                 if error in body:
    #                     vulnerabilities.append({
    #                         "type": "SQL Injection",
    #                         "payload": payload,
    #                         "confidence": "低",
    #                         "tested_url": test_url,
    #                         "params": params,
    #                     })
    #                     break
    #         except requests.exceptions.RequestException as e:
    #             print(f"请求错误: {e}")
    #             continue
    #     return vulnerabilities

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
    
    def check_xss(self, url_input):
        """ XSS扫描"""
        testpayloads=[
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
        ]

        vulnerabilities=[]

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

            for payload in testpayloads:
                try:
                    test_url=f"{url}?test={payload}"
                    print(test_url)
                    if test_url:
                        request_info={
                            'method' : 'GET',
                            'url':test_url,
                            'headers':{}
                        }
                    response=self.send_controlled_request(request_info)
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
                        else:
                            print(error_msg)
                        continue
                    body=response['parsed']

                    # response=self.session.get(test_url,timeout=5)#修改成包，利用受控制的请求发包
                    if payload in str(body).lower():
                        vulnerabilities.append({
                            "type":"反射型XSS",
                            "payload":payload,
                            "confidence":"低"
                        })
                        
                except requests.exceptions.RequestException as e:
                    print(f"请求错误: {e}")
                    continue
        scan_results=self.results
        return vulnerabilities,scan_results
    
    # def crawl_links(self, url_input):
    # # 爬取页面中的链接
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
    #     try:
    #         response=self.session.get(url,timeout=10)
    #         soup=BeautifulSoup(response.text,"html.parser") 
    #         print(soup) 
    #         # 解析基础URL的域名
    #         base_domain = urlparse(url).netloc
    #         links=[]
    #         for link in soup.find_all("a",href=True):
    #             href=link['href']
    #             # 解析链接的域名
    #             absolute_url=urljoin(url,href)
    #             link_domain = urlparse(absolute_url).netloc                
    #             # 只爬取同域名链接（忽略协议差异）
    #             if link_domain == base_domain:
    #                 links.append(absolute_url)
    #         return list(set(links)) #去重
    #     except Exception as e:
    #         self.logger.error(f"爬取链接失败: {url}, 错误: {e}")
    #         return []

    
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
            
        
