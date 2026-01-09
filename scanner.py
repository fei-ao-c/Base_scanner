import argparse
import ipaddress
import json
import os
import sys
import time
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from config.logging_config import ScannerLogger
    from modules.request_manager import RateLimiter
    from modules.request_builder import RequestBuilder
    from modules.request_queue import RequestQueueManager
    from modules.request_sender import RequestSender
    from modules.response_parse import ResponseParse
    from port_scanner import PortScanner
    from web_scanner import sampilescanner
    from utils import load_config, save_results, print_colored
except ImportError as e:
    print(f"导入模块时出错: {e}")
    print("请确保所有相关文件都在同一目录下。")
    sys.exit(1)

class VulnerabilityScanner:
    def __init__(self,config=None,log_dir='logs',args=None):
        self.config =  config or load_config(True)
        # print(f"加载配置: {self.config}")
        # 保存外部传来的 args
        self.args = args 

        #初始化日志系统
        self.logger=ScannerLogger(log_dir=log_dir)
        self.scan_id=self.logger.scanner_id

        #初始化速率限制器
        self.rate_limiter=RateLimiter(
            max_requests_per_second=self.config.get("max_requests_per_second",10),
            max_requests_per_minute=self.config.get("max_requests_per_minute",60)
        )

        #初始化请求队列
        self.request_queue=RequestQueueManager(
            max_concurrent=self.config.get("max_concurrent_requests",5),
            max_queue_size=self.config.get("max_queue_size",100),
            rate_limiter=self.rate_limiter,
        )
            
        #初始化请求发送器
        self.request_sender=RequestSender(
            timeout=self.config.get("request_timeout",10),
            verify_ssl=self.config.get("verify_ssl",False),
            user_agent=self.config.get("user_agint"),
            proxies=self.config.get("proxies"),
            max_retries=self.config.get("max_retries",3),
        )

        #初始化请求构造器和响应解析器
        self.request_builder=RequestBuilder()
        self.response_parser=ResponseParse()

        #初始化结果存储
        self.results = {
            "scan_id":self.scan_id,
            "scan_time":str(datetime.now()),
            "target":"",
            "request":[],
            "response":[],
            "open_ports": [],
            "vulnerabilities": [],
            "scan_summary": {},
            "statistics":{},
            "logs": [] #存储日志信息    
        }
        #记录初始化
        self.logger.main_logger.info(f"初始化漏洞扫描器完成,扫描ID: {self.scan_id}")

    # def send_controlled_request(self,request_info):
    #     """发送受控制的请求"""
    #     def _make_request():
    #         method=request_info.get("method","GET")
    #         url=request_info.get("url")

    #         if not url:
    #             raise ValueError("请求 URL 不能为空")
            
    #         #发送请求
    #         response=self.request_sender.send_request(
    #             method=method,
    #             url=url,
    #             params=request_info.get("params"),
    #             data=request_info.get("data"),
    #             json_data=request_info.get("json"),
    #             headers=request_info.get("headers"),
    #             cookies=request_info.get("cookies"),
    #             allow_redirects=request_info.get("allow_redirects",True),
    #         )

    #         #解析响应
    #         parsed_response=self.response_parser.parse_response(
    #             response,
    #             extract_links=True,
    #             extract_forms=True,
    #             base_url=url,
    #         )

    #         return {
    #             'request':request_info,
    #             'response':{
    #                 'status_code':response.status_code,
    #                 'url':str(response.url),
    #                 'headers':dict(response.headers),
    #                 'content_length': len(response.content),
    #             },
    #             'parsed':parsed_response,
    #         }
    #     #提交到队列
    #     task_id=f"req_{int(time.time()*1000)}_{hash(str(request_info))%10000}"

    #     self.request_queue.submit(task_id,_make_request)

    #     #等待结果
    #     try:
    #         result=self.request_queue.get_result(task_id,timeout=30)

    #         #记录结果
    #         self._record_request_result(result)
    #         return result
    #     except Exception as e:
    #         self.logger.error_logger.error(f"请求失败：{request_info.get('url')} - {e}")
    #         return None
        
    # def _record_request_result(self,result):
    #     """记录请求结果"""
    #     if not result:
    #         return
        
    #     self.results['requests'].append(result['request'])
    #     self.results['responses'].append(result['response'])

    #     #分析响应中的敏感信息
    #     self._analyze_response_for_sensitive_info(result)

    #     #检查常见漏洞
    #     self._check_response_for_vulnerabilities(result)

    #     ###测试
    #     print(f"请求结果: {result}")

    # def _analyze_response_for_sensitive_info(self,result):
    #     """分析响应中的敏感信息"""
    #     parsed=result.get('parsed',{})

    #     if not parsed.get('parsed_content'):
    #         return
        
    #     #提取敏感信息
    #     sensitive_patterns={
    #         'api_keys': r'(?:api[_-]?key|access[_-]?token|secret[_-]?key)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
    #         'passwords': r'(?:password|passwd|pwd)[\s:=]+["\']?([^\s"\']+)["\']?',
    #         'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    #         'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    #         'credit_cards': r'\b(?:\d{4}[ -]?){3}\d{4}\b',
    #         'jwt_tokens': r'\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b'
    #     }

    #     content_text=str(parsed.get('parsed_content',''))

    #     for info_type,pattern in sensitive_patterns.items():
    #         matches= self.response_parser.find_pattern(content_text,{info_type:pattern})
    #         if matches.get(info_type):
    #             self.logger.log_vulnerability_found(
    #                 result['request'].get('url'),
    #                 f"敏感信息泄露: {info_type}",
    #                 "中",
    #                 matches[info_type][:3] #只记录前3个匹配项
    #             )

    # def _check_response_for_vulnerabilities(self,result):
    #     """检查常见漏洞"""
    #     response=result.get('response',{})
    #     parsed=result.get('parsed',{})

    #     #检查安全头
    #     headers=response.get('headers',{})
    #     self._check_security_headers(headers,result['request'].get('url'))

    #     #检查响应中的漏洞迹象
    #     if parsed.get('content_type')=='html':
    #         self._check_html_for_vulnerabilities(parsed,result['request'].get('url'))

    # def _check_security_headers(self,headers,url):
    #     """检查安全头"""
    #     security_headers={
    #         'X-Content-Type-Options': 'nosniff',
    #         'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
    #         'Content-Security-Policy': None,  # 只要存在就行
    #         'Strict-Transport-Security': None,
    #         'X-XSS-Protection': '1; mode=block'
    #     }

    #     missing_headers=[]

    #     for header,excepted_value in security_headers.items():
    #         if header not in headers:
    #             missing_headers.append(header)
    #         elif excepted_value and headers[header] != excepted_value:
    #             self.logger.log_vulnerability_found(
    #                 url,
    #                 f"安全头缺失或配置错误: {header}",
    #                 "低",
    #                 f"当前值：{headers[header]},推荐值：{excepted_value}"
    #             )
        
    #     if missing_headers:
    #         self.logger.log_vulnerability_found(
    #             url,
    #             "安全头缺失",
    #             "中",
    #             f"缺失头: {', '.join(missing_headers)}"
    #         )

    # def _check_html_for_vulnerabilities(self,parsed,url):
    #     """检查 HTML 响应中的漏洞"""
    #     soup=parsed.get('parsed_content')
    #     if not soup:
    #         return
        
    #     #检查调试信息
    #     debug_keywords=['debug','test','localhost','127.0.0.1','phpinfo']
    #     html_text=str(soup).lower()

    #     for keywords in debug_keywords:
    #         if keywords in html_text:
    #             self.logger.log_vulnerability_found(
    #                 url,
    #                 f"调试信息泄露",
    #                 "低",
    #                 f"存在关键字: {keywords}"
    #             )
    #             break


    def parse_range(self,range_str):
    # """
    # 将类似 '1-100' 的字符串转换为整数列表
    # """
        try:
            # 使用 ipaddress 模块解析范围
            # 注意：start 和 stop 都是整数
            start, stop = map(int, range_str.split('-'))

            # 生成列表
            return list(range(start, stop + 1))

        except ValueError:
            # 处理单个数字（如 '80'）或格式错误
            if range_str.isdigit():
                print("………………………………………………………………………………………………出错……………………………………………………………………")
                return [int(range_str)]
            else:
                raise ValueError(f"Invalid format: {range_str}")

    def run_port_scan(self, target,ports=None):
        """执行端口扫描"""
        print(f"[*] 执行端口扫描: {target}")
        self.logger.log_scan_start(target,"端口扫描")
        start_time=time.time()
        
            # 解析端口参数
        try:
            # 如果传入了 ports 参数，解析它
            if ports:
                # 如果 ports 是字符串，解析范围；如果是列表，直接使用
                if isinstance(ports, str):
                    ports_to_scan = self.parse_range(ports)
                elif isinstance(ports, list):
                    ports_to_scan = ports
                else:
                    ports_to_scan = self.config.get("common_ports", [])
            else:
                ports_to_scan = self.config.get("common_ports", [])
        except Exception as e:
            print(f"端口解析错误: {e}")
            ports_to_scan = self.config.get("common_ports", [])

        print(f"扫描端口列表: {ports_to_scan}")
        try:
            scanner = PortScanner(timeout=self.config.get("timeout",2),
                                  max_threads=self.config.get("max_threads",50))
            
            #获取要扫描的端口
            # ports_to_scan=self.args.ports if self.args else self.config.get("common_ports",[])  #######标记
            # print(f"扫描端口列表: {ports_to_scan}")
            open_ports = scanner.scan_target(target,ports=ports_to_scan)

            # 获取服务信息
            port_details = []
            for port in open_ports:
                service = scanner.get_service_name(port)
                port_details.append({
                    "port": port,
                    "service": service,
                    "status": "open"
                })
                #记录日志
                self.logger.log_port_scan_result(target,port,"open",service)
            #记录扫描耗时
            duration=time.time()-start_time
            self.logger.log_performance("端口扫描",duration,target)
            self.logger.main_logger.info(f"端口扫描完成: {target}, 开放端口数量: {len(open_ports)}")

            #记录到结果中
            self._add_log_entry("端口扫描完成", f"发现 {len(open_ports)} 个开放端口")
            self.results["open_ports"] = port_details
            return port_details
        except Exception as e:
            self.logger.main_logger.error(f"端口扫描失败: {target}, 错误: {e}", exc_info=True)
            self._add_log_entry(f"端口扫描错误",str(e), level="ERROR")
            return []

    def run_web_scan(self,url):
        """web漏洞扫描"""
        print(f"开始扫描: {url}")
        self.logger.log_scan_start(url,"Web漏洞扫描")
        start_time=time.time()

        try:
            scanner=sampilescanner()
            vulnerabilities=[]

            # sql注入检测
            self.logger.main_logger.info(f"开始SQL注入检测: {url}")
            sql_vulns,scan_results=scanner.check_sql_injection(url)
            
            self.results={**self.results,**scan_results}
            # print(scan_results)
            # print("\n")
            # #print(totals)#为空
            # print("\n")
            # print(self.results)
            for vuln in sql_vulns:
                vuln['url']=url
                vulnerabilities.append(vuln)
                self.logger.log_vulnerability_found(
                    url,
                    vuln['type'],
                    vuln.get('confidence','未知'),
                    vuln.get('payload')
                )
            
            
#后续要进一步挖掘

            # XSS检测
            self.logger.main_logger.info(f"开始XSS检测: {url}")
            xss_vulns,scan_results=scanner.check_xss(url)
            
            self.results={**self.results,**scan_results}
            for vuln in xss_vulns:
                vuln['url']=url
                vulnerabilities.append(vuln)
                self.logger.log_vulnerability_found(
                    url,
                    vuln['type'],
                    vuln.get('confidence','未知'),
                    vuln.get('payload')
                )
            
           # vulnerabilities.extend(xss_vulns)

            if self.config.get("crawl_depth",0)>0:
                links=scanner.crawl_links(url)[:5]  # 限制爬取链接数量以节省时间
                print(f"爬取到 {len(links)} 个链接，分别是{links}，开始扫描...")
                try:
                    for link in links:
                        link_sql_vulns,scan_results=scanner.check_sql_injection(link)
                        
                        #self.results={**self.results,**scan_results,**totals}
                        for vuln in link_sql_vulns:
                            vuln['url']=link 
                            vulnerabilities.append(vuln)
                            self.logger.log_vulnerability_found(
                                link,
                                vuln['type'],
                                vuln.get('confidence','未知'),
                                vuln.get('payload')
                            )
                        
                except Exception as e:
                    print(f"爬取链接时出错: {e}")

            #记录扫描耗时
            duration=time.time()-start_time
            self.logger.log_performance("Web漏洞扫描",duration,url)
            self.logger.main_logger.info(f"Web漏洞扫描完成: {url}, 发现漏洞数量: {len(vulnerabilities)}")
            self._add_log_entry("Web漏洞扫描完成:", f"{url}, 发现漏洞数量: {len(vulnerabilities)}")
            # self.results={**self.results,**scan_results}
            
            ##print(self.results)
            
            return vulnerabilities
        except Exception as e:
            self.logger.main_logger.error(f"web扫描失败: {url}, 错误: {e}", exc_info=True)
            self._add_log_entry("web扫描错误",str(e), level="ERROR")
            return []

    def _add_log_entry(self, action, message, level="INFO"):
        """添加日志条目到结果中"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "message": message,
            "level": level
        }
        self.results["logs"].append(log_entry)

    def scan_with_rate_control(self,target,ports=None,type=None):
        """使用速率控制的扫描"""
        self.results["target"]=target
        print(f"开始扫描目标: {target}")
        print("[*]" + "=" *50)
        self.port=ports
        self.type=type
        # 记录扫描开始
        self.logger.log_scan_start(target, "完整扫描")

        try:
            #1.端口扫描
            self.logger.main_logger.info("阶段1: 端口扫描")
            ports=self.run_port_scan(target,ports=self.port)
            self.results["open_ports"]=ports
            #收集漏洞信息

            #2.web漏洞扫描(如果发现http/https端口)
            web_urls=self._identify_web_services(target,ports)
            if web_urls:
                self.logger.main_logger.info(f"扫描Web漏洞: {web_urls}")
                vulns=self.run_web_scan(web_urls)
                # print(f'{vulns}+"------------"')
                self.results["vulnerabilities"]=vulns
            else:
                print("未发现Web服务端口，跳过Web漏洞扫描。")
                self.results["vulnerabilities"]=[]
            
            #3.收集统计信息
            #self._collect_statistics_zong() #这里没发挥作用，因为没有进行web服务扫描

            #4.更新扫描摘要
            self.results["scan_summary"]={
                "total_ports":len(ports),
                "total_vulnerabilities":len(self.results["vulnerabilities"]),
                "high_risk_vulns":[v for v in self.results["vulnerabilities"] if v["confidence"]=="高"],
                "medium_risk_vulns":[v for v in self.results["vulnerabilities"] if v["confidence"]=="中"]
            }
            #5.调用save_results函数保存结果
            timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
            #保存完整结果
            filename=f"scan_results_{target}_{timestamp}.json"
            #确保output目录存在
            os.makedirs("output",exist_ok=True)
            #调用save_results函数
            
            save_results(self.results, filename,"output",self.type)
            #6.显示摘要
            self.show_summary()

            self.logger.main_logger.info(f"扫描完成: {target}")
            self._add_log_entry(f"扫描完成","所有扫描任务已完成。")
        except KeyboardInterrupt:
            print("\n[-] 扫描被用户中断")
            if self.results["open_ports"] or self.results["vulnerabilities"]:
                timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
                filename=f"scan_results_{target}_partial_{timestamp}.json"
                save_results(self.results,filename)
                print(f"[!] 部分结果已保存为 output/{filename}")
        except Exception as e:
            print(f"\n[-] 扫描过程中出现错误: {e}")
            import traceback
            traceback.print_exc()
    
    def _identify_web_services(self, target, ports):
        """识别Web服务"""
        web_urls = []
        
        for port_info in ports:
            port = port_info.get("port")
            
            # 常见Web端口
            if port in [80, 443, 8080, 8443, 8000, 8888]:
                protocol = "https" if port in [443, 8443] else "http"
                web_urls.append(f"{protocol}://{target}:{port}")
            
            # 其他可能运行Web服务的端口
            elif port in [3000, 5000, 7000, 9000]:
                # 尝试HTTP和HTTPS
                for protocol in ["http", "https"]:
                    web_urls.append(f"{protocol}://{target}:{port}")
        
        return list(set(web_urls))
    
    # def _collect_statistics_zong(self,totals={}):
    #     """收集总统计信息"""
    #     self.results={**self.results,**totals}
        
    
#下面是显示扫描摘要的函数
    def show_summary(self):
        """显示扫描摘要"""
        try:
            # 调用 format_results_for_display 获取格式化字符串
            from utils import format_results_for_display
            display_text = format_results_for_display(self.results)

            # 打印格式化结果
            print(display_text)

            # 也可以添加一些额外的统计信息
            summary = self.results.get("scan_summary", {})

            #显示统计信息  这里也没有作用，因为上层没有，results没有这些东西
            if 'statistics' in self.results and isinstance(self.results['statistics'], dict):
                stats = self.results['statistics'].get('request_stats', {})
            # stats = self.results.get('statistics', {}).get('request_stats', {})
            # print(self.results['statistics'])
            # print(self.results)
            # print(f'{stats} "***+++"')
            print("\n" + "=" * 50)
            print("请求统计:")
            print(f"  总请求数: {stats.get('total_requests', 0)}")
            print(f"  成功请求: {stats.get('successful_requests', 0)}")
            print(f"  失败请求: {stats.get('failed_requests', 0)}")
            print(f"  成功率: {stats.get('success_rate', 0):.2f}%")
            print(f"  平均响应时间: {stats.get('average_response_time', 0):.4f}s")
            print("=" * 50)

            if summary:
                print(f"\n详细统计:")
                print(f"- 高风险漏洞: {summary.get('high_risk_vulns', 0)} 个")
                print(f"- 中风险漏洞: {summary.get('medium_risk_vulns', 0)} 个")
                # print(f"- 总扫描端口: {summary.get('total_ports', 0)} 个")
        except Exception as e:
            print(f"[-] 显示摘要时出错: {e}")

            print("\n" + "=" *50)
            print("扫描摘要")
            print("=" *50)
            print(f"目标: {self.results['target']}")
            print(f"扫描时间: {self.results['scan_time']}")
            print(f"开放端口数量: {len(self.results.get('open_ports',[]))}")
            print(f"发现漏洞数量: {len(self.results['vulnerabilities'])}")
            if self.results['vulnerabilities']:
                print("\n发现的漏洞:")
                for vuln in self.results['vulnerabilities']:
                    vuln_type = vuln.get('type', '未知')
                    confidence = vuln.get('confidence', '未知')
                    payload = vuln.get('payload', 'N/A')[:50] + "..." if len(str(vuln.get('payload', ''))) > 50 else vuln.get('payload', 'N/A')
                    print(f"  - {vuln_type} (可信度: {confidence})")
                    print(f"    Payload: {payload}")

            print("\n" + "=" * 50)

            #记录摘要到日志
            summary=self.results.get("scan_summary",{})
            self.logger.main_logger.info(
                f"扫描摘要: 目标: {self.results['target']}, "
                f"开放端口: {summary.get('open_ports',[])}, "
                f"发现漏洞: {summary.get('vulnerabilities', [])}"
            )
    
def main():
    parser=argparse.ArgumentParser(description="简易漏洞扫描工具")
    parser.add_argument("target",help="扫描目标IP或域名")
    parser.add_argument("-p","--ports",help="扫描端口范围,例如 1-1000") 
    parser.add_argument("-o","--output",help="输出报告文件名",choices=["json","txt","all"],default="all")
    parser.add_argument("--log-dir",help="日志目录",default="logs")
    parser.add_argument("--log-level",help="日志级别",choices=['DEBUG','INFO','WARNING','ERROR'],default="INFO")#现在不可指定
    parser.add_argument("--no-log",help="禁用日志",action="store_true")
    parser.add_argument("--view-log",help="查看日志",metavar="FILE")
    parser.add_argument("--analyze-logs",help="分析日志",action="store_true")
    #下面的要进行测试判断----------------------------------------------------------
    parser.add_argument("-rps", "--requests-per-second", type=int, default=10,help="每秒最大请求数")
    parser.add_argument("-rpm", "--requests-per-minute", type=int, default=60,help="每分钟最大请求数")
    parser.add_argument("-c", "--concurrent", type=int, default=5,help="最大并发请求数")
    parser.add_argument("-t", "--timeout", type=int, default=10,help="请求超时时间(秒)")
    parser.add_argument("--no-ssl-verify", action="store_true",help="不验证SSL证书")
    args=parser.parse_args()
    #----------------------------------------------------------------------------------
    print(f"目标: {args.target}")
    print(f"端口范围: {args.ports}") 
    print(f"输出格式: {args.output}")
    print(f"日志级别: {args.log_level}")

    #下面的要进行测试-----------------------------------------------------
    # 创建配置
    config = {
        "max_requests_per_second": args.requests_per_second,
        "max_requests_per_minute": args.requests_per_minute,
        "max_concurrent_requests": args.concurrent,
        "request_timeout": args.timeout,
        "verify_ssl": not args.no_ssl_verify,
        "enable_directory_scan": True,
        "enable_parameter_scan": True,
        "enable_api_scan": False
    }
#--------------------------------------------------------------
    #如果指定了日志相关的操作
    if args.view_log:
        from tools.log_viewer import LogViewer
        viewer=LogViewer(log_dir=args.log_dir)
        viewer.view_log(args.view_log)
        return
    
    if args.analyze_logs:
        from tools.log_viewer import LogViewer
        viewer=LogViewer(log_dir=args.log_dir)
        viewer.analyze_logs()
        return
    
    if not args.target:
        parser.error("需要指定目标地址")
    scanner=VulnerabilityScanner(log_dir=args.log_dir,config=config)#测试

    # 设置日志级别
    if args.log_level:
        import logging
        logging.getLogger('vuln_scanner').setLevel(getattr(logging, args.log_level))

    try:
        scanner.scan_with_rate_control(args.target, ports=args.ports,type=args.output)
    except KeyboardInterrupt:
        print("\n[-] 扫描被用户中断")
    except Exception as e:
        print(f"\n[-] 扫描过程中出现错误: {e}")
if __name__=="__main__":
    main()