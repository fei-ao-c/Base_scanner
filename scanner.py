import argparse
import json
import os
import sys
import time
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from config.logging_config import ScannerLogger
    from port_scanner import PortScanner
    from web_scanner import sampilescanner
    from utils import load_config, save_results, print_colored
except ImportError as e:
    print(f"导入模块时出错: {e}")
    print("请确保所有相关文件都在同一目录下。")
    sys.exit(1)

class VulnerabilityScanner:
    def __init__(self,config=None,log_dir='logs'):
        self.config = load_config() or config

        #初始化日志系统
        self.logger=ScannerLogger(log_dir=log_dir)
        self.scan_id=self.logger.scanner_id
        self.results = {
            "scan_id":self.scan_id,
            "scan_time":str(datetime.now()),
            "target":"",
            "open_ports": [],
            "vulnerabilities": [],
            "scan_summary": {},
            "logs": [] #存储日志信息    
        }
        #记录初始化
        self.logger.main_logger.info(f"初始化漏洞扫描器完成,扫描ID: {self.scan_id}")


    def run_port_scan(self, target):
        """执行端口扫描"""
        print(f"[*] 执行端口扫描: {target}")
        self.logger.log_scan_start(target,"端口扫描")
        start_time=time.time()

        try:
            scanner = PortScanner(timeout=self.config.get("timeout",2),
                                  max_threads=self.config.get("max_threads",50))
            #获取要扫描的端口
            ports_to_scan=self.config.get("common_ports",[])  #######标记
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
        print(f"开始扫描: {url}")
        self.logger.log_scan_start(url,"Web漏洞扫描")
        start_time=time.time()

        try:
            scanner=sampilescanner()
            vulnerabilities=[]

            # sql注入检测
            self.logger.main_logger.info(f"开始SQL注入检测: {url}")
            sql_vulns=scanner.check_sql_injection(url)

            for vuln in sql_vulns:
                vuln['url']=url
                vulnerabilities.append(vuln)
                self.logger.log_vulnerability_found(
                    url,
                    vuln['type'],
                    vuln.get('confidence','未知'),
                    vuln.get('payload')
                )


            # XSS检测
            self.logger.main_logger.info(f"开始XSS检测: {url}")
            xss_vulns=scanner.check_xss(url)
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
                        link_sql_vulns=scanner.check_sql_injection(link)
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
            return vulnerabilities
        except Exception as e:
            self.logger.main_logger.error(f"web扫描失败: {url}, 错误: {e}", exc_info=True)
            self._add_log_entry("web扫描错误",str(e), level="ERROR")
            return []

        #爬取链接并扫描(***未完成***)
        # try:
        #     links=scanner.crawl_links(url)[:5]  # 限制爬取链接数量以节省时间
        #     for link in links:
        #         link_sql_vulns=scanner.check_sql_injection(link)
        #         vulnerabilities.extend(link_sql_vulns)
        # except Exception as e:
        #     print(f"爬取链接时出错: {e}")
        # return vulnerabilities
    

        # if self.config.get("crawl_depth",0)>0:
        #     links=scanner.crawl_links(url)[:5]  # 限制爬取链接数量以节省时间
        #     for link in links:
        #         sql_vulns=scanner.check_sql_injection(link)
        #         vulnerabilities.extend(sql_vulns)

        # self.results["vulnerabilities"]=vulnerabilities
        # return vulnerabilities
    
    # def generate_report(self,format="json"):
    #     timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")

    #     if format=="json":
    #         filename=f"output/scan_report_{timestamp}.json"
    #         with open(filename,"w",encoding="utf-8") as f:
    #             json.dump(self.results,f,ensure_ascii=False,indent=2)
    #         print(f"[+]扫描报告已保存为 {filename}")

    #     elif format=="txt":
    #         filename=f"output/scan_report_{timestamp}.txt"
    #         with open(filename,"w",encoding="utf-8") as f:
    #             f.write("=" *50 + "\n")
    #             f.write("扫描报告\n")
    #             f.write("=" *50 + "\n")
    #             f.write(f"扫描时间: {self.results['scan_time']}\n")
    #             f.write(f"目标: {self.results['target']}\n\n")

    #             f.write("开放端口:\n")
    #             f.write("-" * 30 + "\n")
    #             for port in self.results["open_ports"]:
    #                 f.write(f"- 端口: {port['port']}, 服务: {port['service']}\n")
    #             f.write("\n发现漏洞:\n")
    #             for vuln in self.results["vulnerabilities"]:
    #                 f.write(f"- 类型: {vuln['type']}\n")
    #                 f.write(f" 可信度： {vuln['confidence']}\n")
    #                 f.write(f"payload: {vuln.get('payload','N/A')}\n\n")
    #                 f.write("-" * 30 + "\n")
            
    #         print(f"[+]扫描报告已保存为 {filename}")
    def _add_log_entry(self, action, message, level="INFO"):
        """添加日志条目到结果中"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "message": message,
            "level": level
        }
        self.results["logs"].append(log_entry)

    def scan(self,target):
        self.results["target"]=target
        print(f"开始扫描目标: {target}")
        print("[*]" + "=" *50)

        try:
            #1.端口扫描
            ports=self.run_port_scan(target)
            self.results["open_ports"]=ports
            #收集漏洞信息
            #2.web漏洞扫描(如果发现http/https端口)
            web_ports=[80,443,8080,8443]
            web_url=None
            for port_info in ports:
                if port_info["port"] in web_ports:
                    protocol="https" if port_info["port"] in [443,8443] else "http"
                    web_url=f"{protocol}://{target}:{port_info['port']}/"
                    # self.run_web_scan(web_url)
                    break
            if web_url:
                vulns=self.run_web_scan(web_url)
                self.results["vulnerabilities"]=vulns
            else:
                print("未发现Web服务端口，跳过Web漏洞扫描。")
                self.results["vulnerabilities"]=[]
            #3.更新扫描摘要
            self.results["scan_summary"]={
                "total_ports":len(ports),
                "total_vulnerabilities":len(self.results["vulnerabilities"]),
                "high_risk_vulns":[v for v in self.results["vulnerabilities"] if v["confidence"]=="高"],
                "medium_risk_vulns":[v for v in self.results["vulnerabilities"] if v["confidence"]=="中"]
            }
            #4.调用save_results函数保存结果
            timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
            #保存完整结果
            filename=f"scan_results_{target}_{timestamp}.json"
            #确保output目录存在
            os.makedirs("output",exist_ok=True)
            #调用save_results函数
            save_results(self.results, filename)
            # #3.生成报告
            # self.generate_report(format="json")
            # self.generate_report(format="txt")

            #5.显示摘要
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
    args=parser.parse_args()
    scanner=VulnerabilityScanner()
    try:
        scanner.scan(args.target)
    except KeyboardInterrupt:
        print("\n[-] 扫描被用户中断")
    except Exception as e:
        print(f"\n[-] 扫描过程中出现错误: {e}")
if __name__=="__main__":
    main()