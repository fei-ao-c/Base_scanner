import json
import os
import sys
from datetime import datetime
from tools.report_generator import ReportGenerator

try:
    from colorama import Fore, Style,init
    init(autoreset=True)
    def print_colored(text, color="white"):
        """彩色输出"""
        colors = {
            "red": Fore.RED,
            "green": Fore.GREEN,
            "yellow": Fore.YELLOW,
            "blue": Fore.BLUE,
            "magenta": Fore.MAGENTA,
            "cyan": Fore.CYAN,
            "white": Fore.WHITE
        }
        color_code = colors.get(color.lower(), Fore.WHITE)
        print(color_code + text)
except ImportError:
    def print_colored(text, color="white"):
        """普通输出（无颜色）"""
        print(text)

def load_config(choice=None):
    # 1. 获取当前脚本文件的绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. 构建相对于脚本所在目录的路径
    config_path = os.path.join(current_dir, "config", "config.json")

    if choice==True:
        print(f"正在尝试加载: {config_path}") # 调试用，打印出实际路径
    
    default_config = {
        "timeout": 2,
        "max_threads": 50,
        "crawl_depth": 2,
        "output_dir": "output",
        "user_agent": "Mozilla/5.0 ..."
    }

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r',encoding='utf-8') as f:
                user_config = json.load(f)
                default_config.update(user_config)
                if choice==True:
                    print_colored("配置文件加载成功", "green")
        except Exception as e:
            print_colored(f"[-] 加载配置文件出错: {e}，使用默认配置", "yellow")
    return default_config

def load_xss_payload():
    """加载默认的xss_payload"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
   # 使用 os.path.join 并规范化路径

    # xss_payload_path = os.path.normpath(
    #     os.path.join(current_dir, "payload", "xss.json")
    # )
    xss_payload_path=os.path.join(current_dir, "payload", "xss.json")
    with open(xss_payload_path, 'r',encoding='utf-8') as f:
        xss_payload = json.load(f)
    payload_list = xss_payload['xss_payloads']
    #for payload in payload_list:
        #print(f"xss_payload: {payload}\n")
    return payload_list

def load_sqli_config():
    """加载默认的sqli_payload"""
    try:
        if os.path.exists("payload/sql_injection.json"):
            with open("payload/sql_injection.json", 'r',encoding='utf-8') as f:
                config=json.load(f)
            return config
        else:
            print_colored("[-] 缺少sql_injection.json配置文件，使用默认配置！", "red")
            return get_default_sqli_config()
    except json.JSONDecodeError as e:
        print_colored(f"[-] 解析sql_injection.json配置文件出错: {e}", "red")
        return get_default_sqli_config()

def get_default_sqli_config():
    """获取默认SQL注入配置"""
    return {
        "payloads": {
            "generic_error_based": [
                "'",
                "\"",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR '1'='1' --",
                "' OR 1=1 --",
                "' UNION SELECT NULL --",
                "1' AND SLEEP(5) --",
                "1' OR '1'='1",
                "-1' UNION SELECT 1,2,3 --",
                "admin' --",
                "1' ORDER BY 1 --",
                "1' AND 1=2 UNION SELECT 1,2,3 --"
            ],
            "mysql_specific": {
                "error_based": [
                    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a) --",
                    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) --",
                    "' UNION SELECT NULL, version(), NULL --"
                ],
                "boolean_based": [
                    "' AND 1=1 --",
                    "' AND 1=2 --",
                    "' AND (SELECT ASCII(SUBSTRING(database(),1,1))) > 97 --"
                ],
                "time_based": [
                    "' AND SLEEP(5) --",
                    "' OR BENCHMARK(5000000, MD5('test')) --"
                ]
            },
            "mssql_specific": {
                "error_based": [
                    "' AND 1=CONVERT(int, @@version) --",
                    "' OR 1 IN (SELECT @@version) --"
                ],
                "time_based": [
                    "' WAITFOR DELAY '00:00:05' --",
                    "'; WAITFOR DELAY '00:00:05' --"
                ]
            },
            "postgresql_specific": {
                "error_based": [
                    "' AND 1=CAST((SELECT version()) AS int) --",
                    "' OR (SELECT 1 FROM pg_sleep(5)) --"
                ],
                "time_based": [
                    "' OR (SELECT pg_sleep(5)) --",
                    "'; SELECT pg_sleep(5) --"
                ]
            },
            "oracle_specific": {
                "error_based": [
                    "' AND (SELECT * FROM (SELECT NULL FROM DUAL) WHERE 1=1 AND 1=2) IS NULL --",
                    "' OR 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1)) --"
                ],
                "time_based": [
                    "' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS', 5)=0 --",
                    "' OR DBMS_LOCK.SLEEP(5)=0 --"
                ]
            }
        },
        "error_indicators": {
            "mysql": [
                "you have an error in your sql syntax",
                "warning: mysql",
                "mysql_fetch",
                "mysql_num_rows",
                "mysqli"
            ],
            "mssql": [
                "unclosed quotation mark",
                "sql server",
                "microsoft ole db provider",
                "odbc driver",
                "syntax error converting"
            ],
            "postgresql": [
                "postgresql",
                "pg_",
                "postgres query failed",
                "postgres syntax error"
            ],
            "oracle": [
                "ora-",
                "oracle error",
                "oracle driver",
                "oracle odbc",
                "oracle db"
            ],
            "generic": [
                "sql syntax",
                "syntax error",
                "division by zero",
                "unclosed quotation mark",
                "quoted string not properly terminated",
                "mysql error",
                "sql server",
                "ora-",
                "postgresql",
                "sqlite",
                "odbc",
                "jdbc",
                "pdo",
                "sql command",
                "invalid query",
                "unknown column",
                "table doesn't exist"
            ]
        },
        "boolean_indicators": {
            "true_indicators": [
                "welcome",
                "success",
                "logged in",
                "exists",
                "found"
            ],
            "false_indicators": [
                "error",
                "invalid",
                "not found",
                "failed",
                "access denied"
            ],
            "length_difference_threshold": 0.3
        },
        "time_based_threshold": 3.0,
        "request_config": {
            "timeout": 10,
            "headers": {
                "User-Agent": "SQLi-Scanner/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5"
            },
            "max_redirects": 3,
            "verify_ssl": False
        }
    }

# def save_results(results, filename, output_dir="output",type=None):
#     """
#     保存扫描结果到文件
#     Args:
#         results: 要保存的数据（字典）
#         filename: 文件名（不包含路径）
#         output_dir: 输出目录
#     """
#     try:
#         # 确保输出目录存在
#         os.makedirs(output_dir, exist_ok=True)
        
#         # 构建完整路径
#         filepath = os.path.join(output_dir, filename)
#         # 保存为JSON格式
#         if type=="json":
#             with open(filepath, 'w', encoding='utf-8') as f:
#                 json.dump(results, f, indent=2, ensure_ascii=False)
        
#             print_colored(f"[+] (json)扫描结果已保存到: {filepath}", "green")
#         elif type=="txt":
        
#             # 保存一个简化的文本摘要
#             save_text_summary(results, filename.replace('.json', '_summary.txt'), output_dir)
#             #print_colored(f"[+] (txt)扫描结果已保存到: {filepath.replace('.json', '_summary.txt')}", "green")
#         else:
#             with open(filepath, 'w', encoding='utf-8') as f:
#                 json.dump(results, f, indent=2, ensure_ascii=False)
        
#             print_colored(f"[+] (json)扫描结果已保存到: {filepath}", "green")

#             save_text_summary(results, filename.replace('.json', '_summary.txt'), output_dir)
#             #print_colored(f"[+] (txt)扫描结果已保存到: {filepath.replace('.json', '_summary.txt')}", "green")
#         return True
#     except Exception as e:
#         print_colored(f"[-] 保存结果失败: {e}", "red")
#         return False

# def save_results(results, filename, output_dir="output", save_type=None):
#     """
#     保存扫描结果到文件
    
#     Args:
#         results: 要保存的数据（字典）
#         filename: 文件名（不包含路径）
#         output_dir: 输出目录
#         save_type: 保存类型，可选值为 "json"、"txt"、"all" 或 None（默认为"all"）
#     """
#     try:
#         # 确保输出目录存在
#         os.makedirs(output_dir, exist_ok=True)
        
#         # 1. 清洁文件名，移除非法字符（特别是路径分隔符）
#         clean_filename = filename.replace('/', '_').replace('\\', '_')
        
#         # 2. 构建完整路径
#         filepath = os.path.join(output_dir, clean_filename)
        
#         # 3. 保存为JSON格式
#         if save_type == "json" or save_type == "all" or save_type is None:
#             with open(filepath, 'w', encoding='utf-8') as f:
#                 json.dump(results, f, indent=2, ensure_ascii=False, default=str)
#             print_colored(f"[+] (JSON)扫描结果已保存到: {filepath}", "green")
        
#         # 4. 保存文本摘要（如果需要）
#         if save_type == "txt" or save_type == "all" or save_type is None:
#             # 生成文本摘要文件名
#             txt_filename = clean_filename.replace('.json', '_summary.txt')
#             txt_filepath = os.path.join(output_dir, txt_filename)
            
#             try:
#                 # 保存一个简化的文本摘要
#                 summary_saved = save_text_summary(results, txt_filename, output_dir)
#                 if summary_saved:
#                     print_colored(f"[+] (TXT)扫描摘要已保存到: {txt_filepath}", "green")
#             except Exception as txt_err:
#                 print_colored(f"[-] 保存文本摘要失败: {txt_err}", "yellow")
        
#         return True
    
#     except Exception as e:
#         print_colored(f"[-] 保存结果失败: {e}", "red")
#         # 添加调试信息
#         print(f"[DEBUG] 原始文件名: {filename}")
#         print(f"[DEBUG] 清洁后文件名: {clean_filename if 'clean_filename' in locals() else 'N/A'}")
#         print(f"[DEBUG] 输出目录: {output_dir}")
#         print(f"[DEBUG] 完整路径: {filepath if 'filepath' in locals() else 'N/A'}")
#         return False

def save_results(results, filename, output_dir="output", save_type=None):
    """
    保存扫描结果到文件
    """
    try:
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
        
        # 清洁文件名（移除扩展名，如果有）
        clean_base = os.path.splitext(filename.replace('/', '_').replace('\\', '_'))[0]
        
        saved_files = []
        
        # 保存JSON
        if save_type == "json" or save_type == "all" or save_type is None:
            json_path = os.path.join(output_dir, clean_base + '.json')
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            saved_files.append(('JSON', json_path))
        
        # 保存TXT
        if save_type == "txt" or save_type == "all" or save_type is None:
            txt_path = os.path.join(output_dir, clean_base + '_summary.txt')
            
            # 使用新的 save_text_summary 函数
            save_text_summary(results, txt_path)
            saved_files.append(('TXT', txt_path))
        
        # 保存HTML
        if save_type == "html" or save_type == "all" or save_type is None:
            html_path = os.path.join(output_dir, clean_base + '_report.html')
            
            # 这里需要扫描器实例信息
            # 如果没有扫描器实例，可以使用默认值
            html_content = ReportGenerator.generate_html_report(results) 
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            saved_files.append(('HTML', html_path))
        
        # 输出保存结果
        for file_type, file_path in saved_files:
            print_colored(f"[+] ({file_type})报告已保存到: {file_path}", "green")
        
        return True
        
    except Exception as e:
        print_colored(f"[-] 保存结果失败: {e}", "red")
        import traceback
        traceback.print_exc()  # 打印详细错误信息
        return False

# def _format_html_report(self, report_data, xss_payload_count=None, sql_threshold=None):
#     """格式化HTML报告"""
#     # 使用传入的参数，而不是 self.xss_payloads 和 self.sql_thresholds
#     xss_payload_count = xss_payload_count or len(self.xss_payloads)
#     sql_threshold = sql_threshold or self.sql_thresholds['time_based_threshold']
#     html = '''<!DOCTYPE html>
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
#     sql_data = report_data.get('sql_injection', {})
#     if sql_data.get('vulnerabilities'):
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
#     xss_data = report_data.get('xss', {})
#     if xss_data.get('vulnerabilities'):
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
#     dom_xss_vulns = xss_data.get('dom_xss_vulnerabilities', [])
#     if dom_xss_vulns:
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
#     risk_levels = report_data.get('risk_levels', {})
#     if any(risk_levels.values()):
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
        
#     html += '''
#         <div class="section">
#             <div class="section-title">报告信息</div>
#             <p>本报告由AdvancedWebScanner自动生成。</p>
#             <p>扫描配置: SQL注入配置文件 - sql_injection.json</p>
#             <p>XSS Payload数量: ''' + str(xss_payload_count) + '''</p>
#             <p>时间盲注阈值: ''' + str(sql_threshold) + '''秒</p>
#         </div>
#     </div>
# </body>
# </html>'''
    
#     return html

def save_text_summary(results, filepath):
    """
    保存文本格式的扫描摘要
    Args:
        results: 扫描结果数据
        filepath: 完整文件路径
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            # 写入标题
            f.write("=" * 60 + "\n")
            f.write("扫描结果摘要\n")
            f.write("=" * 60 + "\n\n")
            
            # 写入基本信息
            target = results.get("target", "未知目标")
            f.write(f"目标: {target}\n")
            
            # 写入扫描摘要信息
            scan_summary = results.get("scan_summary", {})
            if scan_summary:
                f.write(f"扫描时间: {scan_summary.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n")
                f.write(f"扫描端口数: {scan_summary.get('total_ports', 0)}\n")
                f.write(f"发现漏洞数: {scan_summary.get('total_vulnerabilities', 0)}\n")
            
            # 写入开放端口信息
            open_ports = results.get("open_ports", [])
            f.write(f"\n开放端口 ({len(open_ports)}个):\n")
            if open_ports:
                for port in sorted(open_ports):
                    f.write(f"  - 端口 {port}\n")
            else:
                f.write("  无开放端口\n")
            
            # 写入漏洞信息
            vulnerabilities = results.get("vulnerabilities", [])
            f.write(f"\n发现漏洞 ({len(vulnerabilities)}个):\n")
            
            if vulnerabilities:
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"\n  {i}. {vuln.get('name', '未知漏洞')}\n")
                    f.write(f"     描述: {vuln.get('description', '无描述')}\n")
                    f.write(f"     风险等级: {vuln.get('risk_level', '未知')}\n")
                    f.write(f"     置信度: {vuln.get('confidence', '未知')}\n")
                    f.write(f"     位置: {vuln.get('location', '未知')}\n")
            else:
                f.write("  未发现漏洞\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("扫描完成\n")
            f.write("=" * 60 + "\n")
        
        return True
    
    except Exception as e:
        print_colored(f"[-] 保存文本摘要失败: {e}", "red")
        return False

# def save_text_summary(results, filename, output_dir="output"):
#     """保存文本格式的扫描摘要"""
#     try:
#         filepath = os.path.join(output_dir, filename)
        
#         with open(filepath, 'w', encoding='utf-8') as f:
#             f.write("=" * 60 + "\n")
#             f.write("漏洞扫描报告摘要\n")
#             f.write("=" * 60 + "\n\n")
            
#             f.write(f"目标地址: {results.get('target', 'N/A')}\n")
#             f.write(f"扫描时间: {results.get('scan_time', 'N/A')}\n\n")
            
#             # 端口信息
#             open_ports = results.get('open_ports', [])
#             f.write(f"开放端口 ({len(open_ports)}个):\n")
#             f.write("-" * 40 + "\n")
#             for port_info in open_ports:
#                 f.write(f"端口 {port_info.get('port', 'N/A')}: {port_info.get('service', '未知服务')}\n")
            
#             f.write("\n")
            
#             # 漏洞信息
#             vulnerabilities = results.get('vulnerabilities', [])
#             f.write(f"发现漏洞 ({len(vulnerabilities)}个):\n")
#             f.write("-" * 40 + "\n")
            
#             if vulnerabilities:
#                 # 按风险等级分类
#                 high_risk = [v for v in vulnerabilities if v.get('confidence') == '高']
#                 medium_risk = [v for v in vulnerabilities if v.get('confidence') == '中']
#                 low_risk = [v for v in vulnerabilities if v.get('confidence') == '低']
                
#                 f.write(f"高风险漏洞: {len(high_risk)}个\n")
#                 f.write(f"中风险漏洞: {len(medium_risk)}个\n")
#                 f.write(f"低风险漏洞: {len(low_risk)}个\n\n")
                
#                 # 列出具体漏洞
#                 for i, vuln in enumerate(vulnerabilities, 1):
#                     f.write(f"{i}. 类型: {vuln.get('type', '未知')}\n")
#                     f.write(f"   风险等级: {vuln.get('confidence', '未知')}\n")
#                     f.write(f"   Payload: {vuln.get('payload', 'N/A')}\n")
#                     f.write(f"   URL: {vuln.get('url', 'N/A')}\n")
#                     f.write("-" * 30 + "\n")
#             else:
#                 f.write("未发现漏洞\n")
            
#             f.write("\n" + "=" * 60 + "\n")
        
#         #print_colored(f"[+] 文本摘要已保存到: {filepath}", "green")
#         return True
#     except Exception as e:
#         print_colored(f"[-] 保存文本摘要失败: {e}", "yellow")
#         return False

# 增强版本
def format_results_for_display(results):
    """格式化结果用于控制台显示（增强版）"""
    output = []
    
    # 标题
    output.append("=" * 70)
    output.append("扫描结果".center(68))
    output.append("=" * 70)
    
    # 基本信息
    target = results.get('target', 'N/A')
    scan_time = results.get('scan_time', 'N/A')
    output.append(f"目标地址: {target}")
    output.append(f"扫描时间: {scan_time}")
    output.append("-" * 70)
    
    # 端口信息
    open_ports = results.get('open_ports', [])
    if open_ports:
        output.append(f"🔍 开放端口 ({len(open_ports)}个):")
        output.append("-" * 40)
        
        # 按端口号排序
        open_ports.sort(key=lambda x: x.get('port', 0))
        
        for port_info in open_ports:
            port = port_info.get('port', 'N/A')
            service = port_info.get('service', '未知服务')
            status = port_info.get('status', 'unknown')
            
            # 标记常见服务
            if port in [80, 443, 8080, 8443]:
                output.append(f"  🌐 端口 {port}: {service} ({status}) [Web服务]")
            elif port in [22, 3389]:
                output.append(f"  🔐 端口 {port}: {service} ({status}) [远程管理]")
            elif port in [21, 23]:
                output.append(f"  ⚠️  端口 {port}: {service} ({status}) [明文协议]")
            else:
                output.append(f"  • 端口 {port}: {service} ({status})")
    else:
        output.append("📭 未发现开放端口")
    
    output.append("")
    
    # 漏洞信息
    vulnerabilities = results.get('vulnerabilities', [])
    if vulnerabilities:
        output.append(f"⚠️  发现漏洞 ({len(vulnerabilities)}个):")
        output.append("-" * 40)
        
        # 按风险等级分组
        high_risk = []
        medium_risk = []
        low_risk = []
        unknown_risk = []
        
        for vuln in vulnerabilities:
            confidence = vuln.get('confidence', '未知')
            if confidence == '高':
                high_risk.append(vuln)
            elif confidence == '中':
                medium_risk.append(vuln)
            elif confidence == '低':
                low_risk.append(vuln)
            else:
                unknown_risk.append(vuln)
        
        # 显示高风险漏洞
        if high_risk:
            output.append("🔴 高风险漏洞:")
            for i, vuln in enumerate(high_risk, 1):
                vuln_type = vuln.get('type', '未知漏洞')
                url = vuln.get('url', vuln.get('target', 'N/A'))
                output.append(f"  {i}. {vuln_type}")
                if vuln.get('payload'):
                    payload = str(vuln['payload'])
                    if len(payload) > 60:
                        payload = payload[:57] + "..."
                    output.append(f"     载荷: {payload}")
                output.append(f"     地址: {url}")
        
        # 显示中风险漏洞
        if medium_risk:
            output.append("\n🟡 中风险漏洞:")
            for i, vuln in enumerate(medium_risk, 1):
                vuln_type = vuln.get('type', '未知漏洞')
                output.append(f"  {i}. {vuln_type}")
        
        # 显示低风险漏洞
        if low_risk:
            output.append("\n🟢 低风险漏洞:")
            for i, vuln in enumerate(low_risk, 1):
                vuln_type = vuln.get('type', '未知漏洞')
                output.append(f"  {i}. {vuln_type}")
        
        # 显示未知风险漏洞
        if unknown_risk:
            output.append("\n⚪ 未知风险漏洞:")
            for i, vuln in enumerate(unknown_risk, 1):
                vuln_type = vuln.get('type', '未知漏洞')
                output.append(f"  {i}. {vuln_type}")
    else:
        output.append("✅ 未发现安全漏洞")
    
    # 统计信息
    output.append("")
    output.append("-" * 70)
    
    summary = results.get('scan_summary', {})
    if summary:
        output.append("📊 扫描统计:")
        # output.append(f"  • 总扫描端口: {summary.get('total_ports', 0)}")
        output.append(f"  • 开放端口: {len(open_ports)}")
        output.append(f"  • 总漏洞数: {summary.get('total_vulnerabilities', 0)}")
        # output.append(f"  • 高风险漏洞: {summary.get('high_risk_vulns', 0)}")
        # output.append(f"  • 中风险漏洞: {summary.get('medium_risk_vulns', 0)}")
    
    output.append("=" * 70)
    
    return "\n".join(output)    