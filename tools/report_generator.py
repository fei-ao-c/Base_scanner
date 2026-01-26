# report_generator.py
import os
import json
import time
from datetime import datetime
import html as html_module  # 重命名以避免冲突

class ReportGenerator:
    """报告生成器"""
    
    @staticmethod
    def generate_html_report(report_data, xss_payload_count=0, sql_threshold=3.0):
        """生成HTML报告 - 修复版"""
        try:
            # 打印调试信息
            print(f"DEBUG: 开始生成报告...")
            print(f"DEBUG: report_data keys: {list(report_data.keys())}")
            
            # 获取基本信息
            target = report_data.get('target', '未知目标')
            
            # 扫描时间
            scan_time = report_data.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            # 获取漏洞数据
            vulnerabilities = report_data.get('vulnerabilities', [])
            
            print(f"DEBUG: 发现 {len(vulnerabilities)} 个漏洞")
            
            # 分类漏洞
            sql_vulnerabilities = []
            xss_vulnerabilities = []
            other_vulnerabilities = []
            
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '').lower()
                if 'sql' in vuln_type:
                    vuln['source'] = 'sql_injection'
                    sql_vulnerabilities.append(vuln)
                elif 'xss' in vuln_type:
                    vuln['source'] = 'xss'
                    xss_vulnerabilities.append(vuln)
                else:
                    vuln['source'] = 'other'
                    other_vulnerabilities.append(vuln)
            
            print(f"DEBUG: SQL注入漏洞: {len(sql_vulnerabilities)} 个")
            print(f"DEBUG: XSS漏洞: {len(xss_vulnerabilities)} 个")
            print(f"DEBUG: 其他漏洞: {len(other_vulnerabilities)} 个")
            
            # 获取开放端口
            open_ports = report_data.get('open_ports', [])
            
            # 获取HTTP响应
            http_responses = report_data.get('http_responses', report_data.get('response', []))
            
            # 计算URL数量
            total_urls_scanned = 0
            if http_responses:
                unique_urls = set()
                for resp in http_responses:
                    url = resp.get('url', '')
                    if url:
                        if isinstance(url, list):
                            for u in url:
                                unique_urls.add(str(u))
                        else:
                            unique_urls.add(str(url))
                total_urls_scanned = len(unique_urls)
            
            # 总漏洞数
            total_vulnerabilities = len(vulnerabilities)
            
            # SQL注入总数
            sql_total = len(sql_vulnerabilities)
            
            # XSS总数
            xss_total = len(xss_vulnerabilities)
            
            # 构建HTML内容
            html_content = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web安全扫描报告</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body { 
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; 
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
            line-height: 1.6;
        }
        
        .container { 
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .header { 
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 25px;
            margin-bottom: 30px;
            background: linear-gradient(135deg, #007bff 0%, #6610f2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-top: -30px;
            margin-left: -30px;
            margin-right: -30px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .section { 
            margin-bottom: 35px;
            padding: 25px;
            border: 1px solid #e1e5eb;
            border-radius: 8px;
            background-color: #fff;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .section:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transform: translateY(-2px);
        }
        
        .section-title { 
            font-size: 1.8em;
            font-weight: 700;
            margin-bottom: 20px;
            color: #007bff;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-title i {
            font-size: 1.2em;
        }
        
        .vulnerability { 
            background-color: #f8f9fa;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid #dc3545;
            border-radius: 6px;
            transition: all 0.3s ease;
        }
        
        .vulnerability:hover {
            background-color: #f1f3f4;
            transform: translateX(5px);
        }
        
        .vuln-title { 
            font-weight: 700;
            color: #dc3545;
            margin-bottom: 15px;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .vuln-badge {
            background-color: #dc3545;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
        }
        
        .stats { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-box { 
            background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-box:hover {
            transform: translateY(-5px);
        }
        
        .stat-value { 
            font-size: 3em;
            font-weight: 800;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .stat-label { 
            font-size: 1em;
            opacity: 0.9;
            font-weight: 500;
        }
        
        .risk-high { border-left-color: #dc3545; }
        .risk-high .vuln-badge { background-color: #dc3545; }
        
        .risk-medium { border-left-color: #fd7e14; }
        .risk-medium .vuln-badge { background-color: #fd7e14; }
        
        .risk-low { border-left-color: #ffc107; }
        .risk-low .vuln-badge { background-color: #ffc107; }
        
        .risk-info { border-left-color: #17a2b8; }
        .risk-info .vuln-badge { background-color: #17a2b8; }
        
        table { 
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        th, td { 
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        th { 
            background-color: #f8f9fa;
            font-weight: 700;
            color: #495057;
            border-top: none;
        }
        
        tr:hover {
            background-color: #f8f9fa;
        }
        
        .summary-item { 
            margin: 12px 0;
            padding: 10px 0;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
        }
        
        .summary-item:last-child {
            border-bottom: none;
        }
        
        .summary-label {
            font-weight: 600;
            color: #495057;
        }
        
        .summary-value {
            color: #6c757d;
            font-weight: 500;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .info-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }
        
        .info-card h4 {
            color: #007bff;
            margin-bottom: 10px;
            font-size: 1.2em;
        }
        
        .payload-code {
            background-color: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .tag {
            display: inline-block;
            background-color: #e9ecef;
            color: #495057;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.85em;
            margin-right: 8px;
            margin-bottom: 8px;
        }
        
        .tag-success { background-color: #d4edda; color: #155724; }
        .tag-warning { background-color: #fff3cd; color: #856404; }
        .tag-danger { background-color: #f8d7da; color: #721c24; }
        .tag-info { background-color: #d1ecf1; color: #0c5460; }
        
        .accordion {
            margin-top: 15px;
        }
        
        .accordion-header {
            background-color: #f8f9fa;
            padding: 15px;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background-color 0.3s;
        }
        
        .accordion-header:hover {
            background-color: #e9ecef;
        }
        
        .accordion-content {
            padding: 15px;
            border: 1px solid #dee2e6;
            border-top: none;
            border-radius: 0 0 6px 6px;
            background-color: #fff;
            display: none;
        }
        
        .response-preview {
            max-height: 300px;
            overflow-y: auto;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Consolas', monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            .header {
                padding: 20px;
                margin-left: -15px;
                margin-right: -15px;
            }
            
            .stats {
                grid-template-columns: 1fr;
            }
            
            .section {
                padding: 15px;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script>
        function toggleAccordion(id) {
            const content = document.getElementById(id);
            const icon = document.querySelector(`[data-target="${id}"] i`);
            if (content.style.display === "block") {
                content.style.display = "none";
                icon.className = "fas fa-chevron-down";
            } else {
                content.style.display = "block";
                icon.className = "fas fa-chevron-up";
            }
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert("已复制到剪贴板");
            });
        }
        
        function showAllResponses() {
            const hiddenRows = document.querySelectorAll('.response-row.hidden');
            hiddenRows.forEach(row => {
                row.classList.remove('hidden');
            });
            document.getElementById('show-all-btn').style.display = 'none';
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Web安全扫描报告</h1>
            <p>生成时间: ''' + html_module.escape(str(scan_time)) + '''</p>
            <p style="margin-top: 10px; font-size: 1.1em;"><i class="fas fa-globe"></i> 目标: ''' + html_module.escape(str(target)) + '''</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">''' + str(total_urls_scanned) + '''</div>
                <div class="stat-label"><i class="fas fa-link"></i> 扫描URL数量</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">''' + str(total_vulnerabilities) + '''</div>
                <div class="stat-label"><i class="fas fa-bug"></i> 发现漏洞总数</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">''' + str(sql_total) + '''</div>
                <div class="stat-label"><i class="fas fa-database"></i> SQL注入漏洞</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">''' + str(xss_total) + '''</div>
                <div class="stat-label"><i class="fas fa-code"></i> XSS漏洞</div>
            </div>
        </div>
        
        <!-- 扫描摘要 -->
        <div class="section">
            <div class="section-title">
                <i class="fas fa-info-circle"></i> 扫描摘要
            </div>
            <div class="info-grid">
                <div class="info-card">
                    <h4><i class="fas fa-cogs"></i> 扫描信息</h4>
                    <div class="summary-item">
                        <span class="summary-label">目标地址:</span>
                        <span class="summary-value">''' + html_module.escape(str(target)) + '''</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">扫描时间:</span>
                        <span class="summary-value">''' + html_module.escape(str(scan_time)) + '''</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">扫描耗时:</span>
                        <span class="summary-value">0 秒</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">扫描URL数量:</span>
                        <span class="summary-value">''' + str(total_urls_scanned) + '''</span>
                    </div>
                </div>
                
                <div class="info-card">
                    <h4><i class="fas fa-chart-pie"></i> 漏洞统计</h4>
                    <div class="summary-item">
                        <span class="summary-label">总漏洞数:</span>
                        <span class="summary-value">''' + str(total_vulnerabilities) + '''</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">SQL注入漏洞:</span>
                        <span class="summary-value">''' + str(sql_total) + '''</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">XSS漏洞:</span>
                        <span class="summary-value">''' + str(xss_total) + '''</span>
                    </div>
                </div>
            </div>
        </div>'''
            
            # 添加SQL注入漏洞部分
            if sql_vulnerabilities:
                html_content += '''
        <!-- SQL注入漏洞 -->
        <div class="section">
            <div class="section-title">
                <i class="fas fa-database"></i> SQL注入漏洞 (''' + str(len(sql_vulnerabilities)) + '''个)
            </div>'''
                
                for i, vuln in enumerate(sql_vulnerabilities, 1):
                    html_content += ReportGenerator._generate_vulnerability_html(vuln, i)
                
                html_content += '''
        </div>'''
            else:
                html_content += '''
        <!-- SQL注入漏洞 -->
        <div class="section">
            <div class="section-title">
                <i class="fas fa-database"></i> SQL注入漏洞
            </div>
            <p style="text-align: center; color: #6c757d; padding: 20px;">
                <i class="fas fa-check-circle" style="font-size: 3em; color: #28a745;"></i><br>
                未发现SQL注入漏洞
            </p>
        </div>'''
            
            # 添加XSS漏洞部分
            if xss_vulnerabilities:
                html_content += '''
        <!-- XSS漏洞 -->
        <div class="section">
            <div class="section-title">
                <i class="fas fa-code"></i> XSS漏洞 (''' + str(len(xss_vulnerabilities)) + '''个)
            </div>'''
                
                for i, vuln in enumerate(xss_vulnerabilities, 1):
                    html_content += ReportGenerator._generate_vulnerability_html(vuln, i)
                
                html_content += '''
        </div>'''
            else:
                html_content += '''
        <!-- XSS漏洞 -->
        <div class="section">
            <div class="section-title">
                <i class="fas fa-code"></i> XSS漏洞
            </div>
            <p style="text-align: center; color: #6c757d; padding: 20px;">
                <i class="fas fa-check-circle" style="font-size: 3em; color: #28a745;"></i><br>
                未发现XSS漏洞
            </p>
        </div>'''
            
            # 添加开放端口信息
            if open_ports:
                html_content += '''
        <!-- 开放端口 -->
        <div class="section">
            <div class="section-title">
                <i class="fas fa-network-wired"></i> 开放端口 (''' + str(len(open_ports)) + '''个)
            </div>
            <table>
                <tr>
                    <th>端口</th>
                    <th>服务</th>
                    <th>状态</th>
                </tr>'''
                
                for port_info in open_ports:
                    html_content += '''
                <tr>
                    <td>''' + str(port_info.get('port', '')) + '''</td>
                    <td>''' + html_module.escape(str(port_info.get('service', ''))) + '''</td>
                    <td>''' + html_module.escape(str(port_info.get('status', ''))) + '''</td>
                </tr>'''
                
                html_content += '''
            </table>
        </div>'''
            
            # 添加报告信息
            html_content += '''
        <!-- 报告信息 -->
        <div class="section">
            <div class="section-title">
                <i class="fas fa-file-alt"></i> 报告信息
            </div>
            <p>本报告由 <strong>AdvancedWebScanner</strong> 自动生成。</p>
            <div class="summary-item">
                <span class="summary-label">XSS Payload数量:</span>
                <span class="summary-value">''' + str(xss_payload_count) + '''</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">时间盲注阈值:</span>
                <span class="summary-value">''' + str(sql_threshold) + ''' 秒</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">生成时间:</span>
                <span class="summary-value">''' + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '''</span>
            </div>
        </div>
        
        <div class="footer">
            <p><i class="fas fa-exclamation-triangle"></i> 本报告仅供安全测试使用，请勿用于非法用途</p>
            <p>© 2024 AdvancedWebScanner | 高级Web安全扫描工具</p>
        </div>
    </div>
</body>
</html>'''
            
            return html_content
            
        except Exception as e:
            print(f"ERROR: 生成报告时发生错误: {e}")
            import traceback
            traceback.print_exc()
            
            # 创建简单的错误报告
            error_html = f'''<!DOCTYPE html>
<html>
<head><title>报告生成错误</title>
<style>
body {{ font-family: Arial, sans-serif; padding: 20px; background-color: #f8d7da; color: #721c24; }}
h1 {{ color: #721c24; }}
pre {{ background-color: #f5c6cb; padding: 15px; border-radius: 5px; overflow: auto; max-height: 500px; }}
</style>
</head>
<body>
    <h1>报告生成错误</h1>
    <p><strong>错误信息:</strong> {html_module.escape(str(e))}</p>
    <h2>报告数据结构:</h2>
    <pre>{html_module.escape(json.dumps(report_data, indent=2, ensure_ascii=False, default=str)[:5000])}</pre>
</body>
</html>'''
            return error_html
    
    @staticmethod
    def _generate_vulnerability_html(vuln, index):
        """生成单个漏洞的HTML"""
        try:
            vuln_type = vuln.get('type', '未知漏洞')
            parameter = vuln.get('parameter', 'N/A')
            payload = vuln.get('payload', 'N/A')
            confidence = vuln.get('confidence', '未知')
            details = vuln.get('details', '')
            evidence = vuln.get('evidence', '')
            url = vuln.get('url', 'N/A')
            
            # 处理URL字段（可能是字符串或列表）
            if isinstance(url, list):
                url_str = url[0] if url else 'N/A'
            else:
                url_str = str(url)
            
            # 根据置信度设置风险等级
            if confidence == "高" or confidence == "high":
                risk_class = "risk-high"
                risk_label = "高风险"
                icon = "fas fa-exclamation-triangle"
            elif confidence == "中" or confidence == "medium":
                risk_class = "risk-medium"
                risk_label = "中风险"
                icon = "fas fa-exclamation-circle"
            elif confidence == "低" or confidence == "low":
                risk_class = "risk-low"
                risk_label = "低风险"
                icon = "fas fa-info-circle"
            else:
                risk_class = "risk-info"
                risk_label = "未知风险"
                icon = "fas fa-question-circle"
            
            # 根据漏洞类型设置图标
            vuln_type_lower = vuln_type.lower()
            if 'sql' in vuln_type_lower:
                vuln_icon = "fas fa-database"
                vuln_prefix = "SQL注入"
            elif 'xss' in vuln_type_lower:
                vuln_icon = "fas fa-code"
                vuln_prefix = "XSS"
            else:
                vuln_icon = "fas fa-bug"
                vuln_prefix = "漏洞"
            
            html = '''
            <div class="vulnerability ''' + risk_class + '''">
                <div class="vuln-title">
                    <span><i class="''' + vuln_icon + '''"></i> ''' + vuln_prefix + ''' #''' + str(index) + ''': ''' + html_module.escape(str(vuln_type)) + '''</span>
                    <span class="vuln-badge"><i class="''' + icon + '''"></i> ''' + risk_label + '''</span>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-bottom: 15px;">
                    <div>
                        <p><strong><i class="fas fa-tag"></i> 类型:</strong> ''' + html_module.escape(str(vuln_type)) + '''</p>
                        <p><strong><i class="fas fa-code"></i> 参数:</strong> <code>''' + html_module.escape(str(parameter)) + '''</code></p>
                        <p><strong><i class="fas fa-link"></i> URL:</strong> <code>''' + html_module.escape(str(url_str))[:100] + '''</code></p>
                    </div>
                    <div>
                        <p><strong><i class="fas fa-shield-alt"></i> 置信度:</strong> ''' + html_module.escape(str(confidence)) + '''</p>'''
            
            if evidence:
                html += '''<p><strong><i class="fas fa-search"></i> 证据:</strong> ''' + html_module.escape(str(evidence)) + '''</p>'''
            
            if details:
                html += '''<p><strong><i class="fas fa-info-circle"></i> 详情:</strong> ''' + html_module.escape(str(details)) + '''</p>'''
            
            html += '''</div>
                </div>
                <div>
                    <p><strong><i class="fas fa-code"></i> Payload:</strong></p>
                    <div class="payload-code">''' + html_module.escape(str(payload)) + '''</div>
                    <button onclick="copyToClipboard(`''' + html_module.escape(str(payload)).replace('`', '\\`') + '''`)" 
                            style="background-color: #6c757d; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; margin-top: 5px;">
                        <i class="fas fa-copy"></i> 复制Payload
                    </button>
                </div>
            </div>'''
            
            return html
        except Exception as e:
            print(f"ERROR: 生成漏洞HTML时发生错误: {e}")
            return '''
            <div class="vulnerability risk-info">
                <div class="vuln-title">
                    <span><i class="fas fa-exclamation-triangle"></i> 漏洞 #''' + str(index) + '''</span>
                    <span class="vuln-badge">错误</span>
                </div>
                <p>生成漏洞信息时发生错误: ''' + html_module.escape(str(e)) + '''</p>
            </div>'''
    
    @staticmethod
    def save_results(results, filename, output_dir="output", save_type=None, scanner=None):
        """保存扫描结果到文件"""
        try:
            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)
            
            # 清洁文件名
            clean_filename = filename.replace('/', '_').replace('\\', '_')
            
            saved_files = []
            
            # 保存JSON
            if save_type == "json" or save_type == "all" or save_type is None:
                json_path = os.path.join(output_dir, clean_filename + '.json')
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False, default=str)
                saved_files.append(('JSON', json_path))
            
            # 保存TXT
            if save_type == "txt" or save_type == "all" or save_type is None:
                txt_path = os.path.join(output_dir, clean_filename + '_summary.txt')
                ReportGenerator.save_text_summary(results, txt_path)
                saved_files.append(('TXT', txt_path))
            
            # 保存HTML
            if save_type == "html" or save_type == "all" or save_type is None:
                html_path = os.path.join(output_dir, clean_filename + '_report.html')
                
                # 获取扫描器配置信息
                xss_count = len(scanner.xss_payloads) if scanner and hasattr(scanner, 'xss_payloads') else 0
                sql_threshold = scanner.sql_thresholds.get('time_based_threshold', 3.0) if scanner and hasattr(scanner, 'sql_thresholds') else 3.0
                
                html_content = ReportGenerator.generate_html_report(
                    results, 
                    xss_payload_count=xss_count,
                    sql_threshold=sql_threshold
                )
                
                with open(html_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                saved_files.append(('HTML', html_path))
            
            # 输出保存结果
            for file_type, file_path in saved_files:
                print(f"[+] ({file_type})报告已保存到: {file_path}")
            
            return True
            
        except Exception as e:
            print(f"[-] 保存结果失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    @staticmethod
    def save_text_summary(results, filepath):
        """保存文本摘要"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("Web安全扫描报告摘要\n")
                f.write("=" * 70 + "\n\n")
                
                # 目标信息
                target = results.get('target', '未知目标')
                f.write(f"目标地址: {target}\n")
                
                # 扫描时间
                scan_time = results.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                f.write(f"扫描时间: {scan_time}\n\n")
                
                # 开放端口
                open_ports = results.get('open_ports', [])
                if open_ports:
                    f.write(f"开放端口 ({len(open_ports)}个):\n")
                    for port_info in open_ports:
                        port = port_info.get('port', 'N/A')
                        service = port_info.get('service', '未知服务')
                        f.write(f"  端口 {port}: {service}\n")
                    f.write("\n")
                
                # 漏洞信息
                vulnerabilities = results.get('vulnerabilities', [])
                if vulnerabilities:
                    f.write(f"发现漏洞 ({len(vulnerabilities)}个):\n")
                    f.write("=" * 50 + "\n")
                    
                    # 分类统计
                    sql_count = 0
                    xss_count = 0
                    other_count = 0
                    
                    for vuln in vulnerabilities:
                        vuln_type = vuln.get('type', '').lower()
                        if 'sql' in vuln_type:
                            sql_count += 1
                        elif 'xss' in vuln_type:
                            xss_count += 1
                        else:
                            other_count += 1
                    
                    f.write(f"SQL注入漏洞: {sql_count} 个\n")
                    f.write(f"XSS漏洞: {xss_count} 个\n")
                    f.write(f"其他漏洞: {other_count} 个\n\n")
                    
                    # 详细漏洞信息
                    for i, vuln in enumerate(vulnerabilities, 1):
                        vuln_type = vuln.get('type', '未知漏洞')
                        confidence = vuln.get('confidence', '未知')
                        parameter = vuln.get('parameter', 'N/A')
                        payload = vuln.get('payload', 'N/A')
                        
                        f.write(f"{i}. {vuln_type} (置信度: {confidence})\n")
                        f.write(f"   参数: {parameter}\n")
                        f.write(f"   Payload: {payload[:100]}\n")
                        f.write("-" * 30 + "\n")
                    
                    f.write("\n")
                else:
                    f.write("未发现漏洞\n\n")
                
                f.write("=" * 70 + "\n")
            
            return True
        except Exception as e:
            print(f"[-] 保存文本摘要失败: {e}")
            return False


# 导出函数别名
generate_html_report = ReportGenerator.generate_html_report