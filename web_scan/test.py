def _format_html_report(self, report_data):
        """格式化HTML报告"""
        html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web安全扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .section-title { font-size: 1.5em; font-weight: bold; margin-bottom: 15px; color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        .vulnerability { background-color: #f9f9f9; padding: 15px; margin-bottom: 15px; border-left: 4px solid #e74c3c; border-radius: 3px; }
        .vuln-title { font-weight: bold; color: #e74c3c; margin-bottom: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-box { background-color: #3498db; color: white; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
        .risk-high { border-left-color: #e74c3c; }
        .risk-medium { border-left-color: #f39c12; }
        .risk-low { border-left-color: #f1c40f; }
        .risk-info { border-left-color: #3498db; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Web安全扫描报告</h1>
            <p>生成时间: ''' + report_data.get('scan_summary', {}).get('scan_timestamp', 'N/A') + '''</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">''' + str(report_data.get('scan_summary', {}).get('total_urls_scanned', 0)) + '''</div>
                <div class="stat-label">扫描URL数量</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">''' + str(report_data.get('scan_summary', {}).get('total_vulnerabilities', 0)) + '''</div>
                <div class="stat-label">发现漏洞总数</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">''' + str(report_data.get('sql_injection', {}).get('total_found', 0)) + '''</div>
                <div class="stat-label">SQL注入漏洞</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">''' + str(report_data.get('xss', {}).get('total_found', 0)) + '''</div>
                <div class="stat-label">XSS漏洞</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">扫描摘要</div>
            <table>
                <tr><th>项目</th><th>值</th></tr>
                <tr><td>扫描时间</td><td>''' + report_data.get('scan_summary', {}).get('scan_timestamp', 'N/A') + '''</td></tr>
                <tr><td>扫描URL数量</td><td>''' + str(report_data.get('scan_summary', {}).get('total_urls_scanned', 0)) + '''</td></tr>
                <tr><td>发现漏洞总数</td><td>''' + str(report_data.get('scan_summary', {}).get('total_vulnerabilities', 0)) + '''</td></tr>
                <tr><td>扫描耗时</td><td>''' + str(report_data.get('scan_summary', {}).get('scan_duration_seconds', 0)) + '''秒</td></tr>
            </table>
        </div>'''
        
        # SQL注入部分
        sql_data = report_data.get('sql_injection', {})
        if sql_data.get('vulnerabilities'):
            html += '''
        <div class="section">
            <div class="section-title">SQL注入漏洞 (''' + str(sql_data.get('total_found', 0)) + '''个)</div>'''
            
            for i, vuln in enumerate(sql_data.get('vulnerabilities', []), 1):
                risk_class = "risk-high" if "high" in str(vuln.get('confidence', '')).lower() or vuln.get('confidence') == "高" else "risk-medium"
                html += '''
            <div class="vulnerability ''' + risk_class + '''">
                <div class="vuln-title">''' + str(i) + '. ' + vuln.get('type', 'Unknown') + '''</div>
                <p><strong>参数:</strong> ''' + vuln.get('parameter', 'N/A') + '''</p>
                <p><strong>Payload:</strong> <code>''' + vuln.get('payload', 'N/A')[:100] + '''</code></p>
                <p><strong>置信度:</strong> ''' + vuln.get('confidence', 'N/A') + '''</p>
                <p><strong>数据库:</strong> ''' + vuln.get('database', 'N/A') + '''</p>
            </div>'''
            
            html += '''
        </div>'''
        
        # XSS部分
        xss_data = report_data.get('xss', {})
        if xss_data.get('vulnerabilities'):
            html += '''
        <div class="section">
            <div class="section-title">XSS漏洞 (''' + str(xss_data.get('total_found', 0)) + '''个)</div>'''
            
            for i, vuln in enumerate(xss_data.get('vulnerabilities', []), 1):
                confidence = vuln.get('confidence', '')
                if confidence == "高":
                    risk_class = "risk-high"
                elif confidence == "中":
                    risk_class = "risk-medium"
                else:
                    risk_class = "risk-low"
                    
                html += '''
            <div class="vulnerability ''' + risk_class + '''">
                <div class="vuln-title">''' + str(i) + '. ' + vuln.get('type', 'Unknown') + '''</div>
                <p><strong>参数:</strong> ''' + vuln.get('parameter', 'N/A') + '''</p>
                <p><strong>Payload:</strong> <code>''' + vuln.get('payload', 'N/A')[:100] + '''</code></p>
                <p><strong>置信度:</strong> ''' + vuln.get('confidence', 'N/A') + '''</p>
                <p><strong>详情:</strong> ''' + vuln.get('details', 'N/A') + '''</p>
            </div>'''
            
            html += '''
        </div>'''
        
        # DOM XSS部分
        dom_xss_vulns = xss_data.get('dom_xss_vulnerabilities', [])
        if dom_xss_vulns:
            html += '''
        <div class="section">
            <div class="section-title">DOM型XSS漏洞 (''' + str(len(dom_xss_vulns)) + '''个)</div>'''
            
            for i, vuln in enumerate(dom_xss_vulns, 1):
                html += '''
            <div class="vulnerability risk-info">
                <div class="vuln-title">''' + str(i) + '. ' + vuln.get('type', 'Unknown') + '''</div>
                <p><strong>Payload:</strong> <code>''' + vuln.get('payload', 'N/A') + '''</code></p>
                <p><strong>置信度:</strong> ''' + vuln.get('confidence', 'N/A') + '''</p>
                <p><strong>详情:</strong> ''' + vuln.get('details', 'N/A') + '''</p>
            </div>'''
            
            html += '''
        </div>'''
        
        # 风险等级统计
        risk_levels = report_data.get('risk_levels', {})
        if any(risk_levels.values()):
            html += '''
        <div class="section">
            <div class="section-title">风险等级统计</div>
            <table>
                <tr><th>风险等级</th><th>数量</th></tr>'''
            
            for level, vulns in risk_levels.items():
                if vulns:
                    html += '''
                <tr><td>''' + level.upper() + '''</td><td>''' + str(len(vulns)) + '''</td></tr>'''
            
            html += '''
            </table>
        </div>'''
        
        html += '''
        <div class="section">
            <div class="section-title">报告信息</div>
            <p>本报告由AdvancedWebScanner自动生成。</p>
            <p>扫描配置: SQL注入配置文件 - sql_injection.json</p>
            <p>XSS Payload数量: ''' + str(len(self.xss_payloads)) + '''</p>
            <p>时间盲注阈值: ''' + str(self.sql_thresholds['time_based_threshold']) + '''秒</p>
        </div>
    </div>
</body>
</html>'''
        
        return html