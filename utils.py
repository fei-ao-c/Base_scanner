import json
import os
import sys
from datetime import datetime

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

def load_config():
    # 1. 获取当前脚本文件的绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. 构建相对于脚本所在目录的路径
    config_path = os.path.join(current_dir, "config", "config.json")
    
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
                print_colored("配置文件加载成功", "green")
        except Exception as e:
            print_colored(f"[-] 加载配置文件出错: {e}，使用默认配置", "yellow")
    return default_config


def save_results(results, filename, output_dir="output"):
    """
    保存扫描结果到文件
    Args:
        results: 要保存的数据（字典）
        filename: 文件名（不包含路径）
        output_dir: 输出目录
    """
    try:
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
        
        # 构建完整路径
        filepath = os.path.join(output_dir, filename)
        
        # 保存为JSON格式
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print_colored(f"[+] 扫描结果已保存到: {filepath}", "green")
        
        # 同时保存一个简化的文本摘要
        save_text_summary(results, filename.replace('.json', '_summary.txt'), output_dir)
        
        return True
    except Exception as e:
        print_colored(f"[-] 保存结果失败: {e}", "red")
        return False

def save_text_summary(results, filename, output_dir="output"):
    """保存文本格式的扫描摘要"""
    try:
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("漏洞扫描报告摘要\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"目标地址: {results.get('target', 'N/A')}\n")
            f.write(f"扫描时间: {results.get('scan_time', 'N/A')}\n\n")
            
            # 端口信息
            open_ports = results.get('open_ports', [])
            f.write(f"开放端口 ({len(open_ports)}个):\n")
            f.write("-" * 40 + "\n")
            for port_info in open_ports:
                f.write(f"端口 {port_info.get('port', 'N/A')}: {port_info.get('service', '未知服务')}\n")
            
            f.write("\n")
            
            # 漏洞信息
            vulnerabilities = results.get('vulnerabilities', [])
            f.write(f"发现漏洞 ({len(vulnerabilities)}个):\n")
            f.write("-" * 40 + "\n")
            
            if vulnerabilities:
                # 按风险等级分类
                high_risk = [v for v in vulnerabilities if v.get('confidence') == '高']
                medium_risk = [v for v in vulnerabilities if v.get('confidence') == '中']
                low_risk = [v for v in vulnerabilities if v.get('confidence') == '低']
                
                f.write(f"高风险漏洞: {len(high_risk)}个\n")
                f.write(f"中风险漏洞: {len(medium_risk)}个\n")
                f.write(f"低风险漏洞: {len(low_risk)}个\n\n")
                
                # 列出具体漏洞
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"{i}. 类型: {vuln.get('type', '未知')}\n")
                    f.write(f"   风险等级: {vuln.get('confidence', '未知')}\n")
                    f.write(f"   Payload: {vuln.get('payload', 'N/A')}\n")
                    f.write(f"   URL: {vuln.get('url', 'N/A')}\n")
                    f.write("-" * 30 + "\n")
            else:
                f.write("未发现漏洞\n")
            
            f.write("\n" + "=" * 60 + "\n")
        
        print_colored(f"[+] 文本摘要已保存到: {filepath}", "green")
        return True
    except Exception as e:
        print_colored(f"[-] 保存文本摘要失败: {e}", "yellow")
        return False

# modules/utils.py - 增强版本
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
        output.append(f"  • 高风险漏洞: {summary.get('high_risk_vulns', 0)}")
        output.append(f"  • 中风险漏洞: {summary.get('medium_risk_vulns', 0)}")
    
    output.append("=" * 70)
    
    return "\n".join(output)    