#!/usr/bin/env python3
"""
扫描器测试脚本 - 用于验证检测准确性
"""
import sys
import os

# 确保可以导入模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_payload_loading():
    """测试Payload加载"""
    print("=" * 60)
    print("测试1: Payload文件加载")
    print("=" * 60)
    
    from utils import load_xss_payload, load_sqli_config
    
    # 测试XSS Payload加载
    xss_payloads = load_xss_payload()
    print(f"\n✅ XSS Payload 加载成功:")
    print(f"   - 总数: {len(xss_payloads)}")
    
    # 测试SQL注入配置加载
    sql_config = load_sqli_config()
    print(f"\n✅ SQL注入配置 加载成功:")
    
    # 统计各类型payload数量
    if 'payloads' in sql_config:
        for category, payloads in sql_config['payloads'].items():
            if isinstance(payloads, list):
                print(f"   - {category}: {len(payloads)}")
            elif isinstance(payloads, dict):
                for sub_cat, sub_payloads in payloads.items():
                    if isinstance(sub_payloads, list):
                        print(f"   - {category}.{sub_cat}: {len(sub_payloads)}")
    
    # 测试注入点参数列表
    if 'injection_points' in sql_config:
        print(f"\n✅ 注入点参数列表:")
        for point_type, params in sql_config['injection_points'].items():
            print(f"   - {point_type}: {len(params)} 个参数")
    
    return True


def test_scanner_initialization():
    """测试扫描器初始化"""
    print("\n" + "=" * 60)
    print("测试2: 扫描器初始化")
    print("=" * 60)
    
    try:
        from web_scanner import sampilescanner
        
        scanner = sampilescanner()
        print(f"\n✅ 扫描器初始化成功")
        
        # 检查配置
        print(f"\n   配置信息:")
        print(f"   - SQL时间盲注阈值: {scanner.sql_thresholds.get('time_based_threshold')}秒")
        print(f"   - 布尔盲注置信度阈值: {scanner.sql_thresholds.get('boolean_confidence_min')}")
        print(f"   - 响应相似度阈值: {scanner.sql_thresholds.get('response_similarity_threshold')}")
        
        return scanner
    except Exception as e:
        print(f"\n❌ 扫描器初始化失败: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_parameter_detection(scanner):
    """测试参数检测功能"""
    print("\n" + "=" * 60)
    print("测试3: 参数检测功能")
    print("=" * 60)
    
    if not scanner:
        print("❌ 扫描器未初始化")
        return
    
    # 获取注入点参数列表
    injection_points = scanner.sql_config.get('injection_points', {})
    
    print(f"\n✅ 可测试的参数类型:")
    for point_type, params in injection_points.items():
        print(f"\n   [{point_type}]")
        # 只显示前10个参数
        display_params = params[:10] if len(params) > 10 else params
        print(f"   示例: {', '.join(display_params)}")
        if len(params) > 10:
            print(f"   ... 共 {len(params)} 个")


def test_request_simulation():
    """测试请求模拟（不发送真实请求）"""
    print("\n" + "=" * 60)
    print("测试4: 请求模拟测试")
    print("=" * 60)
    
    from modules.request_sender import RequestSender
    from modules.request_manager import RateLimiter
    
    try:
        # 创建请求发送器
        rate_limiter = RateLimiter(max_requests_per_second=10, max_requests_per_minute=100)
        sender = RequestSender(
            timeout=5,
            verify_ssl=False,
            max_retries=1
        )
        
        print(f"\n✅ 请求发送器初始化成功")
        print(f"   - 超时: 5秒")
        print(f"   - 验证SSL: False")
        print(f"   - 最大重试: 1次")
        
        return True
    except Exception as e:
        print(f"\n❌ 请求发送器初始化失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_quick_validation():
    """运行快速验证"""
    print("\n" + "=" * 60)
    print("快速验证: 检查关键功能模块")
    print("=" * 60)
    
    checks = []
    
    # 1. 检查JSON文件
    try:
        import json
        with open('payload/xss.json', 'r', encoding='utf-8') as f:
            json.load(f)
        checks.append(("XSS Payload JSON", True))
    except Exception as e:
        checks.append(("XSS Payload JSON", False))
        print(f"   ❌ XSS JSON: {e}")
    
    try:
        import json
        with open('payload/sql_injection.json', 'r', encoding='utf-8') as f:
            json.load(f)
        checks.append(("SQLi Payload JSON", True))
    except Exception as e:
        checks.append(("SQLi Payload JSON", False))
        print(f"   ❌ SQLi JSON: {e}")
    
    # 2. 检查模块导入
    try:
        from web_scanner import sampilescanner
        checks.append(("Web Scanner 模块", True))
    except Exception as e:
        checks.append(("Web Scanner 模块", False))
        print(f"   ❌ Web Scanner: {e}")
    
    try:
        from modules.request_sender import RequestSender
        checks.append(("Request Sender 模块", True))
    except Exception as e:
        checks.append(("Request Sender 模块", False))
        print(f"   ❌ Request Sender: {e}")
    
    # 3. 检查工具函数
    try:
        from utils import load_config, load_sqli_config, load_xss_payload
        checks.append(("Utils 工具函数", True))
    except Exception as e:
        checks.append(("Utils 工具函数", False))
        print(f"   ❌ Utils: {e}")
    
    print("\n✅ 验证结果:")
    all_passed = True
    for name, passed in checks:
        status = "✅ 通过" if passed else "❌ 失败"
        print(f"   {name}: {status}")
        if not passed:
            all_passed = False
    
    return all_passed


def print_usage():
    """打印使用说明"""
    print("\n" + "=" * 60)
    print("使用说明")
    print("=" * 60)
    print("""
要验证扫描器准确性，需要在真实测试环境上运行:

1. SQL注入测试 - 使用 DVWA 或 SQLi-Labs:
   scanner = sampilescanner()
   vulns, results = scanner.check_sql_injection(
       "http://target/vuln.php?id=1",
       param_name="id",
       param_value="1"
   )

2. XSS测试 - 使用 XSS-Lab:
   scanner = sampilescanner()
   vulns, results = scanner.check_xss(
       "http://target/xss.php?keyword=test"
   )

3. 自动参数检测:
   scanner = sampilescanner()
   vulns, results = scanner.check_sql_injection(
       "http://target/page.php",
       auto_detect_params=True
   )
""")


if __name__ == "__main__":
    print("🔍 Base Scanner - 扫描器测试脚本")
    print()
    
    # 运行验证
    run_quick_validation()
    
    # 测试Payload加载
    test_payload_loading()
    
    # 测试扫描器初始化
    scanner = test_scanner_initialization()
    
    # 测试参数检测
    test_parameter_detection(scanner)
    
    # 测试请求模拟
    test_request_simulation()
    
    # 打印使用说明
    print_usage()
    
    print("\n" + "=" * 60)
    print("✅ 所有基础测试完成!")
    print("=" * 60)
