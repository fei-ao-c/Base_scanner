#!/usr/bin/env python3
"""测试payload文件加载"""
import json

# 测试加载XSS payloads
with open('payload/xss.json', 'r', encoding='utf-8') as f:
    xss_data = json.load(f)
print('XSS payloads loaded:')
print(f'  - Basic: {len(xss_data.get("xss_payloads", []))}')
print(f'  - DOM-based: {len(xss_data.get("dom_based_xss", []))}')
print(f'  - JSON XSS: {len(xss_data.get("json_xss", []))}')
print(f'  - Angular: {len(xss_data.get("angular_xss", []))}')
print(f'  - Template: {len(xss_data.get("template_injection", []))}')
print(f'  - Bypass: {len(xss_data.get("bypass_techniques", []))}')
print(f'  - Context: {len(xss_data.get("context_specific", {}).keys())} categories')

# 测试加载SQL payloads
with open('payload/sql_injection.json', 'r', encoding='utf-8') as f:
    sqli_data = json.load(f)
print('\nSQL Injection payloads loaded:')
print(f'  - Generic: {len(sqli_data.get("payloads", {}).get("generic_error_based", []))}')
print(f'  - MySQL: {len(sqli_data.get("payloads", {}).get("mysql_specific", {}).get("error_based", []))}')
print(f'  - MSSQL: {len(sqli_data.get("payloads", {}).get("mssql_specific", {}).get("error_based", []))}')
print(f'  - NoSQL (MongoDB): {len(sqli_data.get("payloads", {}).get("nosql_injection", {}).get("mongodb", []))}')
print(f'  - NoSQL (Redis): {len(sqli_data.get("payloads", {}).get("nosql_injection", {}).get("redis", []))}')
print(f'  - NoSQL (Elasticsearch): {len(sqli_data.get("payloads", {}).get("nosql_injection", {}).get("elasticsearch", []))}')
print(f'  - NoSQL (DynamoDB): {len(sqli_data.get("payloads", {}).get("nosql_injection", {}).get("dynamodb", []))}')
print(f'  - NoSQL (Firebase): {len(sqli_data.get("payloads", {}).get("nosql_injection", {}).get("firebase", {}).get("authentication_bypass", []))}')

print('\n=== All payload files loaded successfully! ===')
