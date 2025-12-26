import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from urllib.parse import urlparse

# # 目标 URL
# url = "http://myip.ipip.net/"

# # 发送 GET 请求
# response = requests.get(url)

# # 打印状态码和响应内容
# print(f"Status Code: {response.status_code}")
# print("Response Body:", response.text)

# ip=response.text.split(" ")[1]
# print(ip)

class sampilescanner:
    def __init__(self):
        self.session=requests.Session()
        self.session.headers.update({
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; rv:109.0) Gecko/20100101 Firefox/115.0"
        })
        #获取日志记录器
        self.logger=logging.getLogger('vuln_scanner.scan.port')
    def check_sql_injection(self, url):
        # SQL注入扫描
                 
        testpayloads=[
                "'",
                "\"",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
        ]

        vulnerabilities=[]
        #下面漏洞识别能力未完成
        for payload in testpayloads:
            # 构建测试 URL（保证 base 有结尾斜杠再 join）
            base = url if url.endswith('/') else url + '/'
            test_url = urljoin(base, 'sqli-labs-master/Less-5/')
            params = {'id': f"1{payload}"}
            print(f"Testing: {test_url} params={params}")
            try:
                response = self.session.get(test_url, params=params, timeout=5)
                body = response.text.lower()
                # 常见的 SQL 错误指示器（全部小写以便比较）
                error_indicators = [
                    "you have an error in your sql syntax",
                    "warning: mysql",
                    "sql syntax",
                    "mysql_fetch",
                    "syntax error",
                    "mysql_num_rows",
                    "unclosed quotation mark after the character string",
                    "quoted string not properly terminated",
                    "welcome",
                    "dhakkan"
                ]
                # 只打印响应摘要，避免大量输出
                #print(body[:400])
                for error in error_indicators:
                    if error in body:
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "payload": payload,
                            "confidence": "低",
                            "tested_url": test_url,
                            "params": params,
                        })
                        break
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                continue
        return vulnerabilities
    
    def check_xss(self, url):
        # XSS扫描
        testpayloads=[
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
        ]

        vulnerabilities=[]
        for payload in testpayloads:
            test_url=f"{url}?test={payload}"
            print(test_url)
            try:
                response=self.session.get(test_url,timeout=5)
                if payload in response.text:
                    vulnerabilities.append({
                        "type":"反射型XSS",
                        "payload":payload,
                        "confidence":"低"
                    })
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                continue
        return vulnerabilities
    
    def crawl_links(self, url):
        # 爬取页面中的链接
        try:
            response=self.session.get(url,timeout=10)
            soup=BeautifulSoup(response.text,"html.parser")

            # 解析基础URL的域名
            base_domain = urlparse(url).netloc
            links=[]
            for link in soup.find_all("a",href=True):
                href=link['href']
                # 解析链接的域名
                absolute_url=urljoin(url,href)
                link_domain = urlparse(absolute_url).netloc                
                # 只爬取同域名链接（忽略协议差异）
                if link_domain == base_domain:
                    links.append(absolute_url)
            return list(set(links)) #去重
        except Exception as e:
            self.logger.error(f"爬取链接失败: {url}, 错误: {e}")
            return []

