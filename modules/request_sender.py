# modules/request_sender.py
import requests
import aiohttp
import asyncio
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin, quote
from typing import Dict, Any, Optional, Tuple, Union
import logging
import ssl
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class RequestSender:
    """多功能请求发送器"""
    
    def __init__(self, 
                 timeout: int = 10,
                 verify_ssl: bool = True,
                 user_agent: str = None,
                 proxies: Dict = None,
                 max_retries: int = 3,
                 retry_backoff: float = 0.5):
        """
        Args:
            timeout: 请求超时时间（秒）
            verify_ssl: 是否验证SSL证书
            user_agent: User-Agent头
            proxies: 代理设置
            max_retries: 最大重试次数
            retry_backoff: 重试退避因子
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxies = proxies
        
        # 默认User-Agent
        self.default_headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # 创建会话
        self.session = self._create_session(max_retries, retry_backoff)
        
        # 创建异步会话
        self.async_session = None
        
        # 日志
        self.logger = logging.getLogger('vuln_scanner.request')
        
        # 统计
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_response_size': 0,
            'average_response_time': 0
        }
    
    def _create_session(self, max_retries: int, retry_backoff: float) -> requests.Session:
        """创建带重试机制的会话"""
        session = requests.Session()
        
        # 配置重试策略
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=retry_backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        )
        
        # 创建适配器
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        
        # 挂载适配器
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 设置代理
        if self.proxies:
            session.proxies.update(self.proxies)
        
        return session
    
    async def _get_async_session(self) -> aiohttp.ClientSession:
        """获取异步会话（懒加载）"""
        if self.async_session is None or self.async_session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            # SSL配置
            ssl_context = None
            if not self.verify_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            self.async_session = aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=ssl_context),
                headers=self.default_headers
            )
        
        return self.async_session
    
    def _prepare_headers(self, headers: Dict = None) -> Dict:
        """准备请求头"""
        if headers is None:
            headers = {}
        
        # 合并默认头
        final_headers = self.default_headers.copy()
        final_headers.update(headers)
        
        return final_headers
    
    def _prepare_data(self, data: Any = None, json_data: Any = None) -> Tuple[Any, Dict]:
        """准备请求数据"""
        body = None
        headers = {}
        
        if json_data is not None:
            body = json.dumps(json_data)
            headers['Content-Type'] = 'application/json'
        elif data is not None:
            if isinstance(data, dict):
                body = data
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                body = data
        
        return body, headers
    
    def send_request(self, 
                    method: str,
                    url: str,
                    params: Dict = None,
                    data: Any = None,
                    json_data: Any = None,
                    headers: Dict = None,
                    cookies: Dict = None,
                    allow_redirects: bool = True,
                    timeout: int = None,
                    auth: Tuple = None) -> requests.Response:
        """发送HTTP请求（同步）"""
        start_time = time.time()
        
        try:
            # 准备请求参数
            final_headers = self._prepare_headers(headers)
            body, body_headers = self._prepare_data(data, json_data)
            final_headers.update(body_headers)
            
            # 发送请求
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=body,
                headers=final_headers,
                cookies=cookies,
                allow_redirects=allow_redirects,
                timeout=timeout or self.timeout,
                verify=self.verify_ssl,
                auth=auth
            )
            
            # 更新统计
            response_time = time.time() - start_time
            self._update_stats(success=True, response_time=response_time, 
                             response_size=len(response.content))
            
            self.logger.debug(f"请求成功: {method} {url} - {response.status_code} ({response_time:.2f}s)")
            
            return response
            
        except Exception as e:
            # 更新统计
            response_time = time.time() - start_time
            self._update_stats(success=False, response_time=response_time)
            
            self.logger.error(f"请求失败: {method} {url} - {e}")
            raise
    
    async def send_request_async(self, 
                               method: str,
                               url: str,
                               params: Dict = None,
                               data: Any = None,
                               json_data: Any = None,
                               headers: Dict = None,
                               cookies: Dict = None,
                               allow_redirects: bool = True,
                               timeout: int = None,
                               auth: Tuple = None) -> aiohttp.ClientResponse:
        """发送HTTP请求（异步）"""
        start_time = time.time()
        
        try:
            # 获取异步会话
            session = await self._get_async_session()
            
            # 准备请求参数
            final_headers = self._prepare_headers(headers)
            body, body_headers = self._prepare_data(data, json_data)
            final_headers.update(body_headers)
            
            # 准备cookies
            jar = None
            if cookies:
                jar = aiohttp.CookieJar()
                for name, value in cookies.items():
                    jar.update_cookies({name: value})
            
            # 发送请求
            async with session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=body,
                headers=final_headers,
                cookies=jar,
                allow_redirects=allow_redirects,
                timeout=timeout or self.timeout,
                auth=auth
            ) as response:
                
                # 读取响应内容
                await response.read()
                
                # 更新统计
                response_time = time.time() - start_time
                self._update_stats(success=True, response_time=response_time,
                                 response_size=len(response.content))
                
                self.logger.debug(f"异步请求成功: {method} {url} - {response.status} ({response_time:.2f}s)")
                
                return response
                
        except Exception as e:
            # 更新统计
            response_time = time.time() - start_time
            self._update_stats(success=False, response_time=response_time)
            
            self.logger.error(f"异步请求失败: {method} {url} - {e}")
            raise
    
    def _update_stats(self, success: bool, response_time: float, response_size: int = 0):
        """更新统计信息"""
        self.stats['total_requests'] += 1
        
        if success:
            self.stats['successful_requests'] += 1
            self.stats['total_response_size'] += response_size
            
            # 更新平均响应时间（加权平均）
            old_avg = self.stats['average_response_time']
            old_count = self.stats['successful_requests'] - 1
            
            if old_count > 0:
                self.stats['average_response_time'] = (
                    old_avg * old_count + response_time
                ) / self.stats['successful_requests']
            else:
                self.stats['average_response_time'] = response_time
        else:
            self.stats['failed_requests'] += 1
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """发送GET请求"""
        return self.send_request('GET', url, **kwargs)
    
    def post(self, url: str, data: Any = None, **kwargs) -> requests.Response:
        """发送POST请求"""
        return self.send_request('POST', url, data=data, **kwargs)
    
    def put(self, url: str, data: Any = None, **kwargs) -> requests.Response:
        """发送PUT请求"""
        return self.send_request('PUT', url, data=data, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """发送DELETE请求"""
        return self.send_request('DELETE', url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """发送HEAD请求"""
        return self.send_request('HEAD', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> requests.Response:
        """发送OPTIONS请求"""
        return self.send_request('OPTIONS', url, **kwargs)
    
    def patch(self, url: str, data: Any = None, **kwargs) -> requests.Response:
        """发送PATCH请求"""
        return self.send_request('PATCH', url, data=data, **kwargs)
    
    async def close(self):
        """关闭会话"""
        # 关闭同步会话
        if hasattr(self, 'session'):
            self.session.close()
        
        # 关闭异步会话
        if self.async_session and not self.async_session.closed:
            await self.async_session.close()
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        stats = self.stats.copy()
        
        # 计算成功率
        if stats['total_requests'] > 0:
            stats['success_rate'] = (
                stats['successful_requests'] / stats['total_requests'] * 100
            )
        else:
            stats['success_rate'] = 0
        
        # 计算平均响应大小
        if stats['successful_requests'] > 0:
            stats['average_response_size'] = (
                stats['total_response_size'] / stats['successful_requests']
            )
        else:
            stats['average_response_size'] = 0
        
        return stats