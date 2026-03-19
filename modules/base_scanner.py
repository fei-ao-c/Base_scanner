"""
基础扫描器类 - 提供所有扫描器的公共功能
"""
import time
import logging
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse

try:
    from .common_utils import (
        parse_cookies, build_url_with_param, calculate_similarity,
        ErrorHandler, format_vulnerability_result
    )
    from .request_manager import RateLimiter
    from .request_queue import RequestQueueManager
    from .request_sender import RequestSender
    from .request_builder import RequestBuilder
    from .response_parse import ResponseParse
except ImportError:
    from common_utils import (
        parse_cookies, build_url_with_param, calculate_similarity,
        ErrorHandler, format_vulnerability_result
    )


class BaseScanner:
    """
    基础扫描器类 - 所有扫描器的父类
    
    提供:
    - 统一的请求发送
    - 基准响应管理
    - 错误处理
    - 结果格式化
    """
    
    def __init__(self, config: Dict = None, scanner_name: str = "base"):
        """
        初始化基础扫描器
        
        Args:
            config: 配置字典
            scanner_name: 扫描器名称（用于日志）
        """
        self.config = config or {}
        self.scanner_name = scanner_name
        self.logger = logging.getLogger(f'vuln_scanner.{scanner_name}')
        
        # 错误处理器
        self.error_handler = ErrorHandler()
        
        # 初始化请求组件
        self._init_request_components()
        
        # 基准响应缓存
        self.baseline_responses = {}
        
        # 结果存储
        self.results = {
            "requests": [],
            "responses": [],
            "statistics": {},
            "vulnerabilities": []
        }
    
    def _init_request_components(self):
        """初始化请求相关组件"""
        # 速率限制器
        self.rate_limiter = RateLimiter(
            max_requests_per_second=self.config.get("max_requests_per_second", 10),
            max_requests_per_minute=self.config.get("max_requests_per_minute", 60)
        )
        
        # 请求队列
        self.request_queue = RequestQueueManager(
            max_concurrent=self.config.get("max_concurrent_requests", 5),
            max_queue_size=self.config.get("max_queue_size", 100),
            rate_limiter=self.rate_limiter
        )
        
        # 请求发送器
        self.request_sender = RequestSender(
            timeout=self.config.get("request_timeout", 10),
            verify_ssl=self.config.get("verify_ssl", False),
            user_agent=self.config.get("user_agent"),
            proxies=self.config.get("proxies"),
            max_retries=self.config.get("max_retries", 3)
        )
        
        # 请求构建器
        self.request_builder = RequestBuilder()
        
        # 响应解析器
        self.response_parser = ResponseParse()
    
    def send_controlled_request(self, request_info: Dict) -> Optional[Dict]:
        """
        发送受控请求（带速率限制）
        
        Args:
            request_info: 请求信息字典
        
        Returns:
            响应结果字典或None
        """
        cookies_str = self.config.get("cookies")
        cookies = parse_cookies(cookies_str)
        
        def _make_request():
            method = request_info.get('method', 'GET')
            url = request_info.get('url')
            
            if not url:
                self.logger.error("请求URL为空")
                return None
            
            try:
                response = self.request_sender.send_request(
                    method=method,
                    url=url,
                    params=request_info.get('params'),
                    data=request_info.get('data'),
                    json_data=request_info.get('json'),
                    headers=request_info.get('headers'),
                    cookies=cookies,
                    allow_redirects=request_info.get('allow_redirects', True)
                )
                
                # 处理响应内容
                response_text = response.text if response else ""
                if not isinstance(response_text, str):
                    response_text = str(response_text) if response_text is not None else ""
                
                content_length = len(response.content) if response and hasattr(response, 'content') else 0
                
                # 解析响应
                parsed_response = {}
                if hasattr(self.response_parser, 'parse_response') and response:
                    try:
                        parsed_response = self.response_parser.parse_response(
                            response,
                            extract_links=True,
                            extract_forms=True,
                            base_url=url
                        )
                    except Exception as e:
                        self.logger.debug(f"解析响应失败: {e}")
                
                return {
                    'request': request_info,
                    'response': {
                        'status_code': response.status_code if response else 0,
                        'url': str(response.url) if response and hasattr(response, 'url') else url,
                        'headers': dict(response.headers) if response and hasattr(response, 'headers') else {},
                        'text': response_text,
                        'content': response_text,
                        'content_length': content_length
                    },
                    'parsed': parsed_response
                }
            except Exception as e:
                # 统一错误处理
                error_type, error_msg = self.error_handler.handle_request_error(
                    e, url, self.scanner_name
                )
                self.error_handler.log_error(self.logger, error_type, error_msg)
                return None
        
        # 提交到队列
        task_id = f"{self.scanner_name}_{int(time.time() * 1000)}"
        
        try:
            self.request_queue.submit(task_id, _make_request)
        except Exception as e:
            self.logger.warning(f"队列提交失败，直接执行: {e}")
            return _make_request()
        
        # 等待结果
        try:
            result = self.request_queue.get_result(task_id, timeout=30)
            if result:
                self._record_request_result(result)
            return result
        except Exception as e:
            self.logger.error(f"获取结果失败: {e}")
            return None
    
    def _record_request_result(self, result: Dict):
        """记录请求结果"""
        if not result:
            return
        
        self.results['requests'].append(result.get('request', {}))
        self.results['responses'].append(result.get('response', {}))
        self._collect_statistics()
    
    def _collect_statistics(self):
        """收集统计信息"""
        self.results['statistics'] = {
            'request_stats': (
                self.request_sender.get_statistics() 
                if hasattr(self.request_sender, 'get_statistics') 
                else {}
            ),
            'queue_stats': (
                self.request_queue.get_statistics() 
                if hasattr(self.request_queue, 'get_statistics') 
                else {}
            ),
            'rate_limit_stats': (
                self.rate_limiter.get_stats() 
                if hasattr(self.rate_limiter, 'get_stats') 
                else {}
            )
        }
    
    def get_baseline_response(self, url: str, param_name: str, param_value: str, 
                             method: str, post_data: Dict = None) -> Optional[Dict]:
        """
        获取基准响应（带缓存）
        
        Args:
            url: 目标URL
            param_name: 参数名
            param_value: 参数值
            method: HTTP方法
            post_data: POST数据
        
        Returns:
            基准响应字典或None
        """
        baseline_key = f"{url}_{param_name}_{method}"
        
        # 返回缓存的基准响应
        if baseline_key in self.baseline_responses:
            return self.baseline_responses[baseline_key]
        
        try:
            request_info = {
                'method': method.upper(),
                'url': url,
                'headers': {},
                'allow_redirects': True
            }
            
            if method.upper() == "GET":
                test_url = build_url_with_param(url, param_name, param_value)
                request_info['url'] = test_url
            else:
                data = (post_data or {}).copy()
                data[param_name] = param_value
                request_info['data'] = data
            
            response = self.send_controlled_request(request_info)
            
            if response and 'response' in response:
                response_data = response['response']
                content = response_data.get('content', '')
                if not isinstance(content, str):
                    content = str(content) if content is not None else ""
                
                baseline = {
                    'content': content,
                    'length': response_data.get('content_length', 0),
                    'status': response_data.get('status_code', 0),
                    'time': 0,
                    'headers': response_data.get('headers', {}),
                    'hash': hash(content) if content else ''
                }
                
                self.baseline_responses[baseline_key] = baseline
                return baseline
        
        except Exception as e:
            self.logger.error(f"获取基准响应失败: {e}")
        
        return None
    
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """
        验证URL格式
        
        Args:
            url: 待验证的URL
        
        Returns:
            (是否有效, 规范化后的URL/错误消息)
        """
        if not url:
            return False, "URL为空"
        
        # 确保URL有协议
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False, "无效的主机名"
            return True, url
        except Exception as e:
            return False, f"URL解析失败: {e}"
    
    def add_vulnerability(self, vuln: Dict):
        """
        添加漏洞结果
        
        Args:
            vuln: 漏洞信息字典
        """
        if isinstance(vuln, dict):
            self.results['vulnerabilities'].append(vuln)
    
    def get_results(self) -> Dict:
        """获取扫描结果"""
        return self.results
    
    def clear_baseline_cache(self):
        """清除基准响应缓存"""
        self.baseline_responses.clear()
    
    def clear_results(self):
        """清除结果缓存"""
        self.results = {
            "requests": [],
            "responses": [],
            "statistics": {},
            "vulnerabilities": []
        }


class VulnerabilityScannerMixin:
    """
    漏洞扫描器混入类 - 提供漏洞相关的通用功能
    """
    
    @staticmethod
    def calculate_vulnerability_confidence(evidence_points: int) -> str:
        """
        根据证据点计算漏洞可信度
        
        Args:
            evidence_points: 证据点数量
        
        Returns:
            可信度等级 (高/中/低)
        """
        if evidence_points >= 5:
            return "高"
        elif evidence_points >= 3:
            return "中"
        else:
            return "低"
    
    @staticmethod
    def filter_false_positives(vulnerabilities: List[Dict], 
                             baseline_content: str = None) -> List[Dict]:
        """
        过滤误报
        
        Args:
            vulnerabilities: 漏洞列表
            baseline_content: 基准响应内容
        
        Returns:
            过滤后的漏洞列表
        """
        filtered = []
        
        # 误报模式
        false_positive_patterns = [
            (r'<script[^>]*>.*?</script>', 'javascript_code'),
            (r'function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(', 'javascript_function'),
            (r'console\.log\(', 'console_log'),
            (r'error\s+page', 'error_page'),
            (r'404\s+not\s+found', '404_page'),
        ]
        
        import re
        
        for vuln in vulnerabilities:
            evidence = str(vuln.get('evidence', ''))
            
            # 检查是否匹配误报模式
            is_false_positive = False
            for pattern, pattern_name in false_positive_patterns:
                if re.search(pattern, evidence, re.IGNORECASE | re.DOTALL):
                    is_false_positive = True
                    break
            
            if not is_false_positive:
                filtered.append(vuln)
        
        return filtered
