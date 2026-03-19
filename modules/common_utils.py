"""
公共工具模块 - 提取各模块中重复使用的功能
"""
import json
import time
import hashlib
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from typing import Dict, Any, Optional, Tuple, Union

# 统一的日志记录器
logger = logging.getLogger('vuln_scanner.common')


def parse_cookies(cookies_input):
    """
    将cookies字符串/字典转换为字典
    支持格式：
    1. 字典类型：直接返回副本
    2. 字符串："name1=value1; name2=value2"
    3. JSON字符串：'{"name1": "value1", "name2": "value2"}'
    """
    if not cookies_input:
        return {}

    # 1. 如果已经是字典，直接返回
    if isinstance(cookies_input, dict):
        return cookies_input.copy()

    # 2. 如果是字符串
    if isinstance(cookies_input, str):
        cookies_input = cookies_input.strip()
        
        # 2.1 尝试解析为JSON
        if cookies_input.startswith('{') and cookies_input.endswith('}'):
            try:
                return json.loads(cookies_input)
            except json.JSONDecodeError:
                pass
        
        # 2.2 处理可能存在的'Cookie:'前缀
        if cookies_input.lower().startswith('cookie:'):
            cookies_input = cookies_input[7:].strip()

        # 2.3 按分号分割的键值对解析
        cookies_dict = {}
        pairs = cookies_input.split(';')
        for pair in pairs:
            pair = pair.strip()
            if not pair:
                continue
            # 使用 split('=', 1)，只分割第一个等号
            if '=' in pair:
                key, value = pair.split('=', 1)
                cookies_dict[key.strip()] = value.strip()
            else:
                cookies_dict[pair] = ''
        return cookies_dict

    return {}


def ensure_string_url(url_input):
    """确保URL是字符串类型"""
    if isinstance(url_input, str):
        return url_input
    elif isinstance(url_input, list):
        if url_input:
            return str(url_input[0])
        return ""
    elif url_input is None:
        return ""
    return str(url_input)


def build_url_with_param(url, param_name, value):
    """
    构建带参数的URL
    
    Args:
        url: 基础URL
        param_name: 参数名
        value: 参数值
    
    Returns:
        str: 带参数的URL
    """
    url = ensure_string_url(url)
    if not url:
        return ""

    try:
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        query_dict[param_name] = [value]

        new_query = urlencode(query_dict, doseq=True)
        return parsed._replace(query=new_query).geturl()
    except Exception as e:
        logger.debug(f"构建URL参数失败: {e}")
        if '?' in url:
            return f"{url}&{param_name}={value}"
        else:
            return f"{url}?{param_name}={value}"


def calculate_similarity(text1, text2):
    """
    计算两个文本的相似度
    
    Args:
        text1: 文本1
        text2: 文本2
    
    Returns:
        float: 相似度 (0-1)
    """
    from difflib import SequenceMatcher
    
    # 确保两个参数都是字符串
    if not isinstance(text1, str):
        text1 = str(text1) if text1 is not None else ''
    if not isinstance(text2, str):
        text2 = str(text2) if text2 is not None else ''

    if not text1 or not text2:
        return 0.0
    
    # 对较长的文本进行采样以提高性能
    sample_size = 1500
    if len(text1) > sample_size:
        text1_sample = text1[:1000] + text1[-500:]
    else:
        text1_sample = text1
        
    if len(text2) > sample_size:
        text2_sample = text2[:1000] + text2[-500:]
    else:
        text2_sample = text2
    
    # 使用SequenceMatcher计算相似度
    matcher = SequenceMatcher(None, text1_sample, text2_sample)
    similarity = matcher.ratio()
    
    # 考虑内容长度的差异
    length_ratio = min(len(text1_sample), len(text2_sample)) / max(len(text1_sample), len(text2_sample)) if max(len(text1_sample), len(text2_sample)) > 0 else 0
    
    # 综合相似度
    weighted_similarity = (similarity * 0.7 + length_ratio * 0.3)
    
    return weighted_similarity


def calculate_content_signature(content):
    """
    计算内容签名，用于快速比较
    
    Args:
        content: 文本内容
    
    Returns:
        dict: 内容签名
    """
    if not content:
        return {'line_count': 0, 'word_count': 0, 'avg_line_length': 0, 'common_patterns': []}
    
    lines = content.split('\n')
    words = content.split()
    
    return {
        'line_count': len(lines),
        'word_count': len(words),
        'avg_line_length': sum(len(line) for line in lines) / max(len(lines), 1),
        'common_patterns': extract_common_patterns(content)
    }


def extract_common_patterns(content):
    """提取常见模式"""
    patterns = []
    
    # 检测HTML标签
    html_tags = re.findall(r'<(div|span|p|a|img|form|input|button)[^>]*>', content, re.I)
    if html_tags:
        patterns.append(f"html_tags:{len(set(html_tags))}")
    
    # 检测数字
    numbers = re.findall(r'\b\d{3,}\b', content)
    if numbers:
        patterns.append(f"large_numbers:{len(numbers)}")
    
    # 检测错误模式
    error_patterns = ['error', 'exception', 'warning', 'notice', 'failed']
    for pattern in error_patterns:
        if pattern in content.lower():
            patterns.append(f"contains_{pattern}")
    
    return patterns


def get_indicator_context(text, indicator, window=100):
    """获取指示器上下文"""
    if indicator not in text:
        return ""
    
    idx = text.find(indicator)
    start = max(0, idx - window)
    end = min(len(text), idx + len(indicator) + window)
    
    return text[start:end]


def identify_database_type(response_text):
    """
    识别响应中包含的数据库类型
    
    Args:
        response_text: 响应文本
    
    Returns:
        str: 数据库类型 (mysql, mssql, postgresql, oracle, sqlite, unknown)
    """
    if not isinstance(response_text, str):
        response_text = str(response_text)
    
    response_lower = response_text.lower()
    
    # MySQL
    mysql_patterns = ["mysql", "mysqli", "you have an error in your sql syntax"]
    for pattern in mysql_patterns:
        if pattern in response_lower:
            return "mysql"
    
    # SQL Server
    mssql_patterns = ["microsoft sql server", "odbc", "oledb", "sql server", "unclosed quotation mark"]
    for pattern in mssql_patterns:
        if pattern in response_lower:
            return "mssql"
    
    # Oracle
    oracle_patterns = ["ora-", "oracle", "pl/sql"]
    for pattern in oracle_patterns:
        if pattern in response_lower:
            return "oracle"
    
    # PostgreSQL
    postgres_patterns = ["postgresql", "pg_", "syntax error at or near"]
    for pattern in postgres_patterns:
        if pattern in response_lower:
            return "postgresql"
    
    # SQLite
    sqlite_patterns = ["sqlite", "sqlite3", "near.*syntax error"]
    for pattern in sqlite_patterns:
        if pattern in response_lower:
            return "sqlite"
    
    return "unknown"


def check_for_database_errors(response_text, error_indicators=None):
    """
    检查响应中的数据库错误信息
    
    Args:
        response_text: 响应文本
        error_indicators: 自定义错误指示器字典
    
    Returns:
        str or None: 检测到的错误信息，未检测到返回None
    """
    if not isinstance(response_text, str):
        if response_text is None:
            response_text = ''
        else:
            response_text = str(response_text)
    
    if not response_text:
        return None
    
    # 限制检查范围
    check_text = response_text[:10000] if len(response_text) > 10000 else response_text
    check_text_lower = check_text.lower()
    
    # 默认错误指示器
    default_error_indicators = {
        "mysql": ["you have an error in your sql syntax", "warning: mysql", "mysql_fetch", "mysqli"],
        "mssql": ["unclosed quotation mark", "sql server", "microsoft ole db provider", "odbc driver"],
        "postgresql": ["postgresql", "pg_", "postgres query failed"],
        "oracle": ["ora-", "oracle error"],
        "generic": ["sql syntax", "syntax error", "division by zero", "quoted string not properly terminated"]
    }
    
    indicators = error_indicators or default_error_indicators
    
    # 检查特定数据库错误
    db_types = ["mysql", "mssql", "postgresql", "oracle"]
    for db_type in db_types:
        if db_type in indicators:
            for indicator in indicators[db_type]:
                if indicator.lower() in check_text_lower:
                    return f"{db_type.upper()} SQL Error: {indicator}"
    
    # 检查通用错误
    if "generic" in indicators:
        for indicator in indicators["generic"]:
            if indicator.lower() in check_text_lower:
                return f"SQL Error: {indicator}"
    
    return None


class ErrorHandler:
    """统一错误处理类"""
    
    @staticmethod
    def handle_request_error(error, url, context=""):
        """
        处理请求错误
        
        Args:
            error: 异常对象
            url: 请求URL
            context: 错误上下文
        
        Returns:
            tuple: (错误类型, 错误消息)
        """
        error_msg = str(error).lower()
        
        # 超时错误
        if 'timeout' in error_msg or 'timed out' in error_msg:
            return ("timeout", f"请求超时: {url}")
        
        # 连接错误
        if 'connection' in error_msg:
            return ("connection", f"连接失败: {url}")
        
        # SSL错误
        if 'ssl' in error_msg or 'certificate' in error_msg:
            return ("ssl", f"SSL错误: {url}")
        
        # DNS错误
        if 'dns' in error_msg or 'resolve' in error_msg or 'nodename' in error_msg:
            return ("dns", f"DNS解析失败: {url}")
        
        # 通用错误
        return ("general", f"请求失败 [{context}]: {url} - {error}")
    
    @staticmethod
    def log_error(logger, error_type, message, exc_info=False):
        """根据错误类型记录日志"""
        log_methods = {
            "timeout": logger.warning,
            "connection": logger.warning,
            "dns": logger.warning,
            "ssl": logger.warning,
            "general": logger.error
        }
        
        log_method = log_methods.get(error_type, logger.error)
        log_method(message)
        
        if exc_info:
            logger.debug(message, exc_info=True)


def format_vulnerability_result(vuln_data, url, param_name=None, method="GET"):
    """
    格式化漏洞检测结果为统一格式
    
    Args:
        vuln_data: 漏洞检测数据
        url: 目标URL
        param_name: 参数名
        method: HTTP方法
    
    Returns:
        dict: 格式化后的漏洞结果
    """
    if isinstance(vuln_data, dict):
        vuln = vuln_data.copy()
        vuln['url'] = url
        
        if 'parameter' not in vuln and param_name:
            vuln['parameter'] = param_name
        
        if 'method' not in vuln:
            vuln['method'] = method
        
        return vuln
    else:
        return {
            'url': url,
            'type': 'Unknown Vulnerability',
            'parameter': param_name or 'unknown',
            'method': method,
            'confidence': '未知',
            'description': str(vuln_data)
        }


def generate_unique_id(prefix="id"):
    """生成唯一ID"""
    import random
    import string
    timestamp = int(time.time() * 1000)
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    return f"{prefix}_{timestamp}_{random_str}"


def compare_signatures(sig1, sig2):
    """
    比较两个签名
    
    Args:
        sig1: 签名1
        sig2: 签名2
    
    Returns:
        float: 差异度 (0-1)
    """
    if not sig1 or not sig2:
        return 0.0
    
    diff = 0
    total = 0
    
    for key in sig1:
        if key in sig2:
            if isinstance(sig1[key], (int, float)) and isinstance(sig2[key], (int, float)):
                diff += abs(sig1[key] - sig2[key]) / max(sig1[key], sig2[key], 1)
                total += 1
    
    return diff / max(total, 1)
