#基础版日志配置文件，包含文件日志、控制台日志和错误日志的配置
# import logging
# import logging.handlers
# import os
# from datetime import datetime

# def setup_logging(log_dir='logs', log_level=logging.INFO,max_file_size=5*1024*1024,backup_count=5):
#     """
#     配置日志系统
#     Args:
#         log_dir: 日志目录
#         log_level: 日志级别
#         max_file_size: 单个日志文件最大大小（字节）
#         backup_count: 保留的备份文件数量
#     """
#     # 创建日志目录
#     os.makedirs(log_dir, exist_ok=True)

#     #创建主日志记录器
#     logger = logging.getLogger('vuln_scanner')
#     logger.setLevel(log_level)
#     #清楚之前的处理器，避免重复添加
#     logger.handlers.clear()
#     #设置日志格式
#     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#                                   datefmt='%Y-%m-%d %H:%M:%S')
    
#     #1.文件日志处理器-按文件大小轮转
#     log_file=os.path.join(log_dir,'vuln_scanner.log')
#     file_handler=logging.handlers.RotatingFileHandler(
#         log_file,
#         maxBytes=max_file_size,
#         backupCount=backup_count,
#         encoding='utf-8',
#     )
#     file_handler.setFormatter(formatter)
#     file_handler.setLevel(log_level)

#     #2.控制台日志处理器
#     console_handler=logging.StreamHandler()
#     console_handler.setLevel(logging.WARNING)# 控制台只显示WARNING及以上级别日志
#     console_handler.setFormatter(formatter)

#     #3.错误日志处理器-单独记录ERROR级别日志
#     error_log_file=os.path.join(log_dir,'vuln_scanner_error.log')
#     error_handler=logging.handlers.RotatingFileHandler(
#         error_log_file,
#         maxBytes=max_file_size,
#         backupCount=backup_count,
#         encoding='utf-8',
#     )
#     error_handler.setLevel(logging.ERROR)
#     error_handler.setFormatter(formatter)

#     #将处理器添加到记录器
#     logger.addHandler(file_handler)
#     logger.addHandler(console_handler)
#     logger.addHandler(error_handler)
#     return logger

# def get_scanner_logger():
#     '''获取配置好的扫描器日志记录器'''

#     return logging.getLogger('vuln_scanner')


#增强版日志配置文件，包含JSON格式日志和多记录器支持
import logging
import logging.handlers
import os
import json
from datetime import datetime
import sys

class JSONFormatter(logging.Formatter):
    """JSON格式的日志格式化器"""
    
    def format(self, record):
        log_record = {
            'timestamp': datetime.now().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
            'target': getattr(record, 'target', None),
            'port': getattr(record, 'port', None),
            'vulnerability': getattr(record, 'vulnerability', None)
        }
        
        # 如果有异常信息，添加堆栈跟踪
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_record, ensure_ascii=False)

class ScannerLogger:
    """扫描器专用的日志管理器"""
    
    def __init__(self, log_dir="logs", scanner_id=None):
        self.log_dir = log_dir
        self.scanner_id = scanner_id or f"scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 创建日志目录
        os.makedirs(log_dir, exist_ok=True)
        
        # 初始化日志记录器
        self._setup_loggers()
        
    def _setup_loggers(self):
        """设置多个日志记录器"""
        
        # 主日志记录器
        self.main_logger = logging.getLogger('vuln_scanner.main')
        self.main_logger.setLevel(logging.INFO)
        
        # 扫描日志记录器
        self.scan_logger = logging.getLogger('vuln_scanner.scan')
        self.scan_logger.setLevel(logging.INFO)
        
        # 错误日志记录器
        self.error_logger = logging.getLogger('vuln_scanner.error')
        self.error_logger.setLevel(logging.ERROR)
        
        # 性能日志记录器
        self.perf_logger = logging.getLogger('vuln_scanner.performance')
        self.perf_logger.setLevel(logging.INFO)
        
        # 标准格式
        standard_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # JSON格式
        json_formatter = JSONFormatter()
        
        # 设置文件处理器
        self._setup_handlers(standard_formatter, json_formatter)
        
    def _setup_handlers(self, standard_formatter, json_formatter):
        """设置各种处理器"""
        
        # 1. 主日志文件（标准格式）
        main_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, f"{self.scanner_id}_main.log"),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=10,
            encoding='utf-8'
        )
        main_handler.setFormatter(standard_formatter)
        self.main_logger.addHandler(main_handler)
        
        # 2. 扫描日志文件（JSON格式）
        scan_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, f"{self.scanner_id}_scan.json"),
            maxBytes=10*1024*1024,
            backupCount=10,
            encoding='utf-8'
        )
        scan_handler.setFormatter(json_formatter)
        self.scan_logger.addHandler(scan_handler)
        
        # 3. 错误日志文件
        error_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, f"{self.scanner_id}_error.log"),
            maxBytes=5*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        error_handler.setFormatter(standard_formatter)
        error_handler.setLevel(logging.ERROR)
        self.error_logger.addHandler(error_handler)
        
        # 4. 控制台输出
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(standard_formatter)
        console_handler.setLevel(logging.INFO)
        
        # 添加控制台处理器到所有记录器
        for logger in [self.main_logger, self.scan_logger, self.error_logger]:
            logger.addHandler(console_handler)
            
    def log_scan_start(self, target, scan_type):
        """记录扫描开始"""
        extra = {'target': target, 'scan_type': scan_type}
        self.scan_logger.info(f"开始扫描: {target} ({scan_type})", extra=extra)
        
    def log_port_scan_result(self, target, port, status, service=None):
        """记录端口扫描结果"""
        extra = {'target': target, 'port': port, 'status': status, 'service': service}
        if status == 'open':
            self.scan_logger.info(f"端口开放: {target}:{port} ({service})", extra=extra)
        else:
            self.scan_logger.debug(f"端口状态: {target}:{port} - {status}", extra=extra)
            
    def log_vulnerability_found(self, target, vuln_type, confidence, details=None):
        """记录发现的漏洞"""
        extra = {
            'target': target,
            'vulnerability': vuln_type,
            'confidence': confidence,
            'details': details
        }
        self.scan_logger.warning(f"发现漏洞: {vuln_type} ({confidence}) - {target}", extra=extra)
        
    def log_performance(self, operation, duration, target=None):
        """记录性能数据"""
        extra = {'operation': operation, 'duration': duration, 'target': target}
        self.perf_logger.info(f"性能: {operation} 耗时 {duration:.2f}秒", extra=extra)