import logging
import logging.handlers
import os
from datetime import datetime

def setup_logging(log_dir='logs', level=logging.INFO,max_file_size=5*1024*1024,backup_count=5):
    """
    配置日志系统
    Args:
        log_dir: 日志目录
        log_level: 日志级别
        max_file_size: 单个日志文件最大大小（字节）
        backup_count: 保留的备份文件数量
    """
    # 创建日志目录
    os.makedirs(log_dir, exist_ok=True)

    #创建主日志记录器
    logger = logging.getLogger('vuln_scanner')
    logging.setlevel(level)
    #清楚之前的处理器，避免重复添加
    logging.handlers.clear()
