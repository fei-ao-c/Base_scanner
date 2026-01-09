#基础请求控制器
import time
import asyncio
import threading
from queue import  Queue,Empty
from collections import defaultdict
from datetime import datetime,timedelta
import logging

class RateLimiter:
    """请求速率限制器"""

    def __init__(self,max_request_pre_second=10,max_requests_per_minute=60):
        """Args:
            max_request_pre_second: 限制每秒最大请求数
            max_requests_per_minute: 限制每分钟最大请求数
        """
        self.max_rps = max_request_pre_second
        self.max_rpm = max_requests_per_minute

        #存储请求时间戳
        self.request_timestamps=[]
        # 锁，用于安全线程
        self.lock = threading.RLock()
        #日志记录器
        self.logger = logging.getLogger('vuln_scanner.request')

    def _cleanup_old_timestamps(self):
        """清理过期请求时间戳"""
        one_minute_ago = time.time() - 60
        with self.lock:
            #移除超过一分钟的请求时间戳
            self.request_timestamps=[
                ts for ts in self.request_timestamps if ts > one_minute_ago
            ]

    def can_make_request(self):
        """检查是否可以发起新的请求"""
        self._cleanup_old_timestamps()
        current_time=time.time()
        one_second_ago=current_time-1
        with self.lock:
            #检查是否超过每秒最大请求数
            recent_requests=[
                ts for ts in self.request_timestamps if ts > one_second_ago
            ]

            #检查是否超过每分钟最大请求数
            if len(self.request_timestamps) > self.max_rpm:
                self.logger.warning(f"达到分钟限制: {len(self.request_timestamps)}/{self.max_rpm}")
                return False

            if len(recent_requests) > self.max_rps:
                self.logger.warning(f"达到秒限制: {len(recent_requests)}/{self.max_rps}")
                return False
            
            return True
        
    def wait_if_needed(self):
        """如果请求速率超过限制，等待"""
        while not self.can_make_request():
            #计算下一次请求可以发起的时间
            current_time=time.time()
            one_second_ago=current_time-1

            with self.lock:
                recent_requests=[
                    ts for ts in self.request_timestamps if ts > one_second_ago #遍历 self.request_timestamps 中的所有时间戳，只保留那些大于 one_second_ago（即最近一秒内）的时间戳
                ]

                if recent_requests:
                    #等待到下一次请求可以发起的时间
                    oldest_request_time=min(recent_requests)
                    wait_time=oldest_request_time+1-current_time

                    if wait_time>0:
                        self.logger.warning(f"请求过于频繁，等待{wait_time:.2f}秒")
                        time.sleep(min(wait_time,0.1)) #小步等待
                else:
                    #等待一小段时间
                    time.sleep(0.1)
    def record_request(self):
        """记录一个请求"""
        with self.lock:
            self.request_timestamps.append(time.time())
    def get_stats(self):
        """获取当前统计信息"""
        self._cleanup_old_timestamps()

        current_time=time.time()
        one_second_age= current_time - 1

        with self.lock:
            recent_requests=[
                ts for ts in self.request_timestamps if ts > one_second_age
            ]     

            return {
                'total_last_minute':len(self.request_timestamps),
                'recent_per_second':len(recent_requests),
                'max_rps':self.max_rps,
                'max_rpm':self.max_rpm
            }                   
