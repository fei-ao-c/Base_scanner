#请求队列管理器
import threading
import time
import queue
import logging
# from request_manager import RateLimiter,wait_if_needed, record_request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List,Any,Dict,Optional

class RequestTask:
    """请求任务封装"""

    def __init__(self,task_id:str,func:Callable,*args, **kwargs):
        self.task_id = task_id
        self.func=func
        self.args=args
        self.kwargs=kwargs
        self.result=None #任务执行结果
        self.exception=None #任务执行异常
        self.completed=False #任务是否完成
        self.created_at=time.time()
        self.completed_at=None #任务完成时间

    def execute(self): #记
        """执行任务"""
        try:
            self.result=self.func(*self.args,**self.kwargs)
        except Exception as e:
            self.exception=e
            raise
        finally:
            self.completed=True
            self.completed_at=time.time()
        return self.result
class RequestQueueManager:
    """请求队列管理器"""
    def __init__(self,
                 max_concurrent:int=10,
                 max_queue_size:int=1000,
                 rate_limiter=None):
        """Args:
            max_concurrent: 最大并发数
            max_queue_size: 队列最大大小
            rate_limiter: 速率限制器实例
        """
        self.max_concurrent=max_concurrent
        self.max_queue_size=max_queue_size

        #任务队列
        self.task_queue=queue.Queue(maxsize=max_queue_size)
        #任务存储
        self.task:Dict[str,RequestTask]={}
        #线程池
        self.executor=ThreadPoolExecutor(max_workers=max_concurrent)
        #速率限制器
        self.rate_limiter=rate_limiter
        #控制变量
        self.is_running=False
        self.worker_threads=[]
        #统计信息
        self.stats={
            'tasks_submitted':0, #已提交任务数
            'tasks_completed':0, #已完成任务数
            'tasks_failed':0, #失败任务数
            'queue_size':0, #队列大小
            'active_workers':0 #活动工作者数
        }
        #锁
        self.lock=threading.RLock()
        #日志
        self.logger=logging.getLogger('vuln_scanner.queue')
        #启动工作者线程
        self._start_workers()

    def _start_workers(self):
        """启动工作者线程"""
        self.is_running=True
        for i in range(self.max_concurrent):
            thread=threading.Thread(
                target=self._worker_loop,
                name=f"RequestWorker-{i}",
                daemon=True
                )
            thread.start()
            self.worker_threads.append(thread)
        
        self.logger.info(f"启动{self.max_concurrent}个工作者线程")
    
    def _worker_loop(self):
        """工作者线程主循环"""
        while self.is_running:
            try:
                # 从队列获取任务
                task = self.task_queue.get(timeout=1)
                
                if task is None:  # 停止信号
                    break
                
                # 更新统计
                with self.lock:
                    self.stats['active_workers'] += 1
                    self.stats['queue_size'] = self.task_queue.qsize()
                
                try:
                    # 速率限制
                    if self.rate_limiter:
                        self.rate_limiter.wait_if_needed()
                        self.rate_limiter.record_request()
                    
                    # 执行任务
                    task.execute()
                    
                    with self.lock:
                        self.stats['tasks_completed'] += 1
                    
                except Exception as e:
                    self.logger.error(f"任务执行失败: {task.task_id} - {e}")
                    
                    with self.lock:
                        self.stats['tasks_failed'] += 1
                        task.exception = e
                
                finally:
                    # 标记任务完成
                    self.task_queue.task_done()
                    
                    with self.lock:
                        self.stats['active_workers'] -= 1
                        self.stats['queue_size'] = self.task_queue.qsize()
            
            except queue.Empty:
                # 队列为空，继续循环
                continue

    def submit(self,task_id:str,func:Callable,*args, **kwargs) -> str:
        """提交任务到队列"""
        if self.task_queue.full():
            raise queue.Full("任务队列已满")

        task=RequestTask(task_id,func,*args,**kwargs)

        with self.lock:
            self.task[task_id]=task
            self.stats['tasks_submitted'] += 1
        
        self.task_queue.put(task)
        self.logger.debug(f"提交任务：{task_id}")
        return task_id
    
    def get_result(self,task_id:str,timeout:float=None) -> Any:
        """获取任务执行结果（阻塞等待）"""
        task=self.task.get(task_id)
        if not task:
            raise KeyError(f"未找到任务：{task_id}")

        #等待任务完成
        start_time=time.time()
        while not task.completed:
            if timeout and (time.time()-start_time)>timeout:
                raise TimeoutError(f"获取任务结果超时：{task_id}")
            time.sleep(0.01)

        if task.exception:
            raise task.exception

        return task.result
    
    def wait_all(self,timeout:float=None) ->bool:
        """等待所有任务完成"""
        start_time=time.time()
        while True:
            with self.lock:
                pending=self.stats['tasks_submitted']- \
                        (self.stats['task_completed']+self.stats['tasks_failed'])
                if pending==0:
                    return True
            
            if timeout and (time.time()-start_time)>timeout:
                self.logger.warning(f"等待任务超时，仍有{pending}个任务未完成")
                return False
            
            time.sleep(0.1)

    def shutdown(self,wait:bool=True,timeout:float=30):
        """关闭请求队列管理器"""
        self.logger.info("关闭请求队列管理器...")
        self.is_running=False

        #发送停止信号给所有工作者
        for _ in range(self.max_concurrent):
            self.task_queue.put(None)
        if wait:
            #等待所有工作者线程退出
            for thread in self.worker_threads:
                thread.join(timeout=timeout)
            # 关闭线程池
            self.executor.shutdown(wait=True)
        self.logger.info("请求队列管理器已关闭")

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        with self.lock:
            stats = self.stats.copy()
            stats['tasks_pending'] = stats['tasks_submitted'] - \
                                    (stats['tasks_completed'] + stats['tasks_failed'])
            stats['queue_capacity'] = self.max_queue_size
            
            if self.rate_limiter:
                stats['rate_limit'] = self.rate_limiter.get_stats()
        
        return stats
