import json
import argparse
import os
import sys
from datetime import datetime
from colorama import Fore, Style,init

init(autoreset=True)

class LogViewer:
    def __init__(self,log_dir="logs"):
        self.log_dir=log_dir
    
    def list_logs(self,show_all=False):
        """列出可用的日志文件"""
        if not os.path.exists(self.log_dir):
            print(f"{Fore.RED}日志目录不存在: {self.log_dir}")
            return []
        
        print(f"{Fore.CYAN}目录日志：{os.path.abspath(self.log_dir)}")
        print("-" * 80)

        log_files=[]
        for filename in os.listdir(self.log_dir):
            if filename.endswith('.log') or filename.endswith('.json'):
                filepath=os.path.join(self.log_dir,filename)
                size=os.path.getsize(filepath)
                mtime=datetime.fromtimestamp(os.path.getmtime(filepath))

                log_files.append({
                    'name':filename,
                    'size':size,
                    'mtime':mtime,
                    'path':filepath
                })

        # 按修改时间排序，最新的在前
        log_files.sort(key=lambda x:x['mtime'],reverse=True)

        if not show_all:
            log_files=log_files[:20]  # 只显示最新的20个日志文件

        for i,log_file in enumerate(log_files,1):
            size_mb=log_file['size']/1024/1024
            print(f"{i:3d}.{log_file['name']:<40} {size_mb:.2f} MB  {log_file['mtime']}")

    def view_log(self,filename,level_fileter=None,search=None,lines=100):
        """查看日志文件内容"""
        filepath=os.path.join(self.log_dir,filename)
            
        if not os.path.exists(filepath):
            print(f"{Fore.RED}日志文件不存在: {filepath}")
            return
        
        print(f"{Fore.CYAN}查看日志：{filename}")
        print("-" * 80)
        with open(filepath,'r',encoding='utf-8') as f:
            content_lines=f.readlines()

        if filename.endswith('.json'):
            self._view_json_log(content_lines,level_fileter,search,lines)
        else:
            self._view_text_log(content_lines,level_fileter,search,lines)

    def _view_text_log(self,lines,level_filter,search,max_lines):
        """查看文本格式日志"""
        displayed=0

        # 反向遍历日志行，显示最新的日志
        for line in reversed(lines):
            if displayed>=max_lines:
                break

            # 过滤级别
            if level_filter:
                if f"[{level_filter.upper()}]" not in line:
                    continue

            # 关键词搜索
            if search:
                if search.lower() not in line.lower():
                    continue

            #根据日志级别着色输出
            if "[ERROR]" in line:
                color=Fore.RED
            elif "[WARNING]" in line:
                color=Fore.YELLOW
            elif "[INFO]" in line:
                color=Fore.GREEN
            elif "[DEBUG]" in line:
                color=Fore.CYAN
            else:
                color=Fore.WHITE

            print(f"{color}{line.rstrip()}")
            displayed += 1
#下面manmankan
    def _view_json_log(self, lines, level_filter, search, max_lines):
        """查看JSON格式的日志"""
        import json
        
        displayed = 0
        
        for line in reversed(lines):
            if displayed >= max_lines:
                break
            
            try:
                log_entry = json.loads(line.strip())
                
                # 过滤级别
                if level_filter and log_entry.get('level') != level_filter.upper():
                    continue
                
                # 搜索内容
                if search:
                    search_found = False
                    for value in log_entry.values():
                        if search.lower() in str(value).lower():
                            search_found = True
                            break
                    if not search_found:
                        continue
                
                # 格式化输出
                timestamp = log_entry.get('timestamp', '')
                level = log_entry.get('level', '')
                message = log_entry.get('message', '')
                
                # 着色
                if level == 'ERROR':
                    color = Fore.RED
                elif level == 'WARNING':
                    color = Fore.YELLOW
                elif level == 'INFO':
                    color = Fore.GREEN
                else:
                    color = Fore.WHITE
                
                print(f"{color}{timestamp} [{level}] {message}")
                
                # 显示额外信息
                for key in ['target', 'port', 'vulnerability']:
                    if key in log_entry and log_entry[key]:
                        print(f"{Fore.CYAN}  {key}: {log_entry[key]}")
                
                #print()
                displayed += 1
                
            except json.JSONDecodeError:
                continue
    
    def analyze_logs(self, days=7):
        """分析日志数据"""
        import glob
        from collections import Counter
        from datetime import datetime, timedelta
        
        print(f"{Fore.CYAN}分析最近 {days} 天的日志")
        print("-" * 80)
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # 统计信息
        stats = {
            'total_entries': 0,
            'by_level': Counter(),
            'by_target': Counter(),
            'vulnerabilities': Counter(),
            'errors': []
        }
        
        # 查找所有日志文件
        log_patterns = ['*.log', '*.json']
        
        for pattern in log_patterns:
            for filepath in glob.glob(os.path.join(self.log_dir, pattern)):
                mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                
                # 只分析最近的文件
                if mtime < start_date:
                    continue
                
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        stats['total_entries'] += 1
                        
                        # 尝试解析JSON
                        if filepath.endswith('.json'):
                            try:
                                entry = json.loads(line.strip())
                                level = entry.get('level', 'UNKNOWN')
                                stats['by_level'][level] += 1
                                
                                if 'target' in entry:
                                    stats['by_target'][entry['target']] += 1
                                
                                if 'vulnerability' in entry:
                                    stats['vulnerabilities'][entry['vulnerability']] += 1
                                
                                if level == 'ERROR':
                                    stats['errors'].append({
                                        'message': entry.get('message'),
                                        'timestamp': entry.get('timestamp'),
                                        'file': os.path.basename(filepath)
                                    })
                            except:
                                pass
        
        # 显示统计结果
        print(f"总日志条目: {stats['total_entries']}")
        print(f"\n按级别分布:")
        for level, count in stats['by_level'].items():
            print(f"  {level}: {count}")
        
        print(f"\n扫描目标统计:")
        for target, count in list(stats['by_target'].items())[:10]:  # 显示前10个
            print(f"  {target}: {count}")
        
        print(f"\n漏洞类型统计:")
        for vuln, count in stats['vulnerabilities'].items():
            print(f"  {vuln}: {count}")
        
        if stats['errors']:
            print(f"\n最近错误 ({len(stats['errors'])} 个):")
            for error in stats['errors'][:5]:  # 显示最近5个错误
                print(f"  {error['timestamp']} - {error['message']}")

def main():
    parser = argparse.ArgumentParser(description="日志查看和分析工具")
    parser.add_argument("action", choices=['list', 'view', 'analyze'], 
                       help="操作类型")
    parser.add_argument("--file", help="要查看的日志文件名")
    parser.add_argument("--level", choices=['debug', 'info', 'warning', 'error'],
                       help="按级别过滤")
    parser.add_argument("--search", help="搜索关键词")
    parser.add_argument("--lines", type=int, default=100, 
                       help="显示行数")
    parser.add_argument("--days", type=int, default=7,
                       help="分析最近多少天的日志")
    parser.add_argument("--dir", default="logs",
                       help="日志目录")
    
    args = parser.parse_args()
    
    viewer = LogViewer(log_dir=args.dir)
    
    if args.action == 'list':
        viewer.list_logs()
    elif args.action == 'view':
        if not args.file:
            print(f"{Fore.RED}请使用 --file 参数指定要查看的日志文件")
            return
        viewer.view_log(args.file, args.level, args.search, args.lines)
    elif args.action == 'analyze':
        viewer.analyze_logs(args.days)

if __name__ == "__main__":
    main()