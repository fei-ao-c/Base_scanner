# scanner

#### 介绍
初次设计扫描工具，用于扫描网站扫描网站存在的漏洞，目前具备端口扫描功能和请求控制功能，可以用来学习设计扫描工具，在此的基础上你们可以增加其他功能。
后续将增加其他功能。

#### 软件架构
scanner.py是主要文件，是扫描器的核心。
utils.py是工具类，主要是一些工具函数。
web_scanner.py是网站扫描器，主要是扫描网站的端口和漏洞。可以在此增加各种漏洞的扫描和利用功能。
port_scanner.py是端口扫描器，主要是扫描指定IP地址的端口是否开放。
log_viewer.py是日志查看器，主要是查看扫描器的日志。
logging_config.py是日志配置，主要是配置日志的格式。
modules文件夹里是扫描的模块，主要是一些请求控制模块。


#### 使用教程
python scanner.py -h 查看帮助信息
positional arguments:
  target                扫描目标IP或域名

options:
  -h, --help            show this help message and exit
  -p, --ports PORTS     扫描端口范围,例如 1-1000
  -o, --output {json,txt,all}
                        输出报告文件名
  --log-dir LOG_DIR     日志目录
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        日志级别
  --no-log              禁用日志
  --view-log FILE       查看日志
  --analyze-logs        分析日志
  -rps, --requests-per-second REQUESTS_PER_SECOND
                        每秒最大请求数
  -rpm, --requests-per-minute REQUESTS_PER_MINUTE
                        每分钟最大请求数
  -c, --concurrent CONCURRENT
                        最大并发请求数
  -t, --timeout TIMEOUT
                        请求超时时间(秒)
  --no-ssl-verify       不验证SSL证书


#### 使用说明

1.  下载代码到本地
2.  安装依赖库
3.  运行命令 python scanner.py -h 查看帮助信息

#### ⚠️ 安全与道德使用声明

**本工具仅限于：**
*   您拥有明确书面授权进行测试的系统。
*   您自己拥有合法所有权的资产。
*   在符合所有适用法律法规的环境下进行的安全教学、研究和授权演练。

**严格禁止将本工具用于：**
*   未经明确授权的任何形式的网络探测、扫描或攻击。
*   侵犯他人隐私或数据安全。
*   任何违反您所在国家或地区法律，以及目标系统所在司法管辖区法律的活动。

使用者需对使用本工具造成的任何直接或间接后果承担全部法律责任。开发者不对任何滥用行为负责。


