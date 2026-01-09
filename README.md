

# scanner

## 介绍

scanner 是一款功能强大的网络安全扫描工具，主要用于扫描网站存在的漏洞。目前具备端口扫描功能和请求控制功能，可以用来学习设计扫描工具，在此基础上可以扩展其他功能。

## 软件架构

```
scanner/
├── scanner.py           # 主程序入口，扫描器核心
├── port_scanner.py      # 端口扫描器
├── web_scanner.py       # 网站漏洞扫描器
├── log_viewer.py        # 日志查看器
├── logging_config.py    # 日志配置
├── utils.py             # 工具函数
├── config/
│   └── config.json      # 配置文件
├── modules/             # 请求处理模块
│   ├── request_builder.py   # 请求构建器
│   ├── request_manager.py   # 请求管理器
│   ├── request_queue.py     # 请求队列
│   ├── request_sender.py    # 请求发送器
│   └── response_parse.py    # 响应解析器
└── logs/                # 日志目录
```

## 功能特点

### 端口扫描
- 支持自定义端口范围扫描
- 多线程并发扫描
- 自动识别常见服务类型

### 漏洞扫描
- SQL 注入检测
- XSS 跨站脚本检测
- 链接爬取功能

### 请求控制
- 速率限制（每秒/每分钟请求数）
- 最大并发请求控制
- 请求超时设置
- SSL 证书验证控制

### 日志管理
- 支持文本和 JSON 格式日志
- 日志查看和分析功能
- 扫描结果导出

## 安装说明

1. 克隆代码到本地：
```bash
git clone https://github.com/fei-ao-c/Base_scanner.git
cd scanner
```

2. 安装依赖库：
```bash
pip install -r requirements.txt
```

## 使用教程

### 基本用法

```bash
python scanner.py -h
```

### 扫描指定目标的端口

```bash
python scanner.py 192.168.1.1 -p 1-1000
```

### 扫描并输出报告

```bash
python scanner.py example.com -p 1-1000 -o json
```

### 设置并发数和请求速率

```bash
python scanner.py example.com -p 1-1000 -c 50 -rps 20 -rpm 1000
```

### 查看日志

```bash
python scanner.py --view-log logs/scanner_xxx_main.log
```

### 分析日志

```bash
python scanner.py --analyze-logs
```

## 命令行参数

```
positional arguments:
  target                扫描目标IP或域名

options:
  -h, --help            显示帮助信息
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
```

## 配置文件说明

配置文件 `config/config.json` 用于设置扫描器的默认参数：

```json
{
    "timeout": 10,
    "max_threads": 100,
    "requests_per_second": 20,
    "requests_per_minute": 1000,
    "max_concurrent": 50,
    "verify_ssl": true,
    "user_agent": "Mozilla/5.0..."
}
```

## 输出说明

扫描结果会保存在 `output` 目录下：
- `scan_results_xxx.json` - JSON 格式的详细扫描结果
- `scan_results_xxx_summary.txt` - 文本格式的扫描摘要

## ⚠️ 安全与道德使用声明

**本工具仅限于：**
- 您拥有明确书面授权进行测试的系统
- 您自己拥有合法所有权的资产
- 在符合所有适用法律法规的环境下进行的安全教学、研究和授权演练

**严格禁止将本工具用于：**
- 未经明确授权的任何形式的网络探测、扫描或攻击
- 侵犯他人隐私或数据安全
- 任何违反您所在国家或地区法律，以及目标系统所在司法管辖区法律的活动

使用者需对使用本工具造成的任何直接或间接后果承担全部法律责任。开发者不对任何滥用行为负责。

## 许可证

本项目遵循开源协议，具体许可证信息请查看项目根目录下的 LICENSE 文件。