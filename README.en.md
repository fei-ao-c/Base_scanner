# Base Scanner

English | [中文](README.md)

## Introduction

Base Scanner is a powerful network security scanning tool for detecting vulnerabilities in websites. It supports port scanning, Web vulnerability scanning (SQL injection, XSS, etc.), with request control and rate limiting features.

## Software Architecture

```
Base_scanner/
├── scanner.py              # Main entry point
├── port_scanner.py         # Port scanner
├── web_scanner.py          # Web vulnerability scanner
├── commodity_code.py       # Commodity code scanner
├── utils.py                # Utility functions
├── config/                 # Configuration directory
│   ├── config.json
│   ├── code_payloads.json
│   ├── command_payloads.json
│   └── logging_config.py
├── modules/                # Request processing modules
│   ├── request_builder.py
│   ├── request_manager.py
│   ├── request_queue.py
│   ├── request_sender.py
│   └── response_parse.py
├── payload/                # Vulnerability detection payloads
│   ├── xss.json           # XSS payload library
│   └── sql_injection.json # SQL injection payload library
└── tools/                 # Helper tools
    ├── log_viewer.py
    └── report_generator.py
```

## Features

### Port Scanning
- Custom port range scanning
- Multi-threaded concurrent scanning
- Auto-detect common service types

### Web Vulnerability Scanning

#### SQL Injection Detection
- Error-based injection detection
- Boolean-based blind injection detection
- Time-based blind injection detection
- Union-based injection detection
- Stacked queries detection
- Support for multiple databases: MySQL, MSSQL, PostgreSQL, Oracle, SQLite
- NoSQL injection support: MongoDB, Redis, Elasticsearch, DynamoDB, Firebase

#### XSS Detection
- Reflected XSS detection
- Stored XSS detection
- DOM-based XSS detection
- Multiple encoding bypass detection
- Context analysis detection

#### Payload Library
- **XSS**: 378+ Payloads
  - Basic XSS: 240
  - DOM-based: 41
  - JSON XSS: 16
  - Angular: 16
  - Template Injection: 24
  - Bypass Techniques: 25
  - Context-specific: 4 categories

- **SQL Injection**: 250+ Payloads
  - Generic: 32
  - MySQL: 25
  - MSSQL: 58
  - PostgreSQL: 6
  - Oracle: 12
  - NoSQL: 98

#### Injection Point Parameters
- URL parameters: 176
- Form fields: 126
- JSON parameters: 102
- Cookies: 51
- Headers: 31
- Path parameters: 78
- XML parameters: 35

### Request Control
- Rate limiting (requests per second/minute)
- Maximum concurrent requests
- Request timeout settings
- SSL certificate verification control
- Request retry mechanism

### Log Management
- Text and JSON format logs
- Log viewing and analysis
- Scan result export

## Installation

1. Clone the repository:
```bash
git clone https://github.com/fei-ao-c/Base_scanner.git
cd Base_scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python scanner.py -h
```

### Port Scanning

```bash
python scanner.py 192.168.1.1 -p 1-1000
```

### SQL Injection Scanning

```python
from web_scanner import sampilescanner

scanner = sampilescanner()

# Test with specific parameter
vulns, results = scanner.check_sql_injection(
    "http://example.com/page?id=1",
    param_name="id",
    param_value="1"
)

# Auto-detect parameters
vulns, results = scanner.check_sql_injection(
    "http://example.com/page",
    auto_detect_params=True
)
```

### XSS Scanning

```python
from web_scanner import sampilescanner

scanner = sampilescanner()

# Test with specific parameter
vulns, results = scanner.check_xss(
    "http://example.com/search?q=test",
    method="GET"
)

# POST form test
vulns, results = scanner.check_xss(
    "http://example.com/comment",
    method="POST",
    data={"content": "test"}
)
```

### Set Concurrency and Request Rate

```bash
python scanner.py example.com -p 1-1000 -c 50 -rps 20 -rpm 1000
```

### View Logs

```bash
python scanner.py --view-log logs/scanner_xxx_main.log
```

### Analyze Logs

```bash
python scanner.py --analyze-logs
```

## Command Line Arguments

```
positional arguments:
  target                Target IP or domain to scan

options:
  -h, --help            Show help information
  -p, --ports PORTS     Port range to scan, e.g., 1-1000
  -o, --output {json,txt,all}
                        Output report filename
  --log-dir LOG_DIR     Log directory
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        Log level
  --no-log              Disable logging
  --view-log FILE       View log file
  --analyze-logs        Analyze logs
  -rps, --requests-per-second REQUESTS_PER_SECOND
                        Maximum requests per second
  -rpm, --requests-per-minute REQUESTS_PER_MINUTE
                        Maximum requests per minute
  -c, --concurrent CONCURRENT
                        Maximum concurrent requests
  -t, --timeout TIMEOUT
                        Request timeout in seconds
  --no-ssl-verify       Do not verify SSL certificates
```

## Configuration

The configuration file `config/config.json` is used to set default parameters for the scanner:

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

## Output

Scan results are saved in the `output` directory:
- `scan_results_xxx.json` - Detailed scan results in JSON format
- `scan_results_xxx_summary.txt` - Text summary of scan results

## ⚠️ Security and Ethical Use Statement

**This tool is strictly limited to:**
- Systems for which you have explicit written authorization to test
- Assets that you legally own
- Security education, research, and authorized exercises conducted in compliance with all applicable laws and regulations

**STRICTLY PROHIBITED uses of this tool include:**
- Any form of unauthorized network probing, scanning, or attacks
- Infringing upon others' privacy or data security
- Any activity that violates the laws of your country/region or the jurisdiction of the target system

Users bear full legal responsibility for any direct or indirect consequences resulting from their use of this tool. The developer is not liable for any misuse.

## License

This project follows an open source license. Please refer to the LICENSE file in the project root directory for specific license information.

## Contributors

Issues and Pull Requests are welcome!
