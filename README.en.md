# scanccner
#### Introduction

This is an initial design of a scanning tool for detecting vulnerabilities on websites. It currently features port scanning and request throttling capabilities, and can be used to learn about designing scanning tools. You can build upon this foundation to add other functionalities.
Additional features will be included in the future.

#### Software Architecture

scanner.py is the main file and serves as the core of the scanner.
utils.py contains utility classes, primarily consisting of helper functions.
web_scanner.py is the website scanner, mainly responsible for scanning website ports and vulnerabilities. You can add various vulnerability scanning and exploitation features here.
port_scanner.py is the port scanner, primarily used to check whether ports on a specified IP address are open.
log_viewer.py is the log viewer, mainly for reviewing the scanner's logs.
logging_config.py handles logging configuration, primarily defining the log format.
The modules folder contains scanning modules, mainly consisting of request throttling modules.
#### Usage Tutorial

Run python scanner.py -h to view help information.

Positional arguments:
target Target IP or domain to scan

Options:
-h, --help Show this help message and exit
-p, --ports PORTS Port range to scan, e.g., 1-1000
-o, --output {json,txt,all}
Output report filename
--log-dir LOG_DIR Log directory
--log-level {DEBUG,INFO,WARNING,ERROR}
Log level
--no-log Disable logging
--view-log FILE View log file
--analyze-logs Analyze logs
-rps, --requests-per-second REQUESTS_PER_SECOND
Maximum requests per second
-rpm, --requests-per-minute REQUESTS_PER_MINUTE
Maximum requests per minute
-c, --concurrent CONCURRENT
Maximum concurrent requests
-t, --timeout TIMEOUT
Request timeout in seconds
--no-ssl-verify Do not verify SSL certificates
Instructions for Use

####    Download the code to your local machine.

    Install the required dependency libraries.

    Run the command python scanner.py -h to view help information.

#### ⚠️ Security and Ethical Use Statement

**This tool is strictly limited to:**

    Systems for which you have explicit written authorization to test.

    Assets that you legally own.

    Security education, research, and authorized exercises conducted in compliance with all applicable laws and regulations.

**STRICTLY PROHIBITED uses of this tool include:**

    Any form of unauthorized network probing, scanning, or attacks.

    Infringing upon others' privacy or data security.

    Any activity that violates the laws of your country/region or the jurisdiction of the target system.

Users bear full legal responsibility for any direct or indirect consequences resulting from their use of this tool. The developer is not liable for any misuse.