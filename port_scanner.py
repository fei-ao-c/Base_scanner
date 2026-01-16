import socket
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import logging

class PortScanner:
    def __init__(self,timeout=1,max_threads=100,verbose=False):
        self.timeout=timeout
        self.max_threads=max_threads
        self.verbose = verbose
        #获取日志记录器
        self.logger=logging.getLogger('vuln_scanner.scan.port')

        self.common_ports=[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
    def scan_port(self, target, port):
        """扫描单个端口，增强异常处理"""
        # 1. 首先解析目标，获取主机（此步骤可能失败）
        try:
            parsed_target = self._parse_target(target)
            host_to_scan = parsed_target["host"]
        except Exception as parse_err:
            # 如果连目标都无法解析，直接返回错误，不再尝试连接
            error_msg = f"目标解析失败 '{target}': {parse_err}"
            self.logger.error(error_msg)
            return port, f"parse_error: {str(parse_err)}"

        # 2. 现在 host_to_scan 已被安全赋值，开始扫描
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            self.logger.debug(f"正在扫描 {host_to_scan}:{port} (原始输入: {target})")

            result = sock.connect_ex((host_to_scan, port))
            sock.close()

            if result == 0:
                self.logger.debug(f"端口开放: {host_to_scan}:{port}")
                return port, "open"
            else:
                return port, "closed"
        except socket.timeout:
            self.logger.debug(f"端口扫描超时: {host_to_scan}:{port}")
            return port, "timeout"
        except Exception as e:
            # 此时可以安全地使用 host_to_scan 变量
            self.logger.error(f"端口扫描错误: {host_to_scan}:{port}, 错误: {e}", exc_info=True)
            return port, f"socket_error: {str(e)}"

    def scan_target(self, target, ports=None):
        """扫描目标的所有指定端口，支持多种输入格式"""
        # 先解析目标，提取主机信息
        parsed_target = self._parse_target(target)
        host = parsed_target["host"]

        if ports is None:
            # 优先使用URL中指定的端口
            if parsed_target["port"] is not None:
                ports = [parsed_target["port"]]
                print(f"使用URL中指定的端口进行扫描: {parsed_target['port']}")
            else:
                ports = self.common_ports

        open_ports = []

        self.logger.info(f"开始扫描目标: {target} -> {host}, 端口数量: {len(ports)}")
        print(f"扫描目标: {target} (解析为: {host})")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # 提交所有端口扫描任务
            future_to_port = {
                executor.submit(self.scan_port, target, port): port
                for port in ports
            }

            # 收集结果
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port_num, status = future.result()
                    if status == "open":
                        open_ports.append(port_num)
                        print(f"[+] {host}:{port_num} 开放 ({status})")
                        self.logger.info(f"端口开放: {host}:{port_num}")
                    else:
                        if self.verbose:  # 可选：详细模式显示关闭端口
                            print(f"[-] {host}:{port_num} 关闭 ({status})")
                except Exception as e:
                    print(f"[-] 端口 {port} 扫描出错: {e}")
                    self.logger.error(f"端口扫描异常: {host}:{port}, 错误: {e}")

        self.logger.info(f"完成扫描目标: {target}, 开放端口数量: {len(open_ports)}")

        # 显示简要结果
        if open_ports:
            print(f"\n[+] {host} 开放端口: {sorted(open_ports)}")
        else:
            print(f"\n[-] {host} 未发现开放端口")

        return sorted(open_ports)
    
    def _parse_target(self, target):
        """
        增强版目标解析，严格分离主机、端口和路径。
        支持:
        - http://127.0.0.1/path:90
        - 127.0.0.1/sqli-labs-master/Less-1/:90 (这种格式不规范，但尝试兼容)
        - 所有标准格式
        """
        import re
        from urllib.parse import urlparse

        result = {
            "original": target.strip(),
            "protocol": None,
            "host": None,
            "port": None,
            "path": None,
            "full_url": None,
            "is_ip": False,
            "is_domain": False,
            "parse_error": None
        }

        target = target.strip()

        # --- 情况1: 处理包含协议的完整URL (最标准) ---
        if target.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(target)
                result["protocol"] = parsed.scheme
                result["host"] = parsed.hostname
                result["port"] = parsed.port
                result["path"] = parsed.path

                # 处理URL中可能包含的端口
                if not result["port"]:
                    result["port"] = 443 if result["protocol"] == "https" else 80
                result["full_url"] = f"{result['protocol']}://{result['host']}:{result['port']}{result['path'] or '/'}"

            except Exception as e:
                result["parse_error"] = f"URL解析失败: {e}"

        # --- 情况2: 处理不含协议但含端口的格式 (如 127.0.0.1:90/path) ---
        # 先尝试提取端口，因为端口前的部分一定是主机
        if not result["host"]:
            # 匹配主机:端口 模式，端口后可能跟路径
            # 例如: 127.0.0.1:90/path, example.com:443/admin
            match_with_port = re.match(r'^([^:/?#]+):(\d+)([/?#].*)?$', target)

            if match_with_port:
                result["host"] = match_with_port.group(1)
                result["port"] = int(match_with_port.group(2))
                result["path"] = match_with_port.group(3) or "/"
                result["protocol"] = "http" if result["port"] != 443 else "https"

        # --- 情况3: 处理不含端口但含路径的格式 (如 127.0.0.1/path) ---
        if not result["host"]:
            # 匹配主机/路径 模式
            match_with_path = re.match(r'^([^:/?#]+)([/?#].*)$', target)

            if match_with_path:
                result["host"] = match_with_path.group(1)
                result["path"] = match_with_path.group(2)
                result["protocol"] = "http"
                result["port"] = 80  # HTTP默认端口

        # --- 情况4: 纯主机 (IP或域名) ---
        if not result["host"]:
            result["host"] = target
            result["protocol"] = "http"
            result["port"] = 80
            result["path"] = "/"

        # --- 后处理与验证 ---
        # 1. 验证主机格式
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', result["host"]):
            result["is_ip"] = True
        elif '.' in result["host"]:  # 简单域名判断
            result["is_domain"] = True

        # 2. 构建标准full_url (用于Web扫描)
        if not result["full_url"]:
            if result["path"] and result["path"] != "/":
                result["full_url"] = f"{result['protocol']}://{result['host']}:{result['port']}{result['path']}"
            else:
                result["full_url"] = f"{result['protocol']}://{result['host']}:{result['port']}/"

        # 3. 清理路径中的多余斜杠
        if result["path"] and '://' in result["path"]:
            # 防止路径部分错误地包含协议头
            result["path"] = re.sub(r'^[^/]*//[^/]*', '', result["path"])

        return result

    # def scan_port(self,target,port):
    #     """扫描单个端口"""
    #     try:
    #         sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    #         sock.settimeout(self.timeout)

    #         self.logger.debug(f"Scanning {target}:{port}")

    #         result=sock.connect_ex((target,port))
    #         sock.close()

    #         if result==0:
    #             self.logger.debug(f"端口开放: {target}:{port}")
    #             return port, "open"
    #         else:
    #             return port, "closed"
    #     except socket.timeout:
    #         self.logger.debug(f"端口扫描超时: {target}:{port}")
    #         return port, "timeout"
    #     except Exception as e:
    #         self.logger.error(f"端口扫描错误: {target}:{port}, 错误: {e}", exc_info=True)
    #         return port, f"error: {str(e)}"

    # def scan_target(self,target,ports=None):
    #     """扫描目标的所有指定端口"""
    #     if ports is None:
    #         ports=self.common_ports
        
    #     open_ports=[]

    #     # print(f"开始扫描 {target}...")
    #     self.logger.info(f"开始扫描目标: {target}, 端口数量: {len(ports)}")
    #     with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
    #         #提交所有端口扫描任务
    #         future_to_port={
    #             executor.submit(self.scan_port,target,port):port
    #             for port in ports} 
    #         #收集结果
    #         for future in concurrent.futures.as_completed(future_to_port):
    #             port=future_to_port[future]
    #             try:
    #                 port_num,status=future.result()
    #                 if status=="open":
    #                     open_ports.append(port_num)
    #                     # print(f"[+] 端口 {port_num} 开放")
    #                     #self.logger.info(f"端口开放: {target}:{port_num} ")
    #             except Exception as e:
    #                 print(f"[-] 端口 {port} 扫描出错: {e}")
    #     self.logger.info(f"完成扫描目标: {target}, 开放端口数量: {len(open_ports)}")
    #     return sorted(open_ports)
    # def get_service_name(self,port):
    #     services={
    #         21:"FTP",
    #         22:"SSH",
    #         23:"Telnet",
    #         25:"SMTP",
    #         53:"DNS",
    #         80:"HTTP",
    #         110:"POP3",
    #         111:"RPCbind",
    #         135:"MS RPC",
    #         139:"NetBIOS",
    #         143:"IMAP",
    #         443:"HTTPS",
    #         445:"Microsoft-DS",
    #         993:"IMAPS",
    #         995:"POP3S",
    #         1723:"PPTP",
    #         3306:"MySQL",
    #         3389:"RDP",
    #         5900:"VNC",
    #         8080:"HTTP-Proxy"
    #     }     
    #     return services.get(port,"未知服务")
    def get_service_name(self, port):
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPCbind",
            135: "MS RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "Microsoft-DS",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Proxy",
            
            # FTP相关
            20: "FTP-Data",
            69: "TFTP",
            989: "FTPS-Data",
            990: "FTPS",
            
            # SSH相关
            2222: "SSH-Alternate",
            
            # 邮件服务
            26: "SMTP-Alternate",
            109: "POP2",
            465: "SMTPS",
            587: "SMTP-Submission",
            119: "NNTP",
            563: "NNTP-SSL",
            
            # Web服务
            81: "HTTP-Alternate",
            82: "HTTP-Alternate2",
            88: "Kerberos",
            443: "HTTPS",
            800: "HTTP-Alternate3",
            8008: "HTTP-Alternate4",
            8010: "HTTP-Alternate5",
            8081: "HTTP-Proxy2",
            8088: "HTTP-Alternate6",
            8090: "HTTP-Alternate7",
            8181: "HTTP-Alternate8",
            8443: "HTTPS-Alternate",
            8888: "HTTP-Alternate9",
            9000: "HTTP-Alternate10",
            
            # 数据库服务
            1433: "MSSQL",
            1434: "MSSQL-Monitor",
            1521: "Oracle-DB",
            1522: "Oracle-DB2",
            1523: "Oracle-DB3",
            1524: "Oracle-DB4",
            1525: "Oracle-DB5",
            1526: "Oracle-DB6",
            1527: "Oracle-DB7",
            1528: "Oracle-DB8",
            1529: "Oracle-DB9",
            3307: "MySQL2",
            3308: "MySQL3",
            5432: "PostgreSQL",
            5433: "PostgreSQL2",
            6379: "Redis",
            6380: "Redis2",
            27017: "MongoDB",
            27018: "MongoDB2",
            9200: "Elasticsearch",
            9300: "Elasticsearch-Transport",
            
            # 远程访问
            512: "Rexec",
            513: "Rlogin",
            514: "Rsh",
            515: "LPD",
            1080: "SOCKS",
            2000: "Cisco-SCCP",
            2375: "Docker",
            2376: "Docker-SSL",
            2379: "etcd",
            2380: "etcd2",
            3389: "RDP",
            3390: "RDP2",
            5901: "VNC2",
            5902: "VNC3",
            5903: "VNC4",
            5800: "VNC-HTTP",
            5801: "VNC-HTTP2",
            
            # 文件共享
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            139: "NetBIOS-SSN",
            2049: "NFS",
            3260: "iSCSI",
            
            # 目录服务
            389: "LDAP",
            636: "LDAPS",
            3268: "LDAP-GC",
            3269: "LDAP-GC-SSL",
            
            # 打印服务
            631: "IPP",
            9100: "Print-Server",
            
            # 时间服务
            123: "NTP",
            
            # 监控服务
            161: "SNMP",
            162: "SNMP-Trap",
            
            # 虚拟化
            5985: "WinRM",
            5986: "WinRM-SSL",
            5989: "WinRM-SSL2",
            
            # 消息队列
            5672: "AMQP",
            15672: "RabbitMQ-Management",
            1883: "MQTT",
            8883: "MQTT-SSL",
            
            # 缓存服务
            11211: "Memcached",
            11214: "Memcached-SASL",
            11215: "Memcached-SASL2",
            
            # 容器编排
            6443: "Kubernetes-API",
            10250: "Kubelet",
            10255: "Kubelet-ReadOnly",
            
            # CI/CD
            8080: "Jenkins",
            8153: "GoCD",
            7990: "Bitbucket",
            7999: "Bitbucket-SSL",
            
            # 配置管理
            8500: "Consul",
            8600: "Consul-DNS",
            8300: "Consul-Server",
            8301: "Consul-Server2",
            8302: "Consul-Server3",
            8400: "Consul-RPC",
            8501: "Consul-SSL",
            8848: "Nacos",
            8849: "Nacos-Cluster",
            2181: "Zookeeper",
            2888: "Zookeeper-Follower",
            3888: "Zookeeper-Election",
            
            # 监控系统
            9090: "Prometheus",
            9093: "Alertmanager",
            3000: "Grafana",
            5601: "Kibana",
            9200: "Elasticsearch",
            9300: "Elasticsearch-Transport",
            24224: "Fluentd",
            24225: "Fluentd2",
            
            # 游戏服务器
            25565: "Minecraft",
            25575: "Minecraft-RCON",
            27015: "Steam",
            27016: "Steam2",
            27017: "Steam3",
            27018: "Steam4",
            27019: "Steam5",
            27020: "Steam6",
            
            # VoIP
            5060: "SIP",
            5061: "SIP-TLS",
            
            # 代理服务
            3128: "Squid",
            8080: "HTTP-Proxy",
            8118: "Privoxy",
            9050: "Tor-SOCKS",
            9051: "Tor-Control",
            
            # 远程管理
            10000: "Webmin",
            10001: "Webmin-SSL",
            10050: "Zabbix-Agent",
            10051: "Zabbix-Server",
            
            # 备份服务
            10000: "BackupExec",
            
            # 网络安全设备
            514: "Syslog",
            1514: "Syslog-TLS",
            6514: "Syslog-TLS2",
            
            # 云服务
            9999: "Hadoop",
            8020: "Hadoop-HDFS",
            50070: "Hadoop-WebUI",
            50075: "Hadoop-Datanode",
            50090: "Hadoop-Secondary",
            8088: "Hadoop-ResourceManager",
            8032: "Hadoop-ResourceManager2",
            8042: "Hadoop-NodeManager",
            19888: "Hadoop-JobHistory",
            
            # 其他常用
            7: "Echo",
            9: "Discard",
            13: "Daytime",
            17: "Quote",
            19: "Chargen",
            37: "Time",
            42: "WINS",
            43: "Whois",
            79: "Finger",
            88: "Kerberos",
            107: "RemoteTelnet",
            109: "POP2",
            113: "Ident",
            119: "NNTP",
            123: "NTP",
            135: "MSRPC",
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            139: "NetBIOS-SSN",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP-Trap",
            177: "XDMCP",
            179: "BGP",
            194: "IRC",
            199: "SMUX",
            201: "AppleTalk",
            209: "QuickMail",
            210: "ANSI-Z39.50",
            213: "IPX",
            218: "MPP",
            220: "IMAP3",
            259: "ESRO",
            264: "BGMP",
            280: "HTTP-MGMT",
            318: "TSP",
            350: "MATIP",
            351: "MATIP2",
            366: "ODMR",
            369: "RPC2PORTMAP",
            370: "codaauth2",
            371: "Clearcase",
            383: "HP-OpenView",
            384: "RemoteNet",
            387: "AURP",
            389: "LDAP",
            401: "UPS",
            427: "SLP",
            433: "NNSP",
            434: "MobileIP",
            443: "HTTPS",
            444: "SNPP",
            445: "Microsoft-DS",
            464: "Kerberos-Password",
            465: "SMTPS",
            475: "tcpnethaspsrv",
            497: "Retrospect",
            500: "ISAKMP",
            502: "Modbus",
            512: "Rexec",
            513: "Rlogin",
            514: "Rsh",
            515: "LPD",
            517: "Talk",
            518: "NTalk",
            520: "RIP",
            521: "RIPng",
            525: "TimeServer",
            526: "NewDate",
            530: "RPC",
            531: "Chat",
            532: "ReadNews",
            533: "ForEmergency",
            540: "UUCP",
            543: "KLogin",
            544: "KShell",
            546: "DHCPv6-Client",
            547: "DHCPv6-Server",
            548: "AFP",
            550: "RTSP",
            554: "RTSP",
            556: "Remotefs",
            560: "RMONITOR",
            561: "Monitor",
            563: "NNTP-SSL",
            564: "9PFS",
            565: "WHOIS++",
            587: "SMTP-Submission",
            591: "FileMaker",
            593: "HTTP-RPC",
            596: "SMSD",
            598: "CIM",
            599: "IPP",
            601: "Syslog",
            604: "TUNNEL",
            606: "Cray-Unified",
            607: "NSW-FE",
            608: "DLAgent",
            609: "DLMonitor",
            610: "DECdts",
            611: "DECdts2",
            612: "DECdts3",
            613: "DECdts4",
            614: "DECdts5",
            615: "DECdts6",
            616: "DECdts7",
            617: "DECdts8",
            618: "DECdts9",
            619: "DECdts10",
            620: "LPD",
            625: "DECdLM",
            626: "ASIA",
            627: "PassGo",
            628: "QMQP",
            629: "3Com-AMP3",
            630: "RDA",
            631: "IPP",
            632: "IPP2",
            633: "IPP3",
            634: "IPP4",
            635: "IPP5",
            636: "LDAPS",
            637: "LANServer",
            638: "LANServer2",
            639: "MSDP",
            640: "EntrustSPS",
            641: "Repcmd",
            642: "ESRO-EMSDP",
            643: "SANity",
            644: "DWMR",
            645: "PSSC",
            646: "LDP",
            647: "DHCP-Failover",
            648: "RRP",
            649: "Cadview",
            650: "OBEX",
            651: "IEEE-MMS",
            652: "UDLR-DTCP",
            653: "REPSCMD",
            654: "AODV",
            655: "TINC",
            656: "SPMP",
            657: "RMC",
            658: "TenFold",
            659: "URL-Rendezvous",
            660: "MacSRVAdmin",
            661: "HAIP",
            662: "PAShare",
            663: "PAShare2",
            664: "PAShare3",
            665: "PAShare4",
            666: "PAShare5",
            667: "PAShare6",
            668: "PAShare7",
            669: "PAShare8",
            670: "PAShare9",
            671: "PAShare10",
            672: "PAShare11",
            673: "PAShare12",
            674: "PAShare13",
            675: "PAShare14",
            676: "PAShare15",
            677: "PAShare16",
            678: "PAShare17",
            679: "PAShare18",
            680: "PAShare19",
            681: "PAShare20",
            682: "PAShare21",
            683: "PAShare22",
            684: "PAShare23",
            685: "PAShare24",
            686: "PAShare25",
            687: "PAShare26",
            688: "PAShare27",
            689: "PAShare28",
            690: "PAShare29",
            691: "MS-Exchange",
            692: "MS-Exchange2",
            693: "MS-Exchange3",
            694: "MS-Exchange4",
            695: "MS-Exchange5",
            696: "MS-Exchange6",
            697: "MS-Exchange7",
            698: "MS-Exchange8",
            699: "MS-Exchange9",
            700: "MS-Exchange10",
            701: "LDP",
            702: "IRIS",
            704: "ELCSD",
            705: "AgentX",
            706: "SILC",
            707: "Borland-DSJ",
            709: "Entrust-KMSH",
            710: "Entrust-ASH",
            711: "Cisco-TDP",
            712: "TBRPF",
            729: "IBM-NetView",
            730: "IBM-NetView2",
            731: "IBM-NetView3",
            740: "NETCP",
            741: "NETGW",
            742: "NETRCS",
            744: "FlexLM",
            747: "Fujitsu-Dev",
            748: "RIS-CM",
            749: "Kerberos-Admin",
            750: "Kerberos-IV",
            751: "Kerberos-Master",
            752: "qrh",
            753: "rrh",
            754: "Tell",
            758: "NLogin",
            759: "Con",
            760: "NS",
            761: "Rxe",
            762: "Quotad",
            763: "Cycleserv",
            764: "OmServ",
            765: "Webster",
            767: "Phonebook",
            769: "VID",
            770: "Cadlock",
            771: "RTip",
            772: "Cycleserv2",
            773: "Submit",
            774: "Rpasswd",
            775: "Entomb",
            776: "Wpages",
            777: "Multiling",
            780: "WPGS",
            781: "HP-Collector",
            782: "HP-Managed",
            783: "HP-Alarm",
            800: "HTTP-Alternate3",
            801: "Device",
            808: "HTTP-Proxy",
            843: "Adobe-Flash",
            873: "Rsync",
            888: "AccessBuilder",
            898: "Sun-Manager",
            900: "CheckPoint",
            901: "Samba-SWAT",
            902: "VMware-SOAP",
            903: "VMware-Remote",
            911: "xact-backup",
            912: "VMware-Auth",
            989: "FTPS-Data",
            990: "FTPS",
            991: "NAS",
            992: "Telnet-SSL",
            993: "IMAPS",
            994: "IRC-SSL",
            995: "POP3S",
            996: "VSINET",
            997: "MAITRD",
            998: "Busboy",
            999: "Garcon",
            1000: "Cadlock",
            1001: "Webpush",
            1002: "Windows-ICF",
            1008: "UFS-aware",
            1010: "Surf",
            1023: "Reserved",
        }
        
        # 如果端口在字典中，返回服务名，否则返回通用描述
        return services.get(port, f"Port {port}")
    




