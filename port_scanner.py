import socket
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self,timeout=1,max_threads=100):
        self.timeout=timeout
        self.max_threads=max_threads
        self.common_ports=[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    def scan_port(self,target,port):
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result=sock.connect_ex((target,port))
            sock.close()

            if result==0:
                return port, "open"
            else:
                return port, "closed"
        except Exception as e:
            return port, f"error: {str(e)}"

    def scan_target(self,target,ports=None):
        if ports is None:
            ports=self.common_ports
        
        open_ports=[]

        print(f"开始扫描 {target}...")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port={
                executor.submit(self.scan_port,target,port):port
                for port in ports} 
            for future in concurrent.futures.as_completed(future_to_port):
                port=future_to_port[future]
                try:
                    port_num,status=future.result()
                    if status=="open":
                        open_ports.append(port_num)
                        print(f"[+] 端口 {port_num} 开放")
                except Exception as e:
                    print(f"[-] 端口 {port} 扫描出错: {e}")
        return sorted(open_ports)
    def get_service_name(self,port):
        services={
            21:"FTP",
            22:"SSH",
            23:"Telnet",
            25:"SMTP",
            53:"DNS",
            80:"HTTP",
            110:"POP3",
            111:"RPCbind",
            135:"MS RPC",
            139:"NetBIOS",
            143:"IMAP",
            443:"HTTPS",
            445:"Microsoft-DS",
            993:"IMAPS",
            995:"POP3S",
            1723:"PPTP",
            3306:"MySQL",
            3389:"RDP",
            5900:"VNC",
            8080:"HTTP-Proxy"
        }     
        return services.get(port,"未知服务")




