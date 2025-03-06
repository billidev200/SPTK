import socket
import threading
import queue
import time



# Main Menu 
def main():
    while True:
        print("Spartiatis Toolkit")
        print("1. Port Scanner")
        print("6. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            target = input("Enter target IP: ")
            while True:
                try:
                    start_port = int(input("Enter start port [1-65535]: "))
                    end_port = int(input("Enter end port [1-65535]: "))
                    if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                        break
                    print("[!] Invalid port range. Start port must be <= end port [1-65535]")
                except ValueError:
                    print("[!] Please enter valid numbers")
            ports = range(start_port, end_port+1)
            scanner = PortScanner()
            results = scanner.scan_ports(target, ports)
            print("\nScan Results:")
            print("Port\tStatus\tService\t\tBanner")
            print("-----\t------\t-------\t\t------")
            for port, status, service, banner in results:
                print(f"{port}\t{status}\t{service.ljust(8)}\t{banner[:50]}")

            input("\nPress Enter to return to main menu...")

        elif choice == '6':
            print("Exiting...")
            break

        else:
             print("Invalid option, please try again")
             time.sleep(1)
         
        
# Port Scanner 
class PortScanner:
    def __init__(self):
        self.common_services = {
        # Network Core Services
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP',
            80: 'HTTP',
            110: 'POP3',
            123: 'NTP',
            143: 'IMAP',
            161: 'SNMP',
            389: 'LDAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            514: 'Syslog',
            587: 'SMTP Submission',
            636: 'LDAPS',
            993: 'IMAPS',
            995: 'POP3S',
            
            # Database Services
            1433: 'MSSQL',
            1521: 'Oracle DB',
            27017: 'MongoDB',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            
            # Remote Access
            3389: 'RDP',
            5900: 'VNC',
            5985: 'WinRM',
            
            # Web Services
            8000: 'HTTP-Alt',
            8080: 'HTTP-Alt',
            8081: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt',
            9000: 'PHP-FPM',
            9200: 'Elasticsearch',
            
            # Messaging & Cache
            11211: 'Memcached',
            5672: 'AMQP',
            6379: 'Redis',
            
            # Network Services
            1194: 'OpenVPN',
            1723: 'PPTP',
            1812: 'RADIUS',
            2049: 'NFS',
            2375: 'Docker',
            2376: 'Docker TLS',
            3000: 'Node.js',
            5000: 'UPnP',
            5353: 'mDNS',
            5431: 'SCCP',
            5671: 'AMQP SSL',
            6881: 'BitTorrent',
            8333: 'Bitcoin',
            
            # Security Services
            500: 'IPSec',
            5060: 'SIP',
            5222: 'XMPP',
            5269: 'XMPP Server',
            8291: 'Winbox',
            10000: 'Webmin'
        
        }

    def get_service_banner(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((target, port))
                
                
                if port == 80 or port == 443:
                    s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % target.encode())
                    banner = s.recv(1024).decode().split('\n')[0]
                elif port == 21:
                    banner = s.recv(1024).decode().strip()
                elif port == 22:
                    banner = s.recv(1024).decode().strip()
                elif port == 25:
                    banner = s.recv(1024).decode().strip()
                else:
                    s.send(b"\r\n\r\n")
                    banner = s.recv(1024).decode().strip()
                
                return banner.split('\n')[0]  
        except:
            return "Unknown"

    def scan_port(self, target, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target, port))
                if result == 0:
                    service = self.common_services.get(port, 'Unknown')
                    banner = self.get_service_banner(target, port)
                    return (port, 'Open', service, banner)
        except:
            return None
        return None

    def scan_ports(self, target, ports, max_threads=100):
        results = []
        q = queue.Queue()
        print(f"Scanning {target}...")

        def worker():
            while not q.empty():
                port = q.get()
                result = self.scan_port(target, port)
                if result:
                    results.append(result)
                q.task_done()

        for port in ports:
            q.put(port)

        for _ in range(max_threads):
            threading.Thread(target=worker, daemon=True).start()

        q.join()
        return sorted(results, key=lambda x: x[0])
    
if __name__ == "__main__":
    main()  