import socket
import threading
import queue


# Main Menu 
def main():
    print("Spartiatis Toolkit")
    print("1. Port Scanner")
    print("6. Exit")

    choice = input("Select an option: ")

    if choice == '1':
        target = input("Enter target IP: ")
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        ports = range(start_port, end_port+1)
        scanner = PortScanner()
        results = scanner.scan_ports(target, ports)
        print("\nScan Results:")
        print("Port\tStatus\tService\t\tBanner")
        print("-----\t------\t-------\t\t------")
        for port, status, service, banner in results:
            print(f"{port}\t{status}\t{service.ljust(8)}\t{banner[:50]}")
    elif choice == '6':
        exit()

    else:
        print("Invalid option")

# Port Scanner
class PortScanner:
    def __init__(self):
        self.common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            8080: 'HTTP-ALT'
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
                    # Get service name and banner
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