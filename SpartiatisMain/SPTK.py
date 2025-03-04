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
        print("Port\tStatus\tService\t")
        print("-----\t------\t-------\t\t")
        for port, status, service, in results:
            print(f"Port {port} ({service}): {status}")

    elif choice == '6':
        exit()

    else:
        print("Invalid option")

# Port Scanner
class PortScanner:
    def __init__(self):
        self.service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-ALT'
        }

    def scan_port(self, target, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target, port))
                if result == 0:
                    service = self.service_map.get(port, 'Unknown')
                    return (port, 'Open', service)
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