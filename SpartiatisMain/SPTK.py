import socket
import threading
import queue
import time
import re
import paramiko
import ftplib
import telnetlib
import requests
from urllib.parse import urljoin
import os
from tqdm import tqdm  



# Main Menu
def main():
    while True:  
        print("Spartiatis Toolkit")
        print("1. Port Scanner")
        print("2. Vulnerability Scanner")
        print("3. Service Bruteforcer")
        print("4. WAF Scanner")
        print("5. Directory Bruteforcer")
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

        elif choice == '2':
            while True:
                target = input("Enter target IP: ").strip()
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                    print("[!] Invalid IP address format")
                    continue
                try:
                    octets = list(map(int, target.split('.')))
                    if not all(0 <= octet <= 255 for octet in octets):
                        raise ValueError
                except (ValueError, AttributeError):
                    print("[!] Invalid IP address values")
                    continue
                break

            port_scanner = PortScanner()
            ports = port_scanner.scan_ports(target, range(1, 1025))
            vuln_scanner = VulnerabilityScanner()
            vulnerabilities = vuln_scanner.basic_checks(ports)
            
            print("\n[!] Potential vulnerabilities")
            for vuln in vulnerabilities:
                print(f"{vuln}")
            
            input("\n[+] Press Enter to return to main menu...")

        elif choice == '3':
            service = input("Service (SSH/FTP/Telnet): ").lower()
            target = input("Target IP: ")
            username = input("Username: ")
            wordlist = input("Wordlist path: ")

            bruteforcer = BruteForcer()
            if service == 'ssh':
                result = bruteforcer.ssh_bruteforce(target, username, wordlist)
            elif service == 'ftp':
                result = bruteforcer.ftp_bruteforce(target, username, wordlist)
            elif service == 'telnet':
                result = bruteforcer.telnet_bruteforce(target, username, wordlist)
            else:
                print("Invalid service")
                continue  

            if result:
                print(f"Successful login: {result[0]}:{result[1]}")
            else:
                print("Bruteforce failed")

            input("\nPress Enter to return to main menu...")
            
        elif choice == '4':
            while True:
                url = input("Enter URL (e.g., http://example.com): ").strip()
                if not re.match(r'^https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/.*)?$', url):
                    print("[!] Invalid URL format. Must include http:// or https:// and valid domain")
                    continue
                
                
                try:
                    parsed = requests.utils.urlparse(url)
                    if not parsed.netloc:
                        raise ValueError
                except:
                    print("[!] Invalid URL structure")
                    continue
                break

            waf_scanner = WafScanner()
            result = waf_scanner.detect_waf(url)
            print(f"WAF Detection Result: {result}")
            
            input("\n[+] Press Enter to return to main menu...")

        elif choice == '5':
            while True:
                url = input("Enter base URL (e.g., http://example.com): ").strip()
                if not re.match(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
                    print("[!] Invalid URL format. Must include http:// or https://")
                    continue
                
                try:
                    parsed = requests.utils.urlparse(url)
                    if not all([parsed.scheme, parsed.netloc]):
                        raise ValueError
                    response = requests.head(url, timeout=5)
                    if response.status_code >= 400:
                        print("[!] Base URL appears unreachable")
                        continue
                except Exception as e:
                    print(f"[!] URL validation failed: {str(e)}")
                    continue
                break

        
            while True:
                wordlist = input("Wordlist path: ").strip()
                if not os.path.isfile(wordlist):
                    print("[!] File does not exist")
                    continue
                
                try:
                    with open(wordlist, 'r') as f:
                        if not f.read(1):  
                            print("[!] Wordlist is empty")
                            continue
                except UnicodeDecodeError:
                    print("[!] Not a text file")
                    continue
                except Exception as e:
                    print(f"[!] Error reading file: {str(e)}")
                    continue
                break

            bruteforcer = DirectoryBruteforcer()
            found = bruteforcer.discover_directories(url, wordlist)
            print(f"\nFound {len(found)} directories")
            input("\n[+] Press Enter to return to main menu...")

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

                # Try to get banner
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


# Vulnerability Scanner
class VulnerabilityScanner:
    def basic_checks(self, open_ports):
        vulnerabilities = []
        for port, status, service, banner in open_ports: 
            if service == 'FTP' and port == 21:
                vulnerabilities.append("Potential FTP anonymous login")
            elif service == 'SSH' and port == 22:
                vulnerabilities.append("Check for outdated SSH versions")
            elif service == 'HTTP' and port == 80:
                vulnerabilities.append("Check for common web vulnerabilities")
        return vulnerabilities


# Service BruteForcer
class BruteForcer:
    def ssh_bruteforce(self, target, username, wordlist, port=22, timeout=5):
        with open(wordlist, 'r') as f:
            for password in f:
                password = password.strip()
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target, port=port, username=username, password=password, timeout=timeout)
                    print(f"[+] SSH Success: {username}:{password}")
                    ssh.close()
                    return (username, password)
                except:
                    continue
        return None

    def ftp_bruteforce(self, target, username, wordlist, port=21, timeout=5):
        with open(wordlist, 'r') as f:
            for password in f:
                password = password.strip()
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=timeout)
                    ftp.login(username, password)
                    print(f"[+] FTP Success: {username}:{password}")
                    ftp.quit()
                    return (username, password)
                except:
                    continue
        return None

    def telnet_bruteforce(self, target, username, wordlist, port=23, timeout=5):
        with open(wordlist, 'r') as f:
            for password in f:
                password = password.strip()
                try:
                    tn = telnetlib.Telnet(target, port=port, timeout=timeout)
                    tn.read_until(b"login: ")
                    tn.write(username.encode('ascii') + b"\n")
                    tn.read_until(b"Password: ")
                    tn.write(password.encode('ascii') + b"\n")
                    result = tn.expect([b"Login incorrect", b"Last login"], timeout=timeout)
                    if result[0] == 1:
                        print(f"[+] Telnet Success: {username}:{password}")
                        tn.close()
                        return (username, password)
                    tn.close()
                except:
                    continue
        return None


# Waf Scanner
class WafScanner:
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cloudflare'],
                'cookies': ['__cfduid', '__cflb'],
                'body': ['cloudflare'],
                'status': [403, 503]
            },
            'AWS WAF': {
                'headers': ['x-amz-cf-pop', 'aws-waf'],
                'body': ['aws-waf'],
                'status': [403]
            },
            'Akamai': {
                'headers': ['akamai-request-id'],
                'body': ['akamaighost'],
                'status': [403]
            },
            'Sucuri': {
                'cookies': ['sucuri_cloudproxy'],
                'body': ['sucuri/cloudproxy', 'access denied - sucuri'],
                'status': [403, 406]
            },
            'FortiWeb': {
                'headers': ['fortigate', 'fortiwaf'],
                'body': ['fgd_icon'],
                'status': [403]
            },
            'Barracuda': {
                'headers': ['barracuda'],
                'body': ['barracuda'],
                'status': [406]
            },
            'F5 BIG-IP': {
                'headers': ['f5'],
                'body': ['bigip', 'f5'],
                'status': [401, 413]
            },
            'Incapsula': {
                'cookies': ['incap_ses_', 'visid_incap_'],
                'body': ['incapsula'],
                'status': [403]
            },
            'Palo Alto': {
                'headers': ['palosession'],
                'body': ['palo alto'],
                'status': [403]
            },
            'Citrix Netscaler': {
                'headers': ['ns_af'],
                'body': ['citrix'],
                'status': [403]
            },
            'Radware': {
                'headers': ['x-secured-by'],
                'body': ['cloudwebsec'],
                'status': [403]
            },
            'ModSecurity': {
                'headers': ['mod_security'],
                'body': ['mod_security', 'this error was generated by mod_security'],
                'status': [403]
            },
            'Imperva': {
                'headers': ['x-cdn', 'incap-id'],
                'body': ['imperva'],
                'status': [403]
            },
            'Sophos UTM': {
                'headers': ['x-utm'],
                'body': ['protected by sophos'],
                'status': [403]
            },
            'Juniper': {
                'headers': ['juniper'],
                'body': ['juniper networks'],
                'status': [403]
            },
            'Check Point': {
                'headers': ['checkpoint'],
                'body': ['check point'],
                'status': [403]
            },
            'ASP.NET Firewall': {
                'body': ['<h2>asp.net has detected data in the request'],
                'status': [404]
            },
            'Wordfence': {
                'headers': ['x-wf-'],
                'body': ['wordfence'],
                'status': [503]
            },
            'Comodo': {
                'body': ['protected by comodo waf'],
                'status': [406]
            },
            'Cloudbric': {
                'headers': ['x-powered-by-cloudbric'],
                'body': ['cloudbric'],
                'status': [403]
            }
        }

    def detect_waf(self, url):
        try:
            response = requests.get(url, timeout=5)
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            content = response.text.lower()
            status = response.status_code

            for waf, indicators in self.waf_signatures.items():
                
                if status in indicators.get('status', []):
                    return waf
                
                
                for header in indicators.get('headers', []):
                    if any(h.startswith(header) for h in headers.keys()):
                        return waf
                
                
                for cookie in indicators.get('cookies', []):
                    if 'set-cookie' in headers:
                        if any(cookie in c for c in headers['set-cookie'].split(';')):
                            return waf
                
                
                for pattern in indicators.get('body', []):
                    if pattern in content:
                        return waf

            return "No WAF detected"

        except requests.exceptions.RequestException:
            return "Connection error"
        except Exception as e:
            return f"Detection error: {str(e)}"

# Directory Bruteforcer
class DirectoryBruteforcer:
    def __init__(self, max_threads=10):
        self.max_threads = max_threads
        self.found = set()
        self.lock = threading.Lock()
        self.progress = 0
        self.total_tasks = 0

    def discover_directories(self, base_url, wordlist):
        q = queue.Queue()
        
        with open(wordlist, 'r') as f:
            lines = [line.strip() for line in f]
            self.total_tasks = len(lines)
            for line in lines:
                q.put(line)

        progress_thread = threading.Thread(target=self._update_progress, daemon=True)
        progress_thread.start()

        def worker():
            while not q.empty():
                path = q.get()
                url = urljoin(base_url, path)
                try:
                    response = requests.get(url, timeout=3)
                    if response.status_code in [200, 301, 302, 403]:
                        with self.lock:
                            if url not in self.found:
                                self.found.add(url)
                                tqdm.write(f"[+] Found: {url}")  
                except Exception as e:
                    pass
                finally:
                    with self.lock:
                        self.progress += 1
                    q.task_done()

        for _ in range(self.max_threads):
            threading.Thread(target=worker, daemon=True).start()

        q.join()
        return list(self.found)

    def _update_progress(self):
        with tqdm(total=self.total_tasks, desc="Scan Progress", position=0, leave=True) as pbar:
            while self.progress < self.total_tasks:
                pbar.n = self.progress
                pbar.refresh()
                time.sleep(0.1)
            pbar.n = self.total_tasks
            pbar.refresh()

if __name__ == "__main__":
    main()