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
from colorama import Fore, Style, init
from tqdm import tqdm 
import dns.resolver
import sys
init(autoreset=True)



#Exit Shortcut
def get_input(prompt):
    user_input = input(prompt).strip()
    if user_input.lower() == ('exit'):
        print(Fore.RED + "\nExiting..." + Style.RESET_ALL)
        sys.exit(0)
    return user_input

# Main Menu 
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    while True:
        clear_screen() 
        show_banner()  
        menu_items = [
            Fore.GREEN + "[1]" + Style.RESET_ALL + " Port Scanner",
            Fore.GREEN + "[2]" + Style.RESET_ALL + " Vulnerability Scanner",
            Fore.GREEN + "[3]" + Style.RESET_ALL + " Service Bruteforcer",
            Fore.GREEN + "[4]" + Style.RESET_ALL + " WAF Detector",
            Fore.GREEN + "[5]" + Style.RESET_ALL + " Web Directory Bruteforcer",
            Fore.GREEN + "[6]" + Style.RESET_ALL + " Subdomain Bruteforcer",
            Fore.GREEN + "[8]" + Style.RESET_ALL + " CMS Detector",
            Fore.RED + "[9]" + Style.RESET_ALL + " Exit"
        ]
        
        for item in menu_items:
            print(item)
            time.sleep(0.1)

        choice = get_input("\n" + Fore.YELLOW + "[+] Select an option: " + Style.RESET_ALL)

        if choice == '1':
            while True:
                target = get_input("Enter target IP: ").strip()
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                    print(Fore.RED + "[!] Invalid IP address format" + Style.RESET_ALL)
                    continue
                try:
                    octets = list(map(int, target.split('.')))
                    if not all(0 <= octet <= 255 for octet in octets):
                        raise ValueError
                except:
                    print(Fore.RED + "[!] Invalid IP address values" + Style.RESET_ALL)
                    continue
                break

            while True:
                print("\nPort Range Options:")
                print(f"{Fore.CYAN}[1]{Style.RESET_ALL} Default (1-1024)")
                print(f"{Fore.CYAN}[2]{Style.RESET_ALL} Full range (1-65535)")
                print(f"{Fore.CYAN}[3]{Style.RESET_ALL} Custom range")
                range_choice = get_input(Fore.YELLOW + "\nSelect port range: " + Style.RESET_ALL)

                try:
                    if range_choice == '1':
                        ports = range(1, 1025)
                    elif range_choice == '2':
                        ports = range(1, 65536)
                    elif range_choice == '3':
                        start = int(get_input("Start port (1-65535): "))
                        end = int(get_input("End port (1-65535): "))
                        if not (1 <= start <= 65535 and 1 <= end <= 65535):
                            raise ValueError
                        if start > end:
                            print(Fore.RED + "[!] Start port must be <= end port" + Style.RESET_ALL)
                            continue
                        ports = range(start, end+1)
                    else:
                        raise ValueError
                    break
                except ValueError:
                    print(Fore.RED + "[!] Invalid selection" + Style.RESET_ALL)
                    continue

            scanner = PortScanner()
            results = scanner.scan_ports(target, ports)
            
            print(Fore.RED + "\n[!] Scan Results:\n")
            print("Port\tStatus\tService\t\tBanner")
            print("-----\t------\t-------\t\t------")
            for port, status, service, banner in results:
                print(f"{Fore.WHITE}{port:<8}{Fore.GREEN}{status:<10}{Fore.YELLOW}{service.ljust(15)}{Fore.CYAN}{banner[:50]}")
            
            get_input(Fore.YELLOW + "\n[+] Press Enter to return to main menu..." + Style.RESET_ALL)
        
        elif choice == '2':
            while True:
                target = get_input("Enter target IP: ").strip()
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                    print(Fore.RED + "[!] Invalid IP address format" + Style.RESET_ALL)
                    continue
                try:
                    octets = list(map(int, target.split('.')))
                    if not all(0 <= octet <= 255 for octet in octets):
                        raise ValueError
                except:
                    print(Fore.RED + "[!] Invalid IP address values" + Style.RESET_ALL)
                    continue
                break

            while True:
                print("\nPort Range Options:")
                print(f"{Fore.CYAN}[1]{Style.RESET_ALL} Default (1-1024)")
                print(f"{Fore.CYAN}[2]{Style.RESET_ALL} Full range (1-65535)")
                print(f"{Fore.CYAN}[3]{Style.RESET_ALL} Custom range")
                range_choice = get_input(Fore.YELLOW + "\nSelect port range: " + Style.RESET_ALL)

                try:
                    if range_choice == '1':
                        ports = range(1, 1025)
                    elif range_choice == '2':
                        ports = range(1, 65536)
                    elif range_choice == '3':
                        start = int(get_input("Start port (1-65535): "))
                        end = int(get_input("End port (1-65535): "))
                        if not (1 <= start <= 65535 and 1 <= end <= 65535):
                            raise ValueError
                        if start > end:
                            print(Fore.RED + "[!] Start port must be <= end port" + Style.RESET_ALL)
                            continue
                        ports = range(start, end+1)
                    else:
                        raise ValueError
                    break
                except ValueError:
                    print(Fore.RED + "[!] Invalid selection" + Style.RESET_ALL)
                    continue

            port_scanner = PortScanner()
            scanned_ports = port_scanner.scan_ports(target, ports)
            vuln_scanner = VulnerabilityScanner()
            vulnerabilities = vuln_scanner.basic_checks(scanned_ports)
            
            print(Fore.RED + "\n[!] Potential vulnerabilities")
            for vuln in vulnerabilities:
                print(Fore.RED + f"{vuln}" + Style.RESET_ALL)
            
            get_input(Fore.YELLOW + "\n[+] Press Enter to return to main menu..."+ Style.RESET_ALL )

        elif choice == '3':
            bruteforcer = BruteForcer()
            
            service = bruteforcer._get_input("Select Service (SSH, FTP, Telnet): ", bruteforcer._validate_service)
            target = bruteforcer._get_input("Target IP: ")
            port = bruteforcer._get_port(service)
            use_dual_wordlist = bruteforcer._get_yes_no("Use separate wordlists for username and password? (y/n): ")

            if use_dual_wordlist:
                username_wordlist = bruteforcer._get_wordlist("Username wordlist path: ")
                password_wordlist = bruteforcer._get_wordlist("Password wordlist path: ")
            else:
                username = bruteforcer._get_input("Username: ")
                password_wordlist = bruteforcer._get_wordlist("Password wordlist path: ")

            if service == 'ssh':
                result = bruteforcer.ssh_bruteforce(target, 
                    username if not use_dual_wordlist else username_wordlist, 
                    password_wordlist, port)
            elif service == 'ftp':
                result = bruteforcer.ftp_bruteforce(target, 
                    username if not use_dual_wordlist else username_wordlist, 
                    password_wordlist, port)
            elif service == 'telnet':
                result = bruteforcer.telnet_bruteforce(target, 
                    username if not use_dual_wordlist else username_wordlist, 
                    password_wordlist, port)

            if result:
                print(Fore.GREEN + f"[+] Successful login: {result[0]}:{result[1]}" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[!] Bruteforce failed." + Style.RESET_ALL)

            get_input(Fore.YELLOW + "\n[+] Press Enter to return to main menu..." + Style.RESET_ALL)

        elif choice == '4':
            while True:
                url = get_input("Enter URL (e.g., http://example.com): ").strip()
                if not re.match(r'^https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/.*)?$', url):
                    print(Fore.RED + "[!] Invalid URL format. Must include http:// or https:// and valid domain" + Style.RESET_ALL)
                    continue
                
                
                try:
                    parsed = requests.utils.urlparse(url)
                    if not parsed.netloc:
                        raise ValueError
                except:
                    print(Fore.RED + "[!] Invalid URL structure" + Style.RESET_ALL)
                    continue
                break

            waf_scanner = WafScanner()
            result = waf_scanner.detect_waf(url)
            print(Fore.YELLOW + f"WAF Detection Result: {result}" + Style.RESET_ALL)
            
            get_input(Fore.YELLOW + "\n[+] Press Enter to return to main menu..."+ Style.RESET_ALL )

        elif choice == '5':
            while True:
                url = get_input("Enter base URL (e.g., http://example.com): ").strip()
                if not re.match(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
                    print(Fore.RED + "[!] Invalid URL format. Must include http:// or https://" + Style.RESET_ALL)
                    continue
                
                try:
                    parsed = requests.utils.urlparse(url)
                    if not all([parsed.scheme, parsed.netloc]):
                        raise ValueError
                    response = requests.head(url, timeout=5)
                    if response.status_code >= 400:
                        print(Fore.RED + "[!] Base URL appears unreachable" + Style.RESET_ALL)
                        continue
                except Exception as e:
                    print(Fore.RED + f"[!] URL validation failed: {str(e)}" + Style.RESET_ALL)
                    continue
                break

            while True:
                wordlist = get_input("Wordlist path: ").strip()
                if not os.path.isfile(wordlist):
                    print(Fore.RED + "[!] File does not exist" + Style.RESET_ALL)
                    continue
                
                try:
                    with open(wordlist, 'r') as f:
                        if not f.read(1):
                            print(Fore.RED + "[!] Wordlist is empty" + Style.RESET_ALL)
                            continue
                except UnicodeDecodeError:
                    print(Fore.RED + "[!] Not a text file" + Style.RESET_ALL)
                    continue
                except Exception as e:
                    print(Fore.RED + f"[!] Error reading file: {str(e)}" + Style.RESET_ALL)
                    continue
                break

            bruteforcer = DirectoryBruteforcer()
            found = bruteforcer.discover_directories(url, wordlist)
            print(f"\nFound {len(found)} directories")
            get_input(Fore.YELLOW + "\n[+] Press Enter to return to main menu..."+ Style.RESET_ALL )
            
        elif choice == '6':
            while True:
                domain = get_input("Enter target domain (e.g., example.com): ").strip()
                cleaned_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
                
                if not re.match(
                    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$",
                    cleaned_domain
                ):
                    print(Fore.RED + "[!] Invalid URL format. Must include http:// or https://" + Style.RESET_ALL)
                    continue
                                
                try:
                    dns.resolver.resolve(cleaned_domain, 'A')
                except dns.resolver.NXDOMAIN:
                    print(Fore.YELLOW + "[!] Base domain doesn't resolve. Continue anyway? (y/n)" + Style.RESET_ALL)
                    if get_input().lower() != 'y':
                        continue
                except dns.resolver.NoAnswer:
                    print(Fore.YELLOW + "[!] No DNS records found. Continue anyway? (y/n)" + Style.RESET_ALL)
                    if get_input().lower() != 'y':
                        continue
                except Exception as e:
                    print(Fore.RED + f"[!] DNS resolution error: {str(e)}" + Style.RESET_ALL)
                    continue
                break

            while True:
                wordlist = get_input("Wordlist path: ").strip()
                
                
                if not os.path.isfile(wordlist):
                    print(Fore.RED + "[!] File not found" + Style.RESET_ALL)
                    continue
                
                try:
                    with open(wordlist, 'r') as f:
                        lines = [line.strip() for line in f if line.strip()]
                        if len(lines) < 5:
                            print(Fore.RED + "[!] Wordlist should contain at least 5 entries" + Style.RESET_ALL)
                            continue
                            
                        invalid_lines = [line for line in lines if not re.match(r"^[a-zA-Z0-9-]{1,63}$", line)]
                        if invalid_lines:
                            print(Fore.RED + f"[!] {len(invalid_lines)} invalid entries (max 63 chars, a-z, 0-9, hyphens)" + Style.RESET_ALL)
                            continue
                except UnicodeDecodeError:
                    print(Fore.RED + "[!] Not a text file" + Style.RESET_ALL)
                    continue
                except Exception as e:
                    print(Fore.RED + f"[!] File read error: {str(e)}" + Style.RESET_ALL)
                    continue
                break

            bruteforcer = SubdomainBruteforcer()
            found = bruteforcer.discover_subdomains(cleaned_domain, wordlist)
            print(f"\nFound {len(found)} subdomains")
            get_input(Fore.YELLOW + "\n[+] Press Enter to return to main menu..."+ Style.RESET_ALL )
        
        elif choice == '8':
            while True:
                url = get_input("Enter website URL (e.g., http://example.com): ").strip()
                if not re.match(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
                    print(Fore.RED + "[!] Invalid URL format. Must include http:// or https://" + Style.RESET_ALL)
                    continue
                break
            
            cms_detector = CMSDetector()
            with tqdm(total=len(cms_detector.cms_signatures), 
                    desc=f"{Fore.CYAN}Scanning for CMS{Style.RESET_ALL}",
                    bar_format="{l_bar}{bar:50}{r_bar}") as pbar:
                
                cms_list, version = cms_detector.detect_cms(url)
                pbar.update(len(cms_detector.cms_signatures))
            
            if cms_list:
                print(f"\n{Fore.GREEN}[+] Detected CMS:{Style.RESET_ALL}")
                for cms in cms_list:
                    ver_info = f" ({version})" if version and cms in ['WordPress','Joomla','Drupal'] else ""
                    print(f"{Fore.YELLOW}- {cms}{ver_info}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}[!] No known CMS detected{Style.RESET_ALL}")
            
            get_input(Fore.YELLOW + "\n[+] Press Enter to return to main menu..." + Style.RESET_ALL)

        elif choice == '9':  
            print(Fore.RED + "Exiting...")
            break

        else:
            print(Fore.RED + "[!] Invalid option, please try again")
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
            137: 'NetBIOS-NS',
            138: 'NetBIOS-DGM',
            139: 'NetBIOS-SSN',
            143: 'IMAP',
            161: 'SNMP',
            389: 'LDAP',
            443: 'HTTPS',
            111: 'RPC',
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
        self.lock = threading.Lock()
        self.progress = 0
        self.total_tasks = 0

    def _update_progress(self, bar_format):
        with tqdm(
            total=self.total_tasks,
            desc=f"{Fore.CYAN}Port Scan Progress{Style.RESET_ALL}",
            bar_format=bar_format,
            position=0,
            leave=False,  # True/False to keep or remove the progress bar after resutls
            ascii=" █",
            dynamic_ncols=True
        ) as pbar:
            self.pbar = pbar
            while self.progress < self.total_tasks and not self.scan_complete:
                pbar.n = self.progress
                pbar.refresh()
                time.sleep(0.1)
            pbar.close()

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
        self.scan_complete = False
        results = []
        q = queue.Queue()
        self.total_tasks = len(ports)
        self.progress = 0

        
        BAR_COLOR = Fore.BLUE
        TEXT_COLOR = Fore.CYAN
        RESET = Style.RESET_ALL
        
        bar_format = (
            f"{TEXT_COLOR}{{desc}}: {{percentage:3.0f}}%|"
            f"{BAR_COLOR}{{bar}}{RESET}| "
            f"{TEXT_COLOR}{{n_fmt}}/{{total_fmt}} [{{elapsed}}<{{remaining}}, {{rate_fmt}}]{RESET}"
        )

        
        progress_thread = threading.Thread(
            target=self._update_progress,
            args=(bar_format,),
            daemon=True
        )
        progress_thread.start()

        def worker():
            while not q.empty():
                port = q.get()
                result = self.scan_port(target, port)
                if result:
                    with self.lock:
                        results.append(result)
                with self.lock:
                    self.progress += 1
                q.task_done()

        
        for port in ports:
            q.put(port)

       
        for _ in range(max_threads):
            threading.Thread(target=worker, daemon=True).start()

        q.join()
        self.scan_complete = True  
        
        
        while progress_thread.is_alive():
            time.sleep(0.1)
        
        
        return sorted(results, key=lambda x: x[0])

# Vulnerability Scanner 
class VulnerabilityScanner:
    def basic_checks(self, open_ports):
        vulnerabilities = []
        for port, status, service, banner in open_ports:
            # Existing checks
            if service == 'FTP' and port == 21:
                vulnerabilities.append("Potential FTP anonymous login")
                if "vsFTPd" in banner and "2.3.4" in banner:
                    vulnerabilities.append("Critical: vsFTPd 2.3.4 backdoor vulnerability (CVE-2011-2523)")
            elif service == 'SSH' and port == 22:
                vulnerabilities.append("Check for outdated SSH versions")
                if "OpenSSH" in banner and ("7.4" in banner or "7.6" in banner):
                    vulnerabilities.append("Potential outdated OpenSSH version (check for CVE-2021-41617)")
            elif service == 'HTTP' and port == 80:
                vulnerabilities.append("Check for common web vulnerabilities")
                if "Apache/2.4.49" in banner or "Apache/2.4.50" in banner:
                    vulnerabilities.append("Critical: Apache Path Traversal (CVE-2021-41773)")
            
            # New vulnerability checks
            # 1. HTTP Server Header Disclosure
            if service in ['HTTP', 'HTTPS']:
                if "Server: " in banner:
                    server_header = banner.split("Server: ")[1].split("\r\n")[0]
                    vulnerabilities.append(f"Server header disclosure: {server_header}")
                    if "Apache/2.2." in server_header:
                        vulnerabilities.append("Outdated Apache version (2.2.x EOL)")

            # 2. SSL/TLS Basic Check
            if service == 'HTTPS' and port == 443:
                if "SSLv3" in banner or "TLSv1.0" in banner:
                    vulnerabilities.append("Deprecated SSL/TLS version detected")

            # 3. PHP Version Disclosure
            if "PHP/" in banner:
                php_version = banner.split("PHP/")[1].split(" ")[0]
                if php_version.startswith(('5.', '7.0', '7.1')):
                    vulnerabilities.append(f"Outdated PHP version ({php_version})")

            # 4. Tomcat Default Pages
            if service == 'HTTP' and "Apache-Coyote" in banner:
                vulnerabilities.append("Apache Tomcat detected - check for default pages")

            # 5. SMB Protocol Check
            if port == 445:
                vulnerabilities.append("SMB port open - check for SMBv1 vulnerability")

            # 6. DNS Zone Transfer
            if port == 53:
                vulnerabilities.append("DNS port open - check for zone transfer vulnerability")

            # 7. MySQL Empty Password
            if service == 'MySQL' and port == 3306:
                vulnerabilities.append("Check for MySQL empty root password")

            # 8. RDP Security
            if port == 3389:
                vulnerabilities.append("RDP exposed - check Network Level Authentication")

            # 9. SNMP Default Community Strings
            if port == 161:
                vulnerabilities.append("SNMP open - check for default community strings")

            # 10. Web Framework Default Credentials
            if service == 'HTTP':
                if "WordPress" in banner:
                    vulnerabilities.append("WordPress detected - check default admin credentials")
                elif "Jenkins" in banner:
                    vulnerabilities.append("Jenkins detected - check anonymous access")

            # 11. Elasticsearch Exposure
            if service == 'Elasticsearch' and port == 9200:
                vulnerabilities.append("Elasticsearch exposed - check for unauthenticated access (CVE-2015-1427)")
            
            # 12. Redis Unauthenticated Access
            if service == 'Redis' and port == 6379:
                vulnerabilities.append("Redis exposed - unauthenticated access could allow data manipulation")
            
            # 13. MongoDB Default Configuration
            if service == 'MongoDB' and port == 27017:
                vulnerabilities.append("MongoDB exposed - check for default authentication configuration")
            
            # 14. Docker API Exposure
            if service == 'Docker' and port in [2375, 2376]:
                vulnerabilities.append("Docker API exposed - unsecured daemon could allow container takeover")
            
            # 15. Jenkins RCE
            if "Jenkins" in banner and service == 'HTTP':
                vulnerabilities.append("Jenkins detected - check for:")
                vulnerabilities.append("  - Unauthenticated script console (CVE-2018-1999002)")
                vulnerabilities.append("  - Arbitrary file read vulnerability (CVE-2024-23897)")
            
            # 16. WebLogic Vulnerabilities
            if "WebLogic" in banner and port == 7001:
                vulnerabilities.append("Oracle WebLogic detected - check for:")
                vulnerabilities.append("  - Unauthenticated RCE (CVE-2020-14882)")
                vulnerabilities.append("  - XMLDecoder deserialization (CVE-2017-10271)")
            
            # 17. Nginx Vulnerabilities
            if "nginx" in banner.lower():
                if "1.16.0" in banner:
                    vulnerabilities.append("Nginx 1.16.0 vulnerable to directory traversal (CVE-2019-20372)")
            
            # 18. PHP-FPM Exposure
            if service == 'PHP-FPM' and port == 9000:
                vulnerabilities.append("PHP-FPM exposed - potential RCE if misconfigured with Nginx")
            
            # 19. Memcached Amplification
            if service == 'Memcached' and port == 11211:
                vulnerabilities.append("Memcached exposed - UDP amplification attack vector")
            
            # 20. VNC Authentication
            if service == 'VNC' and port == 5900:
                vulnerabilities.append("VNC exposed - check for authentication bypass (CVE-2023-32560)")
            
            # 21. RDP BlueKeep
            if service == 'RDP' and "Microsoft Terminal Services" in banner:
                if "8.1.7601" in banner or "10.0.10240" in banner:
                    vulnerabilities.append("RDP vulnerable to BlueKeep (CVE-2019-0708)")
            
            # 22. SSL Heartbleed
            if "OpenSSL/1.0.1" in banner and "f" not in banner.split("OpenSSL/1.0.1")[1][:2]:
                vulnerabilities.append("OpenSSL vulnerable to Heartbleed (CVE-2014-0160)")
            
            # 23. Apache Struts RCE
            if "Apache Struts" in banner:
                if "2.3.5" in banner or "2.3.31" in banner or "2.5.10" in banner:
                    vulnerabilities.append("Apache Struts RCE vulnerability (CVE-2017-5638)")
            
            # 24. IIS Buffer Overflow
            if "Microsoft-IIS" in banner:
                if "6.0" in banner:
                    vulnerabilities.append("IIS 6.0 vulnerable to buffer overflow (CVE-2017-7269)")
            
            # 25. WebDAV Misconfiguration
            if "Microsoft-HTTPAPI" in banner and "WebDAV" in banner:
                vulnerabilities.append("WebDAV enabled - check for PUT method vulnerabilities")
            # NetBIOS Vulnerability Checks
            if service in ['NetBIOS-NS', 'NetBIOS-DGM', 'NetBIOS-SSN']:
                vulnerabilities.append("NetBIOS service exposed (ports 137-139) - check for:")
                vulnerabilities.append("  - Null session vulnerabilities (CVE-1999-0519)")
                vulnerabilities.append("  - SMBv1 vulnerabilities (MS17-010/EternalBlue)")
                vulnerabilities.append("  - Unauthenticated share enumeration")
                vulnerabilities.append("  - Zone transfer attacks")
                
            # SMB-specific checks (port 445)
            if service == 'SMB' and port == 445:
                vulnerabilities.append("SMB port exposed - check for:")
                vulnerabilities.append("  - SMBv1 protocol usage (CVE-2017-0143-0148)")
                vulnerabilities.append("  - EternalBlue exploit potential (MS17-010)")
                vulnerabilities.append("  - Unauthenticated access to shares")
                if "Samba" in banner:
                    vulnerabilities.append("  - Check for SambaCry (CVE-2017-7494)")
                
            # Additional NetBIOS-related checks
            if port == 137 and "NetBIOS" in banner:
                vulnerabilities.append("NetBIOS Name Service exposed - possible hostname enumeration")
                
            if port == 139 and "SMB" in banner:
                vulnerabilities.append("NetBIOS Session Service running - check for legacy SMB configurations")

        return list(set(vulnerabilities))

#Service BruteForcer 
class BruteForcer:
    def __init__(self):
        self.reset_state()

    def reset_state(self):
        self.lock = threading.Lock()
        self.progress = 0
        self.total_tasks = 0
        self.scan_complete = False

    def _update_progress(self):
        bar_format = (
            f"{Fore.CYAN}{{desc}}: {{percentage:3.0f}}%|"
            f"{Fore.BLUE}{{bar}}{Style.RESET_ALL}| "
            f"{Fore.CYAN}{{n_fmt}}/{{total_fmt}} [{{elapsed}}<{{remaining}}, {{rate_fmt}}]{Style.RESET_ALL}"
        )

        with tqdm(
            total=self.total_tasks,
            desc=f"{Fore.CYAN}Brute Force Progress{Style.RESET_ALL}",
            bar_format=bar_format,
            position=0,
            leave=False,
            ascii=" █",
            dynamic_ncols=True
        ) as pbar:
            while self.progress < self.total_tasks and not self.scan_complete:
                pbar.n = self.progress
                pbar.refresh()
                time.sleep(0.1)
            pbar.close()

    def _validate_service(self, service):
        valid_services = ['ssh', 'ftp', 'telnet']
        if service.lower() not in valid_services:
            print(Fore.RED + "[!] Invalid service. Please choose SSH, FTP, or Telnet." + Style.RESET_ALL)
            return False
        return True

    def _get_yes_no(self, prompt):
        while True:
            response = get_input(prompt).strip().lower()
            if response in ('y', 'n'):
                return response == 'y'
            print(Fore.RED + "[!] Invalid choice. Please enter Y or N." + Style.RESET_ALL)

    def _get_input(self, prompt, validation_func=None):
        while True:
            user_input = get_input(prompt).strip()
            if not user_input:
                print(Fore.RED + "[!] get_input cannot be empty. Please provide a valid value." + Style.RESET_ALL)
                continue
            if validation_func and not validation_func(user_input):
                continue
            return user_input

    def _get_wordlist(self, prompt):
        while True:
            path = self._get_input(prompt)
            if not os.path.isfile(path):
                print(Fore.RED + "[!] File not found." + Style.RESET_ALL)
                continue
            with open(path, 'r') as f:
                if len(f.readlines()) == 0:
                    print(Fore.RED + "[!] Wordlist is empty." + Style.RESET_ALL)
                    continue
            return path

    def _get_port(self, service):
        default_port = 22 if service == 'ssh' else 21 if service == 'ftp' else 23
        while True:
            port_input = get_input(f"Port (default {default_port}): ").strip()
            if not port_input:
                return default_port
            if port_input.isdigit() and 1 <= int(port_input) <= 65535:
                return int(port_input)
            print(Fore.RED + "[!] Invalid port. Please enter a number between 1 and 65535." + Style.RESET_ALL)

    def ssh_bruteforce(self, target, username_or_wordlist, password_wordlist, port=22, timeout=5):
        progress_thread = None
        try:
            if os.path.isfile(username_or_wordlist):
                with open(username_or_wordlist, 'r') as user_file, open(password_wordlist, 'r') as pass_file:
                    usernames = [line.strip() for line in user_file]
                    passwords = [line.strip() for line in pass_file]
                    self.total_tasks = len(usernames) * len(passwords)
                    progress_thread = threading.Thread(target=self._update_progress, daemon=True)
                    progress_thread.start()

                    for username in usernames:
                        for password in passwords:
                            try:
                                ssh = paramiko.SSHClient()
                                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                ssh.connect(target, port=port, username=username, password=password, timeout=timeout)
                                tqdm.write(Fore.GREEN + f"\n[!] SSH Success: {username}:{password}" + Style.RESET_ALL)
                                ssh.close()
                                self.scan_complete = True
                                return (username, password)
                            except:
                                with self.lock:
                                    self.progress += 1
                                continue
            else:
                username = username_or_wordlist
                with open(password_wordlist, 'r') as f:
                    passwords = [line.strip() for line in f]
                    self.total_tasks = len(passwords)
                    progress_thread = threading.Thread(target=self._update_progress, daemon=True)
                    progress_thread.start()

                    for password in passwords:
                        try:
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(target, port=port, username=username, password=password, timeout=timeout)
                            tqdm.write(Fore.GREEN + f"\n[!] SSH Success: {username}:{password}" + Style.RESET_ALL)
                            ssh.close()
                            self.scan_complete = True
                            return (username, password)
                        except:
                            with self.lock:
                                self.progress += 1
                            continue
        finally:
            self.scan_complete = True
            if progress_thread and progress_thread.is_alive():
                progress_thread.join(timeout=1)
            print("\033[2K\r", end="")

    def ftp_bruteforce(self, target, username_or_wordlist, password_wordlist, port=21, timeout=5):
        progress_thread = None
        try:
            if os.path.isfile(username_or_wordlist):
                with open(username_or_wordlist, 'r') as user_file, open(password_wordlist, 'r') as pass_file:
                    usernames = [line.strip() for line in user_file]
                    passwords = [line.strip() for line in pass_file]
                    self.total_tasks = len(usernames) * len(passwords)
                    progress_thread = threading.Thread(target=self._update_progress, daemon=True)
                    progress_thread.start()

                    for username in usernames:
                        for password in passwords:
                            try:
                                ftp = ftplib.FTP()
                                ftp.connect(target, port, timeout=timeout)
                                ftp.login(username, password)
                                tqdm.write(f"\n[+] FTP Success: {username}:{password}")
                                ftp.quit()
                                self.scan_complete = True
                                return (username, password)
                            except:
                                with self.lock:
                                    self.progress += 1
                                continue
            else:
                username = username_or_wordlist
                with open(password_wordlist, 'r') as f:
                    passwords = [line.strip() for line in f]
                    self.total_tasks = len(passwords)
                    progress_thread = threading.Thread(target=self._update_progress, daemon=True)
                    progress_thread.start()

                    for password in passwords:
                        try:
                            ftp = ftplib.FTP()
                            ftp.connect(target, port, timeout=timeout)
                            ftp.login(username, password)
                            tqdm.write(f"\n[+] FTP Success: {username}:{password}")
                            ftp.quit()
                            self.scan_complete = True
                            return (username, password)
                        except:
                            with self.lock:
                                self.progress += 1
                            continue
        finally:
            self.scan_complete = True
            if progress_thread and progress_thread.is_alive():
                progress_thread.join(timeout=1)
            print("\033[2K\r", end="")

    def telnet_bruteforce(self, target, username_or_wordlist, password_wordlist, port=23, timeout=5):
        progress_thread = None
        try:
            if os.path.isfile(username_or_wordlist):
                with open(username_or_wordlist, 'r') as user_file, open(password_wordlist, 'r') as pass_file:
                    usernames = [line.strip() for line in user_file]
                    passwords = [line.strip() for line in pass_file]
                    self.total_tasks = len(usernames) * len(passwords)
                    progress_thread = threading.Thread(target=self._update_progress, daemon=True)
                    progress_thread.start()

                    for username in usernames:
                        for password in passwords:
                            try:
                                tn = telnetlib.Telnet(target, port=port, timeout=timeout)
                                tn.read_until(b"login: ")
                                tn.write(username.encode('ascii') + b"\n")
                                tn.read_until(b"Password: ")
                                tn.write(password.encode('ascii') + b"\n")
                                result = tn.expect([b"Login incorrect", b"Last login"], timeout=timeout)
                                if result[0] == 1:
                                    tqdm.write(f"\n[+] Telnet Success: {username}:{password}")
                                    tn.close()
                                    self.scan_complete = True
                                    return (username, password)
                                tn.close()
                            except:
                                with self.lock:
                                    self.progress += 1
                                continue
            else:
                username = username_or_wordlist
                with open(password_wordlist, 'r') as f:
                    passwords = [line.strip() for line in f]
                    self.total_tasks = len(passwords)
                    progress_thread = threading.Thread(target=self._update_progress, daemon=True)
                    progress_thread.start()

                    for password in passwords:
                        try:
                            tn = telnetlib.Telnet(target, port=port, timeout=timeout)
                            tn.read_until(b"login: ")
                            tn.write(username.encode('ascii') + b"\n")
                            tn.read_until(b"Password: ")
                            tn.write(password.encode('ascii') + b"\n")
                            result = tn.expect([b"Login incorrect", b"Last login"], timeout=timeout)
                            if result[0] == 1:
                                tqdm.write(f"\n[+] Telnet Success: {username}:{password}")
                                tn.close()
                                self.scan_complete = True
                                return (username, password)
                            tn.close()
                        except:
                            with self.lock:
                                self.progress += 1
                            continue
        finally:
            self.scan_complete = True
            if progress_thread and progress_thread.is_alive():
                progress_thread.join(timeout=1)
            print("\033[2K\r", end="")  

# WAF Scanner 
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

#Directory Bruteforcer
class DirectoryBruteforcer:
    def __init__(self, max_threads=10):
        self.max_threads = max_threads
        self.found = set()
        self.lock = threading.Lock()
        self.progress = 0
        self.total_tasks = 0
        self.scan_complete = False  

    def discover_directories(self, base_url, wordlist):
        # Color definitions
        BAR_COLOR = Fore.GREEN  # Progress bar color
        TEXT_COLOR = Fore.CYAN  # Text color (percentage)
        RESET = Style.RESET_ALL

        q = queue.Queue()

        
        with open(wordlist, 'r') as f:
            lines = [line.strip() for line in f]
            self.total_tasks = len(lines)
            for line in lines:
                q.put(line)

        
        bar_format = (
            f"{TEXT_COLOR}{{desc}}: {{percentage:3.0f}}%|"
            f"{BAR_COLOR}{{bar}}{RESET}| "
            f"{TEXT_COLOR}{{n_fmt}}/{{total_fmt}} [{{elapsed}}<{{remaining}}, {{rate_fmt}}]{RESET}"
        )

        
        progress_thread = threading.Thread(
            target=self._update_progress,
            args=(bar_format,),
            daemon=True
        )
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
                                tqdm.write(f"{Fore.RED}[!] Found: {url}{RESET}")
                except Exception as e:
                    pass
                finally:
                    with self.lock:
                        self.progress += 1
                    q.task_done()

        
        for _ in range(self.max_threads):
            threading.Thread(target=worker, daemon=True).start()

        
        q.join()
        self.scan_complete = True 

        
        while progress_thread.is_alive():
            time.sleep(0.1)

        return list(self.found)

    def _update_progress(self, bar_format):
        with tqdm(
            total=self.total_tasks,
            desc=f"{Fore.CYAN}Scan Progress{Style.RESET_ALL}",
            bar_format=bar_format,
            position=0,
            leave=False,  # True/False to keep or remove the progress bar after resutls
            ascii=" █",
            dynamic_ncols=True
        ) as pbar:
            while self.progress < self.total_tasks and not self.scan_complete:
                pbar.n = self.progress
                pbar.refresh()
                time.sleep(0.1)
            pbar.n = self.total_tasks
            pbar.refresh()

#Subdomain Bruteforcer
class SubdomainBruteforcer:
    def __init__(self, max_threads=10):
        self.max_threads = max_threads
        self.found = set()
        self.lock = threading.Lock()
        self.progress = 0
        self.total_tasks = 0
        self.scan_complete = False  

    def discover_subdomains(self, domain, wordlist):
        
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

        # Color definitions
        BAR_COLOR = Fore.GREEN
        TEXT_COLOR = Fore.CYAN
        RESET = Style.RESET_ALL

        q = queue.Queue()

        with open(wordlist, 'r') as f:
            lines = [line.strip().rstrip('.') for line in f if line.strip()]
            self.total_tasks = len(lines)
            for line in lines:
                q.put(line)

        
        bar_format = (
            f"{TEXT_COLOR}{{desc}}: {{percentage:3.0f}}%|"
            f"{BAR_COLOR}{{bar}}{RESET}| "
            f"{TEXT_COLOR}{{n_fmt}}/{{total_fmt}} [{{elapsed}}<{{remaining}}, {{rate_fmt}}]{RESET}"
        )

        
        progress_thread = threading.Thread(
            target=self._update_progress,
            args=(bar_format,),
            daemon=True
        )
        progress_thread.start()

        
        def worker():
            while not q.empty():
                sub = q.get()
                full_domain = f"{sub}.{domain}"
                try:
                    answers = dns.resolver.resolve(full_domain, 'A')
                    if answers:
                        with self.lock:
                            if full_domain not in self.found:
                                self.found.add(full_domain)
                                tqdm.write(f"{Fore.RED}[!] Found: {Fore.YELLOW}{full_domain}{RESET}")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception as e:
                    pass
                finally:
                    with self.lock:
                        self.progress += 1
                    q.task_done()

        
        for _ in range(self.max_threads):
            threading.Thread(target=worker, daemon=True).start()

        
        q.join()
        self.scan_complete = True  

        
        while progress_thread.is_alive():
            time.sleep(0.1)

        return list(self.found)

    def _update_progress(self, bar_format):
        with tqdm(
            total=self.total_tasks,
            desc=f"{Fore.CYAN}Subdomain Scan{Style.RESET_ALL}",
            bar_format=bar_format,
            position=0,
            leave=False,  # True/False to keep or remove the progress bar after resutls
            ascii=" █",
            dynamic_ncols=True
        ) as pbar:
            while self.progress < self.total_tasks and not self.scan_complete:
                pbar.n = self.progress
                pbar.refresh()
                time.sleep(0.1)
            pbar.n = self.total_tasks
            pbar.refresh()

#CMS Detector
class CMSDetector:
    def __init__(self):
        self.cms_signatures = {
            'WordPress': {
                'patterns': [
                    r'<meta name="generator" content="WordPress',
                    r'/wp-content/',
                    r'/wp-includes/',
                    r'wp-json'
                ],
                'files': ['wp-login.php', 'wp-admin/readme.html']
            },
            'Joomla': {
                'patterns': [
                    r'<meta name="generator" content="Joomla',
                    r'/media/system/js/',
                    r'/components/com_'
                ],
                'files': ['administrator/', 'joomla.inc.php']
            },
            'Drupal': {
                'patterns': [
                    r'<meta name="Generator" content="Drupal',
                    r'sites/all/modules/',
                    r'drupal.js'
                ],
                'files': ['CHANGELOG.txt', 'core/misc/drupal.js']
            },
            'Magento': {
                'patterns': [
                    r'Magento',
                    r'var Mage =',
                    r'/skin/frontend/'
                ],
                'files': ['js/mage/', 'app/Mage.php']
            },
            'Shopify': {
                'patterns': [
                    r'shopify-checkout-button',
                    r'shopify-analytics'
                ],
                'headers': ['x-shopid', 'x-shopify-stage']
            }
        }

    def detect_cms(self, url):
        try:
            session = requests.Session()
            response = session.get(url, timeout=10, verify=False)
            content = response.text
            headers = response.headers
            
            detected = []
            
            for cms, data in self.cms_signatures.items():
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in data.get('patterns', [])):
                    detected.append(cms)
                
                if any(header.lower() in (h.lower() for h in headers.keys()) 
                       for header in data.get('headers', [])):
                    detected.append(cms)
            
            for cms, data in self.cms_signatures.items():
                for file_path in data.get('files', []):
                    try:
                        file_url = urljoin(url, file_path)
                        file_response = session.head(file_path, timeout=5)
                        if file_response.status_code == 200:
                            detected.append(cms)
                    except:
                        continue
            
            version = self._get_cms_version(content, detected)
            
            return list(set(detected)), version
        except Exception as e:
            return [], None

    def _get_cms_version(self, content, detected_cms):
        version_patterns = {
            'WordPress': r'content="WordPress (\d+\.\d+\.\d+)',
            'Joomla': r'content="Joomla! (\d+\.\d+)',
            'Drupal': r'content="Drupal (\d+) \((\d+\.\d+\.\d+)\)'
        }
        
        for cms in detected_cms:
            if cms in version_patterns:
                match = re.search(version_patterns[cms], content)
                if match:
                    return match.group(1)
        return None

# Asci art main
def strip_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)

def center_text(text, padding_char=' '):
    term_width = os.get_terminal_size().columns
    lines = text.split('\n')
    centered = []
    
    for line in lines:
        stripped = strip_ansi(line)
        padding = (term_width - len(stripped)) // 2
        if padding > 0:
            centered_line = padding_char * padding + line
        else:
            centered_line = line
        centered.append(centered_line)
    
    return '\n'.join(centered)

def show_banner():
    banner = Fore.CYAN + r"""
  /$$$$$$  /$$$$$$$   /$$$$$$  /$$$$$$$  /$$$$$$$$ /$$$$$$  /$$$$$$  /$$$$$$$$ /$$$$$$  /$$$$$$ 
 /$$__  $$| $$__  $$ /$$__  $$| $$__  $$|__  $$__/|_  $$_/ /$$__  $$|__  $$__/|_  $$_/ /$$__  $$
| $$  \__/| $$  \ $$| $$  \ $$| $$  \ $$   | $$     | $$  | $$  \ $$   | $$     | $$  | $$  \__/
|  $$$$$$ | $$$$$$$/| $$$$$$$$| $$$$$$$/   | $$     | $$  | $$$$$$$$   | $$     | $$  |  $$$$$$ 
 \____  $$| $$____/ | $$__  $$| $$__  $$   | $$     | $$  | $$__  $$   | $$     | $$   \____  $$
 /$$  \ $$| $$      | $$  | $$| $$  \ $$   | $$     | $$  | $$  | $$   | $$     | $$   /$$  \ $$
|  $$$$$$/| $$      | $$  | $$| $$  | $$   | $$    /$$$$$$| $$  | $$   | $$    /$$$$$$|  $$$$$$/
 \______/ |__/      |__/  |__/|__/  |__/   |__/   |______/|__/  |__/   |__/   |______/ \______/ 

                                                                                            
    """ + Fore.YELLOW + "Spartiatis the Hellenic enumeration Pentest Toolkit" + Style.RESET_ALL
    version = Fore.CYAN + "Version:" + Fore.RED + "1.0" + Style.RESET_ALL
    authors = Fore.MAGENTA  + "github.com/billidev200/SpartiatisToolkit" + Style.RESET_ALL
    warning = Fore.RED + "WARNING: Use only on authorized systems!" + Style.RESET_ALL
    commands = Fore.GREEN + "Commands: Exit" + Style.RESET_ALL
    
    print(center_text(banner))
    print(center_text(version))
    print(center_text(authors))
    print(center_text(warning))
    print(center_text(commands))

if __name__ == "__main__":
    main()