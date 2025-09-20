"""
Stage 2: Reconnaissance
- Subdomain enumeration
- Port scanning
- Service detection
- Technology fingerprinting
- Information gathering
"""

import os
import socket
import subprocess
import threading
import time
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from .utils import NetworkUtils


class ReconnaissanceStage:
    """Stage 2: Reconnaissance"""
    
    def __init__(self, target, config, logger):
        self.target = target
        self.config = config
        self.logger = logger
        self.results = {
            'stage': 'reconnaissance',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'status': 'Starting reconnaissance...',
            'subdomains': [],
            'ports': {},
            'services': {},
            'technology': {},
            'dns_info': {},
            'http_info': {}
        }
        
    def dns_enumeration(self):
        """Perform DNS enumeration"""
        self.logger.info("Performing DNS enumeration...")
        
        dns_info = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': []
        }
        
        # Common DNS record types to query
        record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                # Use dig command if available
                cmd = ['dig', '+short', record_type, self.target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                    dns_info[f'{record_type.lower()}_records'] = records
                    self.logger.debug(f"Found {len(records)} {record_type} records")
                    
            except subprocess.TimeoutExpired:
                self.logger.warning(f"DNS query for {record_type} records timed out")
            except FileNotFoundError:
                # Fallback to Python DNS resolution for A records
                if record_type == 'A':
                    try:
                        ip = socket.gethostbyname(self.target)
                        dns_info['a_records'] = [ip]
                    except socket.gaierror:
                        pass
            except Exception as e:
                self.logger.debug(f"DNS enumeration error for {record_type}: {e}")
                
        self.results['dns_info'] = dns_info
        return dns_info
        
    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        self.logger.info("Starting subdomain enumeration...")
        
        subdomains = []
        wordlist_path = self.config.get('subdomain_wordlist', 'wordlists/subdomains.txt')
        
        if not os.path.exists(wordlist_path):
            self.logger.warning(f"Wordlist not found: {wordlist_path}")
            return subdomains
            
        # Read wordlist
        try:
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"Error reading wordlist: {e}")
            return subdomains
            
        self.logger.info(f"Testing {len(wordlist)} subdomain candidates...")
        
        # Thread function for subdomain testing
        def test_subdomain(subdomain):
            test_domain = f"{subdomain}.{self.target}"
            try:
                ip = socket.gethostbyname(test_domain)
                return {
                    'subdomain': test_domain,
                    'ip': ip,
                    'found': True
                }
            except socket.gaierror:
                return None
                
        # Use threading for faster enumeration
        max_threads = self.config.get('threads', 10)
        found_subdomains = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(test_subdomain, sub) for sub in wordlist]
            
            for future in futures:
                try:
                    result = future.result(timeout=5)
                    if result:
                        found_subdomains.append(result)
                        self.logger.success(f"Found subdomain: {result['subdomain']} -> {result['ip']}")
                except Exception as e:
                    self.logger.debug(f"Subdomain test error: {e}")
                    
        self.results['subdomains'] = found_subdomains
        self.logger.info(f"Found {len(found_subdomains)} subdomains")
        return found_subdomains
        
    def port_scanning(self):
        """Perform port scanning"""
        self.logger.info("Starting port scanning...")
        
        target_ip = self.results.get('dns_info', {}).get('a_records', [])
        if not target_ip:
            # Try to resolve target directly
            try:
                target_ip = [socket.gethostbyname(self.target)]
            except socket.gaierror:
                self.logger.error("Could not resolve target for port scanning")
                return {}
                
        ip = target_ip[0]
        ports_to_scan = self.config.get('vulnerable_ports', [80, 443, 22, 21, 25, 53, 110, 143, 993, 995])
        
        self.logger.info(f"Scanning {len(ports_to_scan)} ports on {ip}...")
        
        open_ports = {}
        
        def scan_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    return port
            except Exception:
                pass
            return None
            
        # Scan ports with threading
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, ip, port) for port in ports_to_scan]
            
            for future in futures:
                try:
                    result = future.result(timeout=5)
                    if result:
                        open_ports[result] = {
                            'state': 'open',
                            'service': self.identify_service(result)
                        }
                        self.logger.success(f"Found open port: {result}")
                except Exception as e:
                    self.logger.debug(f"Port scan error: {e}")
                    
        self.results['ports'] = open_ports
        self.logger.info(f"Found {len(open_ports)} open ports")
        return open_ports
        
    def identify_service(self, port):
        """Identify service running on port"""
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5985: 'WinRM',
            5986: 'WinRM-HTTPS'
        }
        
        return common_services.get(port, 'Unknown')
        
    def service_detection(self):
        """Detect services and versions"""
        self.logger.info("Performing service detection...")
        
        services = {}
        open_ports = self.results.get('ports', {})
        
        for port, port_info in open_ports.items():
            service_info = {
                'port': port,
                'service': port_info.get('service', 'Unknown'),
                'version': 'Unknown',
                'banner': None
            }
            
            # Try to grab banner
            try:
                target_ip = self.results.get('dns_info', {}).get('a_records', [])
                if target_ip:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target_ip[0], port))
                    
                    # Send HTTP request for web services
                    if port in [80, 443, 8080, 8443]:
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if banner:
                        service_info['banner'] = banner.strip()
                        # Extract server information from HTTP headers
                        if 'Server:' in banner:
                            server_line = [line for line in banner.split('\n') if 'Server:' in line]
                            if server_line:
                                service_info['version'] = server_line[0].split('Server:')[1].strip()
                                
            except Exception as e:
                self.logger.debug(f"Banner grab failed for port {port}: {e}")
                
            services[port] = service_info
            
        self.results['services'] = services
        return services
        
    def technology_fingerprinting(self):
        """Fingerprint web technologies"""
        self.logger.info("Fingerprinting web technologies...")
        
        technology = {
            'web_server': 'Unknown',
            'frameworks': [],
            'cms': 'Unknown',
            'technologies': [],
            'headers': {}
        }
        
        # Check for web services
        web_ports = [port for port in self.results.get('ports', {}) if port in [80, 443, 8080, 8443]]
        
        for port in web_ports:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{self.target}:{port}" if port not in [80, 443] else f"{protocol}://{self.target}"
                
                headers = {
                    'User-Agent': self.config.get('user_agent', 'ABD/1.0 Security Scanner')
                }
                
                response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
                
                # Analyze headers
                response_headers = dict(response.headers)
                technology['headers'].update(response_headers)
                
                # Identify web server
                server = response_headers.get('Server', '').lower()
                if 'apache' in server:
                    technology['web_server'] = 'Apache'
                elif 'nginx' in server:
                    technology['web_server'] = 'Nginx'
                elif 'iis' in server:
                    technology['web_server'] = 'IIS'
                elif 'cloudflare' in server:
                    technology['web_server'] = 'Cloudflare'
                    
                # Check for common technologies in headers
                if 'X-Powered-By' in response_headers:
                    technology['technologies'].append(response_headers['X-Powered-By'])
                    
                # Analyze response content for CMS detection
                content = response.text.lower()
                
                if 'wp-content' in content or 'wordpress' in content:
                    technology['cms'] = 'WordPress'
                elif 'joomla' in content:
                    technology['cms'] = 'Joomla'
                elif 'drupal' in content:
                    technology['cms'] = 'Drupal'
                    
                # Check for common frameworks
                if 'django' in content:
                    technology['frameworks'].append('Django')
                elif 'laravel' in content:
                    technology['frameworks'].append('Laravel')
                elif 'rails' in content:
                    technology['frameworks'].append('Ruby on Rails')
                    
                break  # Only check first working web service
                
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Technology fingerprinting failed for {url}: {e}")
            except Exception as e:
                self.logger.debug(f"Technology fingerprinting error: {e}")
                
        self.results['technology'] = technology
        return technology
        
    def http_information_gathering(self):
        """Gather HTTP-specific information"""
        self.logger.info("Gathering HTTP information...")
        
        http_info = {
            'status_codes': {},
            'redirects': [],
            'cookies': {},
            'security_headers': {},
            'interesting_paths': []
        }
        
        # Common paths to check
        paths_to_check = [
            '/', '/admin', '/login', '/dashboard', '/api', '/robots.txt',
            '/sitemap.xml', '/.git', '/.env', '/backup', '/test'
        ]
        
        web_ports = [port for port in self.results.get('ports', {}) if port in [80, 443, 8080, 8443]]
        
        for port in web_ports:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                base_url = f"{protocol}://{self.target}:{port}" if port not in [80, 443] else f"{protocol}://{self.target}"
                
                for path in paths_to_check:
                    try:
                        url = base_url + path
                        headers = {
                            'User-Agent': self.config.get('user_agent', 'ABD/1.0 Security Scanner')
                        }
                        
                        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                        
                        http_info['status_codes'][path] = response.status_code
                        
                        if response.status_code in [200, 301, 302, 403]:
                            http_info['interesting_paths'].append({
                                'path': path,
                                'status_code': response.status_code,
                                'content_length': len(response.content)
                            })
                            
                        # Check for security headers
                        security_headers = [
                            'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                            'Strict-Transport-Security', 'Content-Security-Policy'
                        ]
                        
                        for header in security_headers:
                            if header in response.headers:
                                http_info['security_headers'][header] = response.headers[header]
                                
                        # Check cookies
                        if response.cookies:
                            for cookie in response.cookies:
                                http_info['cookies'][cookie.name] = {
                                    'value': cookie.value,
                                    'secure': cookie.secure,
                                    'httponly': 'HttpOnly' in str(cookie)
                                }
                                
                    except requests.exceptions.RequestException:
                        pass
                    except Exception as e:
                        self.logger.debug(f"HTTP info gathering error for {path}: {e}")
                        
                break  # Only check first working web service
                
            except Exception as e:
                self.logger.debug(f"HTTP info gathering error: {e}")
                
        self.results['http_info'] = http_info
        return http_info
        
    def execute(self):
        """Execute the reconnaissance stage"""
        self.logger.info("═══ STAGE 2: RECONNAISSANCE ═══")
        
        try:
            # Step 1: DNS enumeration
            self.dns_enumeration()
            
            # Step 2: Subdomain enumeration
            self.subdomain_enumeration()
            
            # Step 3: Port scanning
            self.port_scanning()
            
            # Step 4: Service detection
            self.service_detection()
            
            # Step 5: Technology fingerprinting
            self.technology_fingerprinting()
            
            # Step 6: HTTP information gathering
            self.http_information_gathering()
            
            # Mark as successful
            self.results['success'] = True
            self.results['status'] = 'Reconnaissance completed successfully'
            
            # Summary
            subdomain_count = len(self.results['subdomains'])
            port_count = len(self.results['ports'])
            service_count = len(self.results['services'])
            
            self.logger.success(f"Reconnaissance completed: {subdomain_count} subdomains, {port_count} open ports, {service_count} services detected")
            
        except Exception as e:
            self.results['status'] = f'Reconnaissance failed: {str(e)}'
            self.logger.error(f"Reconnaissance stage failed: {e}")
            
        return self.results