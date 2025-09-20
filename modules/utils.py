"""
Utility classes and functions for ABD
"""

import logging
import json
import os
from datetime import datetime
from colorama import Fore, Style


class Logger:
    """Enhanced logging class with colored output"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('abd.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def set_verbose(self, verbose):
        """Set verbose mode"""
        self.verbose = verbose
        
    def info(self, message):
        """Log info message"""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")
        self.logger.info(message)
        
    def success(self, message):
        """Log success message"""
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
        self.logger.info(f"SUCCESS: {message}")
        
    def warning(self, message):
        """Log warning message"""
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
        self.logger.warning(message)
        
    def error(self, message):
        """Log error message"""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
        self.logger.error(message)
        
    def debug(self, message):
        """Log debug message"""
        if self.verbose:
            print(f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL} {message}")
            self.logger.debug(message)


class Config:
    """Configuration management class"""
    
    def __init__(self, config_file=None):
        self.config = self.load_default_config()
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
            
    def load_default_config(self):
        """Load default configuration"""
        return {
            'output_dir': 'output',
            'timeout': 30,
            'threads': 10,
            'user_agent': 'ABD/1.0 Security Scanner',
            'subdomain_wordlist': 'wordlists/subdomains.txt',
            'ports': [80, 443, 8080, 8443, 3000, 5000, 8000, 9000],
            'vulnerable_ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5985, 5986],
            'payloads': {
                'xss': ['<script>alert(1)</script>', '"><script>alert(1)</script>', "';alert(1);//"],
                'sqli': ["'", "' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users--"],
                'lfi': ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'],
                'rce': ['id', 'whoami', 'cat /etc/passwd']
            }
        }
        
    def load_config(self, config_file):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                self.config.update(user_config)
        except Exception as e:
            print(f"Error loading config file: {e}")
            
    def get(self, key, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
        
    def set(self, key, value):
        """Set configuration value"""
        self.config[key] = value


class ReportGenerator:
    """Generate formatted reports"""
    
    def __init__(self, results, logger):
        self.results = results
        self.logger = logger
        
    def generate_html_report(self, output_file):
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>ABD Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .stage { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }
        .vulnerability { background: #ffe6e6; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .success { color: #27ae60; }
        .error { color: #e74c3c; }
        .warning { color: #f39c12; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ABD Security Assessment Report</h1>
        <p>Target: {target}</p>
        <p>Generated: {timestamp}</p>
    </div>
    
    {content}
</body>
</html>
        """
        
        content = ""
        for stage_name, stage_data in self.results.get('stages', {}).items():
            content += f"""
            <div class="stage">
                <h2>Stage: {stage_name.title()}</h2>
                <p>Status: <span class="{'success' if stage_data.get('success') else 'error'}">{stage_data.get('status', 'Unknown')}</span></p>
                <pre>{json.dumps(stage_data, indent=2)}</pre>
            </div>
            """
            
        html_content = html_template.format(
            target=self.results.get('target', 'Unknown'),
            timestamp=self.results.get('timestamp', 'Unknown'),
            content=content
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
            
        self.logger.success(f"HTML report generated: {output_file}")


class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def is_valid_domain(domain):
        """Check if domain is valid"""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, domain) is not None
        
    @staticmethod
    def is_valid_ip(ip):
        """Check if IP is valid"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    @staticmethod
    def resolve_domain(domain):
        """Resolve domain to IP"""
        import socket
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None


class FileUtils:
    """File utility functions"""
    
    @staticmethod
    def create_wordlist_if_not_exists():
        """Create default wordlist files if they don't exist"""
        os.makedirs('wordlists', exist_ok=True)
        
        subdomain_wordlist = 'wordlists/subdomains.txt'
        if not os.path.exists(subdomain_wordlist):
            subdomains = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'cdn',
                'app', 'blog', 'shop', 'store', 'support', 'help', 'docs', 'secure',
                'vpn', 'remote', 'portal', 'login', 'dashboard', 'panel', 'cpanel',
                'webmail', 'mx', 'ns1', 'ns2', 'dns', 'sub', 'subdomain', 'old',
                'new', 'beta', 'alpha', 'demo', 'sandbox', 'staging', 'production'
            ]
            
            with open(subdomain_wordlist, 'w') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")