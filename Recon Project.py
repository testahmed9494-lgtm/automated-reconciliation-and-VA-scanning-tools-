#!/usr/bin/env python3
"""
Recon Automation Tool - For authorized security testing only
Author: S M Ishtiaque Ahmed
Purpose: Automated reconnaissance for penetration testing
"""

import argparse
import subprocess
import socket
import dns.resolver
import requests
import whois
import shodan
import ssl
import json
import csv
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import urllib3
from urllib.parse import urlparse

# Initialize colorama
init(autoreset=True)

class ReconAutomation:
    def __init__(self, target, output_dir=None, threads=20, timeout=5):
        self.target = target
        self.output_dir = output_dir or f"recon_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.threads = threads
        self.timeout = timeout
        self.results = {
            'subdomains': [],
            'open_ports': [],
            'dns_info': {},
            'whois_info': {},
            'http_headers': {},
            'technologies': {},
            'ssl_info': {}
        }
        
        # Create output directory
        subprocess.run(['mkdir', '-p', self.output_dir])
        
    def log_message(self, message, level="INFO"):
        """Print colored log messages"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "DEBUG": Fore.MAGENTA
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, Fore.WHITE)}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
        
    def save_results(self):
        """Save results to various formats"""
        # Save as JSON
        json_file = f"{self.output_dir}/recon_results.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        self.log_message(f"Results saved to {json_file}", "SUCCESS")
        
        # Save as CSV
        csv_file = f"{self.output_dir}/subdomains.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Subdomain', 'IP Address', 'Status'])
            for sub in self.results['subdomains']:
                writer.writerow([sub.get('domain', ''), sub.get('ip', ''), sub.get('status', '')])
                
    def resolve_domain(self, domain):
        """Resolve domain to IP address"""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None
            
    def enumerate_subdomains(self):
        """Enumerate subdomains using various techniques"""
        self.log_message("Starting subdomain enumeration...", "INFO")
        
        # Common subdomains wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'blog', 'shop',
            'test', 'dev', 'staging', 'admin', 'portal', 'dashboard', 'app', 'secure',
            'vpn', 'remote', 'mysql', 'db', 'database', 'cloud', 'server', 'mx'
        ]
        
        subdomains_found = []
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{self.target}"
            ip = self.resolve_domain(full_domain)
            if ip:
                subdomains_found.append({
                    'domain': full_domain,
                    'ip': ip,
                    'status': 'resolved'
                })
                self.log_message(f"Found: {full_domain} -> {ip}", "SUCCESS")
        
        # Use thread pool for faster enumeration
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_subdomain, common_subdomains)
            
        self.results['subdomains'] = subdomains_found
        self.log_message(f"Found {len(subdomains_found)} subdomains", "SUCCESS")
        
    def scan_ports(self, ports=None):
        """Scan common ports on target"""
        self.log_message("Starting port scanning...", "INFO")
        
        if not ports:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                           993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        else:
            common_ports = ports
            
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    service = self.get_service_name(port)
                    open_ports.append({'port': port, 'service': service})
                    self.log_message(f"Port {port}/{service} is open", "SUCCESS")
                sock.close()
            except:
                pass
                
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(scan_port, common_ports)
            
        self.results['open_ports'] = open_ports
        self.log_message(f"Found {len(open_ports)} open ports", "SUCCESS")
        
    def get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
            3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
        
    def dns_enumeration(self):
        """Perform DNS enumeration"""
        self.log_message("Starting DNS enumeration...", "INFO")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        dns_info = {}
        
        for record in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record)
                dns_info[record] = [str(rdata) for rdata in answers]
                self.log_message(f"Found {record} records: {dns_info[record]}", "INFO")
            except Exception as e:
                dns_info[record] = []
                
        self.results['dns_info'] = dns_info
        
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        self.log_message("Performing WHOIS lookup...", "INFO")
        
        try:
            domain_info = whois.whois(self.target)
            self.results['whois_info'] = {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers': domain_info.name_servers,
                'emails': domain_info.emails
            }
            self.log_message("WHOIS lookup completed", "SUCCESS")
        except Exception as e:
            self.log_message(f"WHOIS lookup failed: {e}", "ERROR")
            
    def http_headers_analysis(self):
        """Analyze HTTP headers for security misconfigurations"""
        self.log_message("Analyzing HTTP headers...", "INFO")
        
        urls = [
            f"http://{self.target}",
            f"https://{self.target}"
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                headers = dict(response.headers)
                self.results['http_headers'][url] = headers
                
                # Security header analysis
                security_headers = [
                    'Strict-Transport-Security', 'Content-Security-Policy',
                    'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection'
                ]
                
                missing_headers = [h for h in security_headers if h not in headers]
                if missing_headers:
                    self.log_message(f"Missing security headers on {url}: {missing_headers}", "WARNING")
                    
                self.log_message(f"Analyzed headers for {url}", "SUCCESS")
            except Exception as e:
                self.log_message(f"Failed to get headers for {url}: {e}", "ERROR")
                
    def technology_detection(self):
        """Detect web technologies being used"""
        self.log_message("Detecting web technologies...", "INFO")
        
        try:
            response = requests.get(f"https://{self.target}", timeout=self.timeout, verify=False)
            headers = response.headers
            content = response.text.lower()
            
            # Simple technology detection
            techs = []
            
            # Server detection
            if 'server' in headers:
                techs.append(f"Server: {headers['server']}")
                
            # Framework detection
            frameworks = {
                'wordpress': '/wp-content/', 'drupal': 'drupal', 'laravel': 'laravel',
                'django': 'csrfmiddlewaretoken', 'rails': 'csrf-param', 'express': 'x-powered-by: express'
            }
            
            for framework, indicator in frameworks.items():
                if indicator in content or indicator in str(headers):
                    techs.append(framework)
                    
            # CMS detection
            cms_indicators = {
                'WordPress': 'wp-content', 'Joomla': 'joomla', 'Drupal': 'drupal',
                'Magento': 'magento', 'Shopify': 'shopify'
            }
            
            for cms, indicator in cms_indicators.items():
                if indicator in content:
                    techs.append(cms)
                    
            self.results['technologies'] = techs
            self.log_message(f"Detected technologies: {techs}", "SUCCESS")
        except Exception as e:
            self.log_message(f"Technology detection failed: {e}", "ERROR")
            
    def ssl_certificate_analysis(self):
        """Analyze SSL/TLS certificate"""
        self.log_message("Analyzing SSL certificate...", "INFO")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results['ssl_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName')
                    }
                    self.log_message("SSL certificate analysis completed", "SUCCESS")
        except Exception as e:
            self.log_message(f"SSL analysis failed: {e}", "ERROR")
            
    def directory_bruteforce(self, wordlist=None):
        """Basic directory bruteforce (use with caution)"""
        self.log_message("Starting directory bruteforce (light mode)...", "WARNING")
        
        common_dirs = ['admin', 'login', 'wp-admin', 'admin/login', 'phpmyadmin', 
                      'backup', 'config', 'uploads', 'images', 'css', 'js', 'api']
        
        found_dirs = []
        
        for directory in common_dirs:
            try:
                url = f"https://{self.target}/{directory}"
                response = requests.get(url, timeout=self.timeout, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    found_dirs.append({
                        'path': directory,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
                    self.log_message(f"Found: {url} (Status: {response.status_code})", "SUCCESS")
            except:
                pass
                
        self.results['directories'] = found_dirs
        
    def generate_report(self):
        """Generate a detailed HTML report"""
        html_file = f"{self.output_dir}/recon_report.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Recon Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
                .section {{ background: white; margin: 20px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .info {{ color: #0066cc; }}
                .success {{ color: #00cc66; }}
                .warning {{ color: #ff9900; }}
                .error {{ color: #ff3300; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:hover {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <h1>Reconnaissance Report</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="section">
                <h2>Subdomains Found ({len(self.results.get('subdomains', []))})</h2>
                <table>
                    <tr><th>Subdomain</th><th>IP Address</th></tr>
                    {''.join([f"<tr><td>{s['domain']}</td><td>{s.get('ip', 'N/A')}</td></tr>" for s in self.results.get('subdomains', [])])}
                </table>
            </div>
            
            <div class="section">
                <h2>Open Ports ({len(self.results.get('open_ports', []))})</h2>
                <table>
                    <tr><th>Port</th><th>Service</th></tr>
                    {''.join([f"<tr><td>{p['port']}</td><td>{p['service']}</td></tr>" for p in self.results.get('open_ports', [])])}
                </table>
            </div>
            
            <div class="section">
                <h2>DNS Information</h2>
                <pre>{json.dumps(self.results.get('dns_info', {}), indent=2)}</pre>
            </div>
            
            <div class="section">
                <h2>Technologies Detected</h2>
                <ul>
                    {''.join([f"<li>{tech}</li>" for tech in self.results.get('technologies', [])])}
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        self.log_message(f"HTML report generated: {html_file}", "SUCCESS")
        
    def run_full_recon(self):
        """Execute all reconnaissance modules"""
        self.log_message(f"Starting full reconnaissance on {self.target}", "INFO")
        start_time = time.time()
        
        # Run all modules
        self.enumerate_subdomains()
        self.dns_enumeration()
        self.whois_lookup()
        self.scan_ports()
        self.http_headers_analysis()
        self.technology_detection()
        self.ssl_certificate_analysis()
        self.directory_bruteforce()
        
        # Save results
        self.save_results()
        self.generate_report()
        
        elapsed_time = time.time() - start_time
        self.log_message(f"Reconnaissance completed in {elapsed_time:.2f} seconds", "SUCCESS")
        
def main():
    parser = argparse.ArgumentParser(description='Recon Automation Tool - For authorized security testing only')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-T', '--timeout', type=int, default=5, help='Timeout in seconds (default: 5)')
    parser.add_argument('--ports', help='Comma-separated list of ports to scan')
    
    args = parser.parse_args()
    
    # Disclaimer
    print(Fore.RED + """
    ╔══════════════════════════════════════════════════════════════╗
    ║                     LEGAL DISCLAIMER                          ║
    ║  This tool is for educational and authorized security       ║
    ║  testing purposes only. Use only on systems you own         ║
    ║  or have explicit permission to test. Unauthorized use      ║
    ║  may violate laws and regulations.                          ║
    ╚══════════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    
    confirm = input("Do you have permission to test this target? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Exiting...")
        return
        
    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
        
    recon = ReconAutomation(args.target, args.output, args.threads, args.timeout)
    recon.run_full_recon()
    
if __name__ == "__main__":
    main()
