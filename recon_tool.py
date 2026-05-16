#!/usr/bin/env python3
"""
Recon Automation Tool - For authorized security testing only
Author: S M Ishtiaque Ahmed
Purpose: Automated reconnaissance for penetration testing
Version: 1.0.0
"""

import argparse
import os
import socket
import ssl
import json
import csv
import time
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
import requests
import urllib3
import dns.resolver
import whois

# Initialize colorama
init(autoreset=True)

# Suppress insecure request warnings (SSL verify=False) with a single notice
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 5

COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
    'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api',
    'blog', 'shop', 'test', 'dev', 'staging', 'admin', 'portal', 'dashboard',
    'app', 'secure', 'vpn', 'remote', 'mysql', 'db', 'database', 'cloud',
    'server', 'mx',
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
]

PORT_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
}

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
]

DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

COMMON_DIRS = [
    'admin', 'login', 'wp-admin', 'admin/login', 'phpmyadmin',
    'backup', 'config', 'uploads', 'images', 'css', 'js', 'api',
]

FRAMEWORK_INDICATORS = {
    'WordPress': '/wp-content/',
    'Drupal': 'drupal',
    'Laravel': 'laravel',
    'Django': 'csrfmiddlewaretoken',
    'Rails': 'csrf-param',
}

CMS_INDICATORS = {
    'WordPress': 'wp-content',
    'Joomla': 'joomla',
    'Drupal': 'drupal',
    'Magento': 'magento',
    'Shopify': 'shopify',
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ReconAutomation:
    """Automated reconnaissance tool for authorized penetration testing."""

    def __init__(self, target: str, output_dir: str = None,
                 threads: int = DEFAULT_THREADS, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialise the recon engine.

        Args:
            target:     Domain name or IP address to scan.
            output_dir: Directory where results will be saved.
                        Defaults to recon_<target>_<timestamp>.
            threads:    Maximum worker threads for concurrent tasks.
            timeout:    Network timeout in seconds.
        """
        self.target = target
        self.output_dir = output_dir or f"recon_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.threads = threads
        self.timeout = timeout
        self.results: dict = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'subdomains': [],
            'open_ports': [],
            'dns_info': {},
            'whois_info': {},
            'http_headers': {},
            'technologies': [],
            'ssl_info': {},
            'directories': [],
        }

        os.makedirs(self.output_dir, exist_ok=True)

        # File logger so results are also written to disk
        log_path = os.path.join(self.output_dir, 'recon.log')
        logging.basicConfig(
            filename=log_path,
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
        )

    # ------------------------------------------------------------------
    # Logging helper
    # ------------------------------------------------------------------

    def log(self, message: str, level: str = "INFO") -> None:
        """Print a colour-coded console message and write to the log file."""
        colours = {
            "INFO":    Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR":   Fore.RED,
            "DEBUG":   Fore.MAGENTA,
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        colour = colours.get(level, Fore.WHITE)
        print(f"{colour}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
        getattr(logging, level.lower(), logging.info)(message)

    # ------------------------------------------------------------------
    # Subdomain enumeration
    # ------------------------------------------------------------------

    def enumerate_subdomains(self) -> None:
        """Enumerate subdomains by resolving common prefix + target combinations."""
        self.log("Starting subdomain enumeration...", "INFO")
        subdomains_found = []

        def check_subdomain(prefix: str) -> None:
            full_domain = f"{prefix}.{self.target}"
            try:
                ip = socket.gethostbyname(full_domain)
                subdomains_found.append({
                    'domain': full_domain,
                    'ip': ip,
                    'status': 'resolved',
                })
                self.log(f"Found: {full_domain} -> {ip}", "SUCCESS")
            except socket.gaierror:
                pass  # Domain does not resolve — expected for most prefixes

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_subdomain, COMMON_SUBDOMAINS)

        self.results['subdomains'] = subdomains_found
        self.log(f"Subdomain enumeration complete — {len(subdomains_found)} found.", "SUCCESS")

    # ------------------------------------------------------------------
    # Port scanning
    # ------------------------------------------------------------------

    def scan_ports(self, ports: list = None) -> None:
        """
        Scan the target for open TCP ports.

        Args:
            ports: List of port numbers to scan.
                   Defaults to COMMON_PORTS if not provided.
        """
        self.log("Starting port scan...", "INFO")
        ports_to_scan = ports if ports else COMMON_PORTS
        open_ports = []

        def scan_port(port: int) -> None:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    if sock.connect_ex((self.target, port)) == 0:
                        service = PORT_SERVICES.get(port, 'Unknown')
                        open_ports.append({'port': port, 'service': service})
                        self.log(f"Port {port}/{service} is open", "SUCCESS")
            except OSError as exc:
                self.log(f"Socket error on port {port}: {exc}", "DEBUG")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(scan_port, ports_to_scan)

        self.results['open_ports'] = open_ports
        self.log(f"Port scan complete — {len(open_ports)} open ports found.", "SUCCESS")

    # ------------------------------------------------------------------
    # DNS enumeration
    # ------------------------------------------------------------------

    def dns_enumeration(self) -> None:
        """Query common DNS record types for the target domain."""
        self.log("Starting DNS enumeration...", "INFO")
        dns_info = {}

        for record_type in DNS_RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                dns_info[record_type] = [str(r) for r in answers]
                self.log(f"{record_type} records: {dns_info[record_type]}", "INFO")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dns_info[record_type] = []
            except dns.exception.DNSException as exc:
                self.log(f"DNS query failed for {record_type}: {exc}", "WARNING")
                dns_info[record_type] = []

        self.results['dns_info'] = dns_info
        self.log("DNS enumeration complete.", "SUCCESS")

    # ------------------------------------------------------------------
    # WHOIS lookup
    # ------------------------------------------------------------------

    def whois_lookup(self) -> None:
        """Fetch WHOIS registration information for the target domain."""
        self.log("Performing WHOIS lookup...", "INFO")
        try:
            domain_info = whois.whois(self.target)
            self.results['whois_info'] = {
                'registrar':       domain_info.registrar,
                'creation_date':   str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers':    domain_info.name_servers,
                'emails':          domain_info.emails,
            }
            self.log("WHOIS lookup complete.", "SUCCESS")
        except Exception as exc:
            self.log(f"WHOIS lookup failed: {exc}", "ERROR")

    # ------------------------------------------------------------------
    # HTTP header analysis
    # ------------------------------------------------------------------

    def http_headers_analysis(self) -> None:
        """
        Retrieve HTTP response headers and flag missing security headers.

        Note: SSL certificate verification is intentionally disabled here
        because recon targets may have self-signed or expired certificates.
        Never disable verification in production applications.
        """
        self.log("Analysing HTTP headers...", "INFO")
        self.log("SSL verification disabled for recon purposes — do not use in production.", "WARNING")

        for scheme in ('http', 'https'):
            url = f"{scheme}://{self.target}"
            try:
                response = requests.get(
                    url, timeout=self.timeout, verify=False, allow_redirects=True
                )
                headers = dict(response.headers)
                self.results['http_headers'][url] = headers

                missing = [h for h in SECURITY_HEADERS if h not in headers]
                if missing:
                    self.log(f"Missing security headers on {url}: {missing}", "WARNING")
                else:
                    self.log(f"All expected security headers present on {url}.", "SUCCESS")

            except requests.exceptions.ConnectionError:
                self.log(f"Could not connect to {url}", "WARNING")
            except requests.exceptions.Timeout:
                self.log(f"Request timed out for {url}", "WARNING")
            except requests.exceptions.RequestException as exc:
                self.log(f"HTTP request failed for {url}: {exc}", "ERROR")

    # ------------------------------------------------------------------
    # Technology detection
    # ------------------------------------------------------------------

    def technology_detection(self) -> None:
        """Fingerprint web technologies, frameworks, and CMS platforms."""
        self.log("Detecting web technologies...", "INFO")
        techs = []

        try:
            response = requests.get(
                f"https://{self.target}", timeout=self.timeout, verify=False
            )
            headers = response.headers
            content = response.text.lower()
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

            if 'server' in headers:
                techs.append(f"Server: {headers['server']}")

            for name, indicator in FRAMEWORK_INDICATORS.items():
                if indicator in content or indicator in str(headers_lower):
                    techs.append(name)

            for name, indicator in CMS_INDICATORS.items():
                if indicator in content and name not in techs:
                    techs.append(name)

            self.results['technologies'] = techs
            self.log(f"Technologies detected: {techs}", "SUCCESS")

        except requests.exceptions.ConnectionError:
            self.log("Could not connect to target for technology detection.", "WARNING")
        except requests.exceptions.RequestException as exc:
            self.log(f"Technology detection failed: {exc}", "ERROR")

    # ------------------------------------------------------------------
    # SSL/TLS analysis
    # ------------------------------------------------------------------

    def ssl_certificate_analysis(self) -> None:
        """Inspect the SSL/TLS certificate presented on port 443."""
        self.log("Analysing SSL certificate...", "INFO")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl_info'] = {
                        'subject':        dict(x[0] for x in cert.get('subject', [])),
                        'issuer':         dict(x[0] for x in cert.get('issuer', [])),
                        'version':        cert.get('version'),
                        'serialNumber':   cert.get('serialNumber'),
                        'notBefore':      cert.get('notBefore'),
                        'notAfter':       cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName'),
                    }
                    self.log("SSL certificate analysis complete.", "SUCCESS")
        except ssl.SSLError as exc:
            self.log(f"SSL error: {exc}", "ERROR")
        except (socket.timeout, ConnectionRefusedError):
            self.log("Port 443 is not reachable — skipping SSL analysis.", "WARNING")
        except OSError as exc:
            self.log(f"SSL analysis failed: {exc}", "ERROR")

    # ------------------------------------------------------------------
    # Directory bruteforce
    # ------------------------------------------------------------------

    def directory_bruteforce(self) -> None:
        """
        Probe common URL paths for accessible directories or files.

        Only checks HTTPS. Use dedicated tools (e.g. gobuster, ffuf) for
        comprehensive directory enumeration with large wordlists.
        """
        self.log("Starting directory bruteforce (light mode)...", "WARNING")
        found_dirs = []

        for directory in COMMON_DIRS:
            url = f"https://{self.target}/{directory}"
            try:
                response = requests.get(
                    url, timeout=self.timeout, verify=False, allow_redirects=False
                )
                if response.status_code in (200, 301, 302, 403):
                    found_dirs.append({
                        'path':   directory,
                        'status': response.status_code,
                        'size':   len(response.content),
                    })
                    self.log(f"Found: {url} (HTTP {response.status_code})", "SUCCESS")
            except requests.exceptions.ConnectionError:
                pass  # Path doesn't exist or host unreachable
            except requests.exceptions.RequestException as exc:
                self.log(f"Request error for {url}: {exc}", "DEBUG")

        self.results['directories'] = found_dirs
        self.log(f"Directory bruteforce complete — {len(found_dirs)} paths found.", "SUCCESS")

    # ------------------------------------------------------------------
    # Save results
    # ------------------------------------------------------------------

    def save_results(self) -> None:
        """Persist scan results to JSON and CSV files."""
        # JSON — full results
        json_path = os.path.join(self.output_dir, 'recon_results.json')
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(self.results, fh, indent=4, default=str)
        self.log(f"JSON results saved → {json_path}", "SUCCESS")

        # CSV — subdomains only
        csv_path = os.path.join(self.output_dir, 'subdomains.csv')
        with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=['domain', 'ip', 'status'])
            writer.writeheader()
            writer.writerows(self.results['subdomains'])
        self.log(f"Subdomain CSV saved → {csv_path}", "SUCCESS")

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def generate_report(self) -> None:
        """Generate a styled HTML report summarising all findings."""
        html_path = os.path.join(self.output_dir, 'recon_report.html')

        subdomain_rows = ''.join(
            f"<tr><td>{s['domain']}</td><td>{s.get('ip', 'N/A')}</td></tr>"
            for s in self.results.get('subdomains', [])
        ) or '<tr><td colspan="2">None found</td></tr>'

        port_rows = ''.join(
            f"<tr><td>{p['port']}</td><td>{p['service']}</td></tr>"
            for p in self.results.get('open_ports', [])
        ) or '<tr><td colspan="2">None found</td></tr>'

        tech_items = ''.join(
            f"<li>{t}</li>" for t in self.results.get('technologies', [])
        ) or '<li>None detected</li>'

        dir_rows = ''.join(
            f"<tr><td>/{d['path']}</td><td>{d['status']}</td><td>{d['size']} bytes</td></tr>"
            for d in self.results.get('directories', [])
        ) or '<tr><td colspan="3">None found</td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Recon Report — {self.target}</title>
  <style>
    body  {{ font-family: Arial, sans-serif; margin: 30px; background: #f5f5f5; color: #333; }}
    h1    {{ color: #222; }}
    h2    {{ color: #444; border-bottom: 2px solid #ddd; padding-bottom: 4px; margin-top: 30px; }}
    .card {{ background: #fff; border-radius: 6px; padding: 16px 20px;
             margin: 16px 0; box-shadow: 0 2px 6px rgba(0,0,0,.1); }}
    table {{ border-collapse: collapse; width: 100%; }}
    th,td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: .9em; }}
    th    {{ background: #f0f0f0; font-weight: 600; }}
    tr:nth-child(even) {{ background: #fafafa; }}
    pre   {{ background: #f8f8f8; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: .85em; }}
    ul    {{ margin: 6px 0; padding-left: 20px; }}
    .badge {{ display:inline-block; padding:2px 8px; border-radius:12px;
              font-size:.8em; font-weight:600; }}
    .ok   {{ background:#d4edda; color:#155724; }}
    .warn {{ background:#fff3cd; color:#856404; }}
  </style>
</head>
<body>
  <h1>🔍 Reconnaissance Report</h1>
  <div class="card">
    <p><strong>Target:</strong> {self.target}</p>
    <p><strong>Scan Date:</strong> {self.results['scan_date']}</p>
    <p><strong>Output Directory:</strong> {self.output_dir}</p>
  </div>

  <h2>Subdomains ({len(self.results.get('subdomains', []))} found)</h2>
  <div class="card">
    <table><tr><th>Subdomain</th><th>IP Address</th></tr>{subdomain_rows}</table>
  </div>

  <h2>Open Ports ({len(self.results.get('open_ports', []))} found)</h2>
  <div class="card">
    <table><tr><th>Port</th><th>Service</th></tr>{port_rows}</table>
  </div>

  <h2>DNS Records</h2>
  <div class="card"><pre>{json.dumps(self.results.get('dns_info', {}), indent=2)}</pre></div>

  <h2>Technologies Detected</h2>
  <div class="card"><ul>{tech_items}</ul></div>

  <h2>Directories ({len(self.results.get('directories', []))} found)</h2>
  <div class="card">
    <table><tr><th>Path</th><th>Status</th><th>Size</th></tr>{dir_rows}</table>
  </div>

  <h2>SSL Certificate</h2>
  <div class="card"><pre>{json.dumps(self.results.get('ssl_info', {}), indent=2, default=str)}</pre></div>

  <h2>WHOIS Information</h2>
  <div class="card"><pre>{json.dumps(self.results.get('whois_info', {}), indent=2, default=str)}</pre></div>
</body>
</html>"""

        with open(html_path, 'w', encoding='utf-8') as fh:
            fh.write(html)
        self.log(f"HTML report saved → {html_path}", "SUCCESS")

    # ------------------------------------------------------------------
    # Full run
    # ------------------------------------------------------------------

    def run_full_recon(self) -> None:
        """Execute all reconnaissance modules sequentially and save results."""
        self.log(f"Starting full reconnaissance on: {self.target}", "INFO")
        start = time.time()

        self.enumerate_subdomains()
        self.dns_enumeration()
        self.whois_lookup()
        self.scan_ports()
        self.http_headers_analysis()
        self.technology_detection()
        self.ssl_certificate_analysis()
        self.directory_bruteforce()

        self.save_results()
        self.generate_report()

        elapsed = time.time() - start
        self.log(f"Reconnaissance completed in {elapsed:.2f} seconds.", "SUCCESS")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

DISCLAIMER = f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════════╗
║                      LEGAL DISCLAIMER                        ║
║  This tool is for EDUCATIONAL and AUTHORISED security        ║
║  testing ONLY. Use only on systems you own or have           ║
║  explicit written permission to test. Unauthorised use       ║
║  may violate local, national, and international law.         ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""


def main() -> None:
    """Parse CLI arguments and run the recon tool."""
    parser = argparse.ArgumentParser(
        description='Recon Automation Tool — for authorised security testing only.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('target',
                        help='Target domain name or IP address')
    parser.add_argument('-o', '--output',
                        help='Output directory for results')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS,
                        help='Number of concurrent worker threads')
    parser.add_argument('-T', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Network timeout in seconds')
    parser.add_argument('--ports',
                        help='Comma-separated list of ports to scan (overrides defaults)')

    args = parser.parse_args()

    print(DISCLAIMER)
    confirm = input("Do you have explicit permission to test this target? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print(Fore.YELLOW + "Exiting — no permission confirmed." + Style.RESET_ALL)
        return

    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print(Fore.RED + "Invalid port list. Use comma-separated integers, e.g. 80,443,8080" + Style.RESET_ALL)
            return

    recon = ReconAutomation(args.target, args.output, args.threads, args.timeout)
    recon.run_full_recon()


if __name__ == '__main__':
    main()
