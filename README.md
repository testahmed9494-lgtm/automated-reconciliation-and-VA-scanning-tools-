# 🔍 Recon Automation Tool

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/use-authorized%20testing%20only-red.svg)](https://github.com)

An automated reconnaissance tool for **authorised** security testing and penetration testing.

---

## ⚠️ Legal Disclaimer

> **IMPORTANT**: This tool is for **educational and authorised security testing purposes only**.  
> Only use on systems you own or have **explicit written permission** to test.  
> Unauthorised use may violate local, national, and international laws.

---

## ✨ Features

| Module | Description |
|---|---|
| 🔍 Subdomain Enumeration | Resolves common subdomain prefixes against the target domain |
| 🌐 DNS Record Discovery | Queries A, AAAA, MX, NS, TXT, SOA, CNAME records |
| 🔌 Port Scanning | Checks 20 common TCP ports with multi-threading |
| 📋 WHOIS Lookup | Retrieves registrar, dates, name servers, and contact emails |
| 🔒 SSL/TLS Analysis | Inspects certificate subject, issuer, validity, and SANs |
| 🛡️ Security Header Analysis | Flags missing headers (CSP, HSTS, X-Frame-Options, etc.) |
| 💻 Technology Detection | Identifies server software, CMS, and frameworks |
| 📂 Directory Bruteforce (Light) | Probes common paths like `/admin`, `/phpmyadmin`, `/backup` |
| 📊 Multi-format Reports | Outputs JSON, CSV, and a styled HTML report |
| ⚡ Multi-threaded Scanning | Configurable thread count for faster results |

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/recon-automation-tool.git
cd recon-automation-tool
```

### 2. (Recommended) Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

**Tested on:** Python 3.8, 3.10, 3.11 · Ubuntu 22.04 · Windows 11 · macOS 13

---

## 🖥️ Usage

```bash
python recon_tool.py <target> [options]
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `target` | Domain name or IP address | *(required)* |
| `-o`, `--output` | Output directory for results | `recon_<target>_<timestamp>` |
| `-t`, `--threads` | Number of worker threads | `20` |
| `-T`, `--timeout` | Network timeout in seconds | `5` |
| `--ports` | Comma-separated port list | 20 common ports |

### Examples

```bash
# Full scan with defaults
python recon_tool.py example.com

# Custom output directory and threads
python recon_tool.py example.com -o results/ -t 30

# Scan specific ports only
python recon_tool.py example.com --ports 22,80,443,8080,8443

# Increase timeout for slow hosts
python recon_tool.py example.com -T 10
```

### Sample output

```
[14:32:01] [INFO]    Starting full reconnaissance on: example.com
[14:32:02] [SUCCESS] Found: www.example.com -> 93.184.216.34
[14:32:02] [SUCCESS] Found: mail.example.com -> 93.184.216.35
[14:32:04] [SUCCESS] Port 80/HTTP is open
[14:32:04] [SUCCESS] Port 443/HTTPS is open
[14:32:05] [WARNING] Missing security headers on https://example.com: ['Content-Security-Policy']
[14:32:06] [SUCCESS] Technologies detected: ['Server: ECS (dcb/7F18)', 'WordPress']
[14:32:08] [SUCCESS] SSL certificate analysis complete.
[14:32:09] [SUCCESS] JSON results saved → results/recon_results.json
[14:32:09] [SUCCESS] HTML report saved  → results/recon_report.html
[14:32:09] [SUCCESS] Reconnaissance completed in 8.34 seconds.
```

---

## 📁 Output Files

After a scan, the output directory contains:

```
recon_example.com_20250101_143200/
├── recon_results.json   ← Full results (all modules)
├── subdomains.csv       ← Subdomain list (domain, IP, status)
├── recon_report.html    ← Styled HTML report
└── recon.log            ← Full execution log
```

---

## 🧪 Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `dnspython` | DNS record queries |
| `requests` | HTTP requests and header analysis |
| `python-whois` | WHOIS lookups |
| `colorama` | Coloured terminal output |
| `urllib3` | HTTP connection management |

Install all at once:

```bash
pip install -r requirements.txt
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**S M Ishtiaque Ahmed**  
For educational use and authorised penetration testing only.
