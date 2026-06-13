# VulnSync — Network Security Auditor

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**VulnSync** is an enterprise-grade network security auditor combining port scanning, service fingerprinting, CVE correlation, and professional multi-format reporting. Built for security engineers who need depth without bloat.

---

## Features

| Capability | Details |
|---|---|
| **Port Scanning** | TCP Connect, SYN stealth, UDP, FIN, NULL, Xmas — multi-threaded |
| **OS Fingerprinting** | TTL + TCP window size analysis (Linux, Windows, macOS, Cisco) |
| **Banner Grabbing** | Service + version extraction across all open ports |
| **Web Tech Detection** | 25+ technologies (nginx, Apache, WordPress, React, Django, etc.) |
| **SSL/TLS Audit** | Protocol support, cipher strength, certificate expiry, grade A–F |
| **DNS Enumeration** | A/AAAA/MX/NS/TXT/CNAME/SOA/PTR + zone transfer + subdomain brute |
| **CVE Correlation** | 30+ built-in signatures + live NVD API fetch for latest CVEs |
| **CVSS Scoring** | Full CVSS 3.1 vector parsing and severity classification |
| **Reporting** | JSON, CSV, HTML (interactive dashboard), PDF |
| **Stealth Mode** | Rate limiting, jitter, randomized timing for evasion |
| **Live Dashboard** | Real-time Rich terminal output with progress bars |

---

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Basic scan
python -m vulnsync.cli.main scan 192.168.1.0/24 -p 22,80,443

# SYN stealth scan with OS detection
sudo python -m vulnsync.cli.main scan target.com -p 1-10000 -sS --os-detect

# Full audit with all reports
python -m vulnsync.cli.main scan 10.0.0.1 -p 1-65535 --web-fingerprint \
  -oJ results.json -oH report.html -oP report.pdf -oC results.csv

# DNS enumeration
python -m vulnsync.cli.main dns example.com --subdomains --zone-transfer

# SSL audit
python -m vulnsync.cli.main ssl scan example.com

# Web fingerprinting
python -m vulnsync.cli.main web https://example.com

# Update CVE database
python -m vulnsync.cli.main vuln update

# Search CVEs
python -m vulnsync.cli.main vuln search "OpenSSH"
```

---

## Scan Types

| Flag | Scan Type | Privilege | Evasion |
|---|---|---|---|
| `-sT` (default) | TCP Connect | None | Low |
| `-sS` | SYN Stealth | root | High |
| `-sU` | UDP | root | Moderate |
| `-sF` | FIN | root | High |
| `-sN` | NULL | root | High |
| `-sX` | Xmas | root | High |

---

## Target Specification

```bash
# IP or CIDR
vulnsync scan 192.168.1.1
vulnsync scan 10.0.0.0/24

# Range syntax
vulnsync scan 192.168.1.1-50

# Hostname
vulnsync scan example.com

# File import (one target per line)
vulnsync scan file:@targets.txt

# Exclude hosts
vulnsync scan 10.0.0.0/24 --exclude 10.0.0.1,10.0.0.2
```

---

## Output Formats

**HTML Report** — Self-contained interactive dashboard with severity cards, host tables, open port details, and CVE references linked to NVD.

**PDF Report** — Professional document suitable for client deliverables.

**JSON** — Machine-parseable structured data for pipeline integration.

**CSV** — Flat format for spreadsheet analysis.

---

## Architecture

```
vulnsync/
├── cli/           # Command-line interface (argparse)
├── core/          # Scanner engine, targets, packets, OS detect
├── fingerprint/   # Web tech, SSL/TLS, DNS enumeration
├── output/        # Rich terminal display, color system
├── report/        # JSON, CSV, HTML, PDF generators
├── utils/         # Networking, rate limiting, logging
├── vuln/          # CVE matching engine, CVSS scoring
└── templates/     # HTML report templates
```

---

## Requirements

- Python 3.10+
- `rich` — terminal UI
- `requests` — HTTP fingerprinting + NVD API
- `jinja2` — HTML report templates
- `aiohttp` — async DNS/HTTP
- `cryptography` — SSL certificate parsing
- `dnspython` — DNS enumeration

---

## License

MIT
