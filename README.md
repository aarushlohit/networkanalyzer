# VulnSync — Enterprise Network Security Auditor

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF)](.github/workflows/scan.yml)

**VulnSync** is an enterprise-grade network security auditor combining port scanning, service fingerprinting, CVE correlation, drift detection, CI/CD integration, and multi-format reporting. Built for security engineers who need depth without bloat.

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
| **YAML Config** | Profile-based configuration (quick/full/web/stealth), 7 discovery paths |
| **Scan History** | SQLite-backed persistent history with drift diff engine |
| **Scheduled Daemon** | Continuous monitoring mode with subprocess-based scanning |
| **Git Hooks** | Pre-commit security scans that block commits on critical CVEs |
| **Slack Alerts** | Block-kit notifications, severity-threshold filtered |
| **Webhook Alerts** | Generic JSON webhook for any notification system |
| **Docker** | Two-stage build (~180MB), compose with daemon mode, host networking |
| **CI/CD** | GitHub Actions — push/PR triggers, weekly infra scans, auto-issues on risk increase |
| **Reporting** | JSON, CSV, HTML (interactive), PDF, rich terminal dashboard |
| **Stealth Mode** | Rate limiting, jitter, randomized timing for evasion |

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Basic scan
vulnsync scan 192.168.1.0/24 -p 22,80,443

# SYN stealth scan with OS detection
sudo vulnsync scan target.com -p 1-10000 -sS --os-detect

# Full audit with all reports
vulnsync scan 10.0.0.1 -p 1-65535 --web-fingerprint \
  -oJ results.json -oH report.html -oP report.pdf -oC results.csv

# DNS enumeration
vulnsync dns example.com --subdomains --zone-transfer

# SSL audit
vulnsync ssl scan example.com

# Web fingerprinting
vulnsync web https://example.com

# Update CVE database
vulnsync vuln update
```

## Production Features

### Configuration Profiles

```bash
# Generate example config
vulnsync config init -o vulnsync.yaml

# View current effective config
vulnsync config show

# List available profiles
vulnsync config list

# Edit config
vulnsync config edit
```

Built-in profiles: `quick` (top-100 ports), `full` (1-65535), `web` (HTTP/HTTPS), `stealth` (slow + evasive). Add custom profiles in `.vulnsync/profiles/`.

### Scan History & Drift Detection

```bash
# List recent scans
vulnsync history list

# View scan details
vulnsync history show <scan_id>

# Compare two scans (drift detection)
vulnsync history diff <scan_a_id> <scan_b_id>

# History statistics
vulnsync history stats

# Purge old records
vulnsync history purge --keep 30
```

Drift diff reports: added/removed hosts, new/closed ports, new CVEs, risk score changes.

### Scheduled Daemon

```bash
# Run a single scan via daemon (with alerts)
vulnsync daemon once

# Start continuous monitoring (default: 60-min interval)
vulnsync daemon start

# Check status
vulnsync daemon status

# Stop daemon
vulnsync daemon stop
```

The daemon runs scans as subprocesses (isolating crashes), saves results to history, diffs against previous scan, and dispatches alerts.

### Git Hook Integration

```bash
# Install git hooks
vulnsync hook install

# Run pre-commit scan manually
vulnsync hook pre-commit --config vulnsync.yaml
```

Blocks commits when scanned targets have critical CVEs. Lightweight mode with `--no-cve` for speed.

### Alerts

Configure in `vulnsync.yaml`:

```yaml
notifiers:
  - type: slack
    url: https://hooks.slack.com/services/...
    severity_threshold: medium
  - type: webhook
    url: https://your-webhook.example.com/alerts
    severity_threshold: high
    headers:
      X-API-Key: your-key
```

### Docker Deployment

```bash
# Build
docker compose -f docker/docker-compose.yml build

# One-shot scan
docker compose -f docker/docker-compose.yml run vulnsync

# Continuous monitoring daemon
docker compose -f docker/docker-compose.yml up -d vulnsync-daemon
```

### CI/CD (GitHub Actions)

- **scan.yml**: Runs on push/PR touching config files, plus weekly schedule + manual dispatch. Uploads JSON/HTML artifacts, posts Slack alert on failure.
- **weekly-scan.yml**: Weekly infra scan → history save → drift diff → auto-creates GitHub issue if risk score increased.

## Architecture

```
vulnsync/
├── cli/              # CLI entry point (11 subcommands)
├── core/             # Scanner, targets, config (YAML), history (SQLite), daemon
├── fingerprint/      # Web tech, SSL/TLS, DNS enumeration
├── output/           # Rich terminal display
├── report/           # JSON, CSV, HTML, PDF generators
├── utils/            # Networking, logging
├── vuln/             # CVE matching engine, CVSS scoring
├── integrations/     # Slack alerts, webhook dispatcher
├── hooks/            # Pre-commit security scanner
├── config/           # Example config + profile definitions
├── scripts/          # Hook installer shell scripts
├── docker/           # Docker Compose configuration
└── .github/          # CI/CD workflows
```

## Requirements

- Python 3.10+
- `rich` — terminal UI
- `requests` — HTTP fingerprinting + NVD API
- `jinja2` — HTML report templates
- `aiohttp` — async DNS/HTTP
- `cryptography` — SSL certificate parsing
- `dnspython` — DNS enumeration
- `pyyaml` — YAML config loading

Optional: `reportlab` for PDF generation, `pytest`/`mypy`/`ruff` for development.

## License

MIT
