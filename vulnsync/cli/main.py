from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnsync import __version__
from vulnsync.core.config import VulnSyncConfig, load_config, gen_example_config, dict_to_profile
from vulnsync.core.history import ScanHistory
from vulnsync.core.scanner import PortScanner, ScanResult
from vulnsync.core.targets import ScanProfile, build_targets, parse_ports
from vulnsync.fingerprint.dns import brute_subdomains, enumerate_dns, try_zone_transfer
from vulnsync.fingerprint.ssl import audit_tls
from vulnsync.fingerprint.webtech import fingerprint_web
from vulnsync.output.display import (
    print_banner, print_host_result, print_scan_summary, print_target_summary,
    print_vuln_summary,
)
from vulnsync.report.csv import generate_csv
from vulnsync.report.html import generate_html
from vulnsync.report.json import generate_json
from vulnsync.report.pdf import generate_pdf
from vulnsync.utils.log import get_logger, setup_logging
from vulnsync.utils.net import parse_ports as parse_port_spec
from vulnsync.vuln.cve import CVEEngine

logger = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnsync",
        description="VulnSync — Enterprise Network Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnsync scan 192.168.1.0/24 -p 22,80,443 --threads 100
  vulnsync scan target.com -p 1-10000 -sS --rate 500 --os-detect
  vulnsync scan 10.0.0.1 -p 80,443 --web-fingerprint -oJ results.json
  vulnsync dns example.com --subdomains --zone-transfer
  vulnsync ssl scan example.com
  vulnsync vuln update
        """,
    )
    parser.add_argument("--version", action="version", version=f"VulnSync v{__version__}")
    parser.add_argument("--log-file", help="Log file path")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Verbosity level")
    parser.add_argument("--json-logs", action="store_true", help="JSON formatted logs")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run a network scan", aliases=["s"])
    scan_p.add_argument("targets", nargs="+", help="Target IP, CIDR, range, hostname, or file:@path")
    scan_p.add_argument("-p", "--ports", default="1-1000", help="Port range (22,80,443 or 1-10000)")
    scan_p.add_argument("--top-ports", type=int, default=0, help="Scan top N ports")
    scan_p.add_argument("-sS", "--syn-scan", action="store_true", help="SYN stealth scan (requires root)")
    scan_p.add_argument("-sT", "--tcp-scan", action="store_true", help="TCP connect scan (default)")
    scan_p.add_argument("-sU", "--udp-scan", action="store_true", help="UDP scan")
    scan_p.add_argument("-sF", "--fin-scan", action="store_true", help="FIN scan (firewall evasion)")
    scan_p.add_argument("-sN", "--null-scan", action="store_true", help="NULL scan (firewall evasion)")
    scan_p.add_argument("-sX", "--xmas-scan", action="store_true", help="Xmas scan (firewall evasion)")
    scan_p.add_argument("--threads", type=int, default=50, help="Thread count (default: 50)")
    scan_p.add_argument("--timeout", type=float, default=3.0, help="Connection timeout in seconds")
    scan_p.add_argument("--rate", type=int, default=0, help="Max packets/sec (0 = unlimited)")
    scan_p.add_argument("--jitter", type=int, default=0, help="Random delay in ms between probes")
    scan_p.add_argument("--exclude", help="Hosts or ports to exclude (comma-separated)")
    scan_p.add_argument("--no-ping", action="store_true", help="Skip ping sweep before scanning")
    scan_p.add_argument("--service-detect", action="store_true", default=True, help="Enable banner grabbing")
    scan_p.add_argument("--os-detect", action="store_true", help="Enable OS fingerprinting")
    scan_p.add_argument("--web-fingerprint", action="store_true", help="HTTP/HTTPS technology detection")
    scan_p.add_argument("--stealth", action="store_true", help="Enable stealth mode (slow + randomized)")
    scan_p.add_argument("-oJ", "--output-json", help="Save JSON report")
    scan_p.add_argument("-oH", "--output-html", help="Save HTML report")
    scan_p.add_argument("-oP", "--output-pdf", help="Save PDF report")
    scan_p.add_argument("-oC", "--output-csv", help="Save CSV report")
    scan_p.add_argument("--cve-check", action="store_true", default=True, help="Enable CVE matching")
    scan_p.add_argument("--no-cve", action="store_true", help="Disable CVE matching")

    dns_p = sub.add_parser("dns", help="DNS enumeration tools")
    dns_p.add_argument("domain", help="Target domain")
    dns_p.add_argument("--subdomains", action="store_true", help="Brute-force subdomains")
    dns_p.add_argument("--zone-transfer", action="store_true", help="Attempt DNS zone transfer")
    dns_p.add_argument("--nameserver", help="Custom DNS server")
    dns_p.add_argument("--threads", type=int, default=20, help="Subdomain brute threads")
    dns_p.add_argument("--timeout", type=float, default=5.0, help="DNS query timeout")
    dns_p.add_argument("-oJ", "--output-json", help="Save JSON output")

    ssl_p = sub.add_parser("ssl", help="SSL/TLS audit tools")
    ssl_sub = ssl_p.add_subparsers(dest="ssl_command", required=True)
    ssl_scan = ssl_sub.add_parser("scan", help="Check SSL/TLS on a host")
    ssl_scan.add_argument("host", help="Target hostname or IP")
    ssl_scan.add_argument("-p", "--port", type=int, default=443, help="Port (default: 443)")
    ssl_scan.add_argument("--timeout", type=float, default=5.0)

    web_p = sub.add_parser("web", help="Web technology fingerprinting")
    web_p.add_argument("url", help="Target URL")
    web_p.add_argument("--timeout", type=float, default=5.0)

    vuln_p = sub.add_parser("vuln", help="Vulnerability database management")
    vuln_sub = vuln_p.add_subparsers(dest="vuln_command", required=True)
    vuln_sub.add_parser("update", help="Update CVE database from NVD")
    vuln_search = vuln_sub.add_parser("search", help="Search CVEs")
    vuln_search.add_argument("query", help="Search term (CVE ID or keyword)")
    vuln_search.add_argument("--limit", type=int, default=20, help="Max results")

    # ── config ───────────────────────────────────────────────────────────
    cfg_p = sub.add_parser("config", help="Manage configuration")
    cfg_sub = cfg_p.add_subparsers(dest="config_command", required=True)
    cfg_show = cfg_sub.add_parser("show", help="Show current effective config")
    cfg_show.add_argument("--profile", default=None, help="Config profile name")
    cfg_edit = cfg_sub.add_parser("edit", help="Open config in editor")
    cfg_edit.add_argument("--editor", default=os.environ.get("EDITOR", "vim"), help="Editor command")
    cfg_init = cfg_sub.add_parser("init", help="Generate example config file")
    cfg_init.add_argument("--output", "-o", default="vulnsync.yaml", help="Output path")
    cfg_list = cfg_sub.add_parser("list", help="List available profiles")

    # ── history ──────────────────────────────────────────────────────────
    hist_p = sub.add_parser("history", help="Scan history management", aliases=["h"])
    hist_sub = hist_p.add_subparsers(dest="history_command", required=True)
    hist_list = hist_sub.add_parser("list", help="List past scans")
    hist_list.add_argument("--limit", type=int, default=10, help="Max results")
    hist_list.add_argument("--status", choices=["success", "failed", "running"], help="Filter by status")
    hist_show = hist_sub.add_parser("show", help="Show scan details")
    hist_show.add_argument("scan_id", help="Scan ID to inspect")
    hist_diff = hist_sub.add_parser("diff", help="Show differences between two scans")
    hist_diff.add_argument("scan_a", help="First scan ID")
    hist_diff.add_argument("scan_b", help="Second scan ID")
    hist_purge = hist_sub.add_parser("purge", help="Purge old scans")
    hist_purge.add_argument("--keep", type=int, default=30, help="Number of recent scans to keep")
    hist_stats = hist_sub.add_parser("stats", help="Scan history statistics")

    # ── daemon ───────────────────────────────────────────────────────────
    daemon_p = sub.add_parser("daemon", help="Scheduled scanning daemon")
    daemon_p.add_argument("action", choices=["start", "stop", "status", "once"], help="Daemon action")
    daemon_p.add_argument("--config", "-c", default=None, help="Path to config file")
    daemon_p.add_argument("--interval", type=int, default=0, help="Override scan interval (minutes)")
    daemon_p.add_argument("--profile", default=None, help="Scan profile to use")
    daemon_p.add_argument("--targets", nargs="*", default=None, help="Override target list")
    daemon_p.add_argument("--pid-file", default=None, help="PID file path")

    # ── hook ─────────────────────────────────────────────────────────────
    hook_p = sub.add_parser("hook", help="Git hook integration")
    hook_sub = hook_p.add_subparsers(dest="hook_command", required=True)
    hook_install = hook_sub.add_parser("install", help="Install git hooks")
    hook_install.add_argument("--force", action="store_true", help="Overwrite existing hooks")
    hook_precommit = hook_sub.add_parser("pre-commit", help="Run pre-commit security scan (for git hook)")
    hook_precommit.add_argument("--config", default=None, help="Config file with targets")
    hook_precommit.add_argument("--no-cve", action="store_true", help="Skip CVE check (faster)")
    hook_precommit.add_argument("--ports", default=None, help="Ports to check")

    return parser


def _scan_command(args):
    print_banner()

    profile = ScanProfile(
        scan_type="tcp",
        threads=args.threads,
        timeout=args.timeout,
        rate=args.rate,
        jitter_ms=args.jitter,
        top_ports=args.top_ports,
        verbose=args.verbose,
        service_detect=args.service_detect,
        os_detect=args.os_detect,
        no_ping=args.no_ping,
        stealth=args.stealth,
    )

    if args.syn_scan:
        profile.scan_type = "syn"
    elif args.udp_scan:
        profile.scan_type = "udp"
    elif args.fin_scan:
        profile.scan_type = "fin"
    elif args.null_scan:
        profile.scan_type = "null"
    elif args.xmas_scan:
        profile.scan_type = "xmas"

    if args.stealth:
        profile.rate = min(profile.rate or 100, 100)
        profile.jitter_ms = max(profile.jitter_ms, 500)

    raw_targets: List[str] = []
    for t in args.targets:
        if t.startswith("file:@"):
            path = t[6:]
            with open(path) as f:
                raw_targets.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
        else:
            raw_targets.append(t)

    exclude_hosts = []
    if args.exclude:
        parts = args.exclude.split(",")
        exclude_hosts = [p.strip() for p in parts]

    targets = build_targets(raw_targets, exclude_hosts)
    if not targets:
        logger.error("No valid targets specified")
        sys.exit(1)

    ports = parse_port_spec(args.ports)
    if not ports:
        logger.error("No valid ports specified")
        sys.exit(1)
    profile.ports = ports

    print_target_summary(len(targets), args.ports, profile.scan_type, args.threads)

    scanner = PortScanner(profile)
    cve_engine = CVEEngine()

    def on_port_found(host: str, port_result):
        if args.cve_check and not args.no_cve and port_result.service:
            matches = cve_engine.match_service(port_result.service, port_result.version)
            if matches:
                port_result.cve_list = [
                    {"cve": m.cve_id, "cvss": m.cvss_score, "desc": m.description}
                    for m in matches
                ]
                if matches:
                    port_result.cvss_score = max(m.cvss_score for m in matches)

    scanner.on_port_found(on_port_found)

    try:
        result = scanner.scan(targets)
    except KeyboardInterrupt:
        print("\n[yellow]Scan interrupted by user[/]")
        scanner.stop()
        return

    for host in result.targets:
        print_host_result(host, args.verbose)

    if args.web_fingerprint:
        for host in result.targets:
            for port in host.ports:
                if port.state == "open" and port.service in ("http", "https", "http-proxy"):
                    proto = "https" if port.port in (443, 8443) else "http"
                    url = f"{proto}://{host.ip}:{port.port}"
                    web_fp = fingerprint_web(url, args.timeout)
                    if web_fp:
                        port.banner = web_fp.tech_summary + (" | " + port.banner if port.banner else "")

    print_vuln_summary(result)
    print_scan_summary(result)

    output_formats = []
    if args.output_json:
        data = generate_json(result)
        Path(args.output_json).write_text(data)
        output_formats.append(f"JSON: {args.output_json}")
    if args.output_html:
        generate_html(result, args.output_html)
        output_formats.append(f"HTML: {args.output_html}")
    if args.output_pdf:
        path = generate_pdf(result, args.output_pdf)
        if path:
            output_formats.append(f"PDF: {path}")
    if args.output_csv:
        data = generate_csv(result)
        Path(args.output_csv).write_text(data)
        output_formats.append(f"CSV: {args.output_csv}")

    for fmt in output_formats:
        print(f"  ✓ {fmt}")

    if result.alive_hosts > 0:
        vuln_count = sum(len(p.cve_list) for h in result.targets for p in h.ports)
        console_str = __import__("rich").get_console()
        console_str.print(f"\n[bold green]Scan complete:[/] {result.alive_hosts} hosts alive, "
                         f"{result.total_open_ports} open ports, {vuln_count} potential CVEs found "
                         f"in {result.duration_seconds:.1f}s")


def _dns_command(args):
    from vulnsync.output.display import console as c

    c.print(f"[bold cyan]DNS Enumeration:[/] {args.domain}")
    result = enumerate_dns(args.domain, args.nameserver, args.timeout)

    if result.a_records:
        c.print(f"\n[bold]A Records:[/] {', '.join(result.a_records)}")
    if result.aaaa_records:
        c.print(f"[bold]AAAA Records:[/] {', '.join(result.aaaa_records)}")
    if result.mx_records:
        for mx in result.mx_records:
            c.print(f"[bold]MX:[/] {mx['target']} (priority {mx['preference']})")
    if result.ns_records:
        c.print(f"[bold]NS Records:[/] {', '.join(result.ns_records)}")
    if result.txt_records:
        for txt in result.txt_records:
            c.print(f"[bold]TXT:[/] {txt[:200]}")
    if result.cname_records:
        for cn in result.cname_records:
            c.print(f"[bold]CNAME:[/] {cn['alias']} → {cn['canonical']}")
    if result.soa_record:
        soa = result.soa_record
        c.print(f"[bold]SOA:[/] {soa['mname']} | Serial: {soa['serial']}")
    if result.ptr_record:
        c.print(f"[bold]PTR:[/] {result.ptr_record}")

    if args.zone_transfer:
        c.print(f"\n[bold yellow]Attempting zone transfer...[/]")
        zt = try_zone_transfer(args.domain)
        if zt.zone_transfer_possible:
            c.print(f"[bold red]VULNERABLE — Zone transfer succeeded![/]")
            for rec in zt.zone_transfer_records[:30]:
                c.print(f"  {rec}")
        else:
            c.print(f"[green]Zone transfer denied (properly configured)[/]")

    if args.subdomains:
        c.print(f"\n[bold]Brute-forcing subdomains...[/]")
        found = brute_subdomains(args.domain, threads=args.threads, timeout=args.timeout)
        if found:
            c.print(f"[bold green]Found {len(found)} subdomain(s):[/]")
            for sub in found:
                c.print(f"  • {sub}")
        else:
            c.print("No additional subdomains discovered")

    if args.output_json:
        import json
        data = {
            "domain": args.domain,
            "a_records": result.a_records,
            "mx_records": result.mx_records,
            "ns_records": result.ns_records,
            "txt_records": result.txt_records,
            "subdomains": result.subdomains,
        }
        Path(args.output_json).write_text(json.dumps(data, indent=2))


def _ssl_command(args):
    from vulnsync.output.display import console as c

    if args.ssl_command == "scan":
        c.print(f"[bold cyan]SSL/TLS Audit:[/] {args.host}:{args.port}")
        with c.status("[bold cyan]Analyzing SSL/TLS configuration...[/]"):
            result = audit_tls(args.host, args.port, args.timeout)

        c.print(f"\n[bold]Supported Protocols:[/]")
        for proto, supported in result.tls_versions.items():
            status = "[green]✓[/]" if supported else "[dim]✗[/]"
            c.print(f"  {status} {proto}")

        c.print(f"\n[bold]Certificate:[/]")
        if result.subject:
            c.print(f"  Subject: {result.subject}")
        if result.issuer:
            c.print(f"  Issuer: {result.issuer}")
        if result.cert_expiry_days is not None:
            color = "red" if result.cert_expired or result.cert_expiry_days < 30 else "green"
            status = "EXPIRED" if result.cert_expired else f"{result.cert_expiry_days} days"
            c.print(f"  Expiry: [{color}]{status}[/]")

        c.print(f"\n[bold]Grade:[/] ", end="")
        grade_colors = {"A": "green", "B": "cyan", "C": "yellow", "D": "orange1", "F": "red"}
        c.print(f"[bold {grade_colors.get(result.grade, 'white')}]{result.grade}[/]")

        if result.vulnerabilities:
            c.print(f"\n[bold red]Vulnerabilities:[/]")
            for v in result.vulnerabilities:
                c.print(f"  • {v}")


def _web_command(args):
    from vulnsync.output.display import console as c

    c.print(f"[bold cyan]Web Fingerprinting:[/] {args.url}")
    fp = fingerprint_web(args.url, args.timeout)
    if not fp:
        c.print("[red]Failed to reach target[/]")
        return

    c.print(f"\n  [bold]Status:[/] {fp.status_code}")
    c.print(f"  [bold]Title:[/] {fp.title or '—'}")
    c.print(f"  [bold]Server:[/] {fp.server or '—'}")
    c.print(f"  [bold]Response Time:[/] {fp.response_time_ms}ms")
    c.print(f"  [bold]Content Length:[/] {fp.content_length} bytes")

    if fp.technologies:
        c.print(f"\n[bold]Technologies ({len(fp.technologies)}):[/]")
        for t in fp.technologies[:15]:
            ver = f" {t.version}" if t.version else ""
            c.print(f"  • {t.name}{ver} (confidence: {t.confidence}%)")

    sec_headers = fp.security_headers
    if any(sec_headers.values()):
        c.print(f"\n[bold]Security Headers:[/]")
        for header, present in sec_headers.items():
            status = "[green]✓ Present[/]" if present else "[red]✗ Missing[/]"
            c.print(f"  {status} — {header}")


def _vuln_command(args):
    from vulnsync.output.display import console as c

    engine = CVEEngine()
    if args.vuln_command == "update":
        c.print("[bold cyan]Updating CVE database from NVD...[/]")
        count = engine.update_from_nvd()
        c.print(f"[green]Updated {count} CVEs[/]")
    elif args.vuln_command == "search":
        c.print(f"[bold cyan]Searching CVEs:[/] {args.query}")
        results = engine.search_cve(args.query, args.limit)
        if results:
            for r in results:
                c.print(f"  {r['cve_id']} (CVSS: {r['cvss']}) — {r['description'][:120]}")
        else:
            c.print("No results found")


def _config_command(args):
    from vulnsync.output.display import console as c

    if args.config_command == "show":
        config = load_config(profile=args.profile)
        c.print(f"[bold cyan]Effective Configuration[/]")
        if args.profile:
            c.print(f"[dim]Profile: {args.profile}[/]")
        c.print(f"\n[bold]Targets:[/] {config.targets or '(none)'}")
        c.print(f"[bold]Ports:[/] {config.ports or '(default)'}")
        c.print(f"[bold]Scan threads:[/] {config.threads}")
        c.print(f"[bold]Timeout:[/] {config.timeout}s")
        c.print(f"[bold]Service detect:[/] {config.service_detect}")
        c.print(f"[bold]OS detect:[/] {config.os_detect}")
        c.print(f"[bold]CVE check:[/] {config.cve_check}")
        if config.daemon:
            d = config.daemon
            c.print(f"\n[bold]Daemon:[/] interval={d.get('interval',60)}m, enabled={d.get('enabled',False)}")
        if config.history:
            h = config.history
            c.print(f"[bold]History:[/] db={h.get('db_path','vulnsync.db')}, retention={h.get('retention_days',90)}d")
        if config.notifiers:
            for nt in config.notifiers:
                c.print(f"[bold]Notifier:[/] {nt.get('type','?')} → {nt.get('url','')[:60]}")

    elif args.config_command == "edit":
        config_paths = [
            Path("vulnsync.yaml"),
            Path.home() / ".config" / "vulnsync" / "vulnsync.yaml",
            Path("/etc/vulnsync/vulnsync.yaml"),
        ]
        target = next((p for p in config_paths if p.is_file()), config_paths[0])
        if not target.exists():
            gen_example_config(str(target))
            c.print(f"[green]Generated example config: {target}[/]")
        os.system(f"{args.editor} {target}")

    elif args.config_command == "init":
        path = Path(args.output)
        if path.exists() and not (hasattr(args, 'force') and args.force):
            c.print(f"[red]File exists: {path}. Use -f to overwrite.[/]")
            return
        gen_example_config(str(path))
        c.print(f"[green]Example config generated: {path}[/]")

    elif args.config_command == "list":
        from vulnsync.core.config import BUILTIN_PROFILES
        c.print("[bold cyan]Available profiles:[/]\n")
        for name, data in BUILTIN_PROFILES.items():
            desc = data.get("description", "—")
            c.print(f"  [bold]{name}[/]  {desc}")
        c.print("\n[dim]Custom: add to .vulnsync/profiles/ or ~/.vulnsync/profiles/[/]")


def _history_command(args):
    from vulnsync.output.display import console as c
    from rich.table import Table

    config = load_config()
    db_path = config.history.get("db_path", "vulnsync.db") if config.history else "vulnsync.db"
    hist = ScanHistory(db_path)

    if args.history_command == "list":
        rows = hist.list_scans(limit=args.limit, status=args.status)
        if not rows:
            c.print("[yellow]No scan history found[/]")
            return
        table = Table(title=f"Scan History (last {len(rows)})")
        table.add_column("ID", style="dim")
        table.add_column("Targets")
        table.add_column("Status")
        table.add_column("Hosts")
        table.add_column("Open Ports")
        table.add_column("CVEs")
        table.add_column("Duration")
        table.add_column("Date")
        for r in rows:
            table.add_row(
                r["scan_id"][:8], r.get("targets","")[:40], r["status"],
                str(r.get("hosts_found","")), str(r.get("open_ports","")),
                str(r.get("cves_found","")), f'{r.get("duration_seconds",0):.1f}s',
                r.get("created_at","")[:19],
            )
        c.print(table)

    elif args.history_command == "show":
        detail = hist.get_scan(args.scan_id)
        if not detail:
            c.print(f"[red]Scan not found: {args.scan_id}[/]")
            return
        scan = detail["scan"]
        c.print(f"[bold cyan]Scan:[/] {scan['scan_id']}")
        c.print(f"  Status: {scan['status']}  |  Targets: {scan.get('targets','?')}")
        c.print(f"  Hosts: {scan.get('hosts_found',0)} alive, {scan.get('open_ports',0)} open ports, {scan.get('cves_found',0)} CVEs")
        c.print(f"  Duration: {scan.get('duration_seconds',0):.1f}s  |  {scan.get('created_at','')[:19]}")
        hosts = detail.get("hosts", [])
        for h in hosts:
            c.print(f"\n  [bold]{h['host']}[/] — Risk: {h.get('risk_score','?')}")
            for p in h.get("ports", []):
                cves = ",".join(p.get("cve_list",[])) or "—"
                c.print(f"    {p['port']}/{p.get('protocol','tcp')}  {p.get('state','?')}  {p.get('service','')} {p.get('version','')}  CVEs: {cves}")

    elif args.history_command == "diff":
        diff = hist.diff(args.scan_a, args.scan_b)
        if "error" in diff:
            c.print(f"[red]{diff['error']}[/]")
            return
        c.print(f"[bold cyan]Drift: {diff['scan_a'][:8]} → {diff['scan_b'][:8]}[/]")
        c.print(f"  Risk change: {diff.get('risk_delta','?')}")
        if diff.get("hosts_removed"):
            c.print(f"  [red]Hosts removed: {diff['hosts_removed']}[/]")
        if diff.get("hosts_added"):
            c.print(f"  [green]Hosts added: {diff['hosts_added']}[/]")
        if diff.get("ports_new"):
            c.print(f"  [red]New ports: {diff['ports_new']}[/]")
        if diff.get("cves_new"):
            c.print(f"  [red]New CVEs: {diff['cves_new']}[/]")

    elif args.history_command == "purge":
        purged = hist.purge(keep=args.keep)
        c.print(f"[green]Purged {purged} old scan records[/]")

    elif args.history_command == "stats":
        stats = hist.stats()
        c.print(f"[bold cyan]Scan History Statistics[/]")
        c.print(f"  Total scans: {stats.get('total_scans',0)}")
        c.print(f"  Successful: {stats.get('successful',0)}")
        c.print(f"  Failed: {stats.get('failed',0)}")
        c.print(f"  Total hosts scanned: {stats.get('total_hosts',0)}")
        c.print(f"  Total CVEs found: {stats.get('total_cves',0)}")


def _daemon_command(args):
    from vulnsync.output.display import console as c
    from vulnsync.core.daemon import ScanDaemon

    config = load_config(cfg_path=args.config)
    daemon = ScanDaemon(config, pid_file=args.pid_file)

    if args.action == "start":
        c.print("[bold cyan]Starting daemon...[/]")
        daemon.run_loop(
            interval_minutes=args.interval or getattr(config.daemon, "interval", 60),
            single_scan=False,
        )

    elif args.action == "stop":
        c.print("[bold cyan]Stopping daemon...[/]")
        daemon.stop()
        c.print("[green]Daemon stopped[/]")

    elif args.action == "status":
        running = daemon.is_running()
        if running:
            pid = daemon.read_pid()
            c.print(f"[green]Daemon is running (PID: {pid})[/]")
        else:
            c.print("[yellow]Daemon is not running[/]")

    elif args.action == "once":
        c.print("[bold cyan]Running single scan via daemon...[/]")
        result = daemon.run_once()
        if result:
            c.print(f"[green]Scan complete: {result.alive_hosts} hosts, {result.total_open_ports} open ports[/]")
        else:
            c.print("[red]Scan failed[/]")


def _hook_command(args):
    from vulnsync.output.display import console as c

    if args.hook_command == "install":
        from vulnsync.hooks.precommit import install_hooks
        ok = install_hooks(force=args.force)
        if ok:
            c.print("[green]Git hooks installed successfully[/]")
        else:
            c.print("[red]Failed to install hooks[/]")

    elif args.hook_command == "pre-commit":
        from vulnsync.hooks.precommit import run_precommit_scan
        result = run_precommit_scan(config_path=args.config, no_cve=args.no_cve, ports=args.ports)
        if result["pass"]:
            c.print(f"[green]✓ Pre-commit scan passed ({result.get('hosts',0)} hosts, {result.get('open_ports',0)} open ports)[/]")
        else:
            critical = result.get("critical_cves", 0)
            if critical > 0:
                c.print(f"[red]✗ Pre-commit blocked: {critical} critical CVEs found[/]")
                sys.exit(1)
            else:
                c.print(f"[green]✓ No critical CVEs (warnings: {result.get('warnings',0)})[/]")


def main():
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(
        level="DEBUG" if args.verbose > 0 else "INFO",
        log_file=args.log_file if hasattr(args, "log_file") else None,
        json_output=args.json_logs if hasattr(args, "json_logs") else False,
    )

    try:
        if args.command in ("scan", "s"):
            _scan_command(args)
        elif args.command == "dns":
            _dns_command(args)
        elif args.command == "ssl":
            _ssl_command(args)
        elif args.command == "web":
            _web_command(args)
        elif args.command == "vuln":
            _vuln_command(args)
        elif args.command == "config":
            _config_command(args)
        elif args.command in ("history", "h"):
            _history_command(args)
        elif args.command == "daemon":
            _daemon_command(args)
        elif args.command == "hook":
            _hook_command(args)
    except KeyboardInterrupt:
        print("\n[yellow]Interrupted[/]")
        sys.exit(1)
    except Exception as e:
        logger.exception("Command failed: %s", e)
        print(f"\n[red]Error: {e}[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()
