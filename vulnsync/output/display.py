from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.layout import Layout

from vulnsync.core.scanner import HostResult, PortResult, ScanResult
from vulnsync.output.colors import severity_color

console = Console()


def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                      V U L N S Y N C                        ║
║              Network Security Auditor  v2.1.0                ║
║        Port Scanner · Service Fingerprint · CVE Engine       ║
╚══════════════════════════════════════════════════════════════╝"""
    console.print(banner, style="bold cyan")


def print_target_summary(targets_count: int, ports: str, scan_type: str, threads: int):
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold", width=20)
    table.add_column(style="")
    table.add_row("Targets:", str(targets_count))
    table.add_row("Ports:", ports)
    table.add_row("Scan Type:", scan_type.upper())
    table.add_row("Threads:", str(threads))
    console.print(Panel(table, title="[bold]Scan Configuration", border_style="cyan"))


def create_live_progress(target_count: int, port_count: int) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


def print_host_result(host: HostResult, verbose: bool = False):
    if not host.alive:
        return

    status_color = "green" if host.open_count > 0 else "yellow"
    console.print(f"\n[bold cyan]→ {host.ip}[/] [dim]{host.hostname or ''}[/] "
                  f"[{status_color}]● Alive ({host.ping_time_ms}ms)[/] "
                  f"[dim]Open: {host.open_count} ports[/]"
                  + (f" | [italic]OS: {host.os_fingerprint}[/]" if host.os_fingerprint else ""))

    if host.open_ports:
        table = Table(show_header=True, header_style="bold", border_style="dim")
        table.add_column("Port", style="cyan", width=8)
        table.add_column("State", width=10)
        table.add_column("Service", style="yellow", width=18)
        table.add_column("Version", style="dim", width=16)
        table.add_column("Risk", width=14)
        table.add_column("Banner", style="dim", width=50, overflow="fold")

        for port in host.open_ports:
            risk_text = ""
            if port.cvss_score:
                color = severity_color(
                    "CRITICAL" if port.cvss_score >= 9 else
                    "HIGH" if port.cvss_score >= 7 else
                    "MEDIUM" if port.cvss_score >= 4 else "LOW"
                )
                risk_text = f"[{color}]{port.cvss_score:.1f}[/]"

            banner_text = port.banner[:80] if port.banner else ""
            table.add_row(
                str(port.port),
                f"[green]{port.state}[/]",
                port.service,
                port.version or "",
                risk_text,
                banner_text,
            )

        console.print(table)


def print_scan_summary(result: ScanResult):
    total_critical = sum(
        1 for h in result.targets for p in h.ports
        if p.cvss_score and p.cvss_score >= 9.0
    )
    total_high = sum(h.high_risk_count for h in result.targets)
    total_medium = sum(h.medium_risk_count for h in result.targets)

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold", width=22)
    summary.add_column(style="", width=20)
    summary.add_row("Total Hosts:", str(result.total_hosts))
    summary.add_row("Hosts Alive:", str(result.alive_hosts))
    summary.add_row("Open Ports:", str(result.total_open_ports))
    summary.add_row("Critical:", f"[red]{total_critical}[/]" if total_critical else "0")
    summary.add_row("High:", f"[orange1]{total_high}[/]" if total_high else "0")
    summary.add_row("Medium:", f"[yellow]{total_medium}[/]" if total_medium else "0")
    summary.add_row("Duration:", f"{result.duration_seconds:.1f}s")

    console.print()
    console.print(Panel(summary, title="[bold]Scan Complete", border_style="green"))
    console.print(f"Results saved — End: {result.end_time[:19]}\n")


def print_vuln_summary(result: ScanResult):
    all_cves = []
    for host in result.targets:
        for port in host.ports:
            if port.cve_list:
                for cve in port.cve_list:
                    all_cves.append((host.ip, port.port, port.service, cve))

    if not all_cves:
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("IP", style="cyan", width=16)
    table.add_column("Port", width=6)
    table.add_column("Service", width=14)
    table.add_column("CVE", style="bold", width=18)
    table.add_column("CVSS", width=8)
    table.add_column("Description", width=60, overflow="fold")

    for ip, port, svc, cve in sorted(all_cves, key=lambda x: x[3].get("cvss", 0), reverse=True):
        table.add_row(
            ip, str(port), svc,
            cve.get("cve", ""),
            str(cve.get("cvss", "")),
            cve.get("desc", "")[:80],
        )

    console.print(Panel(table, title="[bold red]Vulnerability Summary", border_style="red"))
