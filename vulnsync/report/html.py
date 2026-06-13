from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from vulnsync.core.scanner import ScanResult
from vulnsync.utils.log import get_logger

logger = get_logger("report.html")

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _severity_color(score: Optional[float]) -> str:
    if score is None:
        return "#6b7280"
    if score >= 9.0:
        return "#dc2626"
    if score >= 7.0:
        return "#ea580c"
    if score >= 4.0:
        return "#ca8a04"
    if score >= 0.1:
        return "#2563eb"
    return "#6b7280"


def _severity_label(score: Optional[float]) -> str:
    if score is None:
        return "None"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "None"


def _risk_badge(score: Optional[float]) -> str:
    label = _severity_label(score)
    colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
        "None": "#6b7280",
    }
    bg = colors.get(label, "#6b7280")
    return f'<span style="background:{bg};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">{label}</span>'


def _summary_card(label: str, value: Any, color: str = "#3b82f6") -> str:
    return f"""
    <div style="background:white;border-radius:12px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);border-top:4px solid {color}">
        <div style="font-size:0.85em;color:#6b7280;margin-bottom:8px">{label}</div>
        <div style="font-size:1.8em;font-weight:700;color:#111827">{value}</div>
    </div>"""


def generate_html(result: ScanResult, output_path: Optional[str] = None) -> str:
    total_high = sum(h.high_risk_count for h in result.targets)
    total_medium = sum(h.medium_risk_count for h in result.targets)
    total_critical = sum(
        1 for h in result.targets for p in h.ports
        if p.cvss_score and p.cvss_score >= 9.0
    )

    hosts_rows = ""
    for host in result.targets:
        os_info = host.os_fingerprint or "Unknown"
        alive_tag = '<span style="color:#16a34a;font-weight:600">● Alive</span>' if host.alive else '<span style="color:#6b7280">● Dead</span>'
        hosts_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace">{host.ip}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{host.hostname or "—"}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{alive_tag}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:center;font-weight:600">{host.open_count}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{os_info}</td>
        </tr>"""

    ports_html = ""
    for host in result.targets:
        for port in host.ports:
            if port.state != "open":
                continue
            cve_str = "; ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{c.get("cve","")}" style="color:#2563eb">{c.get("cve","")}</a>' for c in port.cve_list) if port.cve_list else "—"
            ports_html += f"""
            <tr>
                <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace">{host.ip}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:center;font-weight:600">{port.port}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{port.protocol}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{port.service}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{port.version or "—"}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{(port.banner or "—")[:80]}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:center">{_risk_badge(port.cvss_score)}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:0.85em">{cve_str}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnSync Security Audit Report</title>
<style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#f3f4f6; color:#111827; }}
    .container {{ max-width:1400px; margin:0 auto; padding:24px; }}
    .header {{ background:linear-gradient(135deg,#1e293b,#334155); color:white; padding:32px; border-radius:16px; margin-bottom:24px; }}
    .header h1 {{ font-size:1.8em; margin-bottom:8px; }}
    .header p {{ color:#94a3b8; font-size:0.95em; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:24px; }}
    table {{ width:100%; border-collapse:collapse; background:white; border-radius:12px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.1); margin-bottom:24px; }}
    th {{ background:#f8fafc; padding:12px; text-align:left; font-weight:600; font-size:0.85em; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; border-bottom:2px solid #e5e7eb; }}
    tr:hover {{ background:#fafafa; }}
    h2 {{ font-size:1.3em; margin:24px 0 12px; color:#1e293b; }}
    .footer {{ text-align:center; color:#9ca3af; font-size:0.85em; padding:24px; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 VulnSync Security Audit Report</h1>
        <p>Scan completed in {result.duration_seconds:.1f}s &nbsp;|&nbsp; {result.start_time[:19]} &nbsp;|&nbsp; v2.1.0</p>
    </div>

    <div class="grid">
        {_summary_card("Hosts Scanned", result.total_hosts, "#3b82f6")}
        {_summary_card("Hosts Alive", result.alive_hosts, "#16a34a")}
        {_summary_card("Open Ports", result.total_open_ports, "#8b5cf6")}
        {_summary_card("Critical", total_critical, "#dc2626")}
        {_summary_card("High Risk", total_high, "#ea580c")}
        {_summary_card("Medium Risk", total_medium, "#ca8a04")}
    </div>

    <h2>📋 Host Summary</h2>
    <table>
        <thead>
            <tr><th>IP</th><th>Hostname</th><th>Status</th><th>Open Ports</th><th>OS Fingerprint</th></tr>
        </thead>
        <tbody>{hosts_rows}</tbody>
    </table>

    <h2>🔌 Open Ports &amp; Services</h2>
    <table>
        <thead>
            <tr><th>IP</th><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Banner</th><th>Risk</th><th>CVEs</th></tr>
        </thead>
        <tbody>{ports_html}</tbody>
    </table>

    <div class="footer">
        Generated by VulnSync v2.1.0 — Network Security Auditor<br>
        Report generated at {result.end_time[:19]}
    </div>
</div>
</body>
</html>"""

    if output_path:
        Path(output_path).write_text(html)
        logger.info("HTML report saved to %s", output_path)

    return html
