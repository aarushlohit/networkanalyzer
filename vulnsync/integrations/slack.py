from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

from vulnsync.utils.log import get_logger

logger = get_logger("slack")


def send_slack_alert(
    webhook_url: str,
    channel: str = "#security-alerts",
    summary: str = "",
    result: Any = None,
    scan_id: str = "",
    min_severity: str = "HIGH",
) -> bool:
    blocks = _build_blocks(result, summary, scan_id, min_severity) if result else [
        {"type": "section", "text": {"type": "mrkdwn", "text": summary}}
    ]

    payload = {
        "channel": channel,
        "username": "VulnSync Scanner",
        "icon_emoji": ":shield:",
        "blocks": blocks,
    }

    return _post(webhook_url, payload)


def _build_blocks(result, summary: str, scan_id: str, min_severity: str) -> List[Dict]:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_level = sev_order.get(min_severity.upper(), 1)

    critical = []
    high = []
    medium = []
    low = []

    for host in result.targets:
        for port in host.ports:
            if port.cvss_score is None or not port.cve_list:
                continue
            if port.cvss_score >= 9.0:
                critical.append((host.ip, port))
            elif port.cvss_score >= 7.0:
                high.append((host.ip, port))
            elif port.cvss_score >= 4.0:
                medium.append((host.ip, port))
            else:
                low.append((host.ip, port))

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"VulnSync Scan Results",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Scan Summary*\n{summary}\n*Scan ID:* `{scan_id[:8]}`",
            },
        },
        {"type": "divider"},
    ]

    if min_level <= 0 and critical:
        text = "\n".join(
            f"• {ip}:{p.port} ({p.service}) — CVSS *{p.cvss_score}* — "
            f"{', '.join(c.get('cve', '') for c in p.cve_list[:3])}"
            for ip, p in critical[:10]
        )
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🔥 Critical ({len(critical)} findings)*\n{text}",
            },
        })

    if min_level <= 1 and high:
        text = "\n".join(
            f"• {ip}:{p.port} ({p.service}) — CVSS *{p.cvss_score}*"
            for ip, p in high[:10]
        )
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*⚠️ High ({len(high)} findings)*\n{text}",
            },
        })

    if len(critical) + len(high) > 20:
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Showing top findings. {len(critical) + len(high)} total high+ severity."},
            ],
        })

    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Hosts:* {result.alive_hosts}"},
            {"type": "mrkdwn", "text": f"*Ports:* {result.total_open_ports}"},
            {"type": "mrkdwn", "text": f"*Duration:* {result.duration_seconds:.1f}s"},
        ],
    })

    return blocks


def _post(webhook_url: str, payload: Dict) -> bool:
    try:
        data = json.dumps(payload).encode()
        req = Request(webhook_url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logger.info("Slack alert sent successfully")
                return True
            logger.warning("Slack returned HTTP %d", resp.status)
            return False
    except Exception as e:
        logger.error("Failed to send Slack alert: %s", e)
        return False
