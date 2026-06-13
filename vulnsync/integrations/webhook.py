from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

from vulnsync.utils.log import get_logger

logger = get_logger("webhook")


def send_webhook(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    summary: str = "",
    result: Any = None,
    scan_id: str = "",
) -> bool:
    findings: List[Dict[str, Any]] = []
    if result:
        for host in result.targets:
            for port in host.ports:
                if port.cve_list:
                    for cve in port.cve_list:
                        findings.append({
                            "host": host.ip,
                            "hostname": host.hostname,
                            "port": port.port,
                            "protocol": port.protocol,
                            "service": port.service,
                            "version": port.version,
                            "cvss_score": port.cvss_score,
                            "cve_id": cve.get("cve", ""),
                            "cve_description": cve.get("desc", ""),
                        })

    payload: Dict[str, Any] = {
        "event": "scan_completed",
        "scan_id": scan_id[:8] if scan_id else "",
        "summary": summary,
        "timestamp": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "targets_count": result.total_hosts if result else 0,
        "alive_hosts": result.alive_hosts if result else 0,
        "open_ports": result.total_open_ports if result else 0,
        "duration_seconds": result.duration_seconds if result else 0,
        "findings": findings[:100],
    }

    return _post(url, payload, headers or {})


def _post(url: str, payload: Dict, extra_headers: Dict[str, str]) -> bool:
    try:
        data = json.dumps(payload).encode()
        req = Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in extra_headers.items():
            req.add_header(k, v)

        with urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                logger.info("Webhook sent successfully to %s", url)
                return True
            logger.warning("Webhook returned HTTP %d from %s", resp.status, url)
            return False
    except Exception as e:
        logger.error("Webhook failed to %s: %s", url, e)
        return False
