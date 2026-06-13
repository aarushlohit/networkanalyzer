from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from vulnsync.core.scanner import ScanResult
from vulnsync.utils.log import get_logger

logger = get_logger("report.json")


def _port_to_dict(port) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "port": port.port,
        "protocol": port.protocol,
        "state": port.state,
        "service": port.service,
        "banner": port.banner,
        "version": port.version,
        "cvss_score": port.cvss_score,
    }
    if port.ssl_info:
        d["ssl"] = port.ssl_info
    if port.cve_list:
        d["cves"] = port.cve_list
    return d


def _host_to_dict(host) -> Dict[str, Any]:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "alive": host.alive,
        "ping_time_ms": host.ping_time_ms,
        "os_fingerprint": host.os_fingerprint,
        "os_accuracy": host.os_accuracy,
        "open_ports": host.open_count,
        "total_ports_scanned": host.total_ports_scanned,
        "high_risk_count": host.high_risk_count,
        "medium_risk_count": host.medium_risk_count,
        "ports": [_port_to_dict(p) for p in host.ports if p.state == "open"],
        "scan_start": host.scan_start,
        "scan_end": host.scan_end,
    }


def generate_json(result: ScanResult) -> str:
    data: Dict[str, Any] = {
        "tool": "VulnSync Network Security Auditor",
        "version": "2.1.0",
        "scan_metadata": {
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration_seconds": result.duration_seconds,
            "targets_configured": result.total_hosts,
            "hosts_alive": result.alive_hosts,
            "total_open_ports": result.total_open_ports,
        },
        "profile": {
            "scan_type": result.profile.scan_type if result.profile else "tcp",
            "threads": result.profile.threads if result.profile else 0,
            "timeout": result.profile.timeout if result.profile else 3.0,
        } if result.profile else {},
        "targets": [_host_to_dict(h) for h in result.targets],
        "summary": {
            "total_hosts": len(result.targets),
            "alive_hosts": result.alive_hosts,
            "total_open_ports": result.total_open_ports,
            "total_high_risk": sum(h.high_risk_count for h in result.targets),
            "total_medium_risk": sum(h.medium_risk_count for h in result.targets),
        },
    }
    return json.dumps(data, indent=2, default=str)
