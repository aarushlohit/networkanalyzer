from __future__ import annotations

import csv
import io
from typing import Any, Dict

from vulnsync.core.scanner import ScanResult


def generate_csv(result: ScanResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP", "Hostname", "Port", "Protocol", "State",
        "Service", "Version", "Banner",
        "CVSS Score", "CVEs", "OS Fingerprint",
        "TLS Version", "Cert Expired",
    ])

    for host in result.targets:
        if not host.ports:
            writer.writerow([
                host.ip, host.hostname or "", "", "", "",
                "", "", "", "", "",
                host.os_fingerprint or "", "", "",
            ])
        for port in host.ports:
            cve_str = "; ".join(c.get("cve", "") for c in port.cve_list) if port.cve_list else ""
            tls_ver = ""
            cert_expired = ""
            if port.ssl_info:
                tls_ver = port.ssl_info.get("tls_version", "")
                cert_expired = str(port.ssl_info.get("cert_expired", ""))

            writer.writerow([
                host.ip, host.hostname or "", port.port, port.protocol, port.state,
                port.service, port.version or "", (port.banner or "")[:200],
                port.cvss_score or "", cve_str,
                host.os_fingerprint or "",
                tls_ver, cert_expired,
            ])

    return output.getvalue()
