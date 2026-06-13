from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from vulnsync.utils.log import get_logger

logger = get_logger("cve")

CVE_DB_PATH = Path.home() / ".vulnsync" / "cve.db"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_UPDATE_INTERVAL = timedelta(hours=24)

VULNERABLE_SERVICES: Dict[str, List[Dict[str, Any]]] = {
    "openssh": [
        {"cve": "CVE-2024-6387", "cvss": 8.1, "version_lt": "8.9p1",
         "desc": "OpenSSH regreSSHion - Remote unauthenticated code execution via signal handler race condition",
         "severity": "HIGH"},
        {"cve": "CVE-2023-38408", "cvss": 7.5, "version_lt": "9.3p2",
         "desc": "Remote code execution in OpenSSH forwarded ssh-agent",
         "severity": "HIGH"},
        {"cve": "CVE-2023-28531", "cvss": 5.5, "version_lt": "9.3p2",
         "desc": "SSH agent Protocol injection via Unix domain socket",
         "severity": "MEDIUM"},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "cvss": 7.5, "version_lt": "2.4.50",
         "desc": "Apache Path Traversal and Remote Code Execution",
         "severity": "HIGH"},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "version_lt": "2.4.51",
         "desc": "Apache HTTP Server Path Traversal Remote Code Execution",
         "severity": "CRITICAL"},
        {"cve": "CVE-2023-25690", "cvss": 9.8, "version_lt": "2.4.56",
         "desc": "HTTP Request Smuggling via mod_proxy",
         "severity": "CRITICAL"},
        {"cve": "CVE-2024-24795", "cvss": 7.5, "version_lt": "2.4.59",
         "desc": "HTTP Response Splitting in Apache HTTP Server",
         "severity": "HIGH"},
    ],
    "nginx": [
        {"cve": "CVE-2024-24989", "cvss": 7.5, "version_lt": "1.24.0",
         "desc": "Denial of Service via HTTP/2 heap overflow",
         "severity": "HIGH"},
        {"cve": "CVE-2023-44487", "cvss": 7.5, "version_lt": "1.25.3",
         "desc": "HTTP/2 Rapid Reset Attack - DDoS via stream cancellation",
         "severity": "HIGH"},
        {"cve": "CVE-2021-23017", "cvss": 6.5, "version_lt": "1.21.0",
         "desc": "DNS resolver vulnerability in nginx",
         "severity": "MEDIUM"},
    ],
    "mysql": [
        {"cve": "CVE-2023-21971", "cvss": 7.5, "version_lt": "8.0.33",
         "desc": "Oracle MySQL Connector/J remote code execution",
         "severity": "HIGH"},
        {"cve": "CVE-2023-22053", "cvss": 6.5, "version_lt": "8.0.34",
         "desc": "MySQL Server unspecified vulnerability",
         "severity": "MEDIUM"},
    ],
    "postgresql": [
        {"cve": "CVE-2024-0985", "cvss": 8.0, "version_lt": "16.2",
         "desc": "PostgreSQL MERGE fails to enforce row security policies",
         "severity": "HIGH"},
    ],
    "iis": [
        {"cve": "CVE-2024-30044", "cvss": 9.8, "version_lt": "10.0.17763.5936",
         "desc": "Microsoft IIS Remote Code Execution via unauthenticated request",
         "severity": "CRITICAL"},
    ],
}


def _parse_version(version: str) -> Tuple[int, ...]:
    parts = version.replace("p", ".").replace("_", ".").split(".")
    result = []
    for p in parts:
        try:
            result.append(int(''.join(c for c in p if c.isdigit())))
        except ValueError:
            result.append(0)
    return tuple(result)


@dataclass
class CVEMatch:
    cve_id: str
    cvss_score: float
    description: str
    severity: str
    affected_version: str
    remediation: str = ""


class CVEEngine:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or CVE_DB_PATH
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    service TEXT,
                    version_lt TEXT,
                    cvss REAL,
                    description TEXT,
                    severity TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def match_service(self, service: str, version: Optional[str]) -> List[CVEMatch]:
        results: List[CVEMatch] = []
        service_lower = service.lower()

        if not version:
            return results

        vulns = VULNERABLE_SERVICES.get(service_lower, [])
        parsed_version = _parse_version(version)

        for vuln in vulns:
            vuln_ver = _parse_version(vuln.get("version_lt", "0"))
            if parsed_version < vuln_ver:
                results.append(CVEMatch(
                    cve_id=vuln["cve"],
                    cvss_score=vuln["cvss"],
                    description=vuln["desc"],
                    severity=vuln["severity"],
                    affected_version=vuln.get("version_lt", ""),
                    remediation=f"Upgrade {service} to version {vuln['version_lt']} or later",
                ))

        return results

    def update_from_nvd(self, days_back: int = 7) -> int:
        count = 0
        try:
            start = datetime.now(timezone.utc) - timedelta(days=days_back)
            params = {
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 50,
            }
            resp = requests.get(NVD_API, params=params, timeout=30)
            if resp.status_code != 200:
                logger.warning("NVD API returned %d", resp.status_code)
                return 0

            data = resp.json()
            with self._lock, sqlite3.connect(str(self.db_path)) as conn:
                for vuln in data.get("vulnerabilities", []):
                    cve_item = vuln.get("cve", {})
                    cve_id = cve_item.get("id", "")
                    metrics = cve_item.get("metrics", {})
                    cvss_score = 0.0
                    if "cvssMetricV31" in metrics:
                        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

                    descs = cve_item.get("descriptions", [])
                    description = next((d["value"] for d in descs if d["lang"] == "en"), "")

                    conn.execute(
                        "INSERT OR REPLACE INTO cve_cache (cve_id, cvss, description, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                        (cve_id, cvss_score, description),
                    )
                    count += 1

            conn.commit()
            logger.info("Updated %d CVEs from NVD", count)
        except Exception as e:
            logger.warning("NVD update failed: %s", e)
        return count

    def search_cve(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        try:
            with self._lock, sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute(
                    "SELECT cve_id, cvss, description, severity FROM cve_cache WHERE cve_id LIKE ? OR description LIKE ? LIMIT ?",
                    (f"%{query}%", f"%{query}%", limit),
                )
                return [
                    {"cve_id": row[0], "cvss": row[1], "description": row[2], "severity": row[3]}
                    for row in cursor.fetchall()
                ]
        except Exception as e:
            logger.warning("CVE search failed: %s", e)
            return []
