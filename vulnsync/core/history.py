from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnsync.utils.log import get_logger

logger = get_logger("history")


@dataclass
class ScanRecord:
    id: Optional[int] = None
    scan_id: str = ""
    target: str = ""
    profile: str = ""
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    total_hosts: int = 0
    alive_hosts: int = 0
    open_ports: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    cve_count: int = 0
    status: str = "completed"
    summary_json: str = "{}"
    report_paths: str = ""


@dataclass
class ScanDiff:
    added_hosts: List[str] = field(default_factory=list)
    removed_hosts: List[str] = field(default_factory=list)
    new_open_ports: List[Dict[str, Any]] = field(default_factory=list)
    closed_ports: List[Dict[str, Any]] = field(default_factory=list)
    new_cves: List[Dict[str, Any]] = field(default_factory=list)
    risk_score_change: float = 0.0
    severity_increased: bool = False
    drift_percentage: float = 0.0


class ScanHistory:
    def __init__(self, db_path: str = "~/.vulnsync/history.db"):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _init_db(self):
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    profile TEXT DEFAULT '',
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    duration_seconds REAL DEFAULT 0,
                    total_hosts INTEGER DEFAULT 0,
                    alive_hosts INTEGER DEFAULT 0,
                    open_ports INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    cve_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'completed',
                    summary_json TEXT DEFAULT '{}',
                    report_paths TEXT DEFAULT '',
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_scans_start ON scans(start_time DESC);
                CREATE INDEX IF NOT EXISTS idx_scans_severity ON scans(critical_count DESC);

                CREATE TABLE IF NOT EXISTS scan_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host_ip TEXT NOT NULL,
                    hostname TEXT DEFAULT '',
                    alive INTEGER DEFAULT 0,
                    os_fingerprint TEXT DEFAULT '',
                    open_ports_count INTEGER DEFAULT 0,
                    ports_json TEXT DEFAULT '[]',
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );

                CREATE INDEX IF NOT EXISTS idx_hosts_scan ON scan_hosts(scan_id);
            """)

    def save_scan(self, scan_result: "vulnsync.core.scanner.ScanResult",
                  profile_name: str = "",
                  report_files: Optional[List[str]] = None) -> str:
        import hashlib
        from vulnsync.core.scanner import ScanResult

        now = datetime.now(timezone.utc)
        scan_id = hashlib.sha256(f"{now.isoformat()}:{id(scan_result)}".encode()).hexdigest()[:16]

        critical = sum(
            1 for h in scan_result.targets for p in h.ports
            if p.cvss_score and p.cvss_score >= 9.0
        )
        high = sum(1 for h in scan_result.targets for p in h.ports
                   if p.cvss_score and 7.0 <= p.cvss_score < 9.0)
        medium = sum(1 for h in scan_result.targets for p in h.ports
                     if p.cvss_score and 4.0 <= p.cvss_score < 7.0)
        cve_count = sum(len(p.cve_list) for h in scan_result.targets for p in h.ports)

        summary = {
            "total_hosts": scan_result.total_hosts,
            "alive_hosts": scan_result.alive_hosts,
            "open_ports": scan_result.total_open_ports,
            "critical": critical,
            "high": high,
            "medium": medium,
            "cves": cve_count,
            "duration": scan_result.duration_seconds,
        }

        target_str = ",".join(
            h.ip for h in scan_result.targets[:10]
        )

        with self.conn:
            self.conn.execute("""
                INSERT INTO scans
                    (scan_id, target, profile, start_time, end_time,
                     duration_seconds, total_hosts, alive_hosts, open_ports,
                     critical_count, high_count, medium_count, cve_count,
                     status, summary_json, report_paths)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, target_str, profile_name,
                scan_result.start_time, scan_result.end_time,
                scan_result.duration_seconds,
                scan_result.total_hosts, scan_result.alive_hosts,
                scan_result.total_open_ports,
                critical, high, medium, cve_count,
                "completed", json.dumps(summary),
                ",".join(report_files or []),
            ))

            for host in scan_result.targets:
                ports_data = [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version,
                        "cvss": p.cvss_score,
                        "cves": [c.get("cve", "") for c in p.cve_list],
                    }
                    for p in host.ports if p.state == "open"
                ]
                self.conn.execute("""
                    INSERT INTO scan_hosts
                        (scan_id, host_ip, hostname, alive, os_fingerprint,
                         open_ports_count, ports_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id, host.ip, host.hostname or "",
                    1 if host.alive else 0,
                    host.os_fingerprint or "",
                    host.open_count,
                    json.dumps(ports_data),
                ))

        logger.info("Scan history saved: %s (%d hosts, %d open ports)",
                    scan_id, scan_result.alive_hosts, scan_result.total_open_ports)
        return scan_id

    def get_recent_scans(self, limit: int = 10,
                         target_filter: Optional[str] = None) -> List[ScanRecord]:
        query = "SELECT * FROM scans"
        params: List[Any] = []
        if target_filter:
            query += " WHERE target LIKE ?"
            params.append(f"%{target_filter}%")
        query += " ORDER BY start_time DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [ScanRecord(**dict(r)) for r in rows]

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        row = self.conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return ScanRecord(**dict(row)) if row else None

    def get_last_scan(self, target: Optional[str] = None) -> Optional[ScanRecord]:
        if target:
            row = self.conn.execute(
                "SELECT * FROM scans WHERE target LIKE ? ORDER BY start_time DESC LIMIT 1",
                (f"%{target}%",)
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM scans ORDER BY start_time DESC LIMIT 1"
            ).fetchone()
        return ScanRecord(**dict(row)) if row else None

    def diff_with_last(self, current_scan_id: str) -> Optional[ScanDiff]:
        current = self.get_scan(current_scan_id)
        if not current:
            return None

        last = self.get_last_scan(current.target)
        if not last or last.scan_id == current_scan_id:
            return None

        return self._compute_diff(last.scan_id, current_scan_id)

    def diff_scans(self, scan_id_a: str, scan_id_b: str) -> Optional[ScanDiff]:
        return self._compute_diff(scan_id_a, scan_id_b)

    def _compute_diff(self, old_id: str, new_id: str) -> Optional[ScanDiff]:
        old_hosts = self.conn.execute(
            "SELECT * FROM scan_hosts WHERE scan_id = ?", (old_id,)
        ).fetchall()
        new_hosts = self.conn.execute(
            "SELECT * FROM scan_hosts WHERE scan_id = ?", (new_id,)
        ).fetchall()

        old_ip_set = {r["host_ip"] for r in old_hosts}
        new_ip_set = {r["host_ip"] for r in new_hosts}

        added = list(new_ip_set - old_ip_set)
        removed = list(old_ip_set - new_ip_set)

        new_ports: List[Dict[str, Any]] = []
        closed_ports: List[Dict[str, Any]] = []
        new_cves: List[Dict[str, Any]] = []

        old_by_ip = {r["host_ip"]: r for r in old_hosts}
        new_by_ip = {r["host_ip"]: r for r in new_hosts}

        common_ips = old_ip_set & new_ip_set
        for ip in common_ips:
            old_ports = json.loads(old_by_ip[ip]["ports_json"])
            new_ports_list = json.loads(new_by_ip[ip]["ports_json"])

            old_port_set = {p["port"] for p in old_ports}
            new_port_set = {p["port"] for p in new_ports_list}

            for p in new_ports_list:
                if p["port"] not in old_port_set:
                    new_ports.append({"host": ip, **p})
                    if p.get("cves"):
                        for cve in p["cves"]:
                            new_cves.append({"host": ip, "port": p["port"], "cve": cve})

            for p in old_ports:
                if p["port"] not in new_port_set:
                    closed_ports.append({"host": ip, **p})

            old_cves = set(
                cve for p in old_ports for cve in p.get("cves", [])
            )
            for p in new_ports_list:
                for cve in p.get("cves", []):
                    if cve not in old_cves:
                        new_cves.append({"host": ip, "port": p["port"], "cve": cve})

        old_summary = json.loads(old_by_ip[list(old_by_ip.keys())[0]]["ports_json"]) if old_by_ip else []
        old_risk = sum(
            p.get("cvss", 0) or 0
            for hosts_data in [old_by_ip.get(ip, {}) for ip in old_by_ip]
            for p in json.loads(hosts_data.get("ports_json", "[]"))
        ) if old_by_ip else 0
        new_risk = sum(
            p.get("cvss", 0) or 0
            for hosts_data in [new_by_ip.get(ip, {}) for ip in new_by_ip]
            for p in json.loads(hosts_data.get("ports_json", "[]"))
        ) if new_by_ip else 0

        change = new_risk - old_risk
        total_ports_old = sum(
            len(json.loads(r["ports_json"])) for r in old_hosts
        ) if old_hosts else 0
        total_ports_new = sum(
            len(json.loads(r["ports_json"])) for r in new_hosts
        ) if new_hosts else 0

        drift = 0.0
        if total_ports_old > 0:
            changed = len(new_ports) + len(closed_ports)
            drift = (changed / max(total_ports_old, 1)) * 100

        return ScanDiff(
            added_hosts=added,
            removed_hosts=removed,
            new_open_ports=new_ports,
            closed_ports=closed_ports,
            new_cves=new_cves,
            risk_score_change=round(change, 2),
            severity_increased=change > 0,
            drift_percentage=round(drift, 1),
        )

    def purge_old(self, retention_days: int = 365):
        cutoff = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute(
                "DELETE FROM scan_hosts WHERE scan_id IN "
                "(SELECT scan_id FROM scans WHERE "
                "julianday(?) - julianday(created_at) > ?)",
                (cutoff, retention_days)
            )
            deleted = self.conn.execute(
                "DELETE FROM scans WHERE "
                "julianday(?) - julianday(created_at) > ?",
                (cutoff, retention_days)
            ).rowcount
        logger.info("Purged %d old scan records (>%d days)", deleted, retention_days)

    def get_stats(self) -> Dict[str, Any]:
        total = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        total_critical = self.conn.execute(
            "SELECT COALESCE(SUM(critical_count), 0) FROM scans"
        ).fetchone()[0]
        total_high = self.conn.execute(
            "SELECT COALESCE(SUM(high_count), 0) FROM scans"
        ).fetchone()[0]
        total_ports = self.conn.execute(
            "SELECT COALESCE(SUM(open_ports), 0) FROM scans"
        ).fetchone()[0]
        unique_targets = self.conn.execute(
            "SELECT COUNT(DISTINCT target) FROM scans"
        ).fetchone()[0]
        last_scan = self.conn.execute(
            "SELECT start_time FROM scans ORDER BY start_time DESC LIMIT 1"
        ).fetchone()

        return {
            "total_scans": total,
            "unique_targets": unique_targets,
            "total_open_ports": total_ports,
            "total_critical": total_critical,
            "total_high": total_high,
            "last_scan": last_scan[0] if last_scan else None,
        }

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
