from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from vulnsync.utils.log import get_logger

logger = get_logger("config")

DEFAULT_PATHS: List[Path] = [
    Path("./vulnsync.yaml"),
    Path("./vulnsync.yml"),
    Path("./config/vulnsync.yaml"),
    Path("./config/vulnsync.yml"),
    Path("~/.config/vulnsync.yaml"),
    Path("~/.config/vulnsync.yml"),
    Path("/etc/vulnsync/config.yaml"),
]

BUILTIN_PROFILES: Dict[str, Dict[str, Any]] = {
    "quick": {
        "description": "Fast top-100 port scan",
        "ports": "top100",
        "threads": 100,
        "timeout": 2.0,
        "service_detect": True,
        "os_detect": False,
        "web_fingerprint": False,
        "no_ping": False,
        "cve_check": True,
    },
    "full": {
        "description": "Full 1-65535 port scan with all fingerprinting",
        "ports": "1-65535",
        "threads": 200,
        "timeout": 3.0,
        "service_detect": True,
        "os_detect": True,
        "web_fingerprint": True,
        "no_ping": False,
        "cve_check": True,
    },
    "web": {
        "description": "Web-focused: HTTP/HTTPS ports + tech detection",
        "ports": "80,443,8080,8443,3000,5000,9090",
        "threads": 50,
        "timeout": 5.0,
        "service_detect": True,
        "os_detect": False,
        "web_fingerprint": True,
        "no_ping": True,
        "cve_check": True,
    },
    "stealth": {
        "description": "Low-and-slow evasive scanning",
        "ports": "top1000",
        "threads": 10,
        "timeout": 10.0,
        "rate": 50,
        "jitter": 2000,
        "service_detect": True,
        "os_detect": False,
        "web_fingerprint": False,
        "no_ping": True,
        "cve_check": True,
    },
}


@dataclass
class NotifierConfig:
    slack_webhook: Optional[str] = None
    slack_channel: str = "#security-alerts"
    slack_min_severity: str = "HIGH"
    webhook_url: Optional[str] = None
    webhook_headers: Dict[str, str] = field(default_factory=dict)
    email_smtp: Optional[str] = None
    email_from: Optional[str] = None
    email_to: List[str] = field(default_factory=list)


@dataclass
class DaemonConfig:
    enabled: bool = False
    interval_minutes: int = 60
    targets: List[str] = field(default_factory=list)
    profile: str = "quick"
    report_dir: str = "./reports"
    max_reports: int = 100
    notify_on_critical: bool = True


@dataclass
class HistoryConfig:
    enabled: bool = True
    db_path: str = "~/.vulnsync/history.db"
    retention_days: int = 365
    max_records: int = 10000


@dataclass
class VulnSyncConfig:
    targets: List[str] = field(default_factory=list)
    ports: str = "1-1000"
    profile: Optional[str] = None
    threads: int = 50
    timeout: float = 3.0
    rate: int = 0
    jitter: int = 0
    scan_type: str = "tcp"
    service_detect: bool = True
    os_detect: bool = False
    web_fingerprint: bool = False
    stealth: bool = False
    no_ping: bool = False
    cve_check: bool = True
    exclude: List[str] = field(default_factory=list)
    output_dir: str = "./reports"
    output_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    log_file: Optional[str] = None
    log_level: str = "INFO"
    daemon: DaemonConfig = field(default_factory=DaemonConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)
    notifiers: NotifierConfig = field(default_factory=NotifierConfig)
    profiles: Dict[str, Dict[str, Any]] = field(default_factory=dict)


def find_config(path: Optional[str] = None) -> Optional[Path]:
    if path:
        p = Path(path).expanduser().resolve()
        if p.exists():
            return p
        logger.warning("Config path %s not found", path)
        return None
    for p in DEFAULT_PATHS:
        expanded = p.expanduser().resolve()
        if expanded.exists():
            return expanded
    return None


def load_config(path: Optional[str] = None) -> VulnSyncConfig:
    config_path = find_config(path)
    if config_path is None:
        logger.info("No config file found, using defaults")
        return VulnSyncConfig()

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        logger.warning("Config file is empty, using defaults")
        return VulnSyncConfig()

    merged = _merge_with_builtins(raw)
    return _parse_config(merged)


def _merge_with_builtins(raw: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    merged["profiles"] = {**BUILTIN_PROFILES, **(raw.get("profiles") or {})}
    for k, v in raw.items():
        if k != "profiles":
            merged[k] = v
    return merged


def _parse_config(raw: Dict[str, Any]) -> VulnSyncConfig:
    config = VulnSyncConfig()

    fields = {
        "targets", "ports", "profile", "threads", "timeout", "rate", "jitter",
        "scan_type", "service_detect", "os_detect", "web_fingerprint",
        "stealth", "no_ping", "cve_check", "exclude", "output_dir",
        "output_formats", "log_file", "log_level",
    }
    for field_name in fields:
        if field_name in raw:
            setattr(config, field_name, raw[field_name])

    if config.profile and config.profile in raw.get("profiles", {}):
        pf = raw["profiles"][config.profile]
        for k, v in pf.items():
            if k in fields and k not in {"targets", "ports", "output_dir"}:
                setattr(config, k, v)

    if "daemon" in raw:
        d = raw["daemon"]
        config.daemon = DaemonConfig(
            enabled=d.get("enabled", False),
            interval_minutes=d.get("interval_minutes", 60),
            targets=d.get("targets", []),
            profile=d.get("profile", "quick"),
            report_dir=d.get("report_dir", "./reports"),
            max_reports=d.get("max_reports", 100),
            notify_on_critical=d.get("notify_on_critical", True),
        )

    if "history" in raw:
        h = raw["history"]
        config.history = HistoryConfig(
            enabled=h.get("enabled", True),
            db_path=h.get("db_path", "~/.vulnsync/history.db"),
            retention_days=h.get("retention_days", 365),
            max_records=h.get("max_records", 10000),
        )

    if "notifiers" in raw:
        n = raw["notifiers"]
        config.notifiers = NotifierConfig(
            slack_webhook=n.get("slack_webhook"),
            slack_channel=n.get("slack_channel", "#security-alerts"),
            slack_min_severity=n.get("slack_min_severity", "HIGH"),
            webhook_url=n.get("webhook_url"),
            webhook_headers=n.get("webhook_headers", {}),
            email_smtp=n.get("email_smtp"),
            email_from=n.get("email_from"),
            email_to=n.get("email_to", []),
        )

    config.profiles = raw.get("profiles", BUILTIN_PROFILES)
    return config


def dict_to_profile(d: Dict[str, Any]) -> "vulnsync.core.targets.ScanProfile":
    from vulnsync.core.targets import ScanProfile
    from vulnsync.utils.net import parse_ports as parse_port_spec

    ports_str = d.get("ports", "1-1000")
    if isinstance(ports_str, str) and ports_str.startswith("top"):
        from vulnsync.utils.net import COMMON_PORTS
        key = ports_str
        ports = COMMON_PORTS.get(key, list(range(1, 1025)))
    else:
        ports = parse_port_spec(ports_str)

    return ScanProfile(
        scan_type=d.get("scan_type", "tcp"),
        ports=ports,
        threads=d.get("threads", 50),
        timeout=d.get("timeout", 3.0),
        rate=d.get("rate", 0),
        jitter_ms=d.get("jitter", 0),
        top_ports=0,
        verbose=d.get("verbose", 0),
        service_detect=d.get("service_detect", True),
        os_detect=d.get("os_detect", False),
        no_ping=d.get("no_ping", False),
        stealth=d.get("stealth", False),
    )


def gen_example_config(path: Path) -> str:
    template = """# VulnSync Configuration
# Auto-generated example config

targets:
  - "192.168.1.0/24"
  - "10.0.0.1"
  - "example.com"

ports: "1-1000"
profile: null          # Use a named profile: quick, full, web, stealth
threads: 50
timeout: 3.0
rate: 0               # 0 = unlimited packets/sec
jitter: 0             # Random ms delay between probes
scan_type: tcp        # tcp, syn, udp, fin, null, xmas
service_detect: true
os_detect: false
web_fingerprint: false
stealth: false
no_ping: false
cve_check: true
exclude: []

output_dir: "./reports"
output_formats: ["json", "html", "csv"]
log_file: null
log_level: "INFO"

daemon:
  enabled: false
  interval_minutes: 60
  targets: ["192.168.1.0/24"]
  profile: quick
  report_dir: "./reports"
  max_reports: 100
  notify_on_critical: true

history:
  enabled: true
  db_path: "~/.vulnsync/history.db"
  retention_days: 365
  max_records: 10000

notifiers:
  slack_webhook: null
  slack_channel: "#security-alerts"
  slack_min_severity: "HIGH"
  webhook_url: null
  webhook_headers: {}
  email_smtp: null
  email_from: null
  email_to: []

profiles:
  custom_scan:
    description: "My custom scan profile"
    ports: "22,80,443,8080,8443"
    threads: 30
    timeout: 5.0
    service_detect: true
    os_detect: false
    web_fingerprint: true
"""
    path.write_text(template)
    return str(path)
