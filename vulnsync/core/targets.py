from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Generator, List, Optional, Set

from vulnsync.utils.net import parse_ports, parse_targets, resolve_host


@dataclass
class ScanTarget:
    host: str
    ip: Optional[str] = None
    hostname: Optional[str] = None


@dataclass
class ScanProfile:
    targets: List[ScanTarget] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    scan_type: str = "tcp"
    threads: int = 50
    timeout: float = 3.0
    rate: int = 0
    jitter_ms: int = 0
    exclude_ports: Set[int] = field(default_factory=set)
    exclude_hosts: Set[str] = field(default_factory=set)
    top_ports: int = 0
    verbose: int = 0
    output_formats: List[str] = field(default_factory=list)
    output_file: Optional[str] = None
    stealth: bool = False
    decoys: List[str] = field(default_factory=list)
    fragment: bool = False
    no_ping: bool = False
    service_detect: bool = True
    os_detect: bool = False
    script_scan: bool = False

    def resolve_all(self):
        resolved: List[ScanTarget] = []
        for t in self.targets:
            ip = resolve_host(t.host)
            if ip:
                t.ip = ip
                t.hostname = t.host if not ipaddress.ip_address(t.host).is_private else None
                resolved.append(t)
        self.targets = resolved


def build_targets(
    raw_targets: List[str],
    exclude_hosts: Optional[List[str]] = None,
) -> List[ScanTarget]:
    seen: Set[str] = set()
    excluded = set(exclude_hosts or [])
    targets: List[ScanTarget] = []
    for raw in raw_targets:
        for host in parse_targets(raw):
            if host not in seen and host not in excluded:
                seen.add(host)
                targets.append(ScanTarget(host=host))
    return targets
