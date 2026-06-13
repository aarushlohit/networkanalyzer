from __future__ import annotations

import random
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set, Any

from vulnsync.core.banner import grab_banner, identify_service, extract_version
from vulnsync.core.osdetect import probe_os
from vulnsync.core.packets import stealth_send
from vulnsync.core.targets import ScanProfile, ScanTarget
from vulnsync.utils.log import get_logger
from vulnsync.utils.throttle import RateLimiter

logger = get_logger("scanner")


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = "unknown"
    banner: Optional[str] = None
    version: Optional[str] = None
    os_hint: Optional[str] = None
    ssl_info: Optional[Dict[str, Any]] = None
    cve_list: List[Dict[str, Any]] = field(default_factory=list)
    cvss_score: Optional[float] = None


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)
    os_fingerprint: Optional[str] = None
    os_accuracy: int = 0
    alive: bool = False
    ping_time_ms: float = 0.0
    scan_start: str = ""
    scan_end: str = ""

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def open_count(self) -> int:
        return len(self.open_ports)

    @property
    def total_ports_scanned(self) -> int:
        return len(self.ports)

    @property
    def high_risk_count(self) -> int:
        return sum(1 for p in self.ports if p.cvss_score and p.cvss_score >= 7.0)

    @property
    def medium_risk_count(self) -> int:
        return sum(1 for p in self.ports if p.cvss_score and 4.0 <= p.cvss_score < 7.0)


@dataclass
class ScanResult:
    targets: List[HostResult] = field(default_factory=list)
    profile: Optional[ScanProfile] = None
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    total_hosts: int = 0
    alive_hosts: int = 0
    total_open_ports: int = 0

    def merge(self, other: ScanResult):
        self.targets.extend(other.targets)
        self.total_hosts += other.total_hosts
        self.alive_hosts += other.alive_hosts
        self.total_open_ports += other.total_open_ports


class PortScanner:
    def __init__(self, profile: ScanProfile):
        self.profile = profile
        self.rate_limiter = RateLimiter(
            max_rate=profile.rate,
            jitter_ms=profile.jitter_ms,
        )
        self._callbacks: List[Callable] = []
        self._stop_flag = False
        self._scan_id = random.randint(1000, 9999)

    def on_port_found(self, callback: Callable):
        self._callbacks.append(callback)

    def stop(self):
        self._stop_flag = True

    def _ping_host(self, host: str, port: int = 80) -> Tuple[bool, float]:
        start = time.monotonic()
        try:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(self.profile.timeout)
                s.connect((host, port))
                elapsed = (time.monotonic() - start) * 1000
                return True, round(elapsed, 1)
        except (socket.timeout, ConnectionRefusedError, OSError):
            try:
                family = socket.AF_INET6 if ":" in host else socket.AF_INET
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.settimeout(self.profile.timeout)
                    s.connect((host, 443))
                    elapsed = (time.monotonic() - start) * 1000
                    return True, round(elapsed, 1)
            except (socket.timeout, ConnectionRefusedError, OSError):
                return False, 0.0

    def _scan_port(self, host: str, port: int) -> PortResult:
        result = PortResult(port=port)
        self.rate_limiter.wait()

        if self._stop_flag:
            return result

        if self.profile.scan_type in ("syn", "fin", "null", "xmas"):
            sent = stealth_send(
                host, port, self.profile.scan_type,
                src_ip="10.0.0.1", src_port=54321,
            )
            if sent:
                result.state = "open" if self.profile.scan_type == "syn" else "open|filtered"
            else:
                result.state = "filtered"
            return result

        try:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(self.profile.timeout)
                result.state = s.connect_ex((host, port))
                if result.state == 0:
                    result.state = "open"
                    result.protocol = "tcp"
                    s.close()
                else:
                    result.state = "closed"
                    return result
        except (socket.timeout, OSError):
            result.state = "filtered"
            return result

        if result.state == "open" and self.profile.service_detect:
            banner = grab_banner(host, port, self.profile.timeout)
            if banner:
                result.banner = banner
                result.service = identify_service(port, banner)
                ver = extract_version(banner)
                if ver:
                    result.version = ver

        if result.state == "open" and port in (443, 8443, 465, 993, 995):
            result.ssl_info = self._check_ssl(host, port)

        return result

    def _check_ssl(self, host: str, port: int) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "tls_version": None,
            "cert_subject": None,
            "cert_issuer": None,
            "cert_expiry": None,
            "cert_valid": False,
            "weak_ciphers": [],
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=self.profile.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    info["tls_version"] = tls.version()
                    cert = tls.getpeercert()
                    if cert:
                        info["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
                        info["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
                        info["cert_expiry"] = cert.get("notAfter")
                        info["cert_valid"] = True

                    cipher = tls.cipher()
                    weak_suites = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"]
                    if cipher and any(w in str(cipher[0]).upper() for w in weak_suites):
                        info["weak_ciphers"].append(cipher[0])
        except (ssl.SSLError, socket.timeout, OSError) as e:
            logger.debug("SSL check failed %s:%d: %s", host, port, e)
        return info

    def scan_host(self, target: ScanTarget) -> HostResult:
        host = target.ip or target.host
        result = HostResult(ip=host, hostname=target.hostname)
        result.scan_start = datetime.now(timezone.utc).isoformat()

        alive, ping_ms = self._ping_host(host)
        if not alive and self.profile.no_ping:
            alive = True
        if not alive:
            result.scan_end = datetime.now(timezone.utc).isoformat()
            return result

        result.alive = alive
        result.ping_time_ms = ping_ms

        if self.profile.os_detect:
            osfp = probe_os(host, self.profile.ports[0] if self.profile.ports else 80)
            if osfp.os_family != "Unknown":
                result.os_fingerprint = osfp.os_family
                result.os_accuracy = osfp.accuracy

        ports_to_scan = self.profile.ports
        if self.profile.top_ports > 0:
            from vulnsync.utils.net import COMMON_PORTS
            top_key = f"top{self.profile.top_ports}"
            if top_key in COMMON_PORTS:
                ports_to_scan = COMMON_PORTS[top_key]

        if not ports_to_scan:
            ports_to_scan = list(range(1, 1025))

        max_workers = min(self.profile.threads, len(ports_to_scan))
        port_results: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._scan_port, host, port): port
                for port in ports_to_scan
                if port not in self.profile.exclude_ports
            }
            for future in as_completed(futures):
                if self._stop_flag:
                    executor.shutdown(wait=False)
                    break
                try:
                    pr = future.result()
                    port_results.append(pr)
                    if pr.state == "open":
                        for cb in self._callbacks:
                            cb(host, pr)
                except Exception as e:
                    logger.debug("Scan error %s:%d: %s", host, futures[future], e)

        result.ports = sorted(port_results, key=lambda p: p.port)
        result.scan_end = datetime.now(timezone.utc).isoformat()
        return result

    def scan(self, targets: List[ScanTarget]) -> ScanResult:
        global_result = ScanResult(
            profile=self.profile,
            start_time=datetime.now(timezone.utc).isoformat(),
        )

        for target in targets:
            if self._stop_flag:
                break
            try:
                host_result = self.scan_host(target)
                global_result.targets.append(host_result)
                if host_result.alive:
                    global_result.alive_hosts += 1
                global_result.total_open_ports += host_result.open_count
            except Exception as e:
                logger.error("Scan failed for %s: %s", target.host, e)

        global_result.total_hosts = len(targets)
        global_result.end_time = datetime.now(timezone.utc).isoformat()
        global_result.duration_seconds = (
            datetime.fromisoformat(global_result.end_time) -
            datetime.fromisoformat(global_result.start_time)
        ).total_seconds()

        return global_result
