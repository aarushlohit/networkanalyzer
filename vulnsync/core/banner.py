from __future__ import annotations

import socket
from typing import Dict, Optional

from vulnsync.utils.log import get_logger

logger = get_logger("banner")

BANNER_TIMEOUT = 5.0
BANNER_SIZE = 4096

SERVICE_PROBES: Dict[int, bytes] = {
    21: b"",
    22: b"",
    23: b"",
    25: b"",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",
    143: b"",
    443: b"",
    445: b"",
    993: b"",
    995: b"",
    3306: b"",
    5432: b"",
    5900: b"",
    6379: b"",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"",
    27017: b"",
}

KNOWN_BANNERS: Dict[str, str] = {
    "OpenSSH": "ssh",
    "Apache httpd": "apache",
    "nginx": "nginx",
    "MySQL": "mysql",
    "PostgreSQL": "postgresql",
    "vsftpd": "ftp",
    "ProFTPD": "ftp",
    "Microsoft-IIS": "iis",
    "lighttpd": "lighttpd",
    "couchdb": "couchdb",
    "mongodb": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "docker": "docker",
    "kubernetes": "kubernetes",
}


def grab_banner(host: str, port: int, timeout: float = BANNER_TIMEOUT) -> Optional[str]:
    probe = SERVICE_PROBES.get(port, b"")
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if probe:
                s.send(probe)
            try:
                banner = s.recv(BANNER_SIZE)
                decoded = _clean_banner(banner)
                if decoded:
                    return decoded
            except (socket.timeout, ConnectionResetError, OSError):
                pass
            try:
                s.send(b"\r\n")
                banner = s.recv(BANNER_SIZE)
                decoded = _clean_banner(banner)
                if decoded:
                    return decoded
            except (socket.timeout, ConnectionResetError, OSError):
                pass
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("Banner grab failed %s:%d: %s", host, port, e)
    return None


def _clean_banner(data: bytes) -> Optional[str]:
    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:
        text = data.decode("latin-1", errors="replace").strip()
    text = text.replace("\r\n", " | ").replace("\n", " | ")
    text = " ".join(text.split())
    return text[:500] if text else None


def identify_service(port: int, banner: Optional[str] = None) -> str:
    common: Dict[int, str] = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
        995: "pop3s", 1433: "ms-sql-s", 1521: "oracle-tns", 2049: "nfs",
        3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
        5900: "vnc", 5985: "wsman", 6379: "redis", 8080: "http-proxy",
        8443: "https-alt", 9090: "http-alt", 27017: "mongod",
    }
    if not banner:
        return common.get(port, "unknown")
    for known_sig, svc in KNOWN_BANNERS.items():
        if known_sig.lower() in banner.lower():
            return svc
    return common.get(port, "unknown")


def extract_version(banner: str) -> Optional[str]:
    import re
    patterns = [
        r'(\d+\.\d+(?:\.\d+)?[a-z0-9]*)',
        r'version\s+(\d+\.\d+(?:\.\d+)?)',
        r'v(\d+\.\d+(?:\.\d+)?)',
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1)
    return None
