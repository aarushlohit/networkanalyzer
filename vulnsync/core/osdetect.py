from __future__ import annotations

import struct
import socket
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

TTL_SIGNATURES: Dict[int, str] = {
    32: "Windows 95/98/NT",
    64: "Linux / macOS / BSD / Solaris",
    128: "Windows NT/2000/XP/7/8/10/11",
    255: "Cisco IOS / UNIX",
}

WINDOW_SIGNATURES: Dict[int, str] = {
    5840: "Linux 2.4+",
    5720: "Linux 2.4",
    65535: "FreeBSD / macOS / Solaris",
    8192: "Windows 2000",
    16384: "Windows XP/2003",
    65520: "Windows 7/8/10/11",
    64240: "Windows 10/11",
    14600: "Linux 2.6+",
    29200: "Linux 3.x+",
}


@dataclass
class OSFingerprint:
    os_family: str = "Unknown"
    accuracy: int = 0
    ttl: int = 0
    window_size: int = 0
    ttl_based: str = ""
    window_based: str = ""


def probe_os(host: str, port: int = 80, timeout: float = 3.0) -> OSFingerprint:
    result = OSFingerprint()
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            ttl, win = _get_tcp_info(s)
            result.ttl = ttl
            result.window_size = win

            if ttl:
                result.ttl_based = TTL_SIGNATURES.get(ttl, f"Unusual TTL ({ttl})")
            if win:
                result.window_based = WINDOW_SIGNATURES.get(win, "")

            _resolve_os(result)
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return result


def _get_tcp_info(sock: socket.socket) -> Tuple[int, int]:
    try:
        import sys
        if sys.platform == "linux":
            TCP_INFO = 11
            info = sock.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 100)
            ttl = info[12] if len(info) > 12 else 0
            win = 0
            if len(info) >= 20:
                win = struct.unpack_from("<H", info, 18)[0]
            return ttl, win
    except (OSError, struct.error):
        pass
    return 0, 0


def probe_ttl_ping(host: str) -> Tuple[int, int]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(3.0)
        sock.connect((host, 1))
        sock.close()
    except (socket.error, PermissionError):
        pass
    return 64, 0


def _resolve_os(fp: OSFingerprint):
    if fp.ttl <= 32:
        fp.os_family = "Windows (9x/NT)"
        fp.accuracy = max(fp.accuracy, 60)
    elif fp.ttl <= 64:
        fp.os_family = "Linux / Unix"
        fp.accuracy = max(fp.accuracy, 70)
    elif fp.ttl <= 128:
        fp.os_family = "Windows (NT+)"
        fp.accuracy = max(fp.accuracy, 80)
    elif fp.ttl <= 255:
        fp.os_family = "Network Device (Cisco/Juniper)"
        fp.accuracy = max(fp.accuracy, 60)

    if fp.window_size in WINDOW_SIGNATURES:
        os_hint = WINDOW_SIGNATURES[fp.window_size]
        fp.accuracy = max(fp.accuracy, 80)
        if "Linux" in os_hint:
            fp.os_family = os_hint
        elif "Windows" in os_hint:
            fp.os_family = os_hint
        elif "FreeBSD" in os_hint or "macOS" in os_hint:
            fp.os_family = os_hint
