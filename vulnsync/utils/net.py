from __future__ import annotations

import ipaddress
import re
import socket
from typing import Generator, List, Optional, Tuple

PORT_REGEX = re.compile(r'^(\d+)(?:-(\d+))?$')

COMMON_PORTS: dict[str, list[int]] = {
    "top20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
              993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 8080, 8443],
    "top100": [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106,
               110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
               443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
               593, 625, 631, 636, 646, 648, 666, 808, 873, 990, 992, 993,
               995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1604,
               1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000,
               3128, 3306, 3389, 3986, 4000, 4001, 4045, 4500, 4899, 5000,
               5001, 5009, 5050, 5060, 5101, 5190, 5357, 5432, 5555, 5631,
               5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
               8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 10000, 32768,
               32769, 32770, 32771, 32772, 32773, 32774, 32775, 49152, 49153,
               49154, 49155, 49156],
}


def is_valid_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_valid_hostname(host: str) -> bool:
    if len(host) > 253:
        return False
    label = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)$'
    return all(re.match(label, part) for part in host.split('.'))


def resolve_host(host: str) -> Optional[str]:
    if is_valid_ip(host):
        return host
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def parse_ports(port_spec: str) -> List[int]:
    ports: List[int] = []
    for part in port_spec.split(','):
        part = part.strip()
        m = PORT_REGEX.match(part)
        if not m:
            continue
        start = int(m.group(1))
        end = m.group(2)
        if end:
            ports.extend(range(start, min(int(end) + 1, 65536)))
        else:
            if 1 <= start <= 65535:
                ports.append(start)
    return sorted(set(p for p in ports if 1 <= p <= 65535))


def parse_targets(target_spec: str) -> Generator[str, None, None]:
    if '/' in target_spec:
        try:
            network = ipaddress.ip_network(target_spec, strict=False)
            yield from (str(ip) for ip in network.hosts())
        except ValueError:
            yield target_spec
    elif '-' in target_spec and not is_valid_hostname(target_spec):
        parts = target_spec.split('-')
        base = parts[0].rstrip('0123456789')
        start = int(''.join(c for c in parts[0] if c.isdigit()))
        end = int(parts[1])
        for i in range(start, end + 1):
            yield f"{base}{i}"
    else:
        yield target_spec


def parse_target_file(path: str) -> List[str]:
    targets: List[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                targets.extend(parse_targets(line))
    return targets


class PortStatus:
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"
