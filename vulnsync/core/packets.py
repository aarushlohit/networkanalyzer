from __future__ import annotations

import socket
import struct
from typing import Optional


def _checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def create_ip_header(src: str, dst: str, proto: int, payload_len: int) -> bytes:
    ver_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ip_id = 0x1234
    flags_offset = 0
    ttl = 64
    s_addr = socket.inet_aton(src)
    d_addr = socket.inet_aton(dst)
    header = struct.pack('!BBHHHBBH', ver_ihl, tos, total_len, ip_id, flags_offset, ttl, proto, 0)
    pseudo = header + s_addr + d_addr
    cksum = _checksum(pseudo)
    header = struct.pack('!BBHHHBBH', ver_ihl, tos, total_len, ip_id, flags_offset, ttl, proto, cksum)
    return header + s_addr + d_addr


def create_tcp_syn(src: str, dst: str, sport: int, dport: int, seq: int = 12345) -> bytes:
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x02, 65535, 0, 0)
    pseudo_hdr = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 6, 0, 20)
    cksum = _checksum(pseudo_hdr + tcp_hdr)
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x02, 65535, 0, cksum)
    ip_hdr = create_ip_header(src, dst, 6, 20)
    return ip_hdr + tcp_hdr


def create_tcp_fin(src: str, dst: str, sport: int, dport: int) -> bytes:
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, 0, 0, 0x50, 0x01, 65535, 0, 0)
    pseudo_hdr = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 6, 0, 20)
    cksum = _checksum(pseudo_hdr + tcp_hdr)
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, 0, 0, 0x50, 0x01, 65535, 0, cksum)
    ip_hdr = create_ip_header(src, dst, 6, 20)
    return ip_hdr + tcp_hdr


def create_tcp_null(src: str, dst: str, sport: int, dport: int) -> bytes:
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, 0, 0, 0x50, 0x00, 65535, 0, 0)
    pseudo_hdr = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 6, 0, 20)
    cksum = _checksum(pseudo_hdr + tcp_hdr)
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, 0, 0, 0x50, 0x00, 65535, 0, cksum)
    ip_hdr = create_ip_header(src, dst, 6, 20)
    return ip_hdr + tcp_hdr


def create_tcp_xmas(src: str, dst: str, sport: int, dport: int) -> bytes:
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, 0, 0, 0x50, 0x29, 65535, 0, 0)
    pseudo_hdr = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 6, 0, 20)
    cksum = _checksum(pseudo_hdr + tcp_hdr)
    tcp_hdr = struct.pack('!HHIIBBHHH', sport, dport, 0, 0, 0x50, 0x29, 65535, 0, cksum)
    ip_hdr = create_ip_header(src, dst, 6, 20)
    return ip_hdr + tcp_hdr


def send_raw_syn(src_ip: str, dst_ip: str, src_port: int, dport: int, timeout: float = 2.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.settimeout(timeout)
        packet = create_tcp_syn(src_ip, dst_ip, src_port, dport)
        sock.sendto(packet, (dst_ip, 0))
        sock.close()
        return True
    except (socket.error, PermissionError):
        return False


def stealth_send(dst_ip: str, dport: int, scan_type: str,
                 src_ip: str = "10.0.0.1", src_port: int = 54321) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.settimeout(1.0)
        creators = {
            "syn": create_tcp_syn,
            "fin": create_tcp_fin,
            "null": create_tcp_null,
            "xmas": create_tcp_xmas,
        }
        creator = creators.get(scan_type)
        if not creator:
            return False
        packet = creator(src_ip, dst_ip, src_port, dport)
        sock.sendto(packet, (dst_ip, 0))
        sock.close()
        return True
    except (socket.error, PermissionError):
        return False
