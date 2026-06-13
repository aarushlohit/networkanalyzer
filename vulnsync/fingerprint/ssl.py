from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from vulnsync.utils.log import get_logger

logger = get_logger("ssl")


@dataclass
class SSLAuditResult:
    host: str
    port: int = 443
    tls_versions: Dict[str, bool] = field(default_factory=dict)
    certificate: Optional[Dict[str, str]] = None
    cert_expiry_days: Optional[int] = None
    cert_expired: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    sni: Optional[str] = None
    weak_ciphers: List[str] = field(default_factory=list)
    strong_ciphers: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    grade: str = "F"

    @property
    def tls_1_3(self) -> bool:
        return self.tls_versions.get("TLSv1.3", False)

    @property
    def has_weak_protocol(self) -> bool:
        return any(self.tls_versions.get(v, False) for v in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"])

    @property
    def score(self) -> int:
        s = 0
        if self.tls_versions.get("TLSv1.3"): s += 30
        if self.tls_versions.get("TLSv1.2"): s += 25
        if not self.has_weak_protocol: s += 20
        if self.cert_expired: s -= 30
        if self.cert_expiry_days and self.cert_expiry_days < 30: s -= 10
        if not self.weak_ciphers: s += 15
        if self.strong_ciphers: s += 10
        return max(0, min(100, s))


TLS_VERSIONS = {
    ssl.TLSVersion.SSLv3: "SSLv3",
    ssl.TLSVersion.TLSv1: "TLSv1",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}

WEAK_CIPHER_INDICATORS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "IDEA", "SEED",
                          "aNULL", "eNULL", "LOW", "ADH", "anon"]


def audit_tls(host: str, port: int = 443, timeout: float = 5.0) -> SSLAuditResult:
    result = SSLAuditResult(host=host, port=port)
    result.sni = host

    for tls_min, tls_max, name in [
        (ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.SSLv3, "SSLv3"),
        (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1, "TLSv1"),
        (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
        (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
        (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = tls_min
            ctx.maximum_version = tls_max
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    result.tls_versions[name] = True
                    if name == "TLSv1.2":
                        cert = tls.getpeercert()
                        if cert:
                            from operator import itemgetter
                            result.subject = dict(itemgetter(*[x[0] for x in cert.get("subject", [])])) if cert.get("subject") else None
                            result.issuer = dict(itemgetter(*[x[0] for x in cert.get("issuer", [])])) if cert.get("issuer") else None
                            result.certificate = {
                                "subject": str(result.subject),
                                "issuer": str(result.issuer),
                                "notBefore": cert.get("notBefore", ""),
                                "notAfter": cert.get("notAfter", ""),
                                "serial": str(cert.get("serialNumber", "")),
                            }
                            if cert.get("notAfter"):
                                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                                result.cert_expiry_days = (expiry - datetime.now()).days
                                result.cert_expired = result.cert_expiry_days < 0
        except (ssl.SSLError, socket.timeout, OSError):
            result.tls_versions[name] = False

    if result.tls_versions.get("SSLv3"):
        result.vulnerabilities.append("SSLv3 enabled (POODLE attack)")
    if result.tls_versions.get("TLSv1"):
        result.vulnerabilities.append("TLS 1.0 enabled (deprecated)")
    if result.tls_versions.get("TLSv1.1"):
        result.vulnerabilities.append("TLS 1.1 enabled (deprecated)")
    if result.cert_expired:
        result.vulnerabilities.append("SSL certificate expired")
    if result.cert_expiry_days and result.cert_expiry_days < 30:
        result.vulnerabilities.append(f"SSL certificate expires in {result.cert_expiry_days} days")

    score = result.score
    if score >= 85:
        result.grade = "A"
    elif score >= 70:
        result.grade = "B"
    elif score >= 50:
        result.grade = "C"
    elif score >= 30:
        result.grade = "D"
    else:
        result.grade = "F"

    return result
