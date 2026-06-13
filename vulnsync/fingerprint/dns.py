from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import dns.resolver
import dns.query
import dns.zone
import dns.reversename

from vulnsync.utils.log import get_logger

logger = get_logger("dns")


@dataclass
class DNSResult:
    domain: str
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[Dict[str, str]] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_records: List[Dict[str, str]] = field(default_factory=list)
    soa_record: Optional[Dict[str, str]] = None
    caa_records: List[str] = field(default_factory=list)
    zone_transfer_possible: bool = False
    zone_transfer_records: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ptr_record: Optional[str] = None
    errors: Dict[str, str] = field(default_factory=dict)

    @property
    def has_mx(self) -> bool:
        return len(self.mx_records) > 0

    @property
    def has_spf(self) -> bool:
        return any("v=spf1" in t for t in self.txt_records)

    @property
    def has_dkim(self) -> bool:
        return any("v=DKIM1" in t for t in self.txt_records)

    @property
    def has_dmarc(self) -> bool:
        return any("v=DMARC1" in t for t in self.txt_records)


COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "cdn", "api", "dev", "test",
    "staging", "ftp", "pop", "owa", "exchange", "autodiscover", "m",
    "img", "static", "assets", "portal", "support", "help", "forum",
    "community", "shop", "store", "status", "git", "jenkins", "jira",
    "confluence", "wiki", "docs", "app", "dashboard", "backup", "db",
    "mysql", "redis", "monitor", "grafana", "prometheus", "kibana",
    "elastic", "kafka", "rabbitmq", "consul", "vault", "jenkins",
    "sonar", "nexus", "artifactory", "docker", "k8s", "kubernetes",
    "swagger", "graphql", "api-docs", "rest", "soap", "webhook",
    "callback", "proxy", "gateway", "firewall", "router", "switch",
    "dns1", "dns2", "mx1", "mx2", "imap", "imap4", "pop3",
]


def enumerate_dns(domain: str, nameserver: Optional[str] = None,
                  timeout: float = 5.0) -> DNSResult:
    result = DNSResult(domain=domain)
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameserver:
        resolver.nameservers = [nameserver]

    queries = {
        "A": ("a_records", False),
        "AAAA": ("aaaa_records", False),
        "MX": ("mx_records", True),
        "NS": ("ns_records", False),
        "TXT": ("txt_records", False),
        "CNAME": ("cname_records", True),
        "CAA": ("caa_records", False),
        "SOA": ("soa_record", True),
    }

    for rtype, (attr, is_complex) in queries.items():
        try:
            answers = resolver.resolve(domain, rtype)
            if is_complex:
                if rtype == "MX":
                    setattr(result, attr, [
                        {"preference": str(mx.preference), "target": str(mx.exchange)}
                        for mx in answers
                    ])
                elif rtype == "CNAME":
                    setattr(result, attr, [
                        {"alias": domain, "canonical": str(cname.target)}
                        for cname in answers
                    ])
                elif rtype == "SOA":
                    soa = answers[0]
                    setattr(result, attr, {
                        "mname": str(soa.mname),
                        "rname": str(soa.rname),
                        "serial": str(soa.serial),
                        "refresh": str(soa.refresh),
                        "retry": str(soa.retry),
                        "expire": str(soa.expire),
                        "minimum": str(soa.minimum),
                    })
            else:
                setattr(result, attr, [str(a) for a in answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            result.errors[rtype] = str(e)
        except Exception as e:
            result.errors[rtype] = str(e)

    try:
        rev = dns.reversename.from_address(result.a_records[0]) if result.a_records else None
        if rev:
            ptr = resolver.resolve(rev, "PTR")
            result.ptr_record = str(ptr[0])
    except Exception:
        pass

    return result


def try_zone_transfer(domain: str, nameservers: Optional[List[str]] = None) -> DNSResult:
    result = DNSResult(domain=domain)
    ns_list = nameservers or []

    if not ns_list:
        try:
            resolver = dns.resolver.Resolver()
            ns_answers = resolver.resolve(domain, "NS")
            ns_list = [str(ns) for ns in ns_answers]
        except Exception:
            return result

    for ns in ns_list:
        try:
            ns_ip = socket.gethostbyname(ns)
            axfr = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            if axfr:
                result.zone_transfer_possible = True
                for name, node in axfr.nodes.items():
                    result.zone_transfer_records.append(f"{name} {node.to_text(axfr)}")
                break
        except (socket.gaierror, dns.exception.DNSException, OSError):
            continue

    return result


def brute_subdomains(domain: str, wordlist: Optional[List[str]] = None,
                     timeout: float = 3.0, threads: int = 20) -> List[str]:
    found: List[str] = []
    subs = wordlist or COMMON_SUBDOMAINS

    import concurrent.futures
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    def check_sub(sub: str) -> Optional[str]:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            if answers:
                return fqdn
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_sub, sub): sub for sub in subs}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    found.append(result)
            except Exception:
                continue

    return sorted(found)
