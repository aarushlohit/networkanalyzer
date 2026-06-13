from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

from vulnsync.utils.log import get_logger

logger = get_logger("webtech")

TECH_PATTERNS: Dict[str, List[Tuple[str, str, str]]] = {
    "Nginx": [
        (r'nginx/([\d.]+)', "header", "Server"),
        (r'nginx', "header", "Server"),
    ],
    "Apache HTTP Server": [
        (r'Apache(?:/([\d.]+))?', "header", "Server"),
        (r'Apache', "header", "Server"),
    ],
    "Microsoft IIS": [
        (r'Microsoft-IIS/([\d.]+)', "header", "Server"),
        (r'IIS', "header", "X-Powered-By"),
    ],
    "Cloudflare": [
        (r'cloudflare', "header", "Server"),
        (r'__cfduid', "cookie", None),
        (r'cf-ray', "header", None),
    ],
    "WordPress": [
        (r'/wp-content/', "body", None),
        (r'/wp-admin/', "body", None),
        (r'wp-json', "body", None),
        (r'WordPress', "header", "X-Powered-By"),
    ],
    "Drupal": [
        (r'Drupal', "header", "X-Generator"),
        (r'Drupal', "header", "X-Drupal"),
        (r'sites/default/files', "body", None),
    ],
    "Joomla": [
        (r'/media/system/js/', "body", None),
        (r'Joomla', "header", "X-Generator"),
    ],
    "Laravel": [
        (r'Laravel', "header", "X-Powered-By"),
        (r'__cfduid', "cookie", None),
        (r'laravel_session', "cookie", None),
    ],
    "Django": [
        (r'Django', "header", "X-Powered-By"),
        (r'csrftoken', "cookie", None),
        (r'sessionid', "cookie", None),
    ],
    "Node.js/Express": [
        (r'Express', "header", "X-Powered-By"),
        (r'Node\.?js', "header", "X-Powered-By"),
        (r'^connect.sid', "cookie", None),
    ],
    "React": [
        (r'data-reactroot', "body", None),
        (r'data-reactid', "body", None),
        (r'__NEXT_DATA__', "body", None),
        (r'react', "body", None),
    ],
    "Vue.js": [
        (r'__VUE__', "body", None),
        (r'vue-app', "body", None),
        (r'data-v-', "body", None),
    ],
    "Angular": [
        (r'ng-version', "body", None),
        (r'_angular', "body", None),
    ],
    "jQuery": [
        (r'jquery', "body", None),
        (r'\$\.', "body", None),
    ],
    "Bootstrap": [
        (r'bootstrap', "body", None),
        (r'data-bs-', "body", None),
    ],
    "PHP": [
        (r'X-Powered-By: PHP/([\d.]+)', "header", None),
        (r'\.php', "body", None),
        (r'PHPSESSID', "cookie", None),
    ],
    "ASP.NET": [
        (r'ASP\.NET', "header", "X-Powered-By"),
        (r'X-AspNet-Version', "header", None),
        (r'__VIEWSTATE', "body", None),
    ],
    "Python": [
        (r'Python/([\d.]+)', "header", "Server"),
        (r'WSGIServer', "header", "Server"),
    ],
    "Ruby on Rails": [
        (r'Rails', "header", "X-Powered-By"),
        (r'rails', "body", None),
    ],
    "Tomcat": [
        (r'Apache.*Tomcat', "header", "Server"),
        (r'Catalina', "header", "X-Powered-By"),
        (r'JSESSIONID', "cookie", None),
    ],
    "JBoss": [
        (r'JBoss', "header", "X-Powered-By"),
    ],
    "Varnish": [
        (r'Varnish', "header", None),
    ],
    "HAProxy": [
        (r'haproxy', "header", None),
    ],
    "WebSocket": [
        (r'Upgrade: websocket', "header", None),
    ],
}


@dataclass
class WebTechResult:
    name: str
    version: Optional[str] = None
    confidence: int = 0

    def __hash__(self):
        return hash(self.name)


@dataclass
class WebFingerprint:
    url: str
    status_code: int = 0
    server: Optional[str] = None
    title: Optional[str] = None
    technologies: List[WebTechResult] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0.0
    content_length: int = 0
    security_headers: Dict[str, bool] = field(default_factory=dict)

    @property
    def tech_summary(self) -> str:
        return ", ".join(
            f"{t.name}{' ' + t.version if t.version else ''}"
            for t in self.technologies
        )


SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
    "X-XSS-Protection": "X-XSS-Protection",
}


def fingerprint_web(url: str, timeout: float = 5.0) -> Optional[WebFingerprint]:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    try:
        start = __import__("time").time()
        resp = requests.get(
            url, timeout=timeout, verify=False,
            headers={"User-Agent": "VulnSync/2.0 Security Scanner"},
            allow_redirects=True,
        )
        elapsed = round((__import__("time").time() - start) * 1000, 1)
    except requests.RequestException as e:
        logger.debug("Web fingerprint failed for %s: %s", url, e)
        return None

    import warnings
    warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

    fp = WebFingerprint(
        url=url,
        status_code=resp.status_code,
        server=resp.headers.get("Server"),
        headers=dict(resp.headers),
        cookies=dict(resp.cookies),
        response_time_ms=elapsed,
        content_length=len(resp.content),
    )

    title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
    if title_match:
        fp.title = title_match.group(1).strip()[:200]

    body = resp.text
    for tech, patterns in TECH_PATTERNS.items():
        for pattern, source, field_name in patterns:
            try:
                if source == "header":
                    header_val = resp.headers.get(field_name or "", "")
                    if "Server" in tech or header_val:
                        m = re.search(pattern, str(resp.headers), re.IGNORECASE)
                        if m:
                            ver = m.group(1) if m.lastindex and m.group(1) else None
                            existing = next((t for t in fp.technologies if t.name == tech), None)
                            if existing:
                                existing.confidence = min(100, existing.confidence + 40)
                                if ver and not existing.version:
                                    existing.version = ver
                            else:
                                fp.technologies.append(WebTechResult(tech, ver, 70))
                elif source == "cookie":
                    cookie_str = "; ".join(f"{k}={v}" for k, v in resp.cookies.items())
                    if re.search(pattern, cookie_str, re.IGNORECASE):
                        if not any(t.name == tech for t in fp.technologies):
                            fp.technologies.append(WebTechResult(tech, confidence=60))
                elif source == "body":
                    if re.search(pattern, body, re.IGNORECASE):
                        if not any(t.name == tech for t in fp.technologies):
                            fp.technologies.append(WebTechResult(tech, confidence=50))
            except (re.error, TypeError):
                continue

    for header, name in SECURITY_HEADERS.items():
        fp.security_headers[name] = header in resp.headers

    fp.technologies = sorted(set(fp.technologies), key=lambda t: t.confidence, reverse=True)
    return fp
