from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from vulnsync.core.config import load_config
from vulnsync.core.targets import ScanProfile, build_targets
from vulnsync.utils.log import get_logger

logger = get_logger("precommit")


def find_changed_hosts(staged_files: List[str]) -> List[str]:
    hosts = []
    for f in staged_files:
        p = Path(f)
        if p.suffix in (".yml", ".yaml", ".json", ".toml", ".ini"):
            try:
                text = p.read_text()
                import re
                found = re.findall(
                    r"(?:\d{1,3}\.){3}\d{1,3}|"
                    r"(?:https?://)?[\w.-]+\.(?:com|org|net|io|dev|app)(?::\d+)?",
                    text,
                )
                hosts.extend(found)
            except Exception:
                pass
    return hosts


def run_precommit_scan(staged_files: Optional[List[str]] = None) -> int:
    if staged_files is None:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True
        )
        staged_files = result.stdout.strip().split("\n") if result.stdout else []

    if not staged_files or not any(f.endswith((".yml", ".yaml", ".json", ".toml", ".ini"))
                                    for f in staged_files):
        print("  ✓ VulnSync pre-commit: no config files changed, skipping")
        return 0

    changed_hosts = find_changed_hosts(staged_files)
    if not changed_hosts:
        print("  ✓ VulnSync pre-commit: no host entries detected in changes")
        return 0

    print(f"  🔍 VulnSync scanning {len(changed_hosts)} host(s) from changed files...")
    config = load_config()
    profile = ScanProfile(
        scan_type="tcp",
        ports=[22, 80, 443, 8080, 8443],
        threads=20,
        timeout=3.0,
        service_detect=True,
        os_detect=False,
        no_ping=True,
    )

    from vulnsync.core.scanner import PortScanner
    from vulnsync.core.targets import ScanTarget

    scanner = PortScanner(profile)
    targets = [ScanTarget(host=ip) for ip in changed_hosts[:5]]
    result = scanner.scan(targets)

    critical_findings = [
        (h, p) for h in result.targets for p in h.ports
        if p.state == "open" and p.cvss_score and p.cvss_score >= 9.0
    ]

    if critical_findings:
        print("  ❌ VulnSync pre-commit: BLOCKING — Critical vulnerabilities found:")
        for h, p in critical_findings:
            cves = ", ".join(c.get("cve", "") for c in p.cve_list[:3])
            print(f"     {h.ip}:{p.port} ({p.service}) CVSS {p.cvss_score} {cves}")
        return 1

    if result.alive_hosts > 0:
        print(f"  ✓ VulnSync pre-commit: {result.alive_hosts} hosts, "
              f"{result.total_open_ports} open ports — no critical issues")
    return 0


def main():
    sys.exit(run_precommit_scan())


if __name__ == "__main__":
    main()
