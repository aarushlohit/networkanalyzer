import pytest

from vulnsync.vuln.cve import CVEEngine, CVEMatch, VULNERABLE_SERVICES, _parse_version


class TestCVEEngine:
    def test_init(self):
        engine = CVEEngine()
        assert len(VULNERABLE_SERVICES) > 0

    def test_match_openssh_vulnerable(self):
        engine = CVEEngine()
        matches = engine.match_service("openssh", "8.0p1")
        assert len(matches) > 0
        assert all(isinstance(m, CVEMatch) for m in matches)

    def test_match_service_no_match(self):
        engine = CVEEngine()
        matches = engine.match_service("unknown_service_xyz", "1.0")
        assert len(matches) == 0

    def test_match_by_alias(self):
        engine = CVEEngine()
        matches = engine.match_service("openssh", "7.9p1")
        assert len(matches) > 0

    def test_match_no_version(self):
        engine = CVEEngine()
        matches = engine.match_service("openssh", None)
        assert len(matches) == 0

    def test_match_apache_vulnerable(self):
        engine = CVEEngine()
        matches = engine.match_service("apache", "2.4.48")
        assert len(matches) > 0

    def test_cve_match_creation(self):
        cve = CVEMatch(
            cve_id="CVE-2024-1234",
            cvss_score=9.8,
            description="Test vuln",
            severity="CRITICAL",
            affected_version="1.0",
            remediation="Upgrade to 2.0",
        )
        assert cve.cve_id == "CVE-2024-1234"
        assert cve.cvss_score == 9.8

    def test_version_parsing(self):
        assert _parse_version("7.9") == (7, 9)
        assert _parse_version("2.4.51") == (2, 4, 51)
        assert _parse_version("1.21.0") == (1, 21, 0)
        assert _parse_version("8.0p1") == (8, 0, 1)

    def test_openssh_regresshion_vulnerable(self):
        engine = CVEEngine()
        matches = engine.match_service("openssh", "4.4p1")
        cves = [m.cve_id for m in matches]
        assert "CVE-2024-6387" in cves

    def test_openssh_patched_not_vulnerable(self):
        engine = CVEEngine()
        matches = engine.match_service("openssh", "9.8p1")
        cves = [m.cve_id for m in matches]
        assert "CVE-2024-6387" not in cves
