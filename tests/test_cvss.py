import pytest

from vulnsync.vuln.cvss import CVSSResult


class TestCVSS:
    def test_default_construction(self):
        result = CVSSResult()
        assert result.score == 0.0
        assert result.severity == "None"

    def test_calculate(self):
        r = CVSSResult()
        r.calculate(9.8)
        assert r.score == pytest.approx(9.8, abs=0.1)
        assert r.severity == "CRITICAL"

    def test_low_severity(self):
        r = CVSSResult()
        r.calculate(2.5)
        assert r.severity == "LOW"

    def test_medium_severity(self):
        r = CVSSResult()
        r.calculate(5.0)
        assert r.severity == "MEDIUM"

    def test_high_severity(self):
        r = CVSSResult()
        r.calculate(7.5)
        assert r.severity == "HIGH"

    def test_zero_score(self):
        r = CVSSResult()
        r.calculate(0.0)
        assert r.severity == "None"

    def test_from_vector(self):
        r = CVSSResult()
        r.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r.severity in ("CRITICAL", "HIGH")
        assert r.score > 7.0
