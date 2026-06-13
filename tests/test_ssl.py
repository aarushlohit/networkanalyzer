import pytest

from vulnsync.fingerprint.ssl import SSLAuditResult, audit_tls


class TestAuditTLS:
    def test_invalid_host(self):
        result = audit_tls("nonexistent.invalid", 443, timeout=2.0)
        assert isinstance(result, SSLAuditResult)

    def test_valid_host(self):
        result = audit_tls("google.com", 443, timeout=5.0)
        assert isinstance(result, SSLAuditResult)
        assert result.grade in ("A", "A+", "B", "C", "D", "F")


class TestSSLAuditResult:
    def test_weak_protocol(self):
        r = SSLAuditResult(
            host="test.com",
            tls_versions={"SSLv3": True},
        )
        assert r.has_weak_protocol is True

    def test_no_weak_protocol(self):
        r = SSLAuditResult(
            host="test.com",
            tls_versions={"TLSv1.2": True, "TLSv1.3": True},
        )
        assert r.has_weak_protocol is False

    def test_tls_1_3_property(self):
        r = SSLAuditResult(host="test.com", tls_versions={"TLSv1.3": True})
        assert r.tls_1_3 is True

    def test_score(self):
        r = SSLAuditResult(
            host="test.com",
            tls_versions={"TLSv1.3": True},
            weak_ciphers=[],
            strong_ciphers=["TLS_AES_256_GCM_SHA384"],
        )
        assert r.score > 50

    def test_defaults(self):
        r = SSLAuditResult(host="localhost")
        assert r.port == 443
