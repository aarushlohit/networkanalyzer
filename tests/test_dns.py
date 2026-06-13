import pytest

from vulnsync.fingerprint.dns import DNSResult, enumerate_dns


class TestEnumerateDns:
    def test_resolve(self):
        result = enumerate_dns("google.com", timeout=3.0)
        assert isinstance(result, DNSResult)
        assert len(result.a_records) > 0

    def test_resolve_nonexistent(self):
        result = enumerate_dns("nonexistent-domain-xyz-123456.com", timeout=2.0)
        assert isinstance(result, DNSResult)
        assert len(result.errors) > 0 or len(result.a_records) == 0


class TestDNSResult:
    def test_properties(self):
        r = DNSResult(
            domain="test.com",
            txt_records=["v=spf1 include:_spf.google.com ~all"],
        )
        assert r.has_spf is True
        assert r.has_dkim is False
        assert r.has_mx is False

    def test_with_dkim(self):
        r = DNSResult(
            domain="test.com",
            txt_records=["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"],
        )
        assert r.has_dkim is True

    def test_with_dmarc(self):
        r = DNSResult(
            domain="test.com",
            txt_records=["v=DMARC1; p=none; rua=mailto:dmarc@test.com"],
        )
        assert r.has_dmarc is True

    def test_defaults(self):
        r = DNSResult(domain="")
        assert r.a_records == []
        assert r.has_mx is False
        assert r.has_spf is False
