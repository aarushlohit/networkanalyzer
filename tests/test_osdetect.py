import pytest

from vulnsync.core.osdetect import OSFingerprint, _resolve_os
from vulnsync.core.osdetect import TTL_SIGNATURES, WINDOW_SIGNATURES


class TestOSFingerprint:
    def test_linux_ttl(self):
        fp = OSFingerprint(ttl=64, window_size=29200)
        _resolve_os(fp)
        assert "Linux" in fp.os_family

    def test_windows_ttl(self):
        fp = OSFingerprint(ttl=128, window_size=65520)
        _resolve_os(fp)
        assert "Windows" in fp.os_family

    def test_network_device_ttl(self):
        fp = OSFingerprint(ttl=255, window_size=65535)
        _resolve_os(fp)
        assert "macOS" in fp.os_family or "FreeBSD" in fp.os_family or "Solaris" in fp.os_family

    def test_low_ttl(self):
        fp = OSFingerprint(ttl=32, window_size=8192)
        _resolve_os(fp)
        assert "Windows" in fp.os_family

    def test_small_ttl_no_window(self):
        fp = OSFingerprint(ttl=1, window_size=0)
        _resolve_os(fp)
        assert "Windows" in fp.os_family

    def test_ttl_signatures(self):
        assert 64 in TTL_SIGNATURES
        assert 128 in TTL_SIGNATURES
        assert 255 in TTL_SIGNATURES

    def test_window_signatures(self):
        assert 5840 in WINDOW_SIGNATURES
        assert 65535 in WINDOW_SIGNATURES

    def test_dataclass_defaults(self):
        fp = OSFingerprint()
        assert fp.os_family == "Unknown"
        assert fp.accuracy == 0
