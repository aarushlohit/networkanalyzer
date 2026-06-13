import pytest

from vulnsync.utils.net import (
    PortStatus,
    is_valid_ip,
    is_valid_hostname,
    parse_ports,
    parse_targets,
    resolve_host,
)


class TestTargetParsing:
    def test_valid_ip(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("10.0.0.1")
        assert is_valid_ip("172.16.0.1")
        assert is_valid_ip("8.8.8.8")

    def test_invalid_ip(self):
        assert not is_valid_ip("999.999.999.999")
        assert not is_valid_ip("abc.def.ghi.hjk")
        assert not is_valid_ip("256.0.0.1")
        assert not is_valid_ip("")

    def test_valid_hostname(self):
        assert is_valid_hostname("example.com")
        assert is_valid_hostname("sub.domain.co.uk")
        assert is_valid_hostname("localhost")
        assert is_valid_hostname("my-host-1.com")

    def test_invalid_hostname(self):
        assert not is_valid_hostname("")
        assert not is_valid_hostname("-start.com")
        assert not is_valid_hostname("end-.com")

    def test_parse_targets_ip(self):
        targets = list(parse_targets("192.168.1.1"))
        assert targets == ["192.168.1.1"]

    def test_parse_targets_cidr(self):
        targets = list(parse_targets("192.168.1.0/31"))
        assert len(targets) == 2

    def test_parse_targets_hostname(self):
        targets = list(parse_targets("example.com"))
        assert targets == ["example.com"]

    def test_resolve_valid(self):
        ip = resolve_host("8.8.8.8")
        assert ip == "8.8.8.8"

    def test_resolve_nonexistent(self):
        result = resolve_host("nonexistent-domain-xyz-123.com")
        assert result is None


class TestPortParsing:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_port_range(self):
        ports = parse_ports("80-85")
        assert ports == [80, 81, 82, 83, 84, 85]

    def test_comma_separated(self):
        ports = parse_ports("22,80,443")
        assert ports == [22, 80, 443]

    def test_mixed(self):
        ports = parse_ports("22,80-82,443")
        assert ports == [22, 80, 81, 82, 443]

    def test_empty(self):
        assert parse_ports("") == []

    def test_invalid_skipped(self):
        assert parse_ports("80,xyz,443") == [80, 443]
        assert parse_ports("0,80") == [80]
        assert parse_ports("65536") == []


class TestPortStatus:
    def test_values(self):
        assert PortStatus.OPEN == "open"
        assert PortStatus.CLOSED == "closed"
        assert PortStatus.FILTERED == "filtered"
