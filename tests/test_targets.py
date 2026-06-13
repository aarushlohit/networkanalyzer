import pytest

from vulnsync.core.targets import ScanTarget, build_targets


class TestBuildTargets:
    def test_single_ip(self):
        targets = build_targets(["192.168.1.1"])
        assert len(targets) == 1
        assert targets[0].host == "192.168.1.1"

    def test_multiple_targets(self):
        targets = build_targets(["10.0.0.1", "10.0.0.2"])
        assert len(targets) == 2

    def test_cidr_expansion(self):
        targets = build_targets(["192.168.1.0/31"])
        assert len(targets) == 2

    def test_hostname(self):
        targets = build_targets(["example.com"])
        assert len(targets) == 1
        assert targets[0].host == "example.com"

    def test_cidr_30_yields_two(self):
        targets = build_targets(["192.168.1.0/30"])
        assert len(targets) == 2

    def test_with_exclude(self):
        targets = build_targets(["192.168.1.0/30"], ["192.168.1.1"])
        hosts = [t.host for t in targets]
        assert "192.168.1.1" not in hosts

    def test_scan_target_defaults(self):
        t = ScanTarget(host="10.0.0.1")
        assert t.host == "10.0.0.1"
        assert t.ip is None
        assert t.hostname is None

    def test_scan_target_with_ip(self):
        t = ScanTarget(host="10.0.0.1", ip="10.0.0.1")
        assert t.ip == "10.0.0.1"
