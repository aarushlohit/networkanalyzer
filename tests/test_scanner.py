import pytest

from vulnsync.core.scanner import PortResult, HostResult, ScanResult


class TestDataClasses:
    def test_port_result_defaults(self):
        p = PortResult(port=80)
        assert p.port == 80
        assert p.state == "closed"
        assert p.service == "unknown"

    def test_port_result_full(self):
        p = PortResult(port=443, state="open", service="https", cvss_score=9.0)
        assert p.cvss_score == 9.0
        assert p.banner is None

    def test_host_result_defaults(self):
        h = HostResult(ip="192.168.1.1")
        assert h.ip == "192.168.1.1"
        assert h.alive is False
        assert h.ports == []

    def test_host_result_with_ports(self):
        p1 = PortResult(port=80, state="open", service="http")
        p2 = PortResult(port=443, state="open", service="https", cvss_score=9.0)
        h = HostResult(ip="10.0.0.1", ports=[p1, p2])
        assert len(h.ports) == 2
        assert h.alive is False

    def test_host_open_ports_property(self):
        h = HostResult(ip="1.2.3.4", alive=True, ports=[
            PortResult(port=22, state="open", service="ssh"),
            PortResult(port=80, state="open", service="http"),
            PortResult(port=443, state="closed"),
        ])
        assert h.open_count == 2
        assert h.total_ports_scanned == 3

    def test_host_properties(self):
        h = HostResult(ip="10.0.0.1")
        assert h.open_count == 0
        assert h.total_ports_scanned == 0
        assert h.high_risk_count == 0
        assert h.medium_risk_count == 0

    def test_host_risk_counts(self):
        h = HostResult(ip="10.0.0.1", ports=[
            PortResult(port=22, state="open", cvss_score=9.0),
            PortResult(port=80, state="open", cvss_score=5.0),
            PortResult(port=443, state="open", cvss_score=2.0),
        ])
        assert h.high_risk_count == 1
        assert h.medium_risk_count == 1

    def test_scan_result_empty(self):
        sr = ScanResult()
        assert sr.targets == []
        assert sr.total_hosts == 0
        assert sr.alive_hosts == 0

    def test_scan_result_with_data(self):
        h1 = HostResult(
            ip="10.0.0.1", alive=True, ports=[
                PortResult(port=80, state="open", service="http"),
                PortResult(port=22, state="open", service="ssh"),
            ],
        )
        sr = ScanResult(
            targets=[h1],
            total_hosts=1,
            alive_hosts=1,
            total_open_ports=2,
        )
        assert len(sr.targets) == 1
        assert sr.alive_hosts == 1
        assert sr.total_open_ports == 2
