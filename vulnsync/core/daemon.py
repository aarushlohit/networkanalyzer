from __future__ import annotations

import json
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnsync.core.config import VulnSyncConfig, load_config
from vulnsync.core.history import ScanHistory
from vulnsync.utils.log import get_logger

logger = get_logger("daemon")

_RUNNING = threading.Event()
_RUNNING.set()


def _signal_handler(signum, frame):
    logger.info("Received signal %d, shutting down...", signum)
    _RUNNING.clear()


class ScanDaemon:
    def __init__(self, config_path: Optional[str] = None):
        self.config: VulnSyncConfig = load_config(config_path)
        self.history = ScanHistory(self.config.history.db_path)
        self._pid_file = Path("/tmp/vulnsync-daemon.pid")
        self._stop_event = threading.Event()

    def run_once(self, profile_override: Optional[str] = None):
        cfg = self.config
        targets = cfg.daemon.targets if cfg.daemon.enabled else cfg.targets
        profile = profile_override or cfg.daemon.profile or cfg.profile

        if not targets:
            logger.warning("No targets configured for daemon scan")
            return None

        report_dir = Path(cfg.daemon.report_dir).expanduser().resolve()
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = report_dir / f"scan_{timestamp}.json"
        html_path = report_dir / f"scan_{timestamp}.html"

        cmd = [sys.executable, "-m", "vulnsync.cli.main", "scan"]
        cmd.extend(targets)
        cmd.extend(["-p", cfg.ports])
        cmd.extend(["--threads", str(cfg.threads)])
        cmd.extend(["--timeout", str(cfg.timeout)])
        if cfg.profile:
            pass
        if cfg.service_detect:
            cmd.append("--service-detect")
        if cfg.os_detect:
            cmd.append("--os-detect")
        if cfg.web_fingerprint:
            cmd.append("--web-fingerprint")
        if cfg.stealth:
            cmd.append("--stealth")
        if cfg.no_ping:
            cmd.append("--no-ping")

        cmd.extend(["-oJ", str(json_path)])
        cmd.extend(["-oH", str(html_path)])

        logger.info("Daemon scan starting: %s", " ".join(cmd))
        start = time.monotonic()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=7200,
            )
            elapsed = time.monotonic() - start
            logger.info("Daemon scan completed in %.1fs (exit %d)",
                        elapsed, result.returncode)

            if result.returncode == 0 and json_path.exists():
                with open(json_path) as f:
                    scan_data = json.load(f)

                from vulnsync.core.scanner import HostResult, PortResult, ScanResult
                hosts = []
                for h in scan_data.get("targets", []):
                    ports = [PortResult(**p) for p in h.get("ports", [])]
                    host = HostResult(
                        ip=h.get("ip", ""),
                        hostname=h.get("hostname"),
                        ports=ports,
                        os_fingerprint=h.get("os_fingerprint"),
                        alive=h.get("alive", False),
                        ping_time_ms=h.get("ping_time_ms", 0.0),
                    )
                    hosts.append(host)

                result_obj = ScanResult(
                    targets=hosts,
                    start_time=scan_data.get("start_time", ""),
                    end_time=scan_data.get("end_time", ""),
                    duration_seconds=scan_data.get("duration_seconds", elapsed),
                    total_hosts=scan_data.get("total_hosts", len(hosts)),
                    alive_hosts=scan_data.get("alive_hosts",
                                              sum(1 for h in hosts if h.alive)),
                    total_open_ports=scan_data.get("total_open_ports",
                                                   sum(h.open_count for h in hosts)),
                )

                scan_id = self.history.save_scan(
                    result_obj, profile,
                    report_files=[str(json_path), str(html_path)],
                )

                if self.config.daemon.notify_on_critical:
                    critical = sum(
                        1 for h in hosts for p in h.ports
                        if p.cvss_score and p.cvss_score >= 9.0
                    )
                    if critical > 0:
                        self._send_alerts(result_obj, scan_id)

                self._rotate_reports(report_dir)
                return scan_id

        except subprocess.TimeoutExpired:
            logger.error("Daemon scan timed out after 7200s")
        except Exception as e:
            logger.exception("Daemon scan failed: %s", e)

        return None

    def run_loop(self):
        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)

        self._write_pid()
        logger.info("ScanDaemon started (interval=%d min)",
                    self.config.daemon.interval_minutes)

        while _RUNNING.is_set():
            try:
                self.run_once()
            except Exception as e:
                logger.exception("Daemon loop error: %s", e)

            for _ in range(self.config.daemon.interval_minutes * 60):
                if not _RUNNING.is_set():
                    break
                time.sleep(1)

        self._cleanup()

    def _write_pid(self):
        self._pid_file.write_text(str(os.getpid()))
        logger.debug("PID written to %s", self._pid_file)

    def _cleanup(self):
        if self._pid_file.exists():
            self._pid_file.unlink()
        self.history.close()
        logger.info("ScanDaemon stopped")

    def _rotate_reports(self, report_dir: Path):
        max_reports = self.config.daemon.max_reports
        reports = sorted(report_dir.glob("scan_*.json"))
        while len(reports) > max_reports:
            oldest = reports[0]
            html_old = oldest.with_suffix(".html")
            oldest.unlink(missing_ok=True)
            if html_old.exists():
                html_old.unlink(missing_ok=True)
            reports = reports[1:]

    def _send_alerts(self, result, scan_id: str):
        try:
            from vulnsync.integrations.slack import send_slack_alert
            from vulnsync.integrations.webhook import send_webhook

            critical = sum(
                1 for h in result.targets for p in h.ports
                if p.cvss_score and p.cvss_score >= 9.0
            )
            high = sum(
                1 for h in result.targets for p in h.ports
                if p.cvss_score and 7.0 <= p.cvss_score < 9.0
            )

            summary = (
                f"Scan #{scan_id[:8]}: {result.alive_hosts} hosts alive, "
                f"{result.total_open_ports} ports open, "
                f"{critical} critical / {high} high"
            )

            if self.config.notifiers.slack_webhook:
                send_slack_alert(
                    webhook_url=self.config.notifiers.slack_webhook,
                    channel=self.config.notifiers.slack_channel,
                    summary=summary,
                    result=result,
                    scan_id=scan_id,
                    min_severity=self.config.notifiers.slack_min_severity,
                )

            if self.config.notifiers.webhook_url:
                send_webhook(
                    url=self.config.notifiers.webhook_url,
                    headers=self.config.notifiers.webhook_headers,
                    summary=summary,
                    result=result,
                    scan_id=scan_id,
                )

        except ImportError:
            logger.warning("Alert dependencies not installed")
        except Exception as e:
            logger.error("Alert failed: %s", e)


def run_daemon(config_path: Optional[str] = None):
    daemon = ScanDaemon(config_path)
    daemon.run_loop()


def run_once(config_path: Optional[str] = None, profile: Optional[str] = None):
    daemon = ScanDaemon(config_path)
    return daemon.run_once(profile)


def stop_daemon():
    pid_file = Path("/tmp/vulnsync-daemon.pid")
    if pid_file.exists():
        pid = int(pid_file.read_text().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info("Sent SIGTERM to daemon PID %d", pid)
        except ProcessLookupError:
            logger.warning("Daemon PID %d not found", pid)
        pid_file.unlink(missing_ok=True)
    else:
        logger.warning("No daemon PID file found")


import os
