from __future__ import annotations

from typing import Dict, Optional

CRITICAL = "#dc2626"
HIGH = "#ea580c"
MEDIUM = "#ca8a04"
LOW = "#2563eb"
INFO = "#6b7280"
SUCCESS = "#16a34a"
WARNING = "#d97706"

SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": CRITICAL,
    "HIGH": HIGH,
    "MEDIUM": MEDIUM,
    "LOW": LOW,
    "NONE": INFO,
    "UNKNOWN": INFO,
}


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity.upper(), INFO)


def risk_bar(score: Optional[float], width: int = 12) -> str:
    if score is None:
        return "░" * width
    filled = max(1, min(width, int((score / 10) * width)))
    empty = width - filled
    color = severity_color(_severity_text(score))
    return f"[{color}]{'█' * filled}[/]{'░' * empty}"


def _severity_text(score: Optional[float]) -> str:
    if score is None:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"
