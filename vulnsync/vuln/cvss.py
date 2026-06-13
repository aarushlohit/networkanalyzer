from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class CVSSResult:
    score: float = 0.0
    severity: str = "None"
    vector: str = ""

    SEVERITY_MAP = [
        (9.0, "CRITICAL"),
        (7.0, "HIGH"),
        (4.0, "MEDIUM"),
        (0.1, "LOW"),
    ]

    def calculate(self, base_score: float) -> CVSSResult:
        self.score = round(base_score, 1)
        for threshold, label in self.SEVERITY_MAP:
            if self.score >= threshold:
                self.severity = label
                break
        return self

    def from_vector(self, vector: str) -> CVSSResult:
        self.vector = vector
        try:
            parts = {k: v for k, v in (p.split(':') for p in vector.split('/') if ':' in p)}
            base_scores = {
                "AV:N": 0.85, "AV:A": 0.62, "AV:L": 0.55, "AV:P": 0.2,
                "AC:L": 0.77, "AC:H": 0.44,
                "PR:N": 0.85, "PR:L": 0.62, "PR:H": 0.27,
                "UI:N": 0.85, "UI:R": 0.62,
                "S:U": 1.0, "S:C": 1.0,
                "C:H": 0.56, "C:L": 0.22, "C:N": 0.0,
                "I:H": 0.56, "I:L": 0.22, "I:N": 0.0,
                "A:H": 0.56, "A:L": 0.22, "A:N": 0.0,
            }
            total = 0.0
            for k, v in parts.items():
                val = base_scores.get(f"{k}:{v}", 0.0)
                total += val
            score = min(10, total * 2.5)
            return self.calculate(score)
        except Exception:
            return self.calculate(5.0)
