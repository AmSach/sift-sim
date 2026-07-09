"""Report dataclasses used across sift-sim."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Finding:
    """One detection hit."""

    detector: str
    confidence: float  # 0..1
    span: tuple[int, int]  # (start, end) char offsets into the input
    snippet: str  # exact text that triggered
    reason: str

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "confidence": round(self.confidence, 3),
            "span": list(self.span),
            "snippet": self.snippet,
            "reason": self.reason,
        }


@dataclass
class SiftReport:
    """Aggregate result for a single piece of text."""

    text_length: int
    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0  # 0..100

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def compute_risk(self) -> float:
        """Weighted aggregate of finding confidences, capped at 100."""
        if not self.findings:
            self.risk_score = 0.0
            return 0.0
        # Each finding contributes its confidence^1.5 (rewards strong signals)
        # and a small density bonus for many findings.
        raw = sum(f.confidence ** 1.5 for f in self.findings)
        density = min(1.0, len(self.findings) / 10.0)
        self.risk_score = min(100.0, raw * 8.0 * (1.0 + density * 0.5))
        return self.risk_score

    def to_dict(self) -> dict:
        return {
            "text_length": self.text_length,
            "risk_score": round(self.risk_score, 2),
            "findings": [f.to_dict() for f in self.findings],
        }
