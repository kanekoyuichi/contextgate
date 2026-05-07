from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExtractedSegment:
    text: str
    hidden: bool = False
    hidden_source: str | None = None


@dataclass
class Finding:
    type: str
    severity: str
    message: str
    matched_text: str | None = None
    source: str | None = None
    score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    blocked: bool
    risk_score: float
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": self.blocked,
            "risk_score": self.risk_score,
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity,
                    "message": f.message,
                    "matched_text": f.matched_text,
                    "source": f.source,
                    "score": f.score,
                    "metadata": f.metadata,
                }
                for f in self.findings
            ],
        }
