import re
from collections.abc import Sequence
from dataclasses import dataclass

from .result import Finding


@dataclass
class Rule:
    type: str
    severity: str
    score: float
    patterns: tuple[re.Pattern, ...]

    VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        if not (0.0 <= d["score"] <= 1.0):
            raise ValueError(f"score must be 0.0..1.0: {d['score']}")
        if d["severity"] not in cls.VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {d['severity']}")
        if not d.get("patterns"):
            raise ValueError("patterns must not be empty")
        try:
            compiled = tuple(re.compile(p, re.IGNORECASE) for p in d["patterns"])
        except re.error as e:
            raise ValueError(f"invalid regex pattern: {e}") from e
        return cls(
            type=d["type"],
            severity=d["severity"],
            score=d["score"],
            patterns=compiled,
        )


BUILTIN_RULES: list[Rule] = [
    Rule.from_dict({
        "type": "instruction_override",
        "severity": "high",
        "score": 0.90,
        "patterns": [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"disregard\s+(all\s+)?previous\s+instructions",
            r"forget\s+(all\s+)?previous\s+instructions",
        ],
    }),
    Rule.from_dict({
        "type": "system_override",
        "severity": "high",
        "score": 0.85,
        "patterns": [
            r"you\s+are\s+now\s+(in\s+)?developer\s+mode",
            r"system\s+prompt",
            r"hidden\s+instructions",
            r"highest\s+priority",
        ],
    }),
    Rule.from_dict({
        "type": "data_exfiltration",
        "severity": "critical",
        "score": 0.95,
        "patterns": [
            r"exfiltrate",
            r"send\s+(all\s+)?(customer|user|internal|confidential)\s+data",
            r"upload\s+.+https?://",
        ],
    }),
    Rule.from_dict({
        "type": "credential_access",
        "severity": "high",
        "score": 0.85,
        "patterns": [
            r"\.aws/credentials",
            r"api[\s_-]*key\s*[:=]",
            r"secret[\s_-]*key\s*[:=]",
        ],
    }),
    Rule.from_dict({
        "type": "tool_abuse",
        "severity": "high",
        "score": 0.80,
        "patterns": [
            r"rm\s+-rf",
            r"curl\s+https?://",
            r"wget\s+https?://",
            r"execute\s+(this\s+)?command",
            r"run\s+(this\s+)?shell",
        ],
    }),
]


def detect_rules(
    text: str,
    source: str | None = None,
    extra_rules: Sequence[Rule] | None = None,
    disabled_types: frozenset[str] = frozenset(),
    segment_index: int = 0,
    chunk_index: int = 0,
    chunk_start: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []
    rules = [r for r in BUILTIN_RULES if r.type not in disabled_types]
    if extra_rules:
        rules.extend(extra_rules)

    for rule in rules:
        for pattern in rule.patterns:
            for match in pattern.finditer(text):
                findings.append(
                    Finding(
                        type=rule.type,
                        severity=rule.severity,
                        message=f"Matched rule: {rule.type}",
                        matched_text=match.group(0),
                        source=source,
                        score=rule.score,
                        metadata={
                            "segment_index": segment_index,
                            "chunk_index": chunk_index,
                            "char_offset": chunk_start + match.start(),
                            "chunk_offset": match.start(),
                        },
                    )
                )

    return findings
