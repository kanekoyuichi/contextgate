import re

from .result import Finding

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9_]{36,}")),
    ("openai_api_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(r"xoxb-[A-Za-z0-9-]+")),
    ("generic_password", re.compile(r"password\s*=\s*[\"']?(?P<val>[^\s\"']+)", re.IGNORECASE)),
]

PLACEHOLDER_KEYWORDS = frozenset([
    "example", "dummy", "placeholder", "xxx", "test", "changeme", "sample",
])


def _is_placeholder(value: str) -> bool:
    v = value.lower()
    if any(keyword in v for keyword in PLACEHOLDER_KEYWORDS):
        return True
    if v.startswith("your_") or (v.startswith("<") and v.endswith(">")):
        return True
    return False


def _mask(value: str) -> str:
    if len(value) < 8:
        return "***"
    return value[:4] + "***" + value[-4:]


def detect_secrets(
    text: str,
    source: str | None = None,
    segment_index: int = 0,
    chunk_index: int = 0,
    chunk_start: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0)
            value = match.group("val") if "val" in pattern.groupindex else raw
            if _is_placeholder(value):
                ftype, severity, score = "secret_placeholder", "medium", 0.40
            else:
                ftype, severity, score = "secret_detected_real", "high", 0.80
            findings.append(
                Finding(
                    type=ftype,
                    severity=severity,
                    message=f"Secret detected: {name}",
                    matched_text=_mask(raw),
                    source=source,
                    score=score,
                    metadata={
                        "secret_kind": name,
                        "segment_index": segment_index,
                        "chunk_index": chunk_index,
                        "char_offset": chunk_start + match.start(),
                        "chunk_offset": match.start(),
                    },
                )
            )
    return findings
