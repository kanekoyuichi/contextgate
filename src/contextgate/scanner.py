from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .chunker import chunk_text
from .exceptions import UnsupportedFormatError
from .extractors.docx import extract_docx
from .extractors.html import extract_html
from .extractors.pdf import extract_pdf
from .extractors.text import extract_text
from .normalizer import normalize_text
from .result import ExtractedSegment, Finding, ScanResult
from .rules import Rule, detect_rules
from .secrets import detect_secrets

SUPPORTED_EXTENSIONS = frozenset({".txt", ".md", ".html", ".htm", ".pdf", ".docx"})


@dataclass
class Scanner:
    extra_rules: list[dict] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    threshold: float = 0.70
    _compiled_extra: tuple[Rule, ...] = field(default_factory=tuple, init=False, repr=False)
    _disabled_types: frozenset[str] = field(default_factory=frozenset, init=False, repr=False)

    def __post_init__(self) -> None:
        if not (0.0 <= self.threshold <= 1.0):
            raise ValueError(f"threshold must be 0.0..1.0: {self.threshold}")
        self._compiled_extra = tuple(Rule.from_dict(d) for d in self.extra_rules)
        self._disabled_types = frozenset(self.disabled_rules)

    def _process_segments(
        self,
        segments: list[ExtractedSegment],
        source: str | None = None,
    ) -> list[Finding]:
        all_findings: list[Finding] = []
        seen: set[tuple] = set()

        for seg_idx, segment in enumerate(segments):
            normalized = normalize_text(segment.text)
            if not normalized:
                continue

            # Rule detection: normalized text (case-folded, whitespace-compressed)
            norm_chunks = chunk_text(normalized)
            # Secret detection: original text (case-sensitive patterns like AKIA...)
            # Run independently to avoid chunk-count mismatch after normalization
            orig_chunks = chunk_text(segment.text)

            rule_chunk_findings: list[Finding] = []
            for chunk_idx, (chunk, chunk_start) in enumerate(norm_chunks):
                rule_chunk_findings.extend(detect_rules(
                    chunk,
                    source=source,
                    extra_rules=self._compiled_extra if self._compiled_extra else None,
                    disabled_types=self._disabled_types,
                    segment_index=seg_idx,
                    chunk_index=chunk_idx,
                    chunk_start=chunk_start,
                ))

            secret_chunk_findings: list[Finding] = []
            for chunk_idx, (orig_chunk, orig_chunk_start) in enumerate(orig_chunks):
                secret_chunk_findings.extend(detect_secrets(
                    orig_chunk,
                    source=source,
                    segment_index=seg_idx,
                    chunk_index=chunk_idx,
                    chunk_start=orig_chunk_start,
                ))

            for f in rule_chunk_findings + secret_chunk_findings:
                dedup_key = (
                    f.metadata.get("segment_index"),
                    f.metadata.get("char_offset"),
                    f.type,
                    f.matched_text,
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                if segment.hidden:
                    f.metadata["hidden"] = True
                    f.metadata["hidden_source"] = segment.hidden_source
                all_findings.append(f)

        return all_findings

    def _make_result(self, findings: list[Finding]) -> ScanResult:
        risk_score = max((f.score for f in findings if f.score is not None), default=0.0)
        blocked = risk_score >= self.threshold
        return ScanResult(blocked=blocked, risk_score=risk_score, findings=findings)

    def scan_text(self, text: str, source: str | None = None) -> ScanResult:
        segments = [ExtractedSegment(text=text)]
        findings = self._process_segments(segments, source=source)
        return self._make_result(findings)

    def scan_file(self, path: str | Path) -> ScanResult:
        p = Path(path)
        ext = p.suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            raise UnsupportedFormatError(f"Unsupported file format: {ext}")
        source = str(p)
        if ext in {".txt", ".md"}:
            segments = extract_text(p)
        elif ext in {".html", ".htm"}:
            segments = extract_html(p)
        elif ext == ".pdf":
            segments = extract_pdf(p)
        elif ext == ".docx":
            segments = extract_docx(p)
        else:
            raise UnsupportedFormatError(f"Unsupported file format: {ext}")
        findings = self._process_segments(segments, source=source)
        return self._make_result(findings)

    def scan_pdf(self, path: str | Path) -> ScanResult:
        segments = extract_pdf(path)
        findings = self._process_segments(segments, source=str(path))
        return self._make_result(findings)

    def scan_docx(self, path: str | Path) -> ScanResult:
        segments = extract_docx(path)
        findings = self._process_segments(segments, source=str(path))
        return self._make_result(findings)

    def scan_html(self, path: str | Path) -> ScanResult:
        segments = extract_html(path)
        findings = self._process_segments(segments, source=str(path))
        return self._make_result(findings)

    def scan_documents(self, texts: list[str]) -> ScanResult:
        all_findings: list[Finding] = []
        seen: set[tuple] = set()
        for doc_idx, text in enumerate(texts):
            segments = [ExtractedSegment(text=text)]
            findings = self._process_segments(segments)
            for f in findings:
                f.metadata["document_index"] = doc_idx
                dedup_key = (
                    doc_idx,
                    f.metadata.get("char_offset"),
                    f.type,
                    f.matched_text,
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                all_findings.append(f)
        return self._make_result(all_findings)


_default_scanner = Scanner()


def scan_text(text: str, source: str | None = None) -> ScanResult:
    return _default_scanner.scan_text(text, source=source)


def scan_file(path: str | Path) -> ScanResult:
    return _default_scanner.scan_file(path)


def scan_pdf(path: str | Path) -> ScanResult:
    return _default_scanner.scan_pdf(path)


def scan_docx(path: str | Path) -> ScanResult:
    return _default_scanner.scan_docx(path)


def scan_html(path: str | Path) -> ScanResult:
    return _default_scanner.scan_html(path)


def scan_documents(texts: list[str]) -> ScanResult:
    return _default_scanner.scan_documents(texts)
