from .exceptions import ExtractionError, FileTooLargeError, UnsupportedFormatError
from .result import ExtractedSegment, Finding, ScanResult
from .scanner import (
    Scanner,
    scan_docx,
    scan_documents,
    scan_file,
    scan_html,
    scan_pdf,
    scan_text,
)

__all__ = [
    "Scanner",
    "ScanResult",
    "Finding",
    "ExtractedSegment",
    "scan_text",
    "scan_file",
    "scan_pdf",
    "scan_docx",
    "scan_html",
    "scan_documents",
    "ExtractionError",
    "FileTooLargeError",
    "UnsupportedFormatError",
]
