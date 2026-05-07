from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from ..exceptions import ExtractionError, FileTooLargeError
from ..result import ExtractedSegment

MAX_FILE_BYTES = 20 * 1024 * 1024


def _check_size(path: Path) -> None:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise FileTooLargeError(f"File exceeds 20MB: {path}")


def extract_pdf(path: str | Path) -> list[ExtractedSegment]:
    p = Path(path)
    _check_size(p)
    try:
        reader = PdfReader(str(p))
    except PdfReadError as e:
        raise ExtractionError(f"Failed to read PDF: {p}: {e}") from e
    except Exception as e:
        raise ExtractionError(f"Unexpected error reading PDF: {p}: {e}") from e

    if reader.is_encrypted:
        raise ExtractionError(f"PDF is encrypted: {p}")

    segments: list[ExtractedSegment] = []

    # metadata
    meta = reader.metadata
    if meta:
        meta_parts: list[str] = []
        for key, value in meta.items():
            if isinstance(value, str) and value.strip():
                meta_parts.append(f"{key}: {value}")
        if meta_parts:
            segments.append(ExtractedSegment(text="\n".join(meta_parts)))

    for page in reader.pages:
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        if text.strip():
            segments.append(ExtractedSegment(text=text))

    return segments
