from pathlib import Path

from ..exceptions import FileTooLargeError
from ..result import ExtractedSegment

MAX_FILE_BYTES = 20 * 1024 * 1024


def _check_size(path: Path) -> None:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise FileTooLargeError(f"File exceeds 20MB: {path}")


def extract_text(path: str | Path) -> list[ExtractedSegment]:
    p = Path(path)
    _check_size(p)
    text = p.read_text(encoding="utf-8", errors="replace")
    return [ExtractedSegment(text=text)]
