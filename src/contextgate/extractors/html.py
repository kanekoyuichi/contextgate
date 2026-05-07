import re
from pathlib import Path

from bs4 import BeautifulSoup, Comment, Tag

from ..exceptions import FileTooLargeError
from ..result import ExtractedSegment

MAX_FILE_BYTES = 20 * 1024 * 1024


def _check_size(path: Path) -> None:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise FileTooLargeError(f"File exceeds 20MB: {path}")


def _normalize_style(style: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in style.split(";"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        result[key.strip().lower()] = val.strip().lower()
    return result


def _is_hidden_by_style(style: str) -> str | None:
    props = _normalize_style(style)
    if props.get("display") == "none":
        return "display_none"
    if props.get("visibility") == "hidden":
        return "visibility_hidden"
    if props.get("opacity") == "0":
        return "opacity_0"
    font_size = props.get("font-size", "")
    if re.match(r"^0*1\s*px$", font_size):
        return "font_size_1px"
    return None


def extract_html(path: str | Path) -> list[ExtractedSegment]:
    p = Path(path)
    _check_size(p)
    raw = p.read_text(encoding="utf-8", errors="replace")
    soup = BeautifulSoup(raw, "html.parser")
    segments: list[ExtractedSegment] = []

    # HTML comments
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        text = str(comment).strip()
        if text:
            segments.append(ExtractedSegment(text=text, hidden=True, hidden_source="html_comment"))

    def _walk(tag: Tag) -> None:
        for child in tag.children:
            if isinstance(child, Comment):
                continue
            if not isinstance(child, Tag):
                text = str(child).strip()
                if text:
                    segments.append(ExtractedSegment(text=text))
                continue

            hidden_source: str | None = None

            style = child.get("style", "")
            if style:
                hidden_source = _is_hidden_by_style(style)

            if hidden_source is None and child.get("hidden") is not None:
                hidden_source = "hidden_attr"

            if hidden_source is None and child.get("aria-hidden") == "true":
                hidden_source = "aria_hidden"

            if hidden_source:
                text = child.get_text(separator=" ").strip()
                if text:
                    segments.append(ExtractedSegment(text=text, hidden=True, hidden_source=hidden_source))
            else:
                _walk(child)

    body = soup.body or soup
    _walk(body)

    return segments
