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


def _detect_hidden_source(tag: Tag) -> str | None:
    style = tag.get("style", "")
    if style:
        source = _is_hidden_by_style(style)
        if source:
            return source
    if tag.get("hidden") is not None:
        return "hidden_attr"
    if tag.get("aria-hidden") == "true":
        return "aria_hidden"
    return None


# Tags that flow inline — safe to merge with surrounding text.
# Includes HTML4 inline elements and HTML5 phrasing content.
_INLINE_TAGS = frozenset({
    "a", "abbr", "acronym", "b", "bdi", "bdo", "big", "br", "button",
    "cite", "code", "data", "del", "dfn", "em", "i", "img", "input",
    "ins", "kbd", "label", "map", "mark", "object", "output", "q",
    "rp", "rt", "ruby", "s", "samp", "select", "small", "span",
    "strong", "sub", "sup", "textarea", "time", "tt", "u", "var", "wbr",
})


def _has_block_child(tag: Tag) -> bool:
    for child in tag.children:
        if isinstance(child, Tag) and child.name not in _INLINE_TAGS:
            return True
    return False


def _build_hidden_ancestor_set(root: Tag) -> set[int]:
    """Return id()s of Tags that contain at least one hidden descendant.

    Iterative post-order DFS: each Tag is processed exactly once → O(n).
    Avoids both repeated subtree scans and ancestor chain walks.
    """
    has_hidden_desc: set[int] = set()
    subtree_has_hidden: dict[int, bool] = {}

    # Stack stores (tag, children_pushed)
    stack: list[tuple[Tag, bool]] = [(root, False)]
    while stack:
        tag, children_pushed = stack.pop()
        if not children_pushed:
            stack.append((tag, True))
            for child in tag.children:
                if isinstance(child, Tag):
                    stack.append((child, False))
        else:
            self_hidden = _detect_hidden_source(tag) is not None
            child_hidden = any(
                subtree_has_hidden.get(id(c), False)
                for c in tag.children
                if isinstance(c, Tag)
            )
            subtree_has_hidden[id(tag)] = self_hidden or child_hidden
            if child_hidden:
                has_hidden_desc.add(id(tag))

    return has_hidden_desc


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

    body = soup.body or soup
    # Pre-compute which elements have hidden descendants — O(n) single pass
    hidden_ancestors = _build_hidden_ancestor_set(body)

    def _walk(tag: Tag) -> None:
        # Accumulate consecutive visible text/inline children into runs so that
        # phrases split by inline markup (e.g. <b>, <em>) stay in one segment.
        # Hidden elements flush the run and are emitted separately.
        visible_run: list = []

        def _flush_run() -> None:
            if not visible_run:
                return
            parts: list[str] = []
            for node in visible_run:
                t = node.get_text(separator=" ") if isinstance(node, Tag) else str(node)
                if t.strip():
                    parts.append(t.strip())
            if parts:
                segments.append(ExtractedSegment(text=" ".join(parts)))
            visible_run.clear()

        for child in tag.children:
            if isinstance(child, Comment):
                continue
            if not isinstance(child, Tag):
                visible_run.append(child)
                continue

            hidden_source = _detect_hidden_source(child)
            if hidden_source:
                _flush_run()
                text = child.get_text(separator=" ").strip()
                if text:
                    segments.append(ExtractedSegment(text=text, hidden=True, hidden_source=hidden_source))
            elif child.name in _INLINE_TAGS:
                if id(child) in hidden_ancestors:
                    # Inline element containing a hidden descendant — flush and recurse
                    _flush_run()
                    _walk(child)
                else:
                    # Visible inline element — accumulate into current run
                    visible_run.append(child)
            else:
                # Block element — flush the inline run first
                _flush_run()
                if id(child) in hidden_ancestors:
                    _walk(child)
                elif not _has_block_child(child):
                    # Block with only inline children — emit as one phrase
                    text = child.get_text(separator=" ").strip()
                    if text:
                        segments.append(ExtractedSegment(text=text))
                else:
                    # Block with block children — recurse to keep blocks separate
                    _walk(child)

        _flush_run()

    _walk(body)

    return segments
