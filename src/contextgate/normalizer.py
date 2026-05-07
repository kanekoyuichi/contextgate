import html
import re
import unicodedata

ZERO_WIDTH_CHARS = ["​", "‌", "‍", "﻿"]


def normalize_text(text: str) -> str:
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    text = text.replace("\x00", "")
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()
