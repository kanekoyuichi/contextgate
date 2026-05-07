def chunk_text(
    text: str,
    chunk_size: int = 1000,
    chunk_overlap: int = 100,
) -> list[tuple[str, int]]:
    chunks: list[tuple[str, int]] = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append((text[start:end], start))
        if end >= len(text):
            break
        start = end - chunk_overlap
    return chunks
