import pytest

from contextgate.exceptions import ExtractionError, FileTooLargeError
from contextgate.extractors.docx import extract_docx


class TestExtractDocx:
    def test_not_docx(self, tmp_path):
        f = tmp_path / "fake.docx"
        f.write_text("This is not a DOCX")
        with pytest.raises(ExtractionError):
            extract_docx(f)

    def test_file_too_large(self, tmp_path, monkeypatch):
        f = tmp_path / "large.docx"
        f.write_bytes(b"PK" + b"x" * 100)
        monkeypatch.setattr(
            "contextgate.extractors.docx.MAX_FILE_BYTES", 50
        )
        with pytest.raises(FileTooLargeError):
            extract_docx(f)
