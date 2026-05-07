import pytest

from contextgate.exceptions import ExtractionError, FileTooLargeError
from contextgate.extractors.pdf import extract_pdf


class TestExtractPdf:
    def test_nonexistent_file(self, tmp_path):
        with pytest.raises(Exception):
            extract_pdf(tmp_path / "nonexistent.pdf")

    def test_not_pdf(self, tmp_path):
        f = tmp_path / "fake.pdf"
        f.write_text("This is not a PDF")
        with pytest.raises(ExtractionError):
            extract_pdf(f)

    def test_file_too_large(self, tmp_path, monkeypatch):
        f = tmp_path / "large.pdf"
        f.write_bytes(b"%PDF-1.4 " + b"x" * 100)
        monkeypatch.setattr(
            "contextgate.extractors.pdf.MAX_FILE_BYTES", 50
        )
        with pytest.raises(FileTooLargeError):
            extract_pdf(f)
