from pathlib import Path

import pytest

from contextgate.extractors.html import extract_html
from contextgate.exceptions import FileTooLargeError


FIXTURES = Path(__file__).parent / "fixtures"


class TestExtractHtml:
    def test_visible_text(self, tmp_path):
        f = tmp_path / "test.html"
        f.write_text("<html><body><p>Hello World</p></body></html>")
        segments = extract_html(f)
        texts = [s.text for s in segments]
        assert any("Hello World" in t for t in texts)
        assert all(not s.hidden for s in segments)

    def test_html_comment(self, tmp_path):
        f = tmp_path / "test.html"
        f.write_text("<html><body><!-- secret comment --><p>visible</p></body></html>")
        segments = extract_html(f)
        hidden = [s for s in segments if s.hidden]
        assert len(hidden) == 1
        assert hidden[0].hidden_source == "html_comment"
        assert "secret comment" in hidden[0].text

    def test_display_none(self, tmp_path):
        f = tmp_path / "test.html"
        f.write_text('<html><body><div style="display:none">hidden</div></body></html>')
        segments = extract_html(f)
        hidden = [s for s in segments if s.hidden]
        assert len(hidden) == 1
        assert hidden[0].hidden_source == "display_none"

    def test_visibility_hidden(self, tmp_path):
        f = tmp_path / "test.html"
        f.write_text('<html><body><div style="visibility:hidden">hidden</div></body></html>')
        segments = extract_html(f)
        hidden = [s for s in segments if s.hidden]
        assert any(s.hidden_source == "visibility_hidden" for s in hidden)

    def test_opacity_zero(self, tmp_path):
        f = tmp_path / "test.html"
        f.write_text('<html><body><div style="opacity:0">hidden</div></body></html>')
        segments = extract_html(f)
        hidden = [s for s in segments if s.hidden]
        assert any(s.hidden_source == "opacity_0" for s in hidden)

    def test_hidden_attr(self, tmp_path):
        f = tmp_path / "test.html"
        f.write_text("<html><body><div hidden>hidden content</div></body></html>")
        segments = extract_html(f)
        hidden = [s for s in segments if s.hidden]
        assert any(s.hidden_source == "hidden_attr" for s in hidden)

    def test_aria_hidden(self, tmp_path):
        f = tmp_path / "test.html"
        f.write_text('<html><body><div aria-hidden="true">hidden</div></body></html>')
        segments = extract_html(f)
        hidden = [s for s in segments if s.hidden]
        assert any(s.hidden_source == "aria_hidden" for s in hidden)

    def test_font_size_1px(self, tmp_path):
        f = tmp_path / "test.html"
        f.write_text('<html><body><span style="font-size:1px">tiny</span></body></html>')
        segments = extract_html(f)
        hidden = [s for s in segments if s.hidden]
        assert any(s.hidden_source == "font_size_1px" for s in hidden)

    def test_hidden_prompt_fixture(self):
        result_segs = extract_html(FIXTURES / "malicious" / "hidden_prompt.html")
        hidden = [s for s in result_segs if s.hidden]
        assert len(hidden) >= 1

    def test_normal_manual_no_hidden(self):
        segs = extract_html(FIXTURES / "safe" / "normal_manual.html")
        assert not any(s.hidden for s in segs)
