"""reflow_text_for_width: text with line breaks must reflow, not crash.
Pillow 13's text layout refuses to measure multi-line text in one call
(raqm_layout() failed), which crashed the sign-message screen."""
from seedsigner.gui.components import reflow_text_for_width
from seedsigner.models.settings import Settings


def test_multiline_text_reflows_line_by_line():
    Settings.get_instance()
    lines = reflow_text_for_width("first line\n\nthird line", width=200)
    assert [l["text"] for l in lines] == ["first line", "", "third line"]


def test_single_line_still_measured_whole():
    Settings.get_instance()
    lines = reflow_text_for_width("short", width=200)
    assert [l["text"] for l in lines] == ["short"] and lines[0]["text_width"] > 0
