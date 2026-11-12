"""
Layout checks for PSBTSpendPathScreen against the REAL renderer (the
240x240 off-device one the screenshot generator uses), so component
positions are the true ones. Not collected by the main suite, which
mocks the renderer module; tests/test_spend_path_must_sign.py runs this
file in its own process. Run directly with:

    pytest --no-cov tests/screenshot_generator/spend_path_layout.py
"""
import sys
from unittest.mock import MagicMock, Mock

import pytest

@pytest.fixture
def renderer(monkeypatch):
    """A 240x240 off-device renderer, the same one the screenshot
    generator uses, so component positions are the real ones."""
    for m in ['seedsigner.hardware.displays.st7789_mpy', 'seedsigner.hardware.displays.ili9341', 'RPi', 'RPi.GPIO']:
        sys.modules.setdefault(m, MagicMock())
    from seedsigner.gui.renderer import Renderer
    from screenshot_generator.utils import ScreenshotRenderer
    ScreenshotRenderer.configure_instance()
    r = ScreenshotRenderer.get_instance()
    monkeypatch.setattr(Renderer, "configure_instance", Mock())
    monkeypatch.setattr(Renderer, "get_instance", Mock(return_value=r))
    return r


WORST_CASES = [
    dict(leaf_index=2, leaf_count=3, quorum_k=1, quorum_n=2, timelock_kind="after_height", timelock_value=900000, num_eligible_keys=1),
    dict(leaf_index=2, leaf_count=3, quorum_k=1, quorum_n=1, timelock_kind="after_height", timelock_value=900000, num_eligible_keys=1, must_sign_count=1, your_must_sign=1),
    dict(leaf_index=2, leaf_count=3, quorum_k=1, quorum_n=1, timelock_kind="after_height", timelock_value=900000, num_eligible_keys=1, must_sign_count=1, your_must_sign=0),
    dict(leaf_index=12, leaf_count=12, quorum_k=3, quorum_n=5, timelock_kind="older_blocks", timelock_value=52560, num_eligible_keys=2, must_sign_count=2, your_must_sign=0),
    dict(leaf_index=2, leaf_count=3, quorum_k=2, quorum_n=3, timelock_kind="after_time", timelock_value=1767225600, num_eligible_keys=2, must_sign_count=2, your_must_sign=1),
    dict(multiple_leaves=True, num_eligible_keys=2),
    dict(num_eligible_keys=1),
]


def _body(screen):
    """The screen's own lines: everything between the title bar and the button."""
    from seedsigner.gui.components import IconTextLine, TextArea
    return [c for c in screen.components if isinstance(c, (IconTextLine, TextArea))]


class TestSpendPathScreenFits:
    @pytest.mark.parametrize("kwargs", WORST_CASES)
    def test_nothing_is_drawn_under_the_button(self, renderer, kwargs):
        from seedsigner.gui.screens.psbt_screens import PSBTSpendPathScreen
        screen = PSBTSpendPathScreen(**kwargs)
        button_top = min(b.screen_y for b in screen.buttons)
        body = _body(screen)
        assert body, 'the screen rendered no lines at all'
        for comp in body:
            assert comp.screen_y + comp.height <= button_top, f"{type(comp).__name__} at y={comp.screen_y} h={comp.height} runs under the button at y={button_top}: {kwargs}"

    def test_the_holder_of_the_must_sign_key_is_told_so(self, renderer):
        from seedsigner.gui.screens.psbt_screens import PSBTSpendPathScreen
        def texts(**kw):
            s = PSBTSpendPathScreen(leaf_index=1, leaf_count=3, quorum_k=1, quorum_n=2, **kw)
            return [getattr(c, "text", None) or getattr(c, "value_text", None) for c in _body(s)]
        assert texts(num_eligible_keys=1, must_sign_count=1, your_must_sign=1) == ["Path 1 of 3", "1 must-sign + 1 of 2", "Your key MUST sign"]
        assert texts(num_eligible_keys=1, must_sign_count=1, your_must_sign=0) == ["Path 1 of 3", "1 must-sign + 1 of 2", "Yours: one of the others"]
        assert texts(num_eligible_keys=2, must_sign_count=1, your_must_sign=1) == ["Path 1 of 3", "1 must-sign + 1 of 2", "Yours: must-sign + other"]
        # A path with no must-sign keys reads exactly as it did.
        assert texts(num_eligible_keys=1, must_sign_count=0, your_must_sign=0) == ["Path 1 of 3", "1 of 2 keys", "1 of your keys is eligible"]
        assert texts(num_eligible_keys=1) == ["Path 1 of 3", "1 of 2 keys", "1 of your keys is eligible"]

    def test_an_unidentified_path_says_what_is_missing(self, renderer):
        """No matching descriptor loaded: the device cannot show the
        signer count, a must-sign key or the timelock, and says so."""
        from seedsigner.gui.screens.psbt_screens import PSBTSpendPathScreen
        lines = [getattr(c, "text", None) or getattr(c, "value_text", None) for c in _body(PSBTSpendPathScreen(num_eligible_keys=1))]
        assert lines == [
            "Path not identified",
            "This device cannot see who must sign or when this path opens. Load the vault's descriptor first.",
            "1 of your keys is eligible",
        ]
        # ...and not on a path that WAS identified, nor on a multi-path spend.
        for kw in (dict(leaf_index=1, leaf_count=3, quorum_k=2, quorum_n=3, num_eligible_keys=1), dict(multiple_leaves=True, num_eligible_keys=2)):
            assert not any("cannot see" in (getattr(c, "text", "") or "") for c in _body(PSBTSpendPathScreen(**kw)))
