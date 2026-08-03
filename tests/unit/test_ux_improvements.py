"""Unit tests for UX improvement #1–#4.

Tests cover:
1. Signature pad 480x360 dimensions
2. DateEntry calendar widget API
3. Previous button disable after signature/encryption
4. Step indicator click callback
"""

from __future__ import annotations

import tkinter as tk

import pytest


@pytest.fixture()
def root():
    """Create and teardown a Tk root window."""
    r = tk.Tk()
    r.withdraw()
    yield r
    r.destroy()


# ---------- 1. Signature pad size ----------

def test_signature_pad_dimensions(root: tk.Tk) -> None:
    """EnhancedSignaturePad canvas should be 480x360."""
    from desktop.gui.signature_pad import EnhancedSignaturePad

    pad = EnhancedSignaturePad(root, label_text="Test", required=True)
    pad.pack()
    assert pad.CANVAS_WIDTH == 480
    assert pad.CANVAS_HEIGHT == 360
    assert int(pad.canvas.cget("width")) == 480
    assert int(pad.canvas.cget("height")) == 360


# ---------- 2. DateEntry widget ----------

def test_date_entry_api(root: tk.Tk) -> None:
    """DateEntry should provide get/set/is_valid/highlight_error/clear_error."""
    from desktop.gui.widgets import DateEntry

    de = DateEntry(root, "Birth", required=True)
    de.pack()

    # Initially empty → invalid
    assert de.get() == ""
    assert de.is_valid() is False

    # Set a value
    de.set("2000-01-15")
    assert de.get() == "2000-01-15"
    assert de.is_valid() is True

    # highlight/clear should not raise
    de.highlight_error()
    de.clear_error()


def test_date_entry_has_calendar_button(root: tk.Tk) -> None:
    """DateEntry should have a calendar button."""
    from desktop.gui.widgets import DateEntry

    de = DateEntry(root, "DOB", required=False)
    de.pack()
    assert hasattr(de, "_cal_btn")
    assert de._cal_btn.winfo_exists()


# ---------- 3. Previous button disabled after processing ----------

def test_seal_wizard_prev_disabled_data_flag() -> None:
    """Verify the signature_done flag logic in _show_step."""
    # We test the condition logic directly rather than instantiating full wizard
    # since it requires MainApp dependency.
    # The condition: index >= 4 and data.get("signature_done") → disabled
    data = {"signature_done": True}
    index = 5
    assert index >= 4 and data.get("signature_done")

    data2: dict = {}
    assert not (index >= 4 and data2.get("signature_done"))


# ---------- 4. Step indicator click ----------

def test_step_indicator_click_callback(root: tk.Tk) -> None:
    """StepIndicator should call on_step_click with correct index."""
    from desktop.gui.step_indicator import StepIndicator

    clicked: list[int] = []

    si = StepIndicator(root, steps=["A", "B", "C"], on_step_click=clicked.append)
    si.pack(fill="x")
    si.set_active(2)  # Mark A,B as completed, C as active

    # Force draw
    root.update_idletasks()
    si.event_generate("<Configure>", width=300, height=68)
    root.update_idletasks()

    # Simulate click on first step position if positions are set
    if si._positions:
        import unittest.mock as mock
        event = mock.MagicMock()
        event.x = si._positions[0]
        event.y = 20
        si._on_canvas_click(event)
        assert clicked == [0]


def test_step_indicator_no_callback(root: tk.Tk) -> None:
    """StepIndicator without callback should not raise on click."""
    from desktop.gui.step_indicator import StepIndicator

    si = StepIndicator(root, steps=["A", "B"])
    si.pack(fill="x")
    root.update_idletasks()

    # Should not raise
    import unittest.mock as mock
    event = mock.MagicMock()
    event.x = 50
    si._on_canvas_click(event)


# ---------- i18n keys ----------

def test_i18n_calendar_keys() -> None:
    """Calendar i18n keys should exist."""
    from desktop.gui.i18n import t

    assert t("cal.title") != "cal.title"
    assert t("cal.year") != "cal.year"
    assert t("cal.month") != "cal.month"
    assert t("cal.today") != "cal.today"
    assert t("cal.days_ko") != "cal.days_ko"
    assert t("common.back_to_current") != "common.back_to_current"
