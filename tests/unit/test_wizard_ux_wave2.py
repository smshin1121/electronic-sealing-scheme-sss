"""Unit tests for Wave 2 wizard UX improvements.

Covers:
- Dynamic calendar year bounds (no 2026 hardcoding)
- Return-key navigation guard for input widgets
- StepIndicator index clamping and click hit radius
- ScrolledFrame / SummaryView widgets
- FileSelector inline error API
- progress_dialog run_async + byte formatting
- Wizard toplevel binding save/restore (no leak after destroy)
- New i18n keys (ko/en)
"""

from __future__ import annotations

import time
from datetime import date
from types import SimpleNamespace

import tkinter as tk

import pytest


@pytest.fixture()
def root():
    """Create and teardown a Tk root window."""
    r = tk.Tk()
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


# ---------- Calendar year bounds ----------

def test_date_entry_default_max_year_is_dynamic(root: tk.Tk) -> None:
    from desktop.gui.widgets import DateEntry

    de = DateEntry(root, "Date", required=False)
    assert de.max_year() == date.today().year + 1


def test_date_entry_dob_max_year_is_current_year(root: tk.Tk) -> None:
    from desktop.gui.widgets import DateEntry

    de = DateEntry(root, "DOB", required=True, max_year_offset=0)
    assert de.max_year() == date.today().year


def test_calendar_min_year_constant() -> None:
    from desktop.gui.widgets import CALENDAR_MIN_YEAR

    assert CALENDAR_MIN_YEAR == 1970


# ---------- Return-key navigation guard ----------

def test_return_guard_blocks_input_widgets(root: tk.Tk) -> None:
    from tkinter import ttk
    from desktop.gui.widgets import is_return_navigation_safe

    assert is_return_navigation_safe(None) is True
    assert is_return_navigation_safe(tk.Frame(root)) is True
    assert is_return_navigation_safe(tk.Label(root)) is True

    assert is_return_navigation_safe(tk.Entry(root)) is False
    assert is_return_navigation_safe(tk.Text(root)) is False
    assert is_return_navigation_safe(tk.Spinbox(root)) is False
    assert is_return_navigation_safe(tk.Listbox(root)) is False
    assert is_return_navigation_safe(tk.Button(root)) is False
    assert is_return_navigation_safe(tk.Checkbutton(root)) is False
    assert is_return_navigation_safe(ttk.Combobox(root)) is False
    assert is_return_navigation_safe(ttk.Entry(root)) is False
    assert is_return_navigation_safe(ttk.Button(root)) is False


# ---------- StepIndicator ----------

def test_step_indicator_set_active_clamps(root: tk.Tk) -> None:
    from desktop.gui.step_indicator import StepIndicator

    si = StepIndicator(root, steps=["A", "B", "C"])
    si.set_active(99)
    assert si._active_index == 2
    si.set_active(-5)
    assert si._active_index == 0


def test_step_indicator_click_radius(root: tk.Tk) -> None:
    from desktop.gui.step_indicator import StepIndicator

    clicked: list[int] = []
    si = StepIndicator(root, steps=["A", "B", "C"], on_step_click=clicked.append)
    # Simulate a drawn state
    si._positions = [50, 150, 250]
    si._circle_cy = 20

    # Click far from any circle (between steps) — must be ignored
    event = SimpleNamespace(x=100, y=20)
    si._on_canvas_click(event)
    assert clicked == []

    # Click far vertically — must be ignored
    event = SimpleNamespace(x=50, y=60)
    si._on_canvas_click(event)
    assert clicked == []

    # Click within CLICK_RADIUS of a circle center — accepted
    event = SimpleNamespace(x=152, y=22)
    si._on_canvas_click(event)
    assert clicked == [1]


def test_step_indicator_keyboard_focus_moves_within_visited(root: tk.Tk) -> None:
    from desktop.gui.step_indicator import StepIndicator

    clicked: list[int] = []
    si = StepIndicator(root, steps=["A", "B", "C", "D"], on_step_click=clicked.append)
    si.set_active(2)
    si._focus_index = 2

    # Cannot move focus beyond the active step
    si._move_focus(1)
    assert si._focus_index == 2

    si._move_focus(-1)
    assert si._focus_index == 1
    si._move_focus(-1)
    assert si._focus_index == 0
    si._move_focus(-1)
    assert si._focus_index == 0

    # Return/Space activates the focused step and breaks propagation
    result = si._on_key_activate(SimpleNamespace())
    assert result == "break"
    assert clicked == [0]


def test_step_indicator_is_focusable(root: tk.Tk) -> None:
    from desktop.gui.step_indicator import StepIndicator

    si = StepIndicator(root, steps=["A", "B"])
    assert int(si.cget("takefocus")) == 1


# ---------- ScrolledFrame / SummaryView ----------

def test_scrolled_frame_body_and_scroll(root: tk.Tk) -> None:
    from desktop.gui.widgets import ScrolledFrame

    sf = ScrolledFrame(root)
    sf.pack(fill="both", expand=True)
    assert isinstance(sf.body, tk.Frame)
    tk.Label(sf.body, text="content").pack()
    sf.scroll_to_top()  # must not raise


def test_summary_view_render_sections(root: tk.Tk) -> None:
    from desktop.gui.widgets import SummaryView

    sv = SummaryView(root)
    sv.pack(fill="both", expand=True)
    sv.render([
        {
            "title": "사건 정보",
            "badge": ("완료", "success"),
            "rows": [
                ("사건번호", "2026-123"),
                ("해시 검증", "통과", "success"),
                ("불일치", "실패", "danger"),
                ("", "참고 문구 행"),
            ],
        },
        {"title": "", "rows": [("", "섹션 제목 없는 카드")]},
    ])
    # One card frame per section
    assert len(sv.body.winfo_children()) == 2

    # Re-render replaces content
    sv.render([{"title": "T", "rows": [("a", "b")]}])
    assert len(sv.body.winfo_children()) == 1


def test_summary_view_strip_brackets() -> None:
    from desktop.gui.widgets import SummaryView

    assert SummaryView._strip_brackets("[사건정보]") == "사건정보"
    assert SummaryView._strip_brackets("  [Case Info]  ") == "Case Info"
    assert SummaryView._strip_brackets("     제목") == "제목"


def test_summary_view_status_colors_use_wcag_tokens() -> None:
    from desktop.gui.widgets import SummaryView
    from desktop.gui.theme import COLORS

    assert SummaryView._status_color("success") == COLORS["success_text"]
    assert SummaryView._status_color("danger") == COLORS["danger_text"]
    assert SummaryView._status_color("warning") == COLORS["warning_text"]
    assert SummaryView._status_color("info") == COLORS["info_text"]
    assert SummaryView._status_color(None) == COLORS["text"]


# ---------- FileSelector inline errors ----------

def test_file_selector_error_api(root: tk.Tk) -> None:
    from desktop.gui.widgets import FileSelector

    fs = FileSelector(root, "Target", required=True)
    fs.pack()
    fs.highlight_error("select a file")
    assert fs._error_label.cget("text") == "select a file"
    fs.clear_error()
    # highlight with default message
    fs.highlight_error()
    assert fs._error_label.cget("text") != ""
    fs.clear_error()


def test_labeled_entry_custom_error_message(root: tk.Tk) -> None:
    from desktop.gui.widgets import LabeledEntry

    le = LabeledEntry(root, "PW", required=True)
    le.pack()
    le.highlight_error("passwords do not match")
    assert le._error_label.cget("text") == "passwords do not match"
    le.clear_error()


# ---------- progress_dialog helpers ----------

def test_fmt_size_human_readable() -> None:
    from desktop.gui.progress_dialog import _fmt_size

    assert _fmt_size(512) == "512 B"
    assert _fmt_size(2048) == "2.0 KB"
    assert _fmt_size(8 * 1024 * 1024) == "8.0 MB"
    assert _fmt_size(3 * 1024 ** 3) == "3.0 GB"


def test_run_async_delivers_result(root: tk.Tk) -> None:
    from desktop.gui.progress_dialog import run_async

    results: list[int] = []
    run_async(root, lambda: 42, results.append, poll_ms=10)

    deadline = time.monotonic() + 5.0
    while not results and time.monotonic() < deadline:
        root.update()
        time.sleep(0.01)
    assert results == [42]


def test_run_async_delivers_error(root: tk.Tk) -> None:
    from desktop.gui.progress_dialog import run_async

    errors: list[Exception] = []

    def boom() -> None:
        raise ValueError("nope")

    run_async(root, boom, on_success=lambda _r: None, on_error=errors.append, poll_ms=10)

    deadline = time.monotonic() + 5.0
    while not errors and time.monotonic() < deadline:
        root.update()
        time.sleep(0.01)
    assert len(errors) == 1
    assert isinstance(errors[0], ValueError)


# ---------- Toplevel binding save/restore (leak fix) ----------

def test_unseal_wizard_restores_toplevel_bindings(root: tk.Tk) -> None:
    from desktop.gui.unseal_wizard import UnsealWizard

    root.bind("<Return>", lambda _e: None)
    root.bind("<Escape>", lambda _e: None)
    prev_return = root.bind("<Return>")
    prev_escape = root.bind("<Escape>")

    app = SimpleNamespace(db_path=":memory:")
    wiz = UnsealWizard(root, app)
    wiz.pack(fill="both", expand=True)
    root.update_idletasks()

    # Wizard installed its own bindings
    assert root.bind("<Return>") != prev_return

    wiz.destroy()
    root.update_idletasks()

    # Previous bindings restored — no dangling wizard callbacks
    assert root.bind("<Return>") == prev_return
    assert root.bind("<Escape>") == prev_escape


def test_seal_wizard_has_no_debug_prints() -> None:
    """P0: personal data must not leak to the console via debug prints."""
    from pathlib import Path
    import desktop.gui.seal_wizard as sw

    source = Path(sw.__file__).read_text(encoding="utf-8")
    assert "[DEBUG]" not in source
    assert "print(" not in source


# ---------- i18n keys ----------

def test_wave2_i18n_keys_exist_in_both_languages() -> None:
    from desktop.gui.i18n import _TRANSLATIONS

    keys = [
        "unseal.verifying",
        "reseal.comparing",
        "progress.bytes_label",
        "progress.speed_mb",
        "validate.fix_errors",
        "summary.seal_id",
        "summary.case_number",
        "summary.hash_verified",
        "summary.record_pdf",
        "summary.notice",
        "summary.verification",
    ]
    for key in keys:
        assert key in _TRANSLATIONS, f"missing i18n key: {key}"
        assert "ko" in _TRANSLATIONS[key], f"missing ko for {key}"
        assert "en" in _TRANSLATIONS[key], f"missing en for {key}"
