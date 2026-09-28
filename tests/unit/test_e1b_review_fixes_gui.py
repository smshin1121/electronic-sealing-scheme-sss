"""Review fixes of the E1b share handout (stage E, E1 fix round).

Share panel: an unsafe seal_id never reaches a suggested file name, and a
temporary copy of a share that could not be deleted is reported to the
operator.

Leaving the wizards (A1, B2, B3a): at R7, Cancel and Escape ask the same
question as the main window's menus, Exit and X while shares 1/2 are
unsaved (default: stay), and release the key material when the operator
leaves; with both shares saved but the reseal not saved (R8 not run or
failed), every way out asks first and names the database record. The
real Cancel button, the Escape key and the window's X handler are used.

Encryption dialogs (B1): S1 and R5 run in a modal progress dialog; the
window's X reaches the main window while the dialog holds the grab, so the
wizard is busy for the dialog's lifetime and X is refused (a real dialog
is open while X is pressed).
"""

from __future__ import annotations

import logging
import os
import threading
import tkinter as tk
from pathlib import Path
from typing import Any, Callable

import pytest

from desktop.crypto import split_key_strict
from desktop.gui.i18n import t
from desktop.share_file import SavedShare
from tests.fixtures.tk_root import destroy_test_root, new_test_root
from tests.unit import test_share_handout_gui as _handout
from tests.unit.test_share_handout_gui import (
    RESEAL_ID,
    _close_button,
    _Reseal,
    _split,
)

app = _handout.app  # the main window fixture (MainApp, dialogs recorded)


@pytest.fixture()
def root():
    r = new_test_root()
    yield r
    destroy_test_root(r)


class _Ask:
    """Save-dialog stand-in: records the options, answers with ``paths``."""

    def __init__(self, paths: list[str]) -> None:
        self.paths = list(paths)
        self.calls: list[dict] = []

    def __call__(self, **options):
        self.calls.append(options)
        return self.paths.pop(0) if self.paths else ""


def _panel(root, ask: _Ask):
    from desktop.gui.share_handout import ShareHandoutPanel

    panel = ShareHandoutPanel(root, ask_save_path=ask)
    panel.pack()
    return panel


# ===================================================================
# A5: the seal_id in suggested file names
# ===================================================================

@pytest.mark.parametrize("seal_id", ["../evil", "C:\\x", "S-1/2", "a b"])
def test_an_unsafe_seal_id_gets_generic_file_names(
    root, tmp_path: Path, seal_id: str, caplog
) -> None:
    caplog.set_level(logging.WARNING)
    ask = _Ask([str(tmp_path / "one.share")])
    panel = _panel(root, ask)
    shares = split_key_strict(os.urandom(32).hex())
    panel.load(seal_id, shares, "strict")

    assert panel.save(1) is not None

    assert ask.calls[0]["initialfile"] == "share1_subject.share"
    assert seal_id not in caplog.text


def test_a_plain_seal_id_is_kept_in_file_names(root, tmp_path: Path) -> None:
    ask = _Ask([str(tmp_path / "one.share")])
    panel = _panel(root, ask)
    panel.load("S-20260928-0A1B2C", split_key_strict(os.urandom(32).hex()), "strict")

    panel.save(1)

    assert ask.calls[0]["initialfile"] == "S-20260928-0A1B2C_share1_subject.share"


# ===================================================================
# A3: a temporary copy that could not be deleted
# ===================================================================

def test_a_temporary_copy_left_behind_is_reported(
    root, tmp_path: Path, monkeypatch
) -> None:
    from tkinter import messagebox

    import desktop.gui.share_handout as share_handout

    left = str(tmp_path / ".share-abc.tmp")
    warnings: list[tuple] = []
    monkeypatch.setattr(messagebox, "showwarning",
                        lambda *a, **_k: warnings.append(a))
    monkeypatch.setattr(
        share_handout, "write_share_file",
        lambda path, _share, *, index, taken_paths: SavedShare(
            index=index, path=str(path), fingerprint="0" * 16, temp_left=left),
    )
    ask = _Ask([str(tmp_path / "one.share")])
    panel = _panel(root, ask)
    panel.load("S-20260928-0A1B2C", split_key_strict(os.urandom(32).hex()), "strict")

    saved = panel.save(1)

    assert saved is not None and panel.saved() == (saved,)
    assert len(warnings) == 1
    title, message = warnings[0][:2]
    assert title == t("handout.temp_left_title")
    assert left in message


def test_a_clean_save_raises_no_warning(root, tmp_path: Path, monkeypatch) -> None:
    from tkinter import messagebox

    warnings: list[tuple] = []
    monkeypatch.setattr(messagebox, "showwarning",
                        lambda *a, **_k: warnings.append(a))
    ask = _Ask([str(tmp_path / "one.share")])
    panel = _panel(root, ask)
    panel.load("S-20260928-0A1B2C", split_key_strict(os.urandom(32).hex()), "strict")

    saved = panel.save(1)

    assert saved is not None and saved.temp_left == ""
    assert warnings == []


# ===================================================================
# Helpers: dialogs answered by the test, the reseal wizard at R7
# ===================================================================

UNSAVED = (t("nav.unsaved_title"), t("nav.unsaved_msg"))
UNRECORDED = (t("nav.unrecorded_title"), t("nav.unrecorded_msg"))


@pytest.fixture()
def asked(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """askyesno answers from ``answers`` (default: No); every dialog recorded."""
    from tkinter import messagebox

    calls: dict[str, list] = {"yesno": [], "answers": [], "error": [], "warning": []}

    def _ask(*a: Any, **k: Any) -> bool:
        calls["yesno"].append((a, k))
        return calls["answers"].pop(0) if calls["answers"] else False

    monkeypatch.setattr(messagebox, "askyesno", _ask)
    monkeypatch.setattr(messagebox, "showerror",
                        lambda *a, **_k: calls["error"].append(a))
    monkeypatch.setattr(messagebox, "showwarning",
                        lambda *a, **_k: calls["warning"].append(a))
    return calls


@pytest.fixture()
def reseal(root, tmp_path, asked):
    made: list[_Reseal] = []

    def _make(mode: str) -> _Reseal:
        r = _Reseal(root, tmp_path, mode)
        made.append(r)
        return r

    yield _make
    for r in made:
        try:
            r.wizard.destroy()
        except tk.TclError:
            pass


def _app_reseal(app: Any, tmp_path: Path, mode: str) -> _Reseal:
    """The main window's own reseal wizard, set up at R4 like ``_Reseal``."""
    app._on_reseal()
    r = _Reseal.__new__(_Reseal)
    r.root, r.mode = app.root, mode
    r.key_hex, r.shares = _split(mode)
    r.share_dir = tmp_path / "reseal-shares"
    r.share_dir.mkdir(exist_ok=True)
    r.completed = []
    r.process = r._process(tmp_path)
    r.wizard = app._active_wizard
    r.wizard._handout_panel._ask_save_path = (
        lambda **kw: str(r.share_dir / kw["initialfile"]))
    r.wizard._data.update({
        "_process": r.process, "seal_id": RESEAL_ID, "seal_mode": mode,
        "prev_record": {"seal_id": RESEAL_ID, "seal_mode": mode},
        "target_dir": str(tmp_path), "output_dir": str(tmp_path),
    })
    r.wizard._r4_investigator.set("Hong")
    r.wizard._r4_reason.set("analysis complete")
    r.wizard._show_step(3)
    return r


def _alive(root: tk.Tk) -> bool:
    try:
        return bool(root.winfo_exists())
    except tk.TclError:
        return False


def _press_escape(root: tk.Tk) -> None:
    """A real Escape key press on the main window (it needs the focus)."""
    root.deiconify()
    root.update()
    root.focus_force()
    root.update()
    root.event_generate("<Escape>")
    root.update()
    root.withdraw()


def _press(r: _Reseal, how: str) -> None:
    if how == "cancel":
        r.wizard._cancel_btn.invoke()
    else:
        _press_escape(r.root)


def _released(wizard: Any) -> bool:
    """Shares and the process (key, shares) dropped from the wizard."""
    return (wizard._handout_panel.holds_shares() is False
            and "_process" not in wizard._data)


# ===================================================================
# A1: Cancel and Escape at R7 with unsaved shares
# ===================================================================

@pytest.mark.parametrize("how", ["cancel", "escape"])
def test_leaving_r7_with_unsaved_shares_asks_first(reseal, asked, how: str) -> None:
    r = reseal("strict")
    r.to_r7()
    w = r.wizard
    w._go_next()  # splits: shares 1/2 held, not saved
    cancelled: list[bool] = []
    w._on_cancel = lambda: cancelled.append(True)

    _press(r, how)  # answered No: stay

    assert len(asked["yesno"]) == 1
    question, options = asked["yesno"][0]
    assert question == UNSAVED
    assert options.get("default") == "no" and options.get("icon") == "warning"
    assert cancelled == [] and w._handout_panel.holds_shares() is True

    asked["answers"].append(True)
    _press(r, how)  # answered Yes: leave

    assert asked["yesno"][1][0] == UNSAVED
    assert cancelled == [True]
    assert _released(w)


def test_cancel_before_the_split_keeps_the_plain_question(reseal, asked) -> None:
    r = reseal("standard")
    r.to_r7()

    r.wizard._cancel_btn.invoke()

    assert asked["yesno"][0][0] == (t("cancel.title"), t("reseal.cancel_confirm"))


# ===================================================================
# B2: both shares saved, the reseal not saved
# ===================================================================

def test_the_unrecorded_reseal_question_follows_r8(reseal, asked) -> None:
    r = reseal("standard")
    saved_result = r.process.run_r8_save.return_value
    r.process.run_r8_save.side_effect = [RuntimeError("disk full"), saved_result]
    r.to_r7()
    w = r.wizard
    cancelled: list[bool] = []
    w._on_cancel = lambda: cancelled.append(True)
    w._go_next()
    assert w.leave_question() == ("nav.unsaved_title", "nav.unsaved_msg")
    w._handout_panel.button(1).invoke()
    w._handout_panel.button(2).invoke()

    # R7, both saved, Next not pressed yet.
    assert w.leave_question() == ("nav.unrecorded_title", "nav.unrecorded_msg")
    w._cancel_btn.invoke()
    question, options = asked["yesno"][-1]
    assert question == UNRECORDED and options.get("default") == "no"
    assert cancelled == []

    w._go_next()  # R8: the first save fails
    r.pump(lambda: bool(asked["error"]))
    assert w.leave_question() == ("nav.unrecorded_title", "nav.unrecorded_msg")
    w._cancel_btn.invoke()
    assert asked["yesno"][-1][0] == UNRECORDED and cancelled == []

    w._go_next()  # retried: saved
    r.pump(lambda: bool(w._data.get("reseal_saved")))
    assert w.leave_question() is None
    w._go_next()  # complete
    assert len(r.completed) == 1 and w.leave_question() is None


def test_x_menus_and_exit_ask_before_leaving_an_unrecorded_reseal(
    app, tmp_path, monkeypatch
) -> None:
    from tkinter import messagebox

    errors: list[tuple] = []
    monkeypatch.setattr(messagebox, "showerror", lambda *a, **_k: errors.append(a))
    r = _app_reseal(app, tmp_path, "standard")
    r.process.run_r8_save.side_effect = RuntimeError("disk full")
    r.to_r7()
    w = r.wizard
    w._go_next()
    w._handout_panel.button(1).invoke()
    w._handout_panel.button(2).invoke()
    w._go_next()  # R8: the save fails
    r.pump(lambda: bool(errors))

    _close_button(app)  # X
    app._on_unseal()    # a menu
    app._on_exit()      # Exit

    assert _alive(app.root) and app._active_wizard is w
    assert [a for a, _k in app.calls["yesno"]] == [UNRECORDED] * 3
    assert all(k.get("default") == "no" for _a, k in app.calls["yesno"])


# ===================================================================
# B3(a): the reseal's unsaved shares through the real X handler
# ===================================================================

def test_x_with_unsaved_reseal_shares_asks_then_releases(app, tmp_path) -> None:
    r = _app_reseal(app, tmp_path, "strict")
    r.to_r7()
    w = r.wizard
    w._go_next()  # splits

    _close_button(app)  # answered No
    assert _alive(app.root)
    question, options = app.calls["yesno"][0]
    assert question == UNSAVED and options.get("default") == "no"
    assert w._handout_panel.holds_shares() is True

    app.calls["answer"] = True
    _close_button(app)  # answered Yes: the window closes

    assert not _alive(app.root)
    assert _released(w)


# ===================================================================
# B1: X while the encryption dialog is open
# ===================================================================

def _press_x_during(app: Any, wizard: Any, release: threading.Event,
                    seen: list[bool]) -> None:
    """Press X once the dialog runs, then let the task finish."""
    def _press() -> None:
        seen.append(wizard.is_busy())
        _close_button(app)
        app.root.after(100, release.set)

    app.root.after(300, _press)


def test_x_is_refused_while_r5_encrypts(app, tmp_path) -> None:
    r = _app_reseal(app, tmp_path, "standard")
    release = threading.Event()
    result = r.process.run_r5_encrypt.return_value
    r.process.run_r5_encrypt.side_effect = (
        lambda progress_cb=None: (release.wait(10), result)[1])
    seen: list[bool] = []
    _press_x_during(app, r.wizard, release, seen)

    try:
        r.wizard._go_next()  # R4 -> R5: the dialog is open until released
    finally:
        release.set()

    assert seen == [True]
    assert _alive(app.root)
    assert [a[0] for a, _k in app.calls["warning"]] == [t("nav.busy_title")]
    assert app.calls["yesno"] == []
    r.pump(lambda: bool(r.wizard._data.get("record_done")))
    assert r.wizard.is_busy() is False


def test_x_is_refused_while_s1_encrypts(app, tmp_path, monkeypatch) -> None:
    from desktop.seal_process import SealProcess

    release = threading.Event()
    out = tmp_path / "out"
    out.mkdir()
    source = tmp_path / "disk.dd"
    source.write_bytes(b"\x00" * 4096)

    def _slow_s1(self: Any, source_file: str, output_dir: str, chunk_gb: int,
                 progress_cb: Callable[..., Any] = None) -> dict[str, Any]:
        release.wait(10)
        return {"enc_filepath": str(out / "disk.dd.enc"), "aes_key_hex": "ab" * 32,
                "metadata": {"filename": "disk.dd", "size": 4096}, "enc_metadata": {}}

    monkeypatch.setattr(SealProcess, "run_s1", _slow_s1)
    app._on_seal()
    w = app._active_wizard
    w._file_selector.set(str(source))
    w._output_selector.set(str(out))
    seen: list[bool] = []
    _press_x_during(app, w, release, seen)

    try:
        w._go_next()  # S1: the dialog is open until released
    finally:
        release.set()

    assert seen == [True]
    assert _alive(app.root)
    assert [a[0] for a, _k in app.calls["warning"]] == [t("nav.busy_title")]
    assert w._current_step == 1 and w.is_busy() is False


def test_a_cancelled_s1_still_says_so(app, tmp_path, monkeypatch) -> None:
    """The busy state ends after the dialog; the cancel notice stays."""
    from desktop.gui import progress_dialog
    from desktop.seal_process import SealProcess

    def _cancelled_s1(self: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("cancelled")

    monkeypatch.setattr(SealProcess, "run_s1", _cancelled_s1)
    monkeypatch.setattr(progress_dialog.ProgressDialog, "was_cancelled",
                        property(lambda _self: True))
    app._on_seal()
    w = app._active_wizard
    source = tmp_path / "disk.dd"
    source.write_bytes(b"\x00" * 4096)
    w._file_selector.set(str(source))
    w._output_selector.set(str(tmp_path))

    w._go_next()

    assert w._current_step == 0 and w.is_busy() is False
    assert w._nav_msg_label.cget("text") == t("progress.task_cancelled")


# ===================================================================
# i18n
# ===================================================================

def test_i18n_keys_of_the_fix_round() -> None:
    from desktop.gui.i18n import _TRANSLATIONS

    for key in ("nav.unrecorded_title", "nav.unrecorded_msg",
                "handout.temp_left_title", "handout.temp_left_msg",
                "unseal.u7_save_failed_title", "unseal.u7_save_failed_msg"):
        assert _TRANSLATIONS[key]["ko"] and _TRANSLATIONS[key]["en"], key
    assert "암호화" in _TRANSLATIONS["nav.busy_msg"]["ko"]
    assert "encryption" in _TRANSLATIONS["nav.busy_msg"]["en"]
