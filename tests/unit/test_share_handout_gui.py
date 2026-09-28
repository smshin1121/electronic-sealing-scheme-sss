"""Share handout in the seal (S6) and reseal (R7) wizards, and the close guard (E1b).

The operator saves share 1 (subject) and share 2 (investigator) to two
separate ``.share`` files; S6 -> S7 and R7 -> R8 wait until both are saved.
Only fingerprints and saved paths are shown; no share text reaches a log
record (any level), a widget or the completion data, and the shares are
dropped from the wizard at completion. The main window's close button (X),
like its menus and Exit, is refused while a wizard seals or reseals, and
asks first while shares are still unsaved.

The wizards run with autospec'd processes (wrong arguments raise as on the
real classes) and realistic shares from ``split_key`` / ``split_key_strict``.
"""

from __future__ import annotations

import dataclasses
import gc
import json
import logging
import os
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from types import SimpleNamespace
from typing import Any, Callable, Optional
from unittest import mock

import pytest

from desktop.crypto import recover_key_for_mode, split_key, split_key_strict
from desktop.gui.i18n import t
from desktop.reseal_process import ResealProcess, ResealResult
from desktop.share_file import fingerprint_of
from tests.fixtures.tk_root import destroy_test_root, new_test_root
from tests.unit.test_seal_wizard_process import SEAL_ID, _Harness, _process

RESEAL_ID = "S-20260928-0B0B0B"


def _split(mode: str) -> tuple[str, tuple[str, str, str, str]]:
    key_hex = os.urandom(32).hex()
    shares = split_key_strict(key_hex) if mode == "strict" else split_key(key_hex)
    return key_hex, tuple(shares)


def _payloads(shares) -> list[str]:
    return [share.split("-", 1)[1] for share in shares]


def _widget_texts(widget: tk.Misc) -> str:
    texts: list[str] = []
    stack = [widget]
    while stack:
        current = stack.pop()
        stack.extend(current.winfo_children())
        if isinstance(current, tk.Text):
            texts.append(current.get("1.0", "end"))
        elif isinstance(current, (tk.Entry, ttk.Entry)):
            texts.append(current.get())
        try:
            texts.append(str(current.cget("text")))
        except tk.TclError:
            pass
    return "\n".join(texts)


def _assert_no_share_text(shares, *texts: str) -> None:
    for payload in _payloads(shares):
        for text in texts:
            assert payload not in text
            assert payload[:16] not in text


def _assert_no_share_in_logs(shares, caplog) -> None:
    messages = "\n".join(record.getMessage() for record in caplog.records)
    _assert_no_share_text(shares, caplog.text, messages)


@pytest.fixture()
def root():
    r = new_test_root()
    yield r
    destroy_test_root(r)


@pytest.fixture()
def dialogs(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[tuple]]:
    from tkinter import messagebox

    calls: dict[str, list[tuple]] = {"error": [], "warning": [], "yesno": []}
    monkeypatch.setattr(messagebox, "showerror",
                        lambda *a, **_k: calls["error"].append(a))
    monkeypatch.setattr(messagebox, "showwarning",
                        lambda *a, **_k: calls["warning"].append(a))
    monkeypatch.setattr(messagebox, "askyesno",
                        lambda *a, **_k: calls["yesno"].append(a) or True)
    return calls


# ===================================================================
# Seal wizard (S6)
# ===================================================================

def _sealing(tmp_path: Path, mode: str) -> tuple[Any, str, tuple[str, ...]]:
    process = _process(tmp_path, mode=mode)
    key_hex, shares = _split(mode)
    process.run_s7.return_value = dataclasses.replace(
        process.run_s7.return_value, key_shares=shares)
    return process, key_hex, shares


@pytest.fixture()
def harness(root, tmp_path, dialogs):
    made: list[_Harness] = []

    def _make(process: Any) -> _Harness:
        h = _Harness(root, process, tmp_path)
        made.append(h)
        return h

    yield _make
    for h in made:
        try:
            h.wizard.destroy()
        except tk.TclError:
            pass


def _sealed_at_s6(h: _Harness, mode: str) -> None:
    h.to_s5(mode=mode, consent=True)
    h.pump(h.sealed)
    h.wizard._go_next()  # S5 -> S6
    assert h.wizard._current_step == 5


@pytest.mark.parametrize("mode", ["standard", "strict"])
def test_s6_to_s7_waits_for_both_share_files(harness, tmp_path, dialogs, mode) -> None:
    process, key_hex, shares = _sealing(tmp_path, mode)
    h = harness(process)
    _sealed_at_s6(h, mode)
    panel = h.wizard._handout_panel

    assert h.wizard._validate_s6() is False
    assert h.wizard._nav_msg_label.cget("text") == t("handout.save_both_first")
    panel.button(1).invoke()
    h.wizard._go_next()
    assert h.wizard._current_step == 5
    panel.button(2).invoke()
    h.wizard._go_next()
    assert h.wizard._current_step == 6
    h.wizard._go_next()
    assert len(h.completed) == 1
    assert dialogs["error"] == []

    files = {saved.index: Path(saved.path) for saved in panel.saved()}
    assert set(files) == {1, 2} and files[1] != files[2]
    for index in (1, 2):
        assert files[index].read_bytes() == f"{shares[index - 1]}\n".encode()
    s1, s2 = (files[i].read_text(encoding="utf-8").strip() for i in (1, 2))
    assert recover_key_for_mode(mode, [s1, s2]) == key_hex


def test_save_dialog_suggests_names_and_leaves_overwrite_to_the_writer(harness, tmp_path) -> None:
    process, _key, _shares = _sealing(tmp_path, "standard")
    h = harness(process)
    _sealed_at_s6(h, "standard")
    h.save_shares()

    first, second = h.dialog_calls
    assert first["initialfile"] == f"{SEAL_ID}_share1_subject.share"
    assert second["initialfile"] == f"{SEAL_ID}_share2_investigator.share"
    for call in (first, second):
        assert call["defaultextension"] == ".share"
        assert call["confirmoverwrite"] is False
        assert any("*.share" in pattern for _label, pattern in call["filetypes"])


def test_overwrite_and_the_same_path_are_refused(harness, tmp_path, dialogs) -> None:
    process, _key, shares = _sealing(tmp_path, "strict")
    h = harness(process)
    _sealed_at_s6(h, "strict")
    panel = h.wizard._handout_panel
    existing = tmp_path / "existing.share"
    existing.write_bytes(b"keep me\n")

    h.next_paths = [str(existing)]
    panel.button(1).invoke()
    assert existing.read_bytes() == b"keep me\n"
    assert panel.saved() == ()
    assert t("handout.error_exists").split("{", 1)[0] in dialogs["error"][-1][1]

    chosen = tmp_path / "subject.share"
    h.next_paths = [str(chosen), str(chosen)]
    panel.button(1).invoke()
    panel.button(2).invoke()
    assert [saved.index for saved in panel.saved()] == [1]
    assert dialogs["error"][-1][1] == t("handout.error_same_path")
    assert chosen.read_bytes() == f"{shares[0]}\n".encode()
    assert h.wizard._validate_s6() is False


def test_a_cancelled_save_dialog_saves_nothing(harness, tmp_path, dialogs) -> None:
    process, _key, _shares = _sealing(tmp_path, "standard")
    h = harness(process)
    _sealed_at_s6(h, "standard")
    h.next_paths = [""]

    h.wizard._handout_panel.button(1).invoke()

    assert h.wizard._handout_panel.saved() == ()
    assert dialogs["error"] == []
    assert list(h.share_dir.iterdir()) == []


def test_strict_s6_says_share_1_must_go_to_the_subject(harness, tmp_path) -> None:
    process, _key, _shares = _sealing(tmp_path, "strict")
    h = harness(process)
    _sealed_at_s6(h, "strict")
    panel = h.wizard._handout_panel

    assert panel.strict_notice_shown() is True
    assert t("handout.strict_notice") in _widget_texts(panel)


def test_standard_s6_has_no_strict_notice(harness, tmp_path) -> None:
    process, _key, _shares = _sealing(tmp_path, "standard")
    h = harness(process)
    _sealed_at_s6(h, "standard")

    assert h.wizard._handout_panel.strict_notice_shown() is False


@pytest.mark.parametrize("mode", ["standard", "strict"])
def test_the_seal_flow_leaks_no_share_text(harness, tmp_path, caplog, mode) -> None:
    caplog.set_level(logging.DEBUG)
    process, _key, shares = _sealing(tmp_path, mode)
    h = harness(process)
    _sealed_at_s6(h, mode)
    h.save_shares()
    at_s6 = _widget_texts(h.root)
    h.wizard._go_next()
    at_s7 = _widget_texts(h.root)
    h.wizard._go_next()

    data = h.completed[0]
    _assert_no_share_text(shares, at_s6, at_s7, json.dumps(data, default=str))
    _assert_no_share_in_logs(shares, caplog)
    for fingerprint in map(fingerprint_of, shares):
        assert fingerprint in at_s6
    # Dropped from the wizard at completion.
    assert h.wizard._handout_panel.holds_shares() is False
    assert h.wizard._seal_result.key_shares == ("", "", "", "")


# ===================================================================
# Reseal wizard (R7 -> R8)
# ===================================================================

class _Reseal:
    """A reseal wizard at R4 with an autospec process and realistic shares."""

    def __init__(self, root: tk.Tk, tmp_path: Path, mode: str) -> None:
        from desktop.gui.reseal_wizard import ResealWizard

        self.root = root
        self.mode = mode
        self.key_hex, self.shares = _split(mode)
        self.share_dir = tmp_path / "reseal-shares"
        self.share_dir.mkdir(exist_ok=True)
        self.completed: list[dict[str, Any]] = []
        self.process = self._process(tmp_path)
        self.wizard = ResealWizard(
            root, SimpleNamespace(db_path=":memory:"),
            on_complete=self.completed.append,
            ask_share_path=lambda **kw: str(self.share_dir / kw["initialfile"]),
        )
        self.wizard._data.update({
            "_process": self.process, "seal_id": RESEAL_ID, "seal_mode": mode,
            "prev_record": {"seal_id": RESEAL_ID, "seal_mode": mode},
            "target_dir": str(tmp_path), "output_dir": str(tmp_path),
        })
        self.wizard._r4_investigator.set("Hong")
        self.wizard._r4_reason.set("analysis complete")
        self.wizard._show_step(3)

    def _process(self, tmp_path: Path) -> mock.MagicMock:
        process = mock.create_autospec(ResealProcess, instance=True)
        process.state, process.config = {}, None
        enc = str(tmp_path / "e.bin.enc")
        process.run_r5_encrypt.return_value = {
            "aes_key_hex": self.key_hex, "encryption_algo": "AES-256-GCM",
            "enc_results": [{"enc_filepath": enc, "original_filepath": "e.bin",
                             "metadata": {"filename": "e.bin"}, "chunk_count": 1}],
        }
        process.run_r6_record.return_value = {
            "record_dict": {"seal_id": RESEAL_ID, "seal_mode": self.mode,
                            "case_info": {"case_number": "2026-E1B"},
                            "history": {"summary": "S1U1R1", "events": []}},
            "record_json_path": str(tmp_path / "r.json"),
            "pdf_path": str(tmp_path / "r.pdf"), "policy_digest": None,
        }
        process.run_r7_split_key.return_value = {
            "shares": list(self.shares), "unlock_time_iso": "2026-10-23T00:00:00Z",
            "encrypted_shares": {}, "wrapped_s3_b64": None,
        }
        process.run_r8_save.return_value = ResealResult(
            seal_id=RESEAL_ID, enc_filepath=enc, pdf_path=str(tmp_path / "r.pdf"),
            key_shares=self.shares, unlock_time_iso="2026-10-23T00:00:00Z",
            record_json="{}",
        )
        return process

    def pump(self, until: Callable[[], bool], timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while not until() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        assert until(), "timed out waiting for the reseal wizard"

    def to_r7(self) -> None:
        w = self.wizard
        w._go_next()  # R4 -> R5: encryption dialog, then R6 on a worker
        self.pump(lambda: bool(w._data.get("record_done")))
        w._go_next()  # R5 -> R6
        w._go_next()  # R6 -> R7
        assert w._current_step == 6


@pytest.fixture()
def reseal(root, tmp_path, dialogs):
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


@pytest.mark.parametrize("mode", ["standard", "strict"])
def test_r7_to_r8_waits_for_both_share_files(reseal, dialogs, caplog, mode) -> None:
    caplog.set_level(logging.DEBUG)
    r = reseal(mode)
    r.to_r7()
    w = r.wizard
    panel = w._handout_panel

    w._go_next()  # splits, stays on R7
    assert w._current_step == 6
    r.process.run_r7_split_key.assert_called_once_with()
    w._go_next()
    assert w._current_step == 6
    assert w._nav_msg_label.cget("text") == t("handout.save_both_first")
    panel.button(1).invoke()
    w._go_next()
    assert w._current_step == 6
    panel.button(2).invoke()
    at_r7 = _widget_texts(r.root)
    w._go_next()  # R7 -> R8, which saves on a worker
    assert w._current_step == 7
    r.process.run_r7_split_key.assert_called_once_with()
    r.pump(lambda: bool(w._data.get("reseal_saved")))
    at_r8 = _widget_texts(r.root)
    w._go_next()  # complete

    assert len(r.completed) == 1 and dialogs["error"] == []
    r.process.run_r8_save.assert_called_once_with()
    data = r.completed[0]
    dumped = json.dumps(data, default=str)
    assert "_process" not in data and "key_shares" not in data
    assert r.key_hex not in dumped and "aes_key_hex" not in dumped
    _assert_no_share_text(r.shares, at_r7, at_r8, dumped)
    _assert_no_share_in_logs(r.shares, caplog)
    assert panel.holds_shares() is False
    files = {saved.index: Path(saved.path) for saved in panel.saved()}
    s1, s2 = (files[i].read_text(encoding="utf-8").strip() for i in (1, 2))
    assert recover_key_for_mode(mode, [s1, s2]) == r.key_hex


def test_strict_r7_says_share_1_must_go_to_the_subject(reseal) -> None:
    r = reseal("strict")
    r.to_r7()
    r.wizard._go_next()

    assert r.wizard._handout_panel.strict_notice_shown() is True


def test_an_r8_save_failure_is_shown_and_retried(reseal, dialogs) -> None:
    r = reseal("standard")
    saved_result = r.process.run_r8_save.return_value
    r.process.run_r8_save.side_effect = [RuntimeError("disk full"), saved_result]
    r.to_r7()
    w = r.wizard
    w._go_next()
    w._handout_panel.button(1).invoke()
    w._handout_panel.button(2).invoke()
    w._go_next()  # R8: first save fails
    r.pump(lambda: bool(dialogs["error"]))

    assert "disk full" in dialogs["error"][0][1]
    assert not w._data.get("reseal_saved")
    assert t("reseal.not_saved_badge") in _widget_texts(w)
    assert t("complete.reseal_saved").strip() not in _widget_texts(w)
    w._go_next()  # retries the save, does not complete
    assert r.completed == []
    r.pump(lambda: bool(w._data.get("reseal_saved")))
    assert t("reseal.not_saved_badge") not in _widget_texts(w)
    assert t("complete.reseal_saved").strip() in _widget_texts(w)
    w._go_next()
    assert len(r.completed) == 1
    assert r.process.run_r8_save.call_count == 2


def test_r8_is_busy_while_saving(reseal) -> None:
    r = reseal("standard")
    import threading

    release = threading.Event()
    result = r.process.run_r8_save.return_value
    r.process.run_r8_save.side_effect = lambda: release.wait(10) and result
    r.to_r7()
    w = r.wizard
    w._go_next()
    w._handout_panel.button(1).invoke()
    w._handout_panel.button(2).invoke()
    w._go_next()

    assert w.is_busy() is True
    w._go_next()
    assert r.completed == []
    release.set()
    r.pump(lambda: bool(w._data.get("reseal_saved")))
    assert w.is_busy() is False


# ===================================================================
# Main window: close button (X), menus and Exit
# ===================================================================

@pytest.fixture()
def app(tmp_path, monkeypatch):
    from tkinter import messagebox

    from desktop.db import init_db
    from desktop.gui.app import MainApp
    from desktop.gui.i18n import remove_listener

    calls: dict[str, Any] = {"warning": [], "yesno": [], "answer": False}
    monkeypatch.setattr(messagebox, "showwarning",
                        lambda *a, **k: calls["warning"].append((a, k)))

    def _ask(*a: Any, **k: Any) -> bool:
        calls["yesno"].append((a, k))
        return calls["answer"]

    monkeypatch.setattr(messagebox, "askyesno", _ask)
    db = str(tmp_path / "app.db")
    init_db(db)
    gc.collect()
    main: Optional[Any] = None
    for attempt in range(3):  # transient Tcl start-up errors (tests/fixtures/tk_root.py)
        try:
            main = MainApp(db_path=db)
            break
        except tk.TclError:
            if attempt == 2:
                raise
            time.sleep(0.2)
    main.root.withdraw()
    main.calls = calls
    yield main
    remove_listener(main._on_language_change)
    destroy_test_root(main.root)


def _close_button(app: Any) -> None:
    """Press the window's X: invoke the registered WM_DELETE_WINDOW handler."""
    handler = app.root.protocol("WM_DELETE_WINDOW")
    assert handler, "no WM_DELETE_WINDOW handler registered"
    app.root.tk.call(handler)


def test_x_is_refused_while_sealing_or_resealing(app) -> None:
    app._on_seal()
    app._active_wizard._busy = True  # S4-S7 running
    _close_button(app)
    assert app.root.winfo_exists() and len(app.calls["warning"]) == 1

    app._active_wizard._busy = False
    app._on_reseal()
    assert type(app._active_wizard).__name__ == "ResealWizard"
    app._active_wizard._busy = True  # R6 record or R8 save running
    _close_button(app)
    app._on_exit()
    assert app.root.winfo_exists() and len(app.calls["warning"]) == 3
    assert app.calls["yesno"] == []


def test_x_closes_when_nothing_runs(app) -> None:
    destroyed: list[bool] = []
    real_destroy = app.root.destroy
    app.root.destroy = lambda: (destroyed.append(True), real_destroy())

    _close_button(app)

    assert destroyed == [True]
    assert app.calls["warning"] == [] and app.calls["yesno"] == []


def test_leaving_with_unsaved_shares_asks_first(app) -> None:
    app._on_seal()
    wizard = app._active_wizard
    wizard._data["signature_done"] = True  # the seal is saved (S7 done)
    _key, shares = _split("strict")
    wizard._handout_panel.load(SEAL_ID, shares[:2], "strict")

    _close_button(app)
    app._on_unseal()
    assert app.root.winfo_exists() and app._active_wizard is wizard
    assert len(app.calls["yesno"]) == 2
    question, options = app.calls["yesno"][0]
    assert question == (t("nav.unsaved_title"), t("nav.unsaved_msg"))
    assert options.get("default") == "no"

    app.calls["answer"] = True
    app._on_unseal()
    assert app._current_view == "unseal"


def test_i18n_keys_of_the_handout() -> None:
    from desktop.gui.i18n import _TRANSLATIONS

    keys = [
        "handout.title", "handout.intro", "handout.strict_notice",
        "handout.share1_label", "handout.share2_label", "handout.save",
        "handout.not_saved", "handout.saved", "handout.dialog_title1",
        "handout.dialog_title2", "handout.error_title", "handout.error_exists",
        "handout.error_same_path", "handout.error_extension", "handout.error_verify",
        "handout.error_io", "handout.error_format", "handout.save_both_first",
        "handout.save_then_next", "filedialog.share_files", "summary.share1_file",
        "summary.share2_file", "nav.unsaved_title", "nav.unsaved_msg",
        "reseal.saving", "reseal.saving_badge", "reseal.not_saved_badge",
        "reseal.save_failed_title",
        "reseal.save_failed_msg", "reseal.save_failed_retry",
    ]
    for key in keys:
        assert _TRANSLATIONS[key]["ko"] and _TRANSLATIONS[key]["en"], key
    # The S6/R7 texts no longer claim that shares 1/2 are stored automatically.
    for key in ("keysplit.subject_store", "keysplit.investigator_store"):
        assert "저장됩니다" not in _TRANSLATIONS[key]["ko"], key
