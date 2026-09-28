"""Stage E, E1 — GUI fixes after the code-reviewer and security-reviewer round.

* S6 (sealing) and R7 (resealing) showed the first 16-20 characters of every
  share. In strict mode K = R xor X with s1 = R and s2 = s3 = s4 = X, so the
  prefixes of s1 and s2 XOR to the first 7-9 bytes of the AES key on screen.
  They now show SHA-256 fingerprints; the shares stay inside the wizard and
  never reach the completion data.
* Strict is refused at S2 when no policy signer is available (S4 would
  refuse it anyway, after the subject has signed).
* R1 warns when nothing but the record file confirms the mode.
* The main window refuses to leave a wizard, or exit, while S4-S7 run.
* A result that arrives after the wizard was closed is logged.
"""

from __future__ import annotations

import gc
import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest

from desktop.gui.i18n import t
from desktop.reseal_process import ResealProcess
from tests.fixtures.tk_root import destroy_test_root, new_test_root
from tests.unit.test_seal_wizard_process import _Harness, _process


def _fingerprint(share: str) -> str:
    return hashlib.sha256(share.encode("utf-8")).hexdigest()[:16]


def _payload_fragments(shares: Any) -> list[str]:
    return [share[2:12] for share in shares]


@pytest.fixture()
def root():
    r = new_test_root()
    yield r
    destroy_test_root(r)


@pytest.fixture()
def harness(root, tmp_path, monkeypatch):
    from tkinter import messagebox

    errors: list[tuple] = []
    monkeypatch.setattr(messagebox, "showerror", lambda *a, **_k: errors.append(a))
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **_k: True)
    made: list[_Harness] = []

    def _make(process: Any) -> _Harness:
        h = _Harness(root, process, tmp_path)
        h.errors = errors
        made.append(h)
        return h

    yield _make
    for h in made:
        h.wizard.destroy()


# ===================================================================
# No share bytes on screen or in the completion data
# ===================================================================

def test_s6_shows_fingerprints_not_share_bytes(harness, tmp_path) -> None:
    process = _process(tmp_path, mode="strict")
    shares = process.run_s7.return_value.key_shares
    h = harness(process)
    h.to_s5(mode="strict", consent=True)
    h.pump(h.sealed)
    h.wizard._go_next()  # S6

    text = h.wizard._s6_result.get("1.0", "end")
    for share in shares:
        assert _fingerprint(share) in text
    for fragment in _payload_fragments(shares):
        assert fragment not in text


def test_completion_data_carries_no_shares(harness, tmp_path) -> None:
    process = _process(tmp_path)
    h = harness(process)
    h.to_s5()
    h.pump(h.sealed)
    h.wizard._go_next()  # S5 -> S6
    h.save_shares()  # E1b: shares 1 and 2 are handed out as files at S6
    h.wizard._go_next()  # S6 -> S7
    h.wizard._go_next()  # complete

    data = h.completed[0]
    assert "key_shares" not in data and "seal_result" not in data
    assert not any(share in json.dumps(data, default=str)
                   for share in process.run_s7.return_value.key_shares)
    # E1b: the wizard keeps no share text after completion.
    assert h.wizard._seal_result.key_shares == ("", "", "", "")
    assert h.wizard._handout_panel.holds_shares() is False
    assert h.wizard._process is None  # key material released with the process


def test_r7_shows_fingerprints_not_share_bytes(root, monkeypatch) -> None:
    from desktop.gui import reseal_wizard

    monkeypatch.setattr(reseal_wizard.messagebox, "showerror", lambda *a, **_k: None)
    wiz = reseal_wizard.ResealWizard(root, SimpleNamespace(db_path=":memory:"))
    shares = ["1-" + "1a" * 32, "2-" + "2b" * 32, "3-" + "2b" * 32, "4-" + "2b" * 32]
    process = mock.create_autospec(ResealProcess, instance=True)
    process.state, process.config = {}, None
    process.run_r7_split_key.return_value = {
        "shares": shares, "unlock_time_iso": "2026-10-23T00:00:00Z",
        "encrypted_shares": {}}
    wiz._data.update({"_process": process, "seal_mode": "strict"})
    try:
        assert wiz._validate_r7() is False  # E1b: split, shares 1/2 still to be saved
        text = wiz._r7_result.get("1.0", "end")
    finally:
        wiz.destroy()

    for share in shares:
        assert _fingerprint(share) in text
    for fragment in _payload_fragments(shares):
        assert fragment not in text


# ===================================================================
# Strict needs a policy signer (checked at S2, only for strict)
# ===================================================================

def _to_s2(h: _Harness) -> None:
    h.fill_s1()
    h.wizard._go_next()
    h.pump(lambda: h.wizard._current_step == 1)


def test_strict_without_a_policy_signer_is_refused_at_s2(harness, tmp_path) -> None:
    process = _process(tmp_path)
    process.policy_signer_available.return_value = False
    h = harness(process)
    _to_s2(h)
    h.fill_s2(mode="strict", consent=True)

    assert h.wizard._validate_s2() is False
    assert h.wizard._nav_msg_label.cget("text") == t("validate.strict_needs_policy")
    process.policy_signer_available.return_value = True
    assert h.wizard._validate_s2() is True


def test_standard_does_not_ask_for_a_policy_signer(harness, tmp_path) -> None:
    process = _process(tmp_path)
    h = harness(process)
    _to_s2(h)
    h.fill_s2(mode="standard")

    assert h.wizard._validate_s2() is True
    process.policy_signer_available.assert_not_called()


def test_i18n_keys_of_the_review_round() -> None:
    from desktop.gui.i18n import _TRANSLATIONS

    for key in ("validate.strict_needs_policy", "reseal.mode_unverified",
                "nav.busy_title", "nav.busy_msg", "keysplit.fingerprint_note"):
        assert _TRANSLATIONS[key]["ko"] and _TRANSLATIONS[key]["en"], key


# ===================================================================
# Reseal R1 warns when only the file vouches for the mode
# ===================================================================

def _record_file(tmp_path: Path, **extra: Any) -> str:
    record = {"seal_id": "S-20260928-0E0E0E", "seal_mode": "standard",
              "history": {"summary": "S1U1R0", "events": []}, **extra}
    path = tmp_path / "prev.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("extra, warned", [
    ({}, True),
    ({"policy": {"seal_mode": "standard"}}, False),
])
def test_r1_warns_when_nothing_confirms_the_mode(root, tmp_path, monkeypatch,
                                                 extra: dict, warned: bool) -> None:
    from desktop.gui import reseal_wizard

    monkeypatch.setattr(reseal_wizard.messagebox, "showerror", lambda *a, **_k: None)
    wiz = reseal_wizard.ResealWizard(root, SimpleNamespace(db_path=":memory:"))
    try:
        wiz._prev_record_selector.set(_record_file(tmp_path, **extra))
        wiz._target_dir_selector.set(str(tmp_path))
        wiz._output_dir_selector.set(str(tmp_path))
        assert wiz._validate_r1() is True
        info = wiz._r1_info.get("1.0", "end")
    finally:
        wiz.destroy()

    assert (t("reseal.mode_unverified") in info) is warned


# ===================================================================
# The main window does not leave a sealing wizard mid-run
# ===================================================================

@pytest.fixture()
def app(tmp_path, monkeypatch):
    import tkinter as tk
    from tkinter import messagebox

    from desktop.db import init_db
    from desktop.gui.app import MainApp
    from desktop.gui.i18n import remove_listener

    warnings: list[tuple] = []
    asked: list[tuple] = []
    monkeypatch.setattr(messagebox, "showwarning", lambda *a, **_k: warnings.append(a))
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **_k: asked.append(a) or False)
    db = str(tmp_path / "app.db")
    init_db(db)
    gc.collect()
    for attempt in range(3):  # transient Tcl start-up errors (tests/fixtures/tk_root.py)
        try:
            main = MainApp(db_path=db)
            break
        except tk.TclError:
            if attempt == 2:
                raise
            time.sleep(0.2)
    main.root.withdraw()
    main.warnings, main.asked = warnings, asked
    yield main
    remove_listener(main._on_language_change)
    destroy_test_root(main.root)


def test_navigation_and_exit_wait_for_the_seal(app) -> None:
    app._on_seal()
    wizard = app._active_wizard
    wizard._busy = True  # S4-S7 running on the worker thread

    app._on_unseal()
    app._on_case_manager()
    app._on_exit()
    assert app._current_view == "seal" and wizard.winfo_exists()
    assert len(app.warnings) == 3
    assert app.asked == []  # exit did not even ask

    wizard._busy = False
    app._on_unseal()
    assert app._current_view == "unseal"
    assert app._active_wizard is None


# ===================================================================
# A result after the wizard closed is logged
# ===================================================================

def test_a_result_after_close_is_logged(root, tmp_path, caplog) -> None:
    from desktop.gui.seal_runner import start_background_seal

    process = _process(tmp_path)
    release = threading.Event()
    process.run_s5.side_effect = lambda status_cb=None: release.wait(10) or {}
    cancel = threading.Event()
    with caplog.at_level(logging.WARNING, logger="desktop.gui.seal_runner"):
        start_background_seal(
            root, process, {"source_file": "s", "output_dir": str(tmp_path),
                            "chunk_size_gb": 1, "case_number": "C"},
            on_progress=lambda _m: None, on_success=lambda _r: None,
            on_error=lambda _e: None, cancel_event=cancel,
        )
        cancel.set()  # the wizard was destroyed
        release.set()
        deadline = time.monotonic() + 10
        while not caplog.records and time.monotonic() < deadline:
            root.update()
            time.sleep(0.02)

    assert any("after the wizard was closed" in r.getMessage() for r in caplog.records)
