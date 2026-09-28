"""The seal wizard seals through SealProcess, with a seal-mode choice (stage E, E1).

Before E1 the wizard encrypted on its own, built an unsigned record without
seal_mode / unlock_time_iso / key_commitment / policy, and without an attached
process fell back to "SealProcess 없이 간이 서명 수행"; an S5 exception was
swallowed and S5 marked done anyway. Now S1 runs ``SealProcess.run_s1`` and
S4-S7 run through ``run_seal_steps``; a failure is shown and blocks the wizard.

S2 carries the seal mode (standard preselected; strict only with a warning and
an explicit consent) and the unlock days, which S4 writes into the record
before S5 signs it.

These tests drive the real wizard widgets with an autospec of SealProcess,
so a call with wrong arguments raises as it would on the real class.
"""

from __future__ import annotations

import json
import threading
import time
import tkinter as tk
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Optional
from unittest import mock

import pytest

from desktop.seal_process import SealConfig, SealProcess, SealResult
from tests.fixtures.tk_root import destroy_test_root, new_test_root

SEAL_ID = "S-20260928-0A1B2C"
STRICT_WARNING_KO = (
    "strict 모드에서는 피압수자 조각(s1)이 없으면 어떤 경우에도 키를 복구할 수 "
    "없습니다. 피압수자가 조각을 보관·제출하지 않으면 증거를 열 수 없게 됩니다."
)


@pytest.fixture()
def root():
    # See tests/fixtures/tk_root.py: garbage collected on the main thread,
    # transient Tcl start-up read errors retried.
    r = new_test_root()
    yield r
    destroy_test_root(r)


@pytest.fixture()
def dialogs(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[tuple]]:
    """Record message boxes instead of blocking on them."""
    from tkinter import messagebox

    calls: dict[str, list[tuple]] = {"error": [], "yesno": [], "warning": []}
    monkeypatch.setattr(messagebox, "showerror",
                        lambda *a, **_k: calls["error"].append(a))
    monkeypatch.setattr(messagebox, "showwarning",
                        lambda *a, **_k: calls["warning"].append(a))
    monkeypatch.setattr(messagebox, "askyesno",
                        lambda *a, **_k: calls["yesno"].append(a) or True)
    return calls


@pytest.fixture()
def no_standalone_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any surviving standalone signing / splitting call fails loudly."""
    import desktop.crypto as crypto_pkg
    import desktop.record as record_pkg
    import desktop.signature as signature_pkg

    def _forbidden(*_a: Any, **_k: Any) -> None:
        raise AssertionError("the wizard must not seal outside SealProcess")

    for module, name in (
        (crypto_pkg, "split_key"), (crypto_pkg, "split_key_strict"),
        (crypto_pkg, "encrypt_file"), (signature_pkg, "generate_keypair"),
        (signature_pkg, "create_self_signed_cert"), (signature_pkg, "sign_pdf"),
        (record_pkg, "render_record_pdf"), (record_pkg, "build_seal_record"),
    ):
        monkeypatch.setattr(module, name, _forbidden)


def _record(mode: str = "standard", seal_id: str = SEAL_ID) -> dict[str, Any]:
    return {
        "seal_id": seal_id, "seal_mode": mode,
        "unlock_time_iso": "2026-10-05T00:00:00Z", "key_commitment": "ab" * 32,
        "case_info": {"case_number": "2026-E1-001"},
        "history": {"summary": "S1U0R0", "events": []},
        "policy": {"seal_mode": mode},
        "policy_signature": "c2ln", "policy_cert": "-----BEGIN CERTIFICATE-----",
    }


def _process(tmp_path: Path, mode: str = "standard",
             seal_id: str = SEAL_ID) -> mock.MagicMock:
    process = mock.create_autospec(SealProcess, instance=True)
    process.state = {}
    process.config = None
    process.run_s1.return_value = {
        "aes_key_hex": "ab" * 32,
        "enc_filepath": str(tmp_path / "out" / "disk.dd.enc"),
        "metadata": {"filename": "disk.dd", "size": 4096, "md5": "0" * 32,
                     "sha256": "1" * 64, "mtime": "2026-09-28T00:00:00Z",
                     "ctime": "2026-09-28T00:00:00Z",
                     "atime": "2026-09-28T00:00:00Z"},
        "chunk_count": 1, "encryption_algo": "AES-256-GCM",
        "enc_metadata": {"nonces": ["00"], "tags": ["11"],
                         "chunk_lengths": [4096]},
    }
    process.run_s7.return_value = SealResult(
        seal_id=seal_id, enc_filepath=str(tmp_path / "out" / "disk.dd.enc"),
        pdf_path=str(tmp_path / "out" / f"{seal_id}_seal_record_signed.pdf"),
        key_shares=("1-" + "a" * 64, "2-" + "b" * 64, "3-" + "c" * 64,
                    "4-" + "d" * 64),
        unlock_time_iso="2026-10-05T00:00:00Z",
        record_json=json.dumps(_record(mode, seal_id), indent=2),
        wrapped_s3_b64="d3JhcHBlZA==",
    )
    return process


class _Harness:
    """A seal wizard wired to a given process, with its completions.

    The share save dialog is stubbed: it answers with ``next_paths`` first,
    then with the suggested file name in ``share_dir`` (calls recorded).
    """

    def __init__(self, root: tk.Tk, process: Any, tmp_path: Path,
                 prefill: Optional[dict[str, Any]] = None) -> None:
        from desktop.gui.seal_wizard import SealWizard

        self.root = root
        self.tmp_path = tmp_path
        self.completed: list[dict[str, Any]] = []
        self.cancelled: list[bool] = []
        self.share_dir = tmp_path / "shares"
        self.share_dir.mkdir(exist_ok=True)
        self.dialog_calls: list[dict[str, Any]] = []
        self.next_paths: list[str] = []
        self.wizard = SealWizard(
            root, SimpleNamespace(db_path=str(tmp_path / "seal.db")),
            on_complete=self.completed.append,
            on_cancel=lambda: self.cancelled.append(True),
            prefill_data=prefill,
            process_factory=lambda: process,
            ask_share_path=self._ask_share_path,
        )

    def _ask_share_path(self, **kwargs: Any) -> str:
        self.dialog_calls.append(kwargs)
        if self.next_paths:
            return self.next_paths.pop(0)
        return str(self.share_dir / kwargs["initialfile"])

    def save_shares(self) -> dict[int, Path]:
        """Save shares 1 and 2 at S6 through the panel's buttons."""
        panel = self.wizard._handout_panel
        panel.button(1).invoke()
        panel.button(2).invoke()
        return {saved.index: Path(saved.path) for saved in panel.saved()}

    def pump(self, until: Callable[[], bool], timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while not until() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        assert until(), "timed out waiting for the wizard"

    def fill_s1(self) -> None:
        source = self.tmp_path / "disk.dd"
        source.write_bytes(b"\x00" * 4096)
        out = self.tmp_path / "out"
        out.mkdir(exist_ok=True)
        self.wizard._file_selector.set(str(source))
        self.wizard._output_selector.set(str(out))

    def fill_s2(self, mode: str = "standard", consent: bool = False,
                days: int = 7) -> None:
        w = self.wizard
        w._case_number.set("2026-E1-001")
        w._seizure_date.set("2026-09-28 01:02")
        w._seizure_location.set("Seoul")
        w._device_user.set("Kim")
        w._storage_type.set("SSD")
        w._media_manufacturer.set("M")
        w._media_model.set("X")
        w._media_serial.set("1")
        w._investigator_name.set("Hong")
        panel = w._policy_panel
        if mode == "strict":
            panel.strict_radio.invoke()
            if consent:
                panel.consent_check.invoke()
        panel.unlock_spin.delete(0, "end")
        panel.unlock_spin.insert(0, str(days))

    def fill_s3(self) -> None:
        w = self.wizard
        w._subject_name.set("Kim")
        w._subject_email.set("k@example.com")
        w._subject_birth.set("1990-01-01")
        w._subject_phone.set("010-0000-0000")
        w._subject_password.set("pw-1234")
        w._subject_password_confirm.set("pw-1234")
        pad = w._signature_pad
        pad._has_signature = True
        pad._confirmed = True
        pad._lines = [(0, 0, 10, 10)]

    def to_s5(self, mode: str = "standard", consent: bool = False) -> None:
        self.fill_s1()
        self.wizard._go_next()  # S1 -> encryption -> S2
        self.pump(lambda: self.wizard._current_step == 1)
        self.fill_s2(mode, consent)
        self.wizard._go_next()
        self.fill_s3()
        self.wizard._go_next()
        self.wizard._go_next()  # S4 preview -> S5 starts the seal

    def sealed(self) -> bool:
        return bool(self.wizard._data.get("signature_done"))


@pytest.fixture()
def harness(root, tmp_path, dialogs, no_standalone_path):
    made: list[_Harness] = []

    def _make(process: Any, prefill: Optional[dict[str, Any]] = None) -> _Harness:
        h = _Harness(root, process, tmp_path, prefill)
        made.append(h)
        return h

    yield _make
    for h in made:
        try:
            h.wizard.destroy()
        except tk.TclError:
            pass


# ===================================================================
# Sealing goes through SealProcess, in order, never the old path
# ===================================================================

def test_wizard_seals_through_the_process_in_order(harness, tmp_path, dialogs) -> None:
    process = _process(tmp_path)
    h = harness(process)
    h.to_s5()
    h.pump(h.sealed)

    names = [c[0] for c in process.mock_calls]
    assert names == ["run_s1", "set_config", "run_s4", "run_s5", "run_s6", "run_s7"]
    config: SealConfig = process.set_config.call_args.args[0]
    assert config.seal_mode == "standard"
    assert config.unlock_days == 7
    assert config.seal_id is None
    assert config.seizure["date"] == "2026-09-28T01:02:00Z"
    assert config.seizure["device_user"] == "Kim"
    assert config.media == {"type": "SSD", "manufacturer": "M", "model": "X",
                            "serial": "1"}
    assert config.subject["password"] == "pw-1234"
    assert dialogs["error"] == []

    h.wizard._go_next()  # S5 -> S6
    h.save_shares()  # E1b: S6 -> S7 needs shares 1 and 2 saved to files
    h.wizard._go_next()  # S6 -> S7
    h.wizard._go_next()  # complete
    assert len(h.completed) == 1
    data = h.completed[0]
    result = process.run_s7.return_value
    assert data["seal_id"] == SEAL_ID
    assert data["record_json"] == result.record_json
    assert data["record_dict"] == json.loads(result.record_json)
    assert data["pdf_path"] == result.pdf_path
    assert "aes_key" not in data and "aes_key_hex" not in data
    assert "password" not in data["subject"]


def test_s1_encrypts_through_the_process(harness, tmp_path) -> None:
    process = _process(tmp_path)
    h = harness(process)
    h.fill_s1()
    h.wizard._go_next()
    h.pump(lambda: h.wizard._current_step == 1)

    process.run_s1.assert_called_once()
    args = process.run_s1.call_args
    assert args.args[:3] == (str(tmp_path / "disk.dd"), str(tmp_path / "out"), 1)
    assert h.wizard._data["enc_path"] == str(tmp_path / "out" / "disk.dd.enc")


def test_s1_inputs_are_fixed_once_encrypted(harness, tmp_path) -> None:
    """S5 writes the signed artifacts to the S1 output folder, next to the container."""
    process = _process(tmp_path)
    h = harness(process)
    h.fill_s1()
    h.wizard._go_next()
    h.pump(lambda: h.wizard._current_step == 1)
    h.wizard._go_prev()

    assert str(h.wizard._output_selector.browse_btn.cget("state")) == "disabled"
    other = tmp_path / "other"
    other.mkdir()
    h.wizard._output_selector.set(str(other))
    h.wizard._go_next()

    assert h.wizard._current_step == 1
    assert h.wizard._data["output_dir"] == str(tmp_path / "out")
    process.run_s1.assert_called_once()


def test_the_standalone_path_is_gone() -> None:
    from desktop.gui import seal_wizard

    for name in ("_run_simple_signing", "_generate_seal_data",
                 "_perform_key_split", "_build_file_info"):
        assert not hasattr(seal_wizard.SealWizard, name), name
    source = Path(seal_wizard.__file__).read_text(encoding="utf-8")
    assert "SealProcess 없이" not in source
    assert "split_key" not in source


# ===================================================================
# Failures surface and block; no silent fallback
# ===================================================================

def test_a_failed_step_is_shown_and_blocks(harness, tmp_path, dialogs) -> None:
    process = _process(tmp_path)
    process.run_s5.side_effect = RuntimeError("TSA down")
    h = harness(process)
    h.to_s5()
    h.pump(lambda: bool(dialogs["error"]))

    assert not h.sealed()
    assert "S5" in dialogs["error"][0][1]
    assert "TSA down" in dialogs["error"][0][1]
    process.run_s6.assert_not_called()
    process.run_s7.assert_not_called()
    assert h.wizard._validate_s5() is False  # retries, stays on S5
    assert h.wizard._current_step == 4


def test_next_retries_after_a_failure(harness, tmp_path, dialogs) -> None:
    process = _process(tmp_path)
    process.run_s5.side_effect = [RuntimeError("TSA down"), {}]
    h = harness(process)
    h.to_s5()
    h.pump(lambda: bool(dialogs["error"]))

    h.wizard._go_next()  # retry
    h.pump(h.sealed)
    assert process.run_s4.call_count == 2
    process.run_s7.assert_called_once()


def test_a_seal_that_cannot_start_is_shown_and_retryable(
    harness, tmp_path, dialogs, monkeypatch
) -> None:
    """A failure before the worker starts must not leave the wizard busy forever."""
    from desktop.gui import seal_wizard

    def _cannot_start(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("can't start new thread")

    process = _process(tmp_path)
    h = harness(process)
    monkeypatch.setattr(seal_wizard, "start_background_seal", _cannot_start)
    h.to_s5()

    assert len(dialogs["error"]) == 1
    assert "can't start new thread" in dialogs["error"][0][1]
    assert h.wizard._busy is False and h.wizard._seal_running is False
    assert str(h.wizard._next_btn.cget("state")) == "normal"
    assert not h.sealed()


def test_cancel_is_disabled_while_sealing_and_after(harness, tmp_path) -> None:
    process = _process(tmp_path)
    release = threading.Event()

    def _slow_s5(status_cb=None):
        release.wait(10)
        return {}

    process.run_s5.side_effect = _slow_s5
    h = harness(process)
    h.to_s5()
    h.pump(lambda: process.run_s5.called)

    assert str(h.wizard._cancel_btn.cget("state")) == "disabled"
    h.wizard._on_escape_key(None)
    release.set()
    h.pump(h.sealed)
    assert str(h.wizard._cancel_btn.cget("state")) == "disabled"
    h.wizard._handle_cancel()
    h.wizard._on_escape_key(None)
    assert h.cancelled == []


def test_review_after_sealing_does_not_reapply_s2(harness, tmp_path) -> None:
    process = _process(tmp_path)
    h = harness(process)
    h.to_s5()
    h.pump(h.sealed)
    h.wizard._go_next()  # S6

    h.wizard._on_step_click(1)  # review S2 read-only
    assert str(h.wizard._case_number.entry.cget("state")) == "disabled"
    h.wizard._case_number._var.set("edited after sealing")
    h.wizard._go_next()  # the Return key path: back, no validation

    assert h.wizard._current_step == 5
    assert h.wizard._data["case_number"] == "2026-E1-001"


# ===================================================================
# Seal mode: standard default, strict needs warning + consent
# ===================================================================

def test_standard_is_preselected_and_the_strict_notice_hidden(harness, tmp_path) -> None:
    h = harness(_process(tmp_path))
    panel = h.wizard._policy_panel

    assert panel.mode == "standard"
    assert panel.strict_notice_shown() is False


def test_strict_without_consent_cannot_proceed(harness, tmp_path) -> None:
    from desktop.gui.i18n import t

    process = _process(tmp_path)
    h = harness(process)
    h.fill_s1()
    h.wizard._go_next()
    h.pump(lambda: h.wizard._current_step == 1)
    h.fill_s2(mode="strict", consent=False)

    assert h.wizard._policy_panel.strict_notice_shown() is True
    h.wizard._go_next()
    assert h.wizard._current_step == 1
    assert h.wizard._nav_msg_label.cget("text") == t("validate.strict_consent")
    process.set_config.assert_not_called()


def test_strict_with_consent_reaches_the_process(harness, tmp_path) -> None:
    process = _process(tmp_path, mode="strict")
    h = harness(process)
    h.to_s5(mode="strict", consent=True)
    h.pump(h.sealed)

    assert process.set_config.call_args.args[0].seal_mode == "strict"
    assert h.wizard._data["seal_mode"] == "strict"


def test_switching_back_to_standard_clears_the_consent(harness, tmp_path) -> None:
    h = harness(_process(tmp_path))
    panel = h.wizard._policy_panel
    panel.strict_radio.invoke()
    panel.consent_check.invoke()
    assert panel.consented is True

    panel.standard_radio.invoke()
    assert panel.consented is False
    assert panel.strict_notice_shown() is False
    panel.strict_radio.invoke()
    assert panel.consented is False  # consent is asked again


def test_strict_texts_exist_in_both_languages() -> None:
    from desktop.gui.i18n import _TRANSLATIONS

    for key in ("mode.strict_warning", "mode.strict_consent",
                "validate.strict_consent", "mode.standard", "mode.strict",
                "mode.shares_standard", "mode.shares_strict"):
        assert _TRANSLATIONS[key]["ko"] and _TRANSLATIONS[key]["en"], key
    assert _TRANSLATIONS["mode.strict_warning"]["ko"] == STRICT_WARNING_KO
    assert "s1" in _TRANSLATIONS["mode.strict_warning"]["en"]


# ===================================================================
# Record fields the programmatic path requires, case workflow
# ===================================================================

def test_s2_requires_the_fields_the_record_schema_requires(harness, tmp_path) -> None:
    h = harness(_process(tmp_path))
    h.fill_s2()
    for entry in (h.wizard._device_user, h.wizard._storage_type,
                  h.wizard._media_manufacturer, h.wizard._media_model,
                  h.wizard._media_serial):
        entry.set("")

    assert h.wizard._validate_s2() is False
    assert "5" in h.wizard._nav_msg_label.cget("text")


def test_s2_rejects_an_unparseable_seizure_time(harness, tmp_path) -> None:
    from desktop.gui.i18n import t

    h = harness(_process(tmp_path))
    h.fill_s2()
    h.wizard._seizure_date.set("yesterday")

    assert h.wizard._validate_s2() is False
    assert h.wizard._nav_msg_label.cget("text") == t("validate.seizure_datetime")


@pytest.mark.parametrize("text, expected", [
    ("2026-09-28 01:02", "2026-09-28T01:02:00Z"),
    ("2026-09-28 01:02:03", "2026-09-28T01:02:03Z"),
    ("2026-09-28T01:02:03Z", "2026-09-28T01:02:03Z"),
    (" 2026-09-28 01:02 ", "2026-09-28T01:02:00Z"),
    ("2026-13-28 01:02", None),
    ("28/09/2026", None),
    ("", None),
])
def test_seizure_time_iso(text: str, expected: Optional[str]) -> None:
    from desktop.gui.seal_wizard import seizure_time_iso

    assert seizure_time_iso(text) == expected


def test_a_case_seal_id_reaches_s4(harness, tmp_path) -> None:
    process = _process(tmp_path)
    h = harness(process, prefill={"seal_id": SEAL_ID, "case_number": "2026-E1-001"})
    h.to_s5()
    h.pump(h.sealed)

    assert process.set_config.call_args.args[0].seal_id == SEAL_ID


def test_a_legacy_case_id_is_refused_before_encryption(harness, tmp_path) -> None:
    process = _process(tmp_path)
    h = harness(process, prefill={"seal_id": "SEAL-0123456789AB"})
    h.fill_s1()

    assert h.wizard._validate_s1() is False
    process.run_s1.assert_not_called()
    assert "SEAL-0123456789AB" in h.wizard._nav_msg_label.cget("text")


def test_app_stores_the_signed_record_json_verbatim(tmp_path) -> None:
    from desktop.db import get_case_detail, init_db, save_seal_bundle
    from desktop.gui.app import MainApp

    db = str(tmp_path / "app.db")
    init_db(db)
    record_json = json.dumps(_record(), ensure_ascii=False, indent=2)
    save_seal_bundle(db, SEAL_ID, record_json, "x.pdf", shares={3: b"s3"})
    data = {"seal_id": SEAL_ID, "record_json": record_json,
            "record_dict": json.loads(record_json), "pdf_path": "x.pdf",
            "case_number": "2026-E1-001", "subject": {"name": "Kim"},
            "investigator": {"name": "Hong"}}

    MainApp._save_case_meta(SimpleNamespace(db_path=db), data, SEAL_ID,
                            default_status="S1U0R0")

    import sqlite3
    with sqlite3.connect(db) as conn:
        stored, case_number = conn.execute(
            "SELECT record_json, case_number FROM seal_records WHERE seal_id=?",
            (SEAL_ID,)).fetchone()
    assert stored == record_json
    assert case_number == "2026-E1-001"
    assert get_case_detail(db, SEAL_ID) is not None
