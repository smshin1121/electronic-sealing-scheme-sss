"""Resealing wizard: the unlock days are chosen before the record exists, and R7 splits without arguments.

In v1.0.1 the wizard asked for the unlock days on the R7 page and passed them to
ResealProcess.run_r7_split_key(unlock_days=...), which takes no argument. The
TypeError was caught, an error dialog was shown and the wizard could not pass R7.
The unlock time is fixed when R6 writes the record, from the configuration set at
R4, so the input belongs on R4.
"""

from __future__ import annotations

import hashlib
import tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from desktop.record.record_builder import build_seal_record
from desktop.reseal_process import ResealProcess


@pytest.fixture()
def root():
    r = tk.Tk()
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture()
def wizard(root, monkeypatch, tmp_path):
    from desktop.gui import reseal_wizard

    errors: list[tuple] = []
    monkeypatch.setattr(reseal_wizard.messagebox, "showerror", lambda *a, **_k: errors.append(a))
    # E1b: R7 hands out shares 1 and 2; the save dialog answers a temp file.
    wiz = reseal_wizard.ResealWizard(
        root, SimpleNamespace(db_path=":memory:"),
        ask_share_path=lambda **kw: str(tmp_path / kw["initialfile"]),
    )
    wiz.errors = errors
    yield wiz
    wiz.destroy()


def _save_shares(wizard) -> None:
    wizard._handout_panel.button(1).invoke()
    wizard._handout_panel.button(2).invoke()


def _process() -> mock.MagicMock:
    """A stand-in with ResealProcess's real method signatures; autospec rejects wrong arguments."""
    process = mock.create_autospec(ResealProcess, instance=True)
    process.state = {}  # instance attributes set in __init__, read by the wizard's cleanup
    process.config = None
    process.run_r7_split_key.return_value = {
        "shares": ["1-aa", "2-bb", "3-cc", "4-dd"],
        "unlock_time_iso": "2026-10-23T00:00:00Z",
        "encrypted_shares": {},
    }
    return process


def _fill_r4(wizard, tmp_path, process) -> None:
    wizard._data.update({"_process": process, "target_dir": str(tmp_path), "output_dir": str(tmp_path)})
    wizard._r4_investigator.set("Investigator")
    wizard._r4_reason.set("Reason")


def test_r7_splits_the_key_without_arguments(wizard) -> None:
    process = _process()
    wizard._data["_process"] = process

    # E1b: the first Next splits and stays on R7 until shares 1 and 2 are saved.
    assert wizard._validate_r7() is False
    process.run_r7_split_key.assert_called_once_with()
    assert wizard.errors == []
    assert wizard._data["unlock_time_iso"] == "2026-10-23T00:00:00Z"
    _save_shares(wizard)
    assert wizard._validate_r7() is True
    process.run_r7_split_key.assert_called_once_with()


def test_r4_passes_the_chosen_unlock_days_to_the_config(wizard, tmp_path) -> None:
    process = _process()
    _fill_r4(wizard, tmp_path, process)
    wizard._r4_unlock_days_var.set(21)

    assert wizard._validate_r4() is True
    config = process.set_config.call_args.args[0]
    assert config.unlock_days == 21
    assert wizard._data["unlock_days"] == 21


def test_r4_rejects_unlock_days_out_of_range(wizard, tmp_path) -> None:
    from desktop.gui.reseal_wizard import MAX_UNLOCK_DAYS

    process = _process()
    _fill_r4(wizard, tmp_path, process)
    wizard._r4_unlock_days_var.set(MAX_UNLOCK_DAYS + 1)

    assert wizard._validate_r4() is False
    process.set_config.assert_not_called()


def _after_encryption(wizard, tmp_path, days: int = 10) -> mock.MagicMock:
    """R4 accepted with ``days``, encryption and the R6 record done, wizard on R6 (index 5)."""
    process = _process()
    _fill_r4(wizard, tmp_path, process)
    wizard._r4_unlock_days_var.set(days)
    assert wizard._validate_r4() is True
    process.set_config.reset_mock()
    wizard._data.update({"encrypt_done": True, "record_done": True})
    wizard._show_step(5)
    return process


def test_nested_review_returns_to_the_actual_step(wizard, tmp_path) -> None:
    """Reviewing R4, then R1, then 'back to current' must return to R6, not to an editable R4."""
    _after_encryption(wizard, tmp_path)
    wizard._on_step_click(3)
    wizard._on_step_click(0)
    wizard._next_btn.invoke()

    assert wizard._current_step == 5


def test_next_in_review_does_not_apply_r4(wizard, tmp_path) -> None:
    """The Return key calls _go_next; in review it must go back, not validate the reviewed R4."""
    process = _after_encryption(wizard, tmp_path)
    wizard._on_step_click(3)
    wizard._r4_unlock_days_var.set(21)
    wizard._go_next()

    assert wizard._current_step == 5
    process.set_config.assert_not_called()
    assert wizard._data["unlock_days"] == 10


def test_r4_inputs_are_disabled_in_review(wizard, tmp_path) -> None:
    _after_encryption(wizard, tmp_path)
    wizard._on_step_click(3)

    assert str(wizard._r4_unlock_spin.cget("state")) == "disabled"
    assert str(wizard._r4_chunk_spin.cget("state")) == "disabled"


def _stub_render(record: dict, template_name: str, output_path: str) -> str:
    Path(output_path).write_bytes(b"%PDF-1.4 stub")
    return output_path


def _prior_seal_record() -> dict:
    return build_seal_record(
        seal_id="S-20260927-0A1B2C",
        case_info={"case_number": "2026-R7-001", "investigator": "Hong", "device_user": "Kim",
                   "suspect": "Kim", "storage_type": "SSD",
                   "storage_info": {"manufacturer": "M", "model": "X", "serial": "1"},
                   "seizure_time": "2026-09-01T00:00:00Z", "seizure_location": "Seoul"},
        process_info={"type": "Sealing", "start_time": "2026-09-01T00:00:00Z",
                      "end_time": "2026-09-01T00:00:00Z", "file_count": 1, "investigator": "Hong",
                      "reason": "", "participation": "yes"},
        file_info={"original_files": [{"filename": "e.bin", "size": 1, "md5": "0" * 32, "sha256": "0" * 64,
                                       "mtime": "2026-09-01T00:00:00Z", "ctime": "2026-09-01T00:00:00Z",
                                       "atime": "2026-09-01T00:00:00Z"}],
                   "result_files": [], "hash_match": True},
        signer_info={"name": "Kim", "email": "k@example.com", "birth_date": "1990-01-01",
                     "phone": "010-0000-0000", "cert_fingerprint": "0" * 64, "signature_image_hash": "0" * 64},
        history={"summary": "S1U0R0", "events": [{"event": "seal", "time": "2026-09-01T00:00:00Z",
                                                  "actor": "Hong", "reason": ""}]},
        unlock_time_iso="2026-10-01T00:00:00Z",
        key_commitment=hashlib.sha256(bytes.fromhex("ab" * 32)).hexdigest(),
    )


def test_r4_days_reach_the_r6_record_and_r7_passes_with_the_real_process(wizard, tmp_path, monkeypatch) -> None:
    """R4's value, through the wizard's ResealConfig, becomes the R6 record's unlock time; R7 then passes."""
    import desktop.record as record_pkg
    from desktop.crypto import init_master_key

    for name in ("ENC_ENVELOPE_POLICY_KEY_PATH", "ENC_ENVELOPE_POLICY_CERT_PATH", "ENC_ENVELOPE_POLICY_KEY_PASSWORD"):
        monkeypatch.delenv(name, raising=False)  # an unsigned-policy record; policy signing is tested elsewhere
    key_path = str(tmp_path / "master.key")
    init_master_key(key_path)
    monkeypatch.setenv("MASTER_KEY_PATH", key_path)
    monkeypatch.setattr(record_pkg, "render_record_pdf", _stub_render)

    process = ResealProcess(db_path=str(tmp_path / "reseal.db"))
    prev = _prior_seal_record()
    process.state["r1"] = {"prev_record": prev, "seal_id": prev["seal_id"], "record_path": ""}
    process.state["r2"] = {"known_files": [], "unknown_files": [], "target_dir": str(tmp_path)}
    process.state["r5"] = {
        "aes_key_hex": "ef" * 32,
        "enc_results": [{"enc_filepath": str(tmp_path / "e.enc"), "original_filepath": str(tmp_path / "e.bin"),
                         "metadata": {"filename": "e.bin", "size": 1, "md5": "0" * 32, "sha256": "0" * 64},
                         "chunk_count": 1}],
        "encryption_algo": "AES-256-GCM",
    }
    _fill_r4(wizard, tmp_path, process)
    wizard._r4_unlock_days_var.set(21)
    assert wizard._validate_r4() is True

    before = datetime.now(timezone.utc)
    record = process.run_r6_record()["record_dict"]  # the wizard runs R6 on a worker thread after R5
    unlock = datetime.fromisoformat(record["unlock_time_iso"].replace("Z", "+00:00"))
    assert timedelta(days=21, minutes=-1) <= unlock - before <= timedelta(days=21, minutes=1)

    assert wizard._validate_r7() is False  # E1b: split done, shares 1/2 not yet saved
    assert wizard.errors == []
    assert wizard._data["unlock_time_iso"] == record["unlock_time_iso"]
    assert len(wizard._share_prints) == 4 and "key_shares" not in wizard._data
    _save_shares(wizard)
    assert wizard._validate_r7() is True
