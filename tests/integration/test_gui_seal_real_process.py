"""GUI sealing with the real SealProcess, end to end (stage E, E1).

The wizard is driven through S1-S7 with the real process: real AES-GCM
encryption of a small synthetic file, S4 record + institutional policy
signature (test CA, key taken from ``ENC_ENVELOPE_POLICY_*`` as in
production), S5 ReportLab render + PAdES signature with an embedded RFC 3161
token + a separately verified TST, S6 split by mode + KMS envelope wrap with
the policy-bound AAD, S7 SQLite save.

Stubbed: only the TSA *location*. ``run_s5`` asks
``desktop.signature.ensure_tsa_server_running()`` for (URL, pinned cert);
here it returns the session test TSA (``release_tsa``, a real RFC 3161 server
on an ephemeral loopback port, certificate issued by the test CA), so the
test never touches ``~/.enc_envelope`` or port 3161. Message boxes are
recorded instead of shown. Everything else runs as in the application.
"""

from __future__ import annotations

import base64
import gc
import hashlib
import logging
import os
import sqlite3
import time
import tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from desktop.crypto import (
    KeyRecoveryError,
    decrypt_envelope,
    decrypt_file,
    init_master_key,
    recover_key,
    recover_key_for_mode,
)
from desktop.db import get_key_share, get_seal_record, init_db
from desktop.signature.seal_policy import (
    POLICY_CERT_PATH_ENV,
    POLICY_KEY_PASSWORD_ENV,
    POLICY_KEY_PATH_ENV,
    policy_digest,
    s3_wrap_aad,
    verify_policy,
)
from tests.fixtures.release_pki import POLICY_KEY_PASSWORD
from tests.fixtures.tk_root import destroy_test_root, new_test_root

UNLOCK_DAYS = 7


@pytest.fixture()
def root():
    # Tk roots of earlier tests may still be cyclic garbage; they are
    # collected on the main thread (tests/fixtures/tk_root.py), because a
    # Tcl interpreter deleted on the S5 worker thread makes Tcl panic.
    r = new_test_root()
    yield r
    destroy_test_root(r)


@pytest.fixture()
def sealing_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                release_pki, release_tsa) -> dict[str, Any]:
    """Master key, policy key (env), test TSA, DB; message boxes recorded."""
    import desktop.signature as signature_pkg
    from tkinter import messagebox

    master = str(tmp_path / "master.key")
    init_master_key(master)
    monkeypatch.setenv("MASTER_KEY_PATH", master)
    monkeypatch.setenv(POLICY_KEY_PATH_ENV, str(release_pki.policy_key_path))
    monkeypatch.setenv(POLICY_CERT_PATH_ENV, str(release_pki.policy_cert_path))
    monkeypatch.setenv(POLICY_KEY_PASSWORD_ENV, POLICY_KEY_PASSWORD)
    monkeypatch.setattr(
        signature_pkg, "ensure_tsa_server_running",
        lambda *_a, **_k: (release_tsa, release_pki.tsa_cert_path),
    )
    errors: list[tuple] = []
    monkeypatch.setattr(messagebox, "showerror", lambda *a, **_k: errors.append(a))
    monkeypatch.setattr(messagebox, "askyesno", lambda *_a, **_k: True)
    db = str(tmp_path / "seal_system.db")
    init_db(db)
    return {"master": master, "db": db, "errors": errors}


def _pump(root: tk.Tk, until: Any, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not until() and time.monotonic() < deadline:
        root.update()
        time.sleep(0.02)
    assert until(), "timed out waiting for the wizard"


def _drive_wizard(
    root: tk.Tk, tmp_path: Path, env: dict[str, Any], mode: str
) -> tuple[dict[str, Any], bytes, dict[int, Path], Any]:
    """Seal a synthetic file through S1-S7, handing out shares 1 and 2 at S6.

    Returns the completion data, the plaintext, the two share files saved at
    S6 (the save dialog answers a folder in tmp_path) and the wizard's
    SealResult after completion (which keeps no share text).
    """
    from desktop.gui.seal_wizard import SealWizard

    source = tmp_path / "evidence.dd"
    plaintext = os.urandom(64 * 1024)
    source.write_bytes(plaintext)
    out = tmp_path / "out"
    out.mkdir()
    share_dir = tmp_path / "handed-out"
    share_dir.mkdir()
    completed: list[dict[str, Any]] = []
    w = SealWizard(root, SimpleNamespace(db_path=env["db"]),
                   on_complete=completed.append,
                   ask_share_path=lambda **kw: str(share_dir / kw["initialfile"]))
    try:
        w._file_selector.set(str(source))
        w._output_selector.set(str(out))
        w._go_next()  # S1: real encryption in the progress dialog
        assert w._current_step == 1, env["errors"]
        for entry, value in (
            (w._case_number, "2026-형제-E1"), (w._seizure_date, "2026-09-28 01:02"),
            (w._seizure_location, "Seoul"), (w._device_user, "Kim"),
            (w._storage_type, "SSD"), (w._media_manufacturer, "M"),
            (w._media_model, "X"), (w._media_serial, "SN-1"),
            (w._investigator_name, "Hong"),
        ):
            entry.set(value)
        if mode == "strict":
            w._policy_panel.strict_radio.invoke()
            w._policy_panel.consent_check.invoke()
        w._policy_panel.unlock_spin.delete(0, "end")
        w._policy_panel.unlock_spin.insert(0, str(UNLOCK_DAYS))
        w._go_next()
        for entry, value in (
            (w._subject_name, "Kim"), (w._subject_email, "k@example.com"),
            (w._subject_birth, "1990-01-01"), (w._subject_phone, "010-0000-0000"),
            (w._subject_password, "subject-pw"),
            (w._subject_password_confirm, "subject-pw"),
        ):
            entry.set(value)
        pad = w._signature_pad
        pad._has_signature, pad._confirmed = True, True
        pad._lines = [(0, 0, 10, 10), (10, 10, 20, 5)]
        w._go_next()
        # The S1 progress dialog is garbage now; collect it on this thread,
        # not during the heavy S5 work on the worker thread.
        gc.collect()
        w._go_next()  # S4 -> S5: S4-S7 run on the worker thread
        _pump(root, lambda: w._data.get("signature_done") or env["errors"], 120)
        assert env["errors"] == []
        w._go_next()  # S5 -> S6
        w._go_next()  # blocked: shares 1 and 2 are not saved yet
        assert w._current_step == 5
        w._handout_panel.button(1).invoke()
        w._handout_panel.button(2).invoke()
        assert env["errors"] == []
        w._go_next()  # S6 -> S7
        w._go_next()  # complete
        files = {s.index: Path(s.path) for s in w._handout_panel.saved()}
        seal_result = w._seal_result
        assert w._handout_panel.holds_shares() is False
    finally:
        w.destroy()
    assert len(completed) == 1
    assert "key_shares" not in completed[0]
    return completed[0], plaintext, files, seal_result


def _signed_pdf_evidence(pdf_path: str, tsa_cert_path: str) -> dict[str, Any]:
    """PAdES integrity and the embedded signature timestamp, verified."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    from desktop.signature import verify_timestamp

    with open(pdf_path, "rb") as f:
        sig = PdfFileReader(f).embedded_signatures[0]
        status = validate_pdf_signature(sig)
        signer_info = sig.signer_info
        tokens = [
            attr["values"][0] for attr in signer_info["unsigned_attrs"]
            if attr["type"].native == "signature_time_stamp_token"
        ]
        assert len(tokens) == 1
        tst_info = tokens[0]["content"]["encap_content_info"]["content"].parsed
        return {
            "intact": status.intact,
            "valid": status.valid,
            "gen_time": verify_timestamp(tokens[0].dump(), tsa_cert_path),
            "imprint": tst_info["message_imprint"]["hashed_message"].native,
            "signature_digest": hashlib.sha256(
                signer_info["signature"].native).digest(),
            "imprint_alg": tst_info["message_imprint"]["hash_algorithm"][
                "algorithm"].native,
        }


# oscrypto (used by pyHanko's validator) still calls datetime.utcnow().
@pytest.mark.filterwarnings(
    "ignore:datetime.datetime.utcnow:DeprecationWarning:oscrypto"
)
def test_gui_strict_seal_with_the_real_process(
    root, tmp_path, sealing_env, release_pki, caplog
) -> None:
    import web.release_gate as gate

    caplog.set_level(logging.DEBUG)  # every record, every logger, every level
    before = datetime.now(timezone.utc)
    data, plaintext, files, seal_result = _drive_wizard(
        root, tmp_path, sealing_env, "strict")
    seal_id = data["seal_id"]

    # The saved record carries the three fields, the mode and the policy.
    stored = get_seal_record(sealing_env["db"], seal_id)
    record = stored["record_json"]
    assert record["seal_mode"] == "strict"
    unlock = datetime.fromisoformat(record["unlock_time_iso"].replace("Z", "+00:00"))
    assert timedelta(days=UNLOCK_DAYS, minutes=-2) <= unlock - before <= timedelta(
        days=UNLOCK_DAYS, minutes=2)
    assert record["case_info"]["seizure_time"] == "2026-09-28T01:02:00Z"
    verified = verify_policy(
        record["policy"], record["policy_signature"], record["policy_cert"],
        ca_cert=release_pki.ca_cert, expected_seal_id=seal_id,
    )
    assert verified.seal_mode == "strict"
    assert verified.unlock_time_iso == record["unlock_time_iso"]
    assert verified.key_commitment == record["key_commitment"]
    # The stored JSON is the one S5 wrote next to the signed PDF, byte for byte.
    with sqlite3.connect(sealing_env["db"]) as conn:
        (stored_text,) = conn.execute(
            "SELECT record_json FROM seal_records WHERE seal_id = ?", (seal_id,)
        ).fetchone()
    assert stored_text == data["record_json"]
    assert stored_text == (tmp_path / "out" / f"{seal_id}_record.json").read_text(
        encoding="utf-8")

    # Shares 1 and 2 as handed out at S6: two files, one line each, in the
    # portal's format; the reference web's own checks accept them.
    assert files[1] != files[2]
    text1 = files[1].read_text(encoding="utf-8")
    text2 = files[2].read_text(encoding="utf-8")
    s1, s2 = text1.strip(), text2.strip()
    assert text1 == f"{s1}\n" and text2 == f"{s2}\n"
    assert gate._slot_share({1: s1}, 1) == (s1, "")
    assert gate._presented_s2(text2) == (s2, "")
    # Shares 3 and 4 from the desktop DB: s3 wrapped and bound to
    # (seal_id, policy digest), s4 wrapped.
    wrapped = get_key_share(sealing_env["db"], seal_id, 3)
    aad = s3_wrap_aad(seal_id, policy_digest(record["policy"]))
    s3 = decrypt_envelope(wrapped, sealing_env["master"], aad=aad).decode()
    s4 = decrypt_envelope(get_key_share(sealing_env["db"], seal_id, 4),
                          sealing_env["master"]).decode()
    assert base64.b64decode(seal_result.wrapped_s3_b64) == wrapped
    assert seal_result.key_shares == ("", "", "", "")  # dropped from the wizard

    # Strict: the key is recovered from the two saved files (s1 + s2); s1 +
    # any institutional share recovers it; institutions alone do not.
    key_hex = recover_key_for_mode("strict", [s1, s2])
    assert hashlib.sha256(bytes.fromhex(key_hex)).hexdigest() == record["key_commitment"]
    assert recover_key_for_mode("strict", [s1, s3]) == key_hex
    assert recover_key_for_mode("strict", [s1, s4]) == key_hex
    for institutional in ([s2, s3], [s2, s4], [s3, s4], [s2, s3, s4]):
        with pytest.raises(KeyRecoveryError):
            recover_key_for_mode("strict", institutional)
    assert s2[2:] == s3[2:] == s4[2:] != s1[2:]  # K = R xor X, X replicated

    # No share text in any log record, at any level, from any logger.
    messages = "\n".join(r.getMessage() for r in caplog.records)
    for share in (s1, s2, s3, s4):
        payload = share.split("-", 1)[1]
        assert payload not in caplog.text and payload not in messages
        assert payload[:16] not in caplog.text and payload[:16] not in messages

    # The recovered key opens the container and restores the evidence.
    (tmp_path / "restored").mkdir()
    restored = decrypt_file(
        enc_filepath=data["enc_path"], aes_key=bytes.fromhex(key_hex),
        output_dir=str(tmp_path / "restored"),
        expected_sha256=record["file_info"]["original_files"][0]["sha256"],
    )
    assert restored.hash_verified
    assert Path(restored.output_filepath).read_bytes() == plaintext

    # PAdES signature with an embedded RFC 3161 token from the test TSA.
    assert stored["pdf_path"].endswith("_seal_record_signed.pdf")
    evidence = _signed_pdf_evidence(stored["pdf_path"],
                                    str(release_pki.tsa_cert_path))
    assert evidence["intact"] and evidence["valid"]
    assert evidence["imprint_alg"] == "sha256"
    assert evidence["imprint"] == evidence["signature_digest"]
    assert before - timedelta(minutes=1) <= evidence["gen_time"] <= datetime.now(
        timezone.utc) + timedelta(minutes=1)

    # The signed PDF binds the record (Codex F3): the record JSON as saved at
    # S5 and as stored at S7 verify against it; an edited copy does not.
    from desktop.record import pdf_renderer
    from desktop.record.record_binding import (
        record_digest,
        verify_record_binding,
        verify_record_file,
    )
    from tests.unit.test_record_binding import pdf_text

    json_path = tmp_path / "out" / f"{seal_id}_record.json"
    assert verify_record_file(json_path, stored["pdf_path"]).ok
    assert verify_record_binding(stored_text, stored["pdf_path"]).ok
    edited = {**record, "seal_mode": "standard"}
    assert verify_record_binding(edited, stored["pdf_path"]).reason == "mismatch"
    if pdf_renderer._get_weasyprint() is None:  # ReportLab: values in Courier
        text = pdf_text(stored["pdf_path"])
        for value in ("strict", record["unlock_time_iso"], record["key_commitment"],
                      record["signer_info"]["cert_fingerprint"], record_digest(record)):
            assert value.encode() in text, value


def test_a_retry_after_an_s5_failure_leaves_no_orphaned_seal(
    tmp_path, monkeypatch, release_pki, release_tsa
) -> None:
    """The failed attempt's S5 files are overwritten by the retry (same seal_id)."""
    import desktop.signature as signature_pkg
    from desktop.seal_process import SealProcess
    from desktop.seal_steps import SealStepError, run_seal_steps

    for name in (POLICY_KEY_PATH_ENV, POLICY_CERT_PATH_ENV, POLICY_KEY_PASSWORD_ENV):
        monkeypatch.delenv(name, raising=False)
    master = str(tmp_path / "master.key")
    init_master_key(master)
    monkeypatch.setenv("MASTER_KEY_PATH", master)
    monkeypatch.setattr(signature_pkg, "ensure_tsa_server_running",
                        lambda *_a, **_k: (release_tsa, release_pki.tsa_cert_path))
    real_sign = signature_pkg.sign_pdf
    calls: list[int] = []

    def _sign_once_failing(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("TSA unreachable")
        return real_sign(*args, **kwargs)

    monkeypatch.setattr(signature_pkg, "sign_pdf", _sign_once_failing)
    db = str(tmp_path / "seal.db")
    init_db(db)
    out = tmp_path / "out"
    out.mkdir()
    source = tmp_path / "evidence.dd"
    source.write_bytes(os.urandom(4096))
    process = SealProcess(db_path=db)
    process.run_s1(str(source), str(out), 1)
    request = {
        "source_file": str(source), "output_dir": str(out), "chunk_size_gb": 1,
        "case_number": "2026-E1-RETRY", "investigator": {"name": "Hong"},
        "seizure": {"date": "2026-09-28T01:02:00Z", "location": "Seoul",
                    "device_user": "Kim"},
        "media": {"type": "SSD", "manufacturer": "M", "model": "X", "serial": "1"},
        "subject": {"name": "Kim", "email": "k@example.com", "birth": "1990-01-01",
                    "phone": "010-0000-0000", "password": "pw", "participation": "yes"},
        "signature_lines": [(0, 0, 1, 1)], "seal_mode": "standard", "unlock_days": 3,
    }

    with pytest.raises(SealStepError) as info:
        run_seal_steps(process, request)
    assert info.value.step == "S5"
    first_id = process.state["s4"]["seal_id"]
    result = run_seal_steps(process, request)

    assert result.seal_id == first_id
    for pattern in ("S-*_record.json", "S-*_cert.pem", "S-*_key.pem",
                    "S-*_seal_record.pdf", "S-*_seal_record_signed.pdf"):
        assert [p.name for p in out.glob(pattern)] == [
            pattern.replace("S-*", first_id)], pattern
    assert get_seal_record(db, first_id) is not None


def test_run_seal_steps_standard_without_policy_key_is_legacy(
    tmp_path, monkeypatch, release_pki, release_tsa
) -> None:
    """Standard mode, no policy key configured: SSS 2-of-4, no policy, no wrapped s3."""
    import desktop.signature as signature_pkg
    from desktop.seal_process import SealProcess
    from desktop.seal_steps import run_seal_steps

    for name in (POLICY_KEY_PATH_ENV, POLICY_CERT_PATH_ENV, POLICY_KEY_PASSWORD_ENV):
        monkeypatch.delenv(name, raising=False)
    master = str(tmp_path / "master.key")
    init_master_key(master)
    monkeypatch.setenv("MASTER_KEY_PATH", master)
    monkeypatch.setattr(signature_pkg, "ensure_tsa_server_running",
                        lambda *_a, **_k: (release_tsa, release_pki.tsa_cert_path))
    db = str(tmp_path / "seal.db")
    init_db(db)
    source = tmp_path / "evidence.dd"
    source.write_bytes(os.urandom(8192))
    process = SealProcess(db_path=db)
    process.run_s1(str(source), str(tmp_path), 1)

    result = run_seal_steps(process, {
        "source_file": str(source), "output_dir": str(tmp_path),
        "chunk_size_gb": 1, "case_number": "2026-E1-STD",
        "investigator": {"name": "Hong"},
        "seizure": {"date": "2026-09-28T01:02:00Z", "location": "Seoul",
                    "device_user": "Kim"},
        "media": {"type": "SSD", "manufacturer": "M", "model": "X", "serial": "1"},
        "subject": {"name": "Kim", "email": "k@example.com", "birth": "1990-01-01",
                    "phone": "010-0000-0000", "password": "pw", "participation": "yes"},
        "signature_lines": [(0, 0, 1, 1)], "seal_mode": "standard",
        "unlock_days": 3,
    })

    record = get_seal_record(db, result.seal_id)["record_json"]
    assert record["seal_mode"] == "standard"
    assert "policy" not in record
    assert result.wrapped_s3_b64 is None
    key_hex = process.state["s1"]["aes_key_hex"]
    assert recover_key(list(result.key_shares[2:])) == key_hex  # any two (s3+s4)
    assert recover_key_for_mode("standard", [result.key_shares[1],
                                             result.key_shares[2]]) == key_hex
