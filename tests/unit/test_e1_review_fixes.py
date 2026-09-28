"""Stage E, E1 — fixes after the code-reviewer and security-reviewer round.

Process layer:
  * strict mode requires a signed seal policy (S4 when sealing, R6 when
    resealing); ``SealProcess.policy_signer_available`` lets the GUI refuse
    strict early;
  * a retry within one sealing process keeps the seal_id (no orphaned
    signed artifacts under a second ID);
  * S7 writes the case columns in its own transaction (no blank case row
    between the save and the wizard's completion);
  * the reseal R1 DB cross-check refuses an unreadable database instead of
    skipping (only "no such table" means nothing to compare) and reports
    what confirmed the mode;
  * a record's seal_id must be a safe file-name token before the reseal
    (R1) or unseal (U3) builds output paths from it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto import init_master_key
from desktop.record.record_builder import build_seal_record
from desktop.reseal_process import ResealConfig, ResealProcess
from desktop.seal_process import SealProcess, SealRecordError
from desktop.seal_steps import seal_config_from_wizard
from desktop.signature.seal_policy import (
    POLICY_CERT_PATH_ENV,
    POLICY_KEY_PASSWORD_ENV,
    POLICY_KEY_PATH_ENV,
    attach_policy,
)
from tests.fixtures.release_pki import load_test_signer

KEY_HEX = "cd" * 32
_POLICY_ENVS = (POLICY_KEY_PATH_ENV, POLICY_CERT_PATH_ENV, POLICY_KEY_PASSWORD_ENV)


@pytest.fixture()
def no_policy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _POLICY_ENVS:
        monkeypatch.delenv(name, raising=False)


def _wizard_data(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "source_file": str(tmp_path / "evidence.bin"), "output_dir": str(tmp_path),
        "chunk_size_gb": 1, "case_number": "2026-E1-FIX",
        "investigator": {"name": "Hong"},
        "seizure": {"date": "2026-09-28T01:02:00Z", "location": "Seoul",
                    "device_user": "Kim"},
        "media": {"type": "SSD", "manufacturer": "M", "model": "X", "serial": "1"},
        "subject": {"name": "Kim", "email": "k@example.com", "birth": "1990-01-01",
                    "phone": "010-0000-0000", "password": "pw", "participation": "yes"},
        "signature_lines": [(0, 0, 1, 1)], "seal_mode": "standard", "unlock_days": 7,
    }
    data.update(overrides)
    return data


def _after_s1(tmp_path: Path, signer: Any = None, **overrides: Any) -> SealProcess:
    enc = tmp_path / "evidence.bin.enc"
    enc.write_bytes(b"x" * 64)
    process = SealProcess(db_path=str(tmp_path / "seal.db"), policy_signer=signer)
    process.set_config(seal_config_from_wizard(_wizard_data(tmp_path, **overrides)))
    process.state["s1"] = {
        "aes_key_hex": KEY_HEX, "enc_filepath": str(enc),
        "encryption_algo": "AES-256-GCM",
        "metadata": {"filename": "evidence.bin", "size": 64, "md5": "0" * 32,
                     "sha256": "0" * 64, "mtime": "2026-09-28T00:00:00Z",
                     "ctime": "2026-09-28T00:00:00Z", "atime": "2026-09-28T00:00:00Z"},
        "enc_metadata": {"enc_ended_time": "2026-09-28T00:00:00Z",
                         "nonces": ["00"], "tags": ["11"], "chunk_lengths": [64]},
    }
    return process


# ===================================================================
# Strict requires a signed policy
# ===================================================================

class TestStrictNeedsPolicy:
    def test_s4_refuses_strict_without_a_policy_key(self, tmp_path, no_policy_env) -> None:
        process = _after_s1(tmp_path, seal_mode="strict")

        with pytest.raises(SealRecordError, match="ENC_ENVELOPE_POLICY_KEY_PATH"):
            process.run_s4()
        assert "s4" not in process.state

    def test_s4_accepts_strict_with_a_policy_key(self, tmp_path, release_pki) -> None:
        s4 = _after_s1(tmp_path, load_test_signer(release_pki), seal_mode="strict").run_s4()

        assert s4["record_dict"]["policy"]["seal_mode"] == "strict"

    def test_standard_without_a_policy_key_stays_legacy(self, tmp_path, no_policy_env) -> None:
        s4 = _after_s1(tmp_path).run_s4()

        assert s4["policy_digest"] is None

    def test_policy_signer_available(self, tmp_path, monkeypatch, release_pki) -> None:
        for name in _POLICY_ENVS:
            monkeypatch.delenv(name, raising=False)
        assert SealProcess(db_path="x").policy_signer_available() is False
        assert SealProcess(db_path="x", policy_signer=load_test_signer(release_pki)
                           ).policy_signer_available() is True
        monkeypatch.setenv(POLICY_KEY_PATH_ENV, str(release_pki.policy_key_path))
        # partial configuration counts: S4 then fails loudly (PolicyError)
        assert SealProcess(db_path="x").policy_signer_available() is True


# ===================================================================
# A retry keeps the seal_id; S7 writes the case columns
# ===================================================================

def test_a_retry_keeps_the_seal_id(tmp_path, no_policy_env) -> None:
    process = _after_s1(tmp_path)
    first = process.run_s4()["seal_id"]
    second = process.run_s4()["seal_id"]  # S5 failed; the wizard retries S4-S7

    assert second == first


def test_s7_writes_the_case_columns(tmp_path, no_policy_env, monkeypatch) -> None:
    from desktop.db import create_case, init_db

    key_path = str(tmp_path / "master.key")
    init_master_key(key_path)
    monkeypatch.setenv("MASTER_KEY_PATH", key_path)
    db = str(tmp_path / "seal.db")
    init_db(db)
    case_id = create_case(db, "2026-E1-FIX", "Hong", "Kim")
    process = _after_s1(tmp_path, seal_id=case_id)
    process._db_path = db
    process.run_s4()
    process.run_s6()
    pdf = tmp_path / "r.pdf"
    pdf.write_bytes(b"%PDF-1.4 test")
    process.state["s5"] = {"pdf_path": str(pdf), "cert_pem": "", "key_pem": b""}
    process.run_s7()

    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT case_number, suspect_name, investigator, status FROM seal_records "
            "WHERE seal_id = ?", (case_id,)).fetchone()
    assert row == ("2026-E1-FIX", "Kim", "Hong", "S1U0R0")


# ===================================================================
# Resealing: strict needs a policy at R6; R1 DB check and seal_id
# ===================================================================

def _prior(mode: str, seal_id: str = "S-20260928-0F1F2F", signer: Any = None) -> dict:
    record = build_seal_record(
        seal_id=seal_id, seal_mode=mode, unlock_time_iso="2026-10-06T00:00:00Z",
        key_commitment=hashlib.sha256(bytes.fromhex(KEY_HEX)).hexdigest(),
        case_info={"case_number": "C", "investigator": "Hong", "device_user": "Kim",
                   "suspect": "Kim", "storage_type": "SSD",
                   "storage_info": {"manufacturer": "M", "model": "X", "serial": "1"},
                   "seizure_time": "2026-09-01T00:00:00Z", "seizure_location": "Seoul"},
        process_info={"type": "Sealing", "start_time": "2026-09-01T00:00:00Z",
                      "end_time": "2026-09-01T00:00:00Z"},
        file_info={"original_files": [{"filename": "e.bin", "size": 1,
                                       "sha256": "0" * 64, "md5": "0" * 32}]},
        signer_info={"name": "Kim"},
        history={"summary": "S1U0R0", "events": [{"event": "seal"}]},
    )
    return record if signer is None else attach_policy(record, signer)[0]


def _load(tmp_path: Path, record: dict, db: str = ":memory:") -> dict:
    path = tmp_path / "prev.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return ResealProcess(db_path=db).run_r1_load(str(path))


class TestResealFixes:
    def test_r6_refuses_to_reseal_strict_without_a_policy_key(
        self, tmp_path, no_policy_env, monkeypatch
    ) -> None:
        import desktop.record as record_pkg

        monkeypatch.setattr(record_pkg, "render_record_pdf",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("rendered")))
        process = ResealProcess(db_path=":memory:")
        path = tmp_path / "prev.json"
        path.write_text(json.dumps(_prior("strict")), encoding="utf-8")
        process.run_r1_load(str(path))
        process.set_config(ResealConfig(
            source_dir=str(tmp_path), output_dir=str(tmp_path), chunk_size_bytes=1 << 30,
            investigator="Hong", reason="r", subject_participated=True, unlock_days=5))
        process.state["r2"] = {"known_files": [], "unknown_files": [],
                               "target_dir": str(tmp_path)}
        process.state["r5"] = {"aes_key_hex": "ef" * 32, "enc_results": [],
                               "encryption_algo": "AES-256-GCM"}

        with pytest.raises(ValueError, match="policy"):
            process.run_r6_record()
        assert "r6" not in process.state
        assert not list(tmp_path.glob("*_reseal_record.*"))

    def test_unreadable_stored_record_refuses(self, tmp_path) -> None:
        from desktop.db import init_db

        db = str(tmp_path / "desk.db")
        init_db(db)
        with sqlite3.connect(db) as conn:
            conn.execute("INSERT INTO seal_records (seal_id, record_json, pdf_path) "
                         "VALUES (?, ?, ?)", ("S-20260928-0F1F2F", "{not json", "x.pdf"))

        with pytest.raises(ValueError, match="S-20260928-0F1F2F|기록"):
            _load(tmp_path, _prior("standard"), db)

    def test_missing_table_means_nothing_to_compare(self, tmp_path) -> None:
        result = _load(tmp_path, _prior("standard"), str(tmp_path / "empty.db"))

        assert result["seal_mode"] == "standard"
        assert result["mode_source"] is None

    def test_mode_source(self, tmp_path, release_pki) -> None:
        from desktop.db import init_db, save_seal_record

        assert _load(tmp_path, _prior("strict", signer=load_test_signer(release_pki))
                     )["mode_source"] == "policy"
        db = str(tmp_path / "desk.db")
        init_db(db)
        save_seal_record(db, "S-20260928-0F1F2F", json.dumps(_prior("strict")), "x.pdf")
        assert _load(tmp_path, _prior("strict"), db)["mode_source"] == "stored"

    @pytest.mark.parametrize("seal_id", ["../../x", "S-1/../..", "a" * 65, "", "C:\\x"])
    def test_r1_refuses_an_unsafe_seal_id(self, tmp_path, seal_id: str) -> None:
        with pytest.raises(ValueError):
            _load(tmp_path, _prior("standard", seal_id=seal_id))

    @pytest.mark.parametrize("seal_id", ["S-20260928-0F1F2F", "SEAL-0123456789AB"])
    def test_r1_accepts_record_and_legacy_ids(self, tmp_path, seal_id: str) -> None:
        assert _load(tmp_path, _prior("standard", seal_id=seal_id))["seal_id"] == seal_id


def test_u3_refuses_an_unsafe_seal_id(tmp_path) -> None:
    from desktop.unseal_process import UnsealConfig, UnsealProcess

    record = tmp_path / "rec.json"
    record.write_text(json.dumps({"seal_id": "../../x"}), encoding="utf-8")
    enc = tmp_path / "e.enc"
    enc.write_bytes(os.urandom(64))
    process = UnsealProcess(db_path=":memory:")
    process.set_config(UnsealConfig(
        enc_filepath=str(enc), seal_record_path=str(record), aes_key_hex="ab" * 32,
        output_dir=str(tmp_path), reason="r", investigator="Hong",
        subject_participated=False))

    with pytest.raises(ValueError, match="seal_id"):
        process.run_u3_validate()
