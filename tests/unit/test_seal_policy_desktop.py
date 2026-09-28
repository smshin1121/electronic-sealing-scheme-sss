"""Desktop side of the authenticated policy and wrapped s3 (stage D, D1/D2).

  - S4 (sealing) and R6 (resealing) attach a signed canonical policy when
    an institutional policy key is configured; without one the record
    stays legacy and a warning is logged; a partial configuration aborts.
  - S6 / R7 wrap s3 bound to (seal_id, policy digest); that ciphertext is
    what the desktop stores as share 3 and what the sync payload carries
    as ``wrapped_s3``. Without a policy the legacy (unbound) wrap is kept.
  - Unsealing carries the unchanged policy forward.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto import KMSError, decrypt_envelope
from desktop.crypto.local_kms import init_master_key
from desktop.record.record_builder import (
    build_seal_record,
    build_unseal_record,
    validate_record,
)
from desktop.signature.seal_policy import (
    POLICY_CERT_PATH_ENV,
    POLICY_KEY_PASSWORD_ENV,
    POLICY_KEY_PATH_ENV,
    PolicyError,
    attach_policy,
    policy_digest,
    s3_wrap_aad,
    verify_policy,
)
from desktop.sync_payload import build_sync_payload
from tests.fixtures.release_pki import POLICY_KEY_PASSWORD, load_test_signer

KEY_HEX = "cd" * 32
NEW_KEY_HEX = "ef" * 32

_POLICY_ENVS = (POLICY_KEY_PATH_ENV, POLICY_CERT_PATH_ENV,
                POLICY_KEY_PASSWORD_ENV)


@pytest.fixture()
def master_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A temporary local-KMS master key used by S6/R7."""
    path = str(tmp_path / "master.key")
    init_master_key(path)
    monkeypatch.setenv("MASTER_KEY_PATH", path)
    return path


@pytest.fixture()
def no_policy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _POLICY_ENVS:
        monkeypatch.delenv(name, raising=False)


def _seal_process(tmp_path: Path, signer: Any = None, unlock_days: int = 7):
    import desktop.seal_process as sp

    enc = tmp_path / "evidence.bin.enc"
    enc.write_bytes(b"x" * 64)
    process = sp.SealProcess(
        db_path=str(tmp_path / "seal.db"), policy_signer=signer
    )
    process.set_config(sp.SealConfig(
        source_file=str(tmp_path / "evidence.bin"),
        output_dir=str(tmp_path),
        chunk_size_bytes=1 << 30,
        case_number="2026-형제-001",
        investigator={"name": "Hong"},
        seizure={"date": "2026-08-02T00:00:00Z", "location": "Seoul",
                 "device_user": "Kim"},
        media={"type": "SSD", "manufacturer": "M", "model": "X",
               "serial": "1"},
        subject={"name": "Kim", "email": "k@example.com",
                 "birth": "1990-01-01", "phone": "010-0000-0000",
                 "participation": "yes", "password": "pw"},
        signature_lines=[(0, 0, 1, 1)],
        unlock_days=unlock_days,
    ))
    process.state["s1"] = {
        "aes_key_hex": KEY_HEX,
        "enc_filepath": str(enc),
        "encryption_algo": "AES-256-GCM",
        "metadata": {
            "filename": "evidence.bin", "size": 4096, "md5": "0" * 32,
            "sha256": "0" * 64, "mtime": "2026-08-02T00:00:00Z",
            "ctime": "2026-08-02T00:00:00Z",
            "atime": "2026-08-02T00:00:00Z",
        },
        "enc_metadata": {
            "enc_ended_time": "2026-08-02T00:00:00Z",
            "nonces": ["00"], "tags": ["11"], "chunk_lengths": [4096],
        },
    }
    return process


def _inject_s5(process: Any, tmp_path: Path) -> None:
    """Stand in for S5 (PDF signing) so S7 can persist the bundle."""
    from desktop.db import init_db

    init_db(process._db_path)
    pdf = tmp_path / "record.pdf"
    pdf.write_bytes(b"%PDF-1.4 test")
    process.state["s5"] = {"pdf_path": str(pdf), "cert_pem": "",
                           "key_pem": b""}


# ===================================================================
# Sealing: S4 attaches, S6 binds, S7 exposes
# ===================================================================

class TestSealingPolicy:
    def test_s4_attaches_a_verifiable_policy(
        self, tmp_path: Path, release_pki
    ) -> None:
        process = _seal_process(tmp_path, load_test_signer(release_pki))
        s4 = process.run_s4()
        record = s4["record_dict"]

        verified = verify_policy(
            record["policy"], record["policy_signature"],
            record["policy_cert"], ca_cert=release_pki.ca_cert,
            expected_seal_id=record["seal_id"],
        )
        assert verified.unlock_time_iso == record["unlock_time_iso"]
        assert verified.key_commitment == hashlib.sha256(
            bytes.fromhex(KEY_HEX)
        ).hexdigest()
        assert verified.seal_mode == record["seal_mode"]
        assert verified.case_no == "2026-형제-001"
        assert s4["policy_digest"] == policy_digest(record["policy"])
        assert validate_record(record) == []

    def test_s4_uses_the_environment_signer(
        self, tmp_path: Path, release_pki, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(POLICY_KEY_PATH_ENV, str(release_pki.policy_key_path))
        monkeypatch.setenv(
            POLICY_CERT_PATH_ENV, str(release_pki.policy_cert_path)
        )
        monkeypatch.setenv(POLICY_KEY_PASSWORD_ENV, POLICY_KEY_PASSWORD)
        s4 = _seal_process(tmp_path).run_s4()
        assert "policy_signature" in s4["record_dict"]

    def test_s4_without_key_is_legacy_with_warning(
        self, tmp_path: Path, no_policy_env: None,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING):
            s4 = _seal_process(tmp_path).run_s4()
        assert "policy" not in s4["record_dict"]
        assert s4["policy_digest"] is None
        assert any("policy" in r.getMessage() for r in caplog.records)

    def test_s4_with_partial_configuration_aborts(
        self, tmp_path: Path, release_pki, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(POLICY_KEY_PATH_ENV, str(release_pki.policy_key_path))
        monkeypatch.delenv(POLICY_CERT_PATH_ENV, raising=False)
        with pytest.raises(PolicyError):
            _seal_process(tmp_path).run_s4()

    def test_s6_binds_s3_to_the_signed_policy(
        self, tmp_path: Path, release_pki, master_key: str
    ) -> None:
        process = _seal_process(tmp_path, load_test_signer(release_pki))
        s4 = process.run_s4()
        s6 = process.run_s6()

        wrapped = s6["encrypted_shares"][3]
        aad = s3_wrap_aad(s4["seal_id"], s4["policy_digest"])
        assert decrypt_envelope(wrapped, master_key, aad=aad).decode(
            "utf-8"
        ) == s6["shares"][2]
        with pytest.raises(KMSError):
            decrypt_envelope(wrapped, master_key)
        assert base64.b64decode(s6["wrapped_s3_b64"]) == wrapped

    def test_s6_without_policy_keeps_the_legacy_wrap(
        self, tmp_path: Path, master_key: str, no_policy_env: None
    ) -> None:
        process = _seal_process(tmp_path)
        process.run_s4()
        s6 = process.run_s6()

        assert decrypt_envelope(
            s6["encrypted_shares"][3], master_key
        ).decode("utf-8") == s6["shares"][2]
        assert s6["wrapped_s3_b64"] is None

    def test_s7_result_and_desktop_store_carry_the_bound_s3(
        self, tmp_path: Path, release_pki, master_key: str
    ) -> None:
        from desktop.db import get_key_share

        process = _seal_process(tmp_path, load_test_signer(release_pki))
        s4 = process.run_s4()
        s6 = process.run_s6()
        _inject_s5(process, tmp_path)
        result = process.run_s7()

        assert result.wrapped_s3_b64 == s6["wrapped_s3_b64"]
        stored = get_key_share(process._db_path, s4["seal_id"], 3)
        assert stored == base64.b64decode(result.wrapped_s3_b64)
        assert json.loads(result.record_json)["policy"] == (
            s4["record_dict"]["policy"]
        )


# ===================================================================
# Resealing: R6 signs a NEW policy, R7 binds s3 to it
# ===================================================================

def _prior_sealing_record(signer: Any) -> dict:
    record = build_seal_record(
        seal_id="S-20260926-0A1B2C",
        unlock_time_iso="2026-10-06T00:00:00Z",
        key_commitment=hashlib.sha256(bytes.fromhex(KEY_HEX)).hexdigest(),
        case_info={
            "case_number": "2026-형제-001", "investigator": "Hong",
            "device_user": "Kim", "suspect": "Kim", "storage_type": "SSD",
            "storage_info": {"manufacturer": "M", "model": "X",
                             "serial": "1"},
            "seizure_time": "2026-08-02T00:00:00Z",
            "seizure_location": "Seoul",
        },
        process_info={
            "type": "Sealing", "start_time": "2026-08-02T00:00:00Z",
            "end_time": "2026-08-02T00:00:00Z", "file_count": 1,
            "investigator": "Hong", "reason": "", "participation": "yes",
        },
        file_info={
            "original_files": [{
                "filename": "e.bin", "size": 1, "md5": "0" * 32,
                "sha256": "0" * 64, "mtime": "2026-08-02T00:00:00Z",
                "ctime": "2026-08-02T00:00:00Z",
                "atime": "2026-08-02T00:00:00Z",
            }],
            "result_files": [],
            "hash_match": True,
        },
        signer_info={
            "name": "Kim", "email": "k@example.com",
            "birth_date": "1990-01-01", "phone": "010-0000-0000",
            "cert_fingerprint": "0" * 64,
            "signature_image_hash": "0" * 64,
        },
        history={"summary": "S1U0R0", "events": [
            {"event": "seal", "time": "2026-08-02T00:00:00Z",
             "actor": "Hong", "reason": ""},
        ]},
    )
    if signer is None:
        return record
    signed_record, _ = attach_policy(record, signer)
    return signed_record


def _reseal_process(
    tmp_path: Path, signer: Any, monkeypatch: pytest.MonkeyPatch
):
    import desktop.record as record_pkg
    import desktop.reseal_process as rp

    def _stub_render(record: dict, template_name: str, output_path: str) -> str:
        Path(output_path).write_bytes(b"%PDF-1.4 stub")
        return output_path

    monkeypatch.setattr(record_pkg, "render_record_pdf", _stub_render)
    process = rp.ResealProcess(
        db_path=str(tmp_path / "reseal.db"), policy_signer=signer
    )
    prev = _prior_sealing_record(signer)
    process.state["r1"] = {"prev_record": prev, "seal_id": prev["seal_id"],
                           "record_path": ""}
    process.state["r2"] = {"known_files": [], "unknown_files": [],
                           "target_dir": str(tmp_path)}
    process.set_config(rp.ResealConfig(
        source_dir=str(tmp_path), output_dir=str(tmp_path),
        chunk_size_bytes=1 << 30, investigator="Hong",
        reason="analysis complete", subject_participated=True,
        unlock_days=5,
    ))
    process.state["r5"] = {
        "aes_key_hex": NEW_KEY_HEX,
        "enc_results": [{
            "enc_filepath": str(tmp_path / "e.enc"),
            "original_filepath": str(tmp_path / "e.bin"),
            "metadata": {"filename": "e.bin", "size": 1, "md5": "0" * 32,
                         "sha256": "0" * 64},
            "chunk_count": 1,
        }],
        "encryption_algo": "AES-256-GCM",
    }
    return process


class TestResealingPolicy:
    def test_r6_signs_a_new_policy_for_the_new_key(
        self, tmp_path: Path, release_pki, master_key: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        process = _reseal_process(
            tmp_path, load_test_signer(release_pki), monkeypatch
        )
        prev_policy = process.state["r1"]["prev_record"]["policy"]
        r6 = process.run_r6_record()
        record = r6["record_dict"]

        verified = verify_policy(
            record["policy"], record["policy_signature"],
            record["policy_cert"], ca_cert=release_pki.ca_cert,
            expected_seal_id=record["seal_id"],
        )
        assert verified.key_commitment == hashlib.sha256(
            bytes.fromhex(NEW_KEY_HEX)
        ).hexdigest()
        assert verified.unlock_time_iso == record["unlock_time_iso"]
        assert record["policy"] != prev_policy
        assert r6["policy_digest"] == policy_digest(record["policy"])

    def test_r7_and_r8_bind_s3_to_the_new_policy(
        self, tmp_path: Path, release_pki, master_key: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from desktop.db import init_db

        process = _reseal_process(
            tmp_path, load_test_signer(release_pki), monkeypatch
        )
        r6 = process.run_r6_record()
        r7 = process.run_r7_split_key()
        aad = s3_wrap_aad(r6["record_dict"]["seal_id"], r6["policy_digest"])
        assert decrypt_envelope(
            r7["encrypted_shares"][3], master_key, aad=aad
        ).decode("utf-8") == r7["shares"][2]

        init_db(process._db_path)
        result = process.run_r8_save()
        assert base64.b64decode(result.wrapped_s3_b64) == (
            r7["encrypted_shares"][3]
        )

    def test_reseal_without_key_stays_legacy(
        self, tmp_path: Path, master_key: str, no_policy_env: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        process = _reseal_process(tmp_path, None, monkeypatch)
        r6 = process.run_r6_record()
        r7 = process.run_r7_split_key()
        assert "policy" not in r6["record_dict"]
        assert r7["wrapped_s3_b64"] is None
        assert decrypt_envelope(
            r7["encrypted_shares"][3], master_key
        ).decode("utf-8") == r7["shares"][2]


# ===================================================================
# Unsealing carries the unchanged policy forward
# ===================================================================

class TestUnsealCarriesPolicy:
    def _unseal(self, prev: dict) -> dict:
        return build_unseal_record(
            prev_record=prev,
            process_info={"type": "Unsealing",
                          "start_time": "2026-10-07T00:00:00Z",
                          "end_time": "2026-10-07T00:00:00Z"},
            file_info={"original_files": prev["file_info"]["original_files"]},
        )

    def test_policy_fields_are_carried_verbatim(self, release_pki) -> None:
        prev = _prior_sealing_record(load_test_signer(release_pki))
        unseal = self._unseal(prev)
        for name in ("policy", "policy_signature", "policy_cert"):
            assert unseal[name] == prev[name]
        verify_policy(
            unseal["policy"], unseal["policy_signature"],
            unseal["policy_cert"], ca_cert=release_pki.ca_cert,
            expected_seal_id=unseal["seal_id"],
        )

    def test_legacy_chain_gains_no_policy_fields(self) -> None:
        unseal = self._unseal(_prior_sealing_record(None))
        assert not {"policy", "policy_signature", "policy_cert"} & set(unseal)


# ===================================================================
# Sync payload (desktop -> web contract)
# ===================================================================

class TestSyncPayload:
    def test_payload_carries_the_wrapped_s3(self) -> None:
        wrapped = base64.b64encode(os.urandom(94)).decode("ascii")
        record_json = json.dumps({"seal_id": "S-20260926-0A1B2C"})
        payload = build_sync_payload(
            seal_id="S-20260926-0A1B2C", event_id=1, event_type="Sealing",
            record_json=record_json, record_pdf=b"%PDF",
            wrapped_s3_b64=wrapped,
        )
        assert payload == {
            "seal_id": "S-20260926-0A1B2C",
            "event_id": 1,
            "event_type": "Sealing",
            "record_json": record_json,
            "record_pdf": base64.b64encode(b"%PDF").decode("ascii"),
            "wrapped_s3": wrapped,
        }

    def test_legacy_payload_has_no_wrapped_s3(self) -> None:
        payload = build_sync_payload(
            seal_id="S-20260926-0A1B2C", event_id=2,
            event_type="Unsealing", record_json="{}",
        )
        assert "wrapped_s3" not in payload
        assert payload["record_pdf"] is None

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"event_type": "Opening"},
            {"event_type": "Unsealing", "wrapped_s3_b64": "AAAA"},
            {"seal_id": ""},
            {"event_id": 0},
        ],
    )
    def test_invalid_payloads_are_refused(self, kwargs: dict) -> None:
        base = {"seal_id": "S-20260926-0A1B2C", "event_id": 1,
                "event_type": "Sealing", "record_json": "{}"}
        with pytest.raises(ValueError):
            build_sync_payload(**{**base, **kwargs})
