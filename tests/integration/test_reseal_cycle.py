"""Integration test: unseal -> reseal -> unseal cycle.

Validates:
- Seal -> unseal -> re-encrypt (reseal) -> unseal again
- build_reseal_record() with history summary "S1U1R1"
- Re-sealed file decryption produces matching hash
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from desktop.crypto import (
    decrypt_file,
    encrypt_file,
    recover_key,
    split_key,
)
from desktop.record.history_manager import append_event, create_initial_history
from desktop.record.record_builder import (
    build_reseal_record,
    build_seal_record,
    build_unseal_record,
    create_seal_id,
)
from tests.fixtures.generate_test_files import SIZE_1MB, create_random_file

_1GB = 1 * 1024**3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_case_info() -> dict:
    return {
        "case_number": "2026-RESEAL-001",
        "investigator": "홍길동",
        "device_user": "김수사",
        "suspect": "이용의",
        "storage_type": "HDD",
        "storage_info": {
            "manufacturer": "Seagate",
            "model": "Barracuda",
            "serial": "SN-RESEAL-99999",
        },
        "seizure_time": datetime.now(tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "seizure_location": "부산광역시 해운대구",
    }


def _make_signer_info() -> dict:
    return {
        "name": "박참여",
        "email": "park@test.kr",
        "birth_date": "1985-05-15",
        "phone": "010-9876-5432",
        "cert_fingerprint": "11:22:33:44:55:66:77:88",
        "signature_image_hash": "cafebabe1234",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestResealCycle:
    """Full seal -> unseal -> reseal -> unseal round-trip test."""

    def test_full_reseal_cycle_hash_match(self, tmp_path: Path) -> None:
        """Encrypt, decrypt, re-encrypt with new key, decrypt again.
        All hashes must match the original."""

        # --- Phase 1: Initial seal ---
        src_file = create_random_file(tmp_path / "evidence.bin", SIZE_1MB)
        original_sha256 = _sha256_of_file(src_file)

        aes_key_1 = os.urandom(32)
        enc_path_1 = str(tmp_path / "evidence.enc")

        encrypt_file(
            filepath=src_file,
            aes_key=aes_key_1,
            output_path=enc_path_1,
            chunk_size=_1GB,
        )

        # --- Phase 2: Unseal ---
        unseal_dir = tmp_path / "unsealed"
        unseal_dir.mkdir()

        dec_result_1 = decrypt_file(
            enc_filepath=enc_path_1,
            aes_key=aes_key_1,
            output_dir=str(unseal_dir),
        )
        assert dec_result_1.hash_verified is True
        unsealed_sha256 = _sha256_of_file(dec_result_1.output_filepath)
        assert unsealed_sha256 == original_sha256

        # --- Phase 3: Reseal with new key ---
        aes_key_2 = os.urandom(32)
        aes_key_2_hex = aes_key_2.hex()
        enc_path_2 = str(tmp_path / "evidence_reseal.enc")

        enc_result_2 = encrypt_file(
            filepath=dec_result_1.output_filepath,
            aes_key=aes_key_2,
            output_path=enc_path_2,
            chunk_size=_1GB,
        )
        assert Path(enc_result_2.enc_filepath).exists()

        # Split the new key
        shares = split_key(aes_key_2_hex)
        assert len(shares) == 4

        # --- Phase 4: Unseal the re-sealed file ---
        reseal_unseal_dir = tmp_path / "reseal_unsealed"
        reseal_unseal_dir.mkdir()

        recovered_hex = recover_key([shares[1], shares[3]])
        recovered_key = bytes.fromhex(recovered_hex)

        dec_result_2 = decrypt_file(
            enc_filepath=enc_path_2,
            aes_key=recovered_key,
            output_dir=str(reseal_unseal_dir),
        )
        assert dec_result_2.hash_verified is True
        assert dec_result_2.sha256_match is True

        # Final hash must match the original
        final_sha256 = _sha256_of_file(dec_result_2.output_filepath)
        assert final_sha256 == original_sha256

    def test_reseal_record_history_s1u1r1(self, tmp_path: Path) -> None:
        """build_reseal_record history summary should be 'S1U1R1'
        after seal -> unseal -> reseal sequence."""

        now = datetime.now(tz=timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        seal_id = create_seal_id()
        case_info = _make_case_info()
        signer_info = _make_signer_info()

        # --- Step 1: Create seal record with history ---
        seal_event = {
            "seal_type": "Sealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "홍길동",
        }
        history = create_initial_history(seal_event)
        assert history["summary"] == "S1U0R0"

        seal_record = build_seal_record(
            unlock_time_iso="2026-12-31T00:00:00Z",
        key_commitment="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  # public-test-fixture; gitleaks:allow
            seal_id=seal_id,
            case_info=case_info,
            process_info={
                "type": "Sealing",
                "start_time": now_iso,
                "end_time": now_iso,
            },
            file_info={
                "original_files": [
                    {
                        "filename": "evidence.bin",
                        "size": SIZE_1MB,
                        "sha256": "aa" * 32,
                        "md5": "bb" * 16,
                        "mtime": now_iso,
                        "ctime": now_iso,
                        "atime": now_iso,
                    }
                ],
            },
            signer_info=signer_info,
            history=history,
        )

        # --- Step 2: Unseal event ---
        unseal_event = {
            "seal_type": "Unsealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "김수사",
        }
        history_after_unseal = append_event(
            seal_record["history"], unseal_event
        )
        assert history_after_unseal["summary"] == "S1U1R0"

        prev_for_unseal = {**seal_record, "history": history_after_unseal}
        unseal_record = build_unseal_record(
            prev_record=prev_for_unseal,
            process_info={
                "type": "Unsealing",
                "start_time": now_iso,
                "end_time": now_iso,
            },
            file_info={
                "original_files": [
                    {
                        "filename": "evidence.bin",
                        "size": SIZE_1MB,
                        "sha256": "aa" * 32,
                        "md5": "bb" * 16,
                        "mtime": now_iso,
                        "ctime": now_iso,
                        "atime": now_iso,
                    }
                ],
                "hash_verified": True,
            },
        )
        assert unseal_record["history"]["summary"] == "S1U1R0"

        # --- Step 3: Reseal event ---
        reseal_event = {
            "seal_type": "Resealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "홍길동",
        }
        history_after_reseal = append_event(
            unseal_record["history"], reseal_event
        )
        assert history_after_reseal["summary"] == "S1U1R1"

        prev_for_reseal = {**unseal_record, "history": history_after_reseal}
        reseal_record = build_reseal_record(
            prev_record=prev_for_reseal,
            process_info={
                "type": "Resealing",
                "start_time": now_iso,
                "end_time": now_iso,
            },
            file_info={
                "original_files": [
                    {
                        "filename": "evidence.bin",
                        "size": SIZE_1MB,
                        "sha256": "aa" * 32,
                        "md5": "bb" * 16,
                        "mtime": now_iso,
                        "ctime": now_iso,
                        "atime": now_iso,
                    }
                ],
                "enc_results": [
                    {"enc_filepath": "/tmp/evidence_reseal.enc"}
                ],
                "encryption_algo": "AES-256-GCM",
            },
            unknown_files=[],
            derived_files=[],
        )

        # Verify final summary
        assert reseal_record["history"]["summary"] == "S1U1R1"
        assert len(reseal_record["history"]["events"]) == 3

        # Verify seal_id preserved across all records
        assert reseal_record["seal_id"] == seal_id

        # Verify immutability: original seal_record unchanged
        assert seal_record["history"]["summary"] == "S1U0R0"
        assert len(seal_record["history"]["events"]) == 1

    def test_reseal_with_derived_and_excluded_files(
        self, tmp_path: Path
    ) -> None:
        """Reseal record properly tracks derived and excluded unknown files."""

        now_iso = datetime.now(tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        seal_id = create_seal_id()
        case_info = _make_case_info()
        signer_info = _make_signer_info()

        # Build minimal history through seal -> unseal -> reseal
        history = create_initial_history({
            "seal_type": "Sealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "홍길동",
        })
        history = append_event(history, {
            "seal_type": "Unsealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "김수사",
        })
        history = append_event(history, {
            "seal_type": "Resealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "홍길동",
        })

        prev_record = {
            "seal_id": seal_id,
            "case_info": case_info,
            "signer_info": signer_info,
            "process_info": {
                "type": "Unsealing",
                "start_time": now_iso,
                "end_time": now_iso,
            },
            "file_info": {
                "original_files": [
                    {
                        "filename": "evidence.bin",
                        "size": SIZE_1MB,
                        "sha256": "cc" * 32,
                        "mtime": now_iso,
                        "ctime": now_iso,
                        "atime": now_iso,
                    }
                ],
            },
            "history": history,
        }

        unknown_files = [
            {
                "filename": "analysis_report.pdf",
                "sha256": "dd" * 32,
                "classification": "derived",
            },
            {
                "filename": "temp_cache.tmp",
                "sha256": "ee" * 32,
                "classification": "excluded",
            },
        ]
        derived_files = [
            {
                "filepath": "/tmp/analysis_report.pdf",
                "filename": "analysis_report.pdf",
                "sha256": "dd" * 32,
                "parent_file": "evidence.bin",
                "derivation_reason": "분석 보고서",
            },
        ]

        reseal_record = build_reseal_record(
            prev_record=prev_record,
            process_info={
                "type": "Resealing",
                "start_time": now_iso,
                "end_time": now_iso,
            },
            file_info={
                "original_files": [
                    {
                        "filename": "evidence.bin",
                        "size": SIZE_1MB,
                        "sha256": "cc" * 32,
                        "mtime": now_iso,
                        "ctime": now_iso,
                        "atime": now_iso,
                    }
                ],
            },
            unknown_files=unknown_files,
            derived_files=derived_files,
        )

        # unknown_files and derived_files should be in file_info
        fi = reseal_record["file_info"]
        assert len(fi["unknown_files"]) == 2
        assert len(fi["derived_files"]) == 1
        assert fi["derived_files"][0]["parent_file"] == "evidence.bin"
