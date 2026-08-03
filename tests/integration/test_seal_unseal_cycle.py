"""Integration test: full seal -> unseal cycle.

Validates:
- 1MB file encryption (seal) -> key split -> key recover -> decryption (unseal)
- Original hash == decrypted file hash
- build_seal_record() -> build_unseal_record() -> history continuity
"""

from __future__ import annotations

import hashlib
import json
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


def _md5_of_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_case_info() -> dict:
    return {
        "case_number": "2026-TEST-001",
        "investigator": "홍길동",
        "device_user": "김수사",
        "suspect": "이용의",
        "storage_type": "USB",
        "storage_info": {
            "manufacturer": "Samsung",
            "model": "T7",
            "serial": "SN-TEST-12345",
        },
        "seizure_time": datetime.now(tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "seizure_location": "서울특별시 종로구",
    }


def _make_signer_info() -> dict:
    return {
        "name": "이참여",
        "email": "signer@test.kr",
        "birth_date": "1990-01-01",
        "phone": "010-1234-5678",
        "cert_fingerprint": "AB:CD:EF:01:23:45:67:89",
        "signature_image_hash": "deadbeefcafe",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSealUnsealCycle:
    """Full seal -> unseal round-trip test."""

    def test_encrypt_split_recover_decrypt_hash_match(
        self, tmp_path: Path
    ) -> None:
        """Encrypt a 1MB file, split key, recover with 2 shares, decrypt,
        and verify original hash matches decrypted file hash."""

        # 1. Create 1MB test file
        src_file = create_random_file(tmp_path / "evidence.bin", SIZE_1MB)
        original_sha256 = _sha256_of_file(src_file)
        original_md5 = _md5_of_file(src_file)

        # 2. Encrypt (seal)
        aes_key = os.urandom(32)
        aes_key_hex = aes_key.hex()
        enc_path = str(tmp_path / "evidence.enc")

        enc_result = encrypt_file(
            filepath=src_file,
            aes_key=aes_key,
            output_path=enc_path,
            chunk_size=_1GB,
        )
        assert Path(enc_result.enc_filepath).exists()
        assert enc_result.chunk_count >= 1

        # 3. Split key (2-of-4 SSS)
        shares = split_key(aes_key_hex)
        assert len(shares) == 4

        # 4. Recover key with shares 0 and 1
        recovered_hex = recover_key([shares[0], shares[1]])
        assert recovered_hex.lower() == aes_key_hex.lower()

        # 5. Decrypt (unseal)
        output_dir = tmp_path / "decrypted"
        output_dir.mkdir()
        recovered_key = bytes.fromhex(recovered_hex)

        dec_result = decrypt_file(
            enc_filepath=enc_path,
            aes_key=recovered_key,
            output_dir=str(output_dir),
        )

        # 6. Hash verification
        assert dec_result.hash_verified is True
        assert dec_result.sha256_match is True
        assert dec_result.md5_match is True

        decrypted_sha256 = _sha256_of_file(dec_result.output_filepath)
        decrypted_md5 = _md5_of_file(dec_result.output_filepath)
        assert decrypted_sha256 == original_sha256
        assert decrypted_md5 == original_md5

    def test_recover_with_different_share_pairs(
        self, tmp_path: Path
    ) -> None:
        """Any 2-of-4 share combination should recover the same key."""

        aes_key = os.urandom(32)
        aes_key_hex = aes_key.hex()
        shares = split_key(aes_key_hex)

        # Test multiple pairs
        pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]
        for i, j in pairs:
            recovered = recover_key([shares[i], shares[j]])
            assert recovered.lower() == aes_key_hex.lower(), (
                f"Recovery failed for share pair ({i}, {j})"
            )

    def test_seal_unseal_record_history_continuity(
        self, tmp_path: Path
    ) -> None:
        """build_seal_record -> build_unseal_record preserves history
        continuity and seal_id."""

        now = datetime.now(tz=timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        seal_id = create_seal_id()

        # Create initial history for sealing
        seal_event = {
            "seal_type": "Sealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "홍길동",
        }
        history = create_initial_history(seal_event)
        assert history["summary"] == "S1U0R0"
        assert len(history["events"]) == 1

        # Build seal record
        case_info = _make_case_info()
        signer_info = _make_signer_info()

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
                        "sha256": "aabbccdd" * 8,
                        "md5": "aabbccdd" * 4,
                        "mtime": now_iso,
                        "ctime": now_iso,
                        "atime": now_iso,
                    }
                ],
            },
            signer_info=signer_info,
            history=history,
        )

        assert seal_record["seal_id"] == seal_id
        assert seal_record["history"]["summary"] == "S1U0R0"

        # Append unseal event to history
        unseal_event = {
            "seal_type": "Unsealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "김수사",
        }
        updated_history = append_event(
            seal_record["history"], unseal_event
        )
        assert updated_history["summary"] == "S1U1R0"
        assert len(updated_history["events"]) == 2

        # Build unseal record using prev_record with updated history
        prev_with_history = {**seal_record, "history": updated_history}

        unseal_record = build_unseal_record(
            prev_record=prev_with_history,
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
                        "sha256": "aabbccdd" * 8,
                        "md5": "aabbccdd" * 4,
                        "mtime": now_iso,
                        "ctime": now_iso,
                        "atime": now_iso,
                    }
                ],
                "output_filepath": "/tmp/decrypted/evidence.bin",
                "hash_verified": True,
                "sha256_match": True,
                "md5_match": True,
            },
        )

        # Verify continuity
        assert unseal_record["seal_id"] == seal_id
        assert unseal_record["case_info"]["case_number"] == "2026-TEST-001"
        assert unseal_record["signer_info"]["name"] == "이참여"
        assert unseal_record["history"]["summary"] == "S1U1R0"
        assert len(unseal_record["history"]["events"]) == 2

        # Verify original seal_record was not mutated
        assert seal_record["history"]["summary"] == "S1U0R0"
        assert len(seal_record["history"]["events"]) == 1

    def test_full_cycle_with_progress_callback(
        self, tmp_path: Path
    ) -> None:
        """Encryption and decryption progress callbacks fire correctly."""

        src_file = create_random_file(tmp_path / "progress_test.bin", SIZE_1MB)
        aes_key = os.urandom(32)
        enc_path = str(tmp_path / "progress_test.enc")

        encrypt_progress: list[tuple[int, int]] = []
        decrypt_progress: list[tuple[int, int]] = []

        encrypt_file(
            filepath=src_file,
            aes_key=aes_key,
            output_path=enc_path,
            chunk_size=_1GB,
            progress_cb=lambda cur, tot: encrypt_progress.append((cur, tot)),
        )

        output_dir = tmp_path / "dec_out"
        output_dir.mkdir()

        decrypt_file(
            enc_filepath=enc_path,
            aes_key=aes_key,
            output_dir=str(output_dir),
            progress_cb=lambda cur, tot: decrypt_progress.append((cur, tot)),
        )

        # Progress callbacks should have been called at least once
        assert len(encrypt_progress) >= 1
        assert len(decrypt_progress) >= 1

        # Final progress should indicate completion
        last_enc = encrypt_progress[-1]
        assert last_enc[0] == last_enc[1]  # completed == total
