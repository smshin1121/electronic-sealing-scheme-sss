"""Tests for encryption resume (interrupt and recover) mechanism.

Validates:
- Forced interruption via progress callback exception
- .enc.progress file persistence after interruption
- Resume with same key produces a valid .enc whose decrypted hash matches
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from desktop.crypto import (
    EncryptionError,
    decrypt_file,
    encrypt_file,
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


class _InterruptAfterN:
    """Progress callback that raises after *n* invocations."""

    def __init__(self, interrupt_after: int) -> None:
        self._count = 0
        self._limit = interrupt_after

    def __call__(self, completed: int, total: int) -> None:
        self._count += 1
        if self._count >= self._limit:
            raise RuntimeError("Simulated interruption")


# ---------------------------------------------------------------------------
# Interrupt during encryption
# ---------------------------------------------------------------------------

class TestEncryptionInterrupt:
    """Force an exception mid-encryption and verify .enc.progress is saved."""

    def test_progress_file_created_on_interrupt(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """Interrupting during encryption must leave a .enc.progress file."""
        enc_path = str(tmp_work_dir / "resume.enc")
        progress_path = enc_path + ".progress"

        # For a 1 MB file with 1 GB chunk_size there is only 1 chunk,
        # so the callback fires once. We interrupt on the first callback.
        cb = _InterruptAfterN(interrupt_after=1)

        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=_1GB,
                progress_cb=cb,
            )

        # Progress file should exist because _save_progress runs before
        # the callback. The callback exception propagates upward.
        assert os.path.isfile(progress_path), (
            ".enc.progress must be created before the callback fires"
        )

    def test_progress_file_json_valid(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """The .enc.progress file must be valid JSON with required keys."""
        enc_path = str(tmp_work_dir / "resume_json.enc")
        progress_path = enc_path + ".progress"

        cb = _InterruptAfterN(interrupt_after=1)

        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=_1GB,
                progress_cb=cb,
            )

        if not os.path.isfile(progress_path):
            pytest.skip("Progress file not created (single-chunk edge case)")

        with open(progress_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        required_keys = {"target_file", "completed_chunks", "chunk_size",
                         "nonces", "tags", "chunk_lengths"}
        assert required_keys.issubset(data.keys())


# ---------------------------------------------------------------------------
# Resume after interrupt
# ---------------------------------------------------------------------------

class TestEncryptionResume:
    """Resume encryption after interruption and verify final integrity."""

    def test_resume_produces_valid_enc(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """After interrupt + resume, decrypted file hash must match original."""
        original_hash = _sha256_of_file(file_1mb)
        enc_path = str(tmp_work_dir / "resume_ok.enc")
        dec_dir = str(tmp_work_dir / "dec_resume")
        os.makedirs(dec_dir)

        # Step 1: Interrupt
        cb = _InterruptAfterN(interrupt_after=1)
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=_1GB,
                progress_cb=cb,
            )

        # Step 2: Resume (no callback this time)
        result = encrypt_file(
            file_1mb, aes_key, enc_path,
            chunk_size=_1GB,
        )

        assert os.path.isfile(result.enc_filepath)

        # Step 3: Decrypt and verify
        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)
        assert dec_result.hash_verified is True
        assert _sha256_of_file(dec_result.output_filepath) == original_hash

    def test_progress_file_removed_on_success(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """The .enc.progress file must be deleted after successful completion."""
        enc_path = str(tmp_work_dir / "resume_clean.enc")
        progress_path = enc_path + ".progress"

        # Interrupt first
        cb = _InterruptAfterN(interrupt_after=1)
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=_1GB,
                progress_cb=cb,
            )

        # Resume
        encrypt_file(
            file_1mb, aes_key, enc_path,
            chunk_size=_1GB,
        )

        assert not os.path.exists(progress_path), (
            ".enc.progress must be deleted after successful encryption"
        )


# ---------------------------------------------------------------------------
# Resume with mismatched parameters
# ---------------------------------------------------------------------------

class TestResumeMismatch:
    """Resume should start fresh if target_file or chunk_size differ."""

    def test_different_chunk_size_starts_fresh(
        self, tmp_work_dir: Path, aes_key: bytes,
    ) -> None:
        """Changing chunk_size between runs should discard old progress."""
        src = create_random_file(tmp_work_dir / "mismatch.bin", SIZE_1MB)
        enc_path = str(tmp_work_dir / "mismatch.enc")
        progress_path = enc_path + ".progress"

        # Create a fake progress file with a different chunk_size
        fake_progress = {
            "target_file": "mismatch.bin",
            "completed_chunks": 1,
            "chunk_size": 2 * 1024**3,  # 2 GB -- differs from 1 GB
            "nonces": ["aa" * 12],
            "tags": ["bb" * 16],
            "chunk_lengths": [1000],
        }
        with open(progress_path, "w", encoding="utf-8") as f:
            json.dump(fake_progress, f)

        dec_dir = str(tmp_work_dir / "dec_mm")
        os.makedirs(dec_dir)

        # Encrypt with 1 GB chunk_size -- should ignore mismatched progress
        result = encrypt_file(src, aes_key, enc_path, chunk_size=_1GB)
        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)

        assert dec_result.hash_verified is True
