"""Regression tests for resume safety guards in AES-GCM encryption.

Covers the resume-safety regression cases:
1. Key fingerprint guard — resuming with a *different* AES key must
   discard the old progress + partial .enc and restart fresh, instead
   of appending mixed-key chunks (which would be permanently
   undecryptable).
2. Legacy progress files without a fingerprint are discarded.
3. Orphaned/stale progress files (missing or truncated .enc output)
   refuse resume and restart fresh.
4. Session key reuse in ResealProcess.run_r5_encrypt — retries within
   the same session must reuse the same AES key.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from desktop.crypto import EncryptionError, decrypt_file, encrypt_file
from desktop.crypto.aes_gcm_encrypt import _key_fingerprint

_1GB = 1 * 1024**3


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


def _interrupt(file_path: str, key: bytes, enc_path: str) -> None:
    """Encrypt with an interrupt so a .enc.progress file is left behind."""
    with pytest.raises(EncryptionError):
        encrypt_file(
            file_path, key, enc_path,
            chunk_size=_1GB,
            progress_cb=_InterruptAfterN(interrupt_after=1),
        )


# ---------------------------------------------------------------------------
# Fix 1a: key fingerprint guard
# ---------------------------------------------------------------------------

class TestKeyFingerprintGuard:
    def test_progress_file_contains_key_fingerprint(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "fp.enc")
        _interrupt(file_1mb, aes_key, enc_path)

        with open(enc_path + ".progress", "r", encoding="utf-8") as f:
            progress = json.load(f)

        assert progress["key_fingerprint"] == _key_fingerprint(aes_key)
        # The fingerprint must never be the key itself.
        assert progress["key_fingerprint"] != aes_key.hex()
        assert aes_key.hex() not in json.dumps(progress)

    def test_key_change_restarts_fresh_and_decrypts(
        self, file_1mb: str, tmp_work_dir: Path
    ) -> None:
        """Interrupt with key A, retry with key B → fresh restart, and
        the final .enc must fully decrypt with key B (no mixed chunks)."""
        original_hash = _sha256_of_file(file_1mb)
        enc_path = str(tmp_work_dir / "keychange.enc")
        dec_dir = str(tmp_work_dir / "dec_keychange")
        os.makedirs(dec_dir)

        key_a = os.urandom(32)
        key_b = os.urandom(32)

        _interrupt(file_1mb, key_a, enc_path)
        assert os.path.isfile(enc_path + ".progress")

        # Retry with a different key — must NOT resume onto key A chunks.
        result = encrypt_file(file_1mb, key_b, enc_path, chunk_size=_1GB)

        dec_result = decrypt_file(result.enc_filepath, key_b, dec_dir)
        assert dec_result.hash_verified is True
        assert _sha256_of_file(dec_result.output_filepath) == original_hash
        assert not os.path.exists(enc_path + ".progress")

    def test_legacy_progress_without_fingerprint_is_discarded(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """A pre-fix progress file (no key_fingerprint) cannot prove the
        key matches — it must be discarded and encryption restarted."""
        enc_path = str(tmp_work_dir / "legacy.enc")
        progress_path = enc_path + ".progress"
        dec_dir = str(tmp_work_dir / "dec_legacy")
        os.makedirs(dec_dir)

        legacy_progress = {
            "target_file": os.path.basename(file_1mb),
            "completed_chunks": 1,
            "chunk_size": _1GB,
            "nonces": ["aa" * 12],
            "tags": ["bb" * 16],
            "chunk_lengths": [1024],
        }
        with open(progress_path, "w", encoding="utf-8") as f:
            json.dump(legacy_progress, f)
        # Fake partial output matching the legacy claim.
        with open(enc_path, "wb") as f:
            f.write(b"\x00" * (8 + 1024 + 16))

        result = encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)
        assert dec_result.hash_verified is True


# ---------------------------------------------------------------------------
# Fix 2: orphaned / truncated output refuses resume
# ---------------------------------------------------------------------------

class TestOrphanedProgressGuard:
    def _write_progress(
        self, progress_path: str, source: str, aes_key: bytes,
        chunk_lengths: list[int],
    ) -> None:
        progress = {
            "target_file": os.path.basename(source),
            "completed_chunks": len(chunk_lengths),
            "chunk_size": _1GB,
            "key_fingerprint": _key_fingerprint(aes_key),
            "nonces": ["aa" * 12] * len(chunk_lengths),
            "tags": ["bb" * 16] * len(chunk_lengths),
            "chunk_lengths": chunk_lengths,
        }
        with open(progress_path, "w", encoding="utf-8") as f:
            json.dump(progress, f)

    def test_progress_without_output_starts_fresh(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """Progress file exists but the .enc does not → refuse resume."""
        enc_path = str(tmp_work_dir / "orphan.enc")
        dec_dir = str(tmp_work_dir / "dec_orphan")
        os.makedirs(dec_dir)

        self._write_progress(
            enc_path + ".progress", file_1mb, aes_key, [1024],
        )
        assert not os.path.exists(enc_path)

        result = encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)
        assert dec_result.hash_verified is True

    def test_progress_with_truncated_output_starts_fresh(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """Partial .enc smaller than the progress claims → refuse resume."""
        enc_path = str(tmp_work_dir / "truncated.enc")
        dec_dir = str(tmp_work_dir / "dec_truncated")
        os.makedirs(dec_dir)

        claimed_len = 512 * 1024
        self._write_progress(
            enc_path + ".progress", file_1mb, aes_key, [claimed_len],
        )
        # Output is far smaller than 8 + claimed_len + 16.
        with open(enc_path, "wb") as f:
            f.write(b"\x00" * 100)

        result = encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)
        assert dec_result.hash_verified is True

    def test_same_key_resume_still_works(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """The guards must not break the legitimate resume path."""
        original_hash = _sha256_of_file(file_1mb)
        enc_path = str(tmp_work_dir / "resume_same.enc")
        dec_dir = str(tmp_work_dir / "dec_same")
        os.makedirs(dec_dir)

        _interrupt(file_1mb, aes_key, enc_path)
        result = encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)

        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)
        assert dec_result.hash_verified is True
        assert _sha256_of_file(dec_result.output_filepath) == original_hash


# ---------------------------------------------------------------------------
# Fix 1b: ResealProcess reuses the session AES key across retries
# ---------------------------------------------------------------------------

class TestResealKeyReuse:
    def test_run_r5_encrypt_reuses_key_on_retry(
        self, file_1mb: str, tmp_work_dir: Path
    ) -> None:
        from desktop.reseal_process import ResealConfig, ResealProcess

        output_dir = tmp_work_dir / "reseal_out"
        output_dir.mkdir()

        process = ResealProcess(db_path=str(tmp_work_dir / "test.db"))
        process.state["r2"] = {
            "target_dir": str(Path(file_1mb).parent),
            "known_files": [{"filepath": file_1mb}],
        }
        process.set_config(ResealConfig(
            source_dir=str(Path(file_1mb).parent),
            output_dir=str(output_dir),
            chunk_size_bytes=_1GB,
            investigator="tester",
            reason="retry-test",
            subject_participated=False,
        ))

        first = process.run_r5_encrypt()
        second = process.run_r5_encrypt()

        assert first["aes_key_hex"] == second["aes_key_hex"]
        # Pending paths are tracked for destroy-time cleanup.
        assert process.state["r5_pending_enc_paths"], (
            "pending enc paths must be recorded for cleanup"
        )
