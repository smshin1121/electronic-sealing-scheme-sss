"""Tests for the streaming GCM encryption path.

Validates:
- Streaming ciphertext/tag is byte-identical to one-shot AESGCM
  (.enc format invariance)
- Legacy .enc files written with the one-shot layout still decrypt
- Optional ``metadata`` parameter skips the internal hash pass
- Inline single-pass MD5/SHA-256 hashing matches a direct computation
- Byte-level (8 MiB buffer) progress callbacks and cancellation
- Ciphertext tampering raises TamperDetectedError
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from desktop.crypto import (
    EncryptionError,
    FileMetadata,
    TamperDetectedError,
    decrypt_file,
    encrypt_file,
)
from tests.fixtures.generate_test_files import SIZE_1MB, SIZE_10MB

_1GB = 1 * 1024**3
_8MB = 8 * 1024**2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_enc_parts(enc_path: str) -> tuple[bytes, dict]:
    """Return (encrypted data section, parsed metadata dict) of an .enc."""
    file_size = os.path.getsize(enc_path)
    with open(enc_path, "rb") as f:
        meta_offset = struct.unpack("<Q", f.read(8))[0]
        data = f.read(meta_offset - 8)
        f.seek(file_size - 4)
        meta_size = struct.unpack("<I", f.read(4))[0]
        f.seek(meta_offset)
        meta = json.loads(f.read(meta_size).decode("utf-8"))
    return data, meta


def _hashes_of_file(path: str) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


# ---------------------------------------------------------------------------
# Format invariance: streaming == one-shot AESGCM
# ---------------------------------------------------------------------------

class TestStreamingOneShotEquivalence:
    """Streaming GCM must produce byte-identical output to AESGCM."""

    def test_ciphertext_and_tag_match_one_shot(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "stream.enc")
        encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)

        data, meta = _read_enc_parts(enc_path)
        assert len(meta["nonces"]) == 1

        nonce = bytes.fromhex(meta["nonces"][0])
        plaintext = Path(file_1mb).read_bytes()
        expected = AESGCM(aes_key).encrypt(nonce, plaintext, None)

        # Data section = ciphertext + 16-byte tag, exactly as one-shot
        assert data == expected
        assert data[-16:] == bytes.fromhex(meta["tags"][0])
        assert meta["chunk_lengths"][0] == len(plaintext)

    def test_legacy_one_shot_enc_still_decrypts(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """An .enc written with the old one-shot writer must decrypt."""
        plaintext = Path(file_1mb).read_bytes()
        nonce = os.urandom(12)
        ct_with_tag = AESGCM(aes_key).encrypt(nonce, plaintext, None)

        md5, sha256 = _hashes_of_file(file_1mb)
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        meta_json = json.dumps({
            "filename": "test_1mb.bin",
            "size": len(plaintext),
            "encryption_algo": "AES-256-GCM",
            "mtime": now_iso,
            "ctime": now_iso,
            "atime": now_iso,
            "enc_ended_time": now_iso,
            "seal_id": "",
            "nonces": [nonce.hex()],
            "tags": [ct_with_tag[-16:].hex()],
            "chunk_lengths": [len(plaintext)],
            "hash_before_sha256": sha256,
            "hash_before_md5": md5,
        }).encode("utf-8")

        enc_path = tmp_work_dir / "legacy.enc"
        with open(enc_path, "wb") as f:
            f.write(struct.pack("<Q", 8 + len(ct_with_tag)))
            f.write(ct_with_tag)
            f.write(meta_json)
            f.write(struct.pack("<I", len(meta_json)))

        dec_dir = tmp_work_dir / "legacy_dec"
        dec_dir.mkdir()
        result = decrypt_file(str(enc_path), aes_key, str(dec_dir))

        assert result.hash_verified is True
        assert Path(result.output_filepath).read_bytes() == plaintext


# ---------------------------------------------------------------------------
# metadata parameter / single-pass hashing
# ---------------------------------------------------------------------------

class TestMetadataParameter:
    """encrypt_file(metadata=...) must skip the internal hash pass."""

    def test_provided_metadata_used_verbatim(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        md5, sha256 = _hashes_of_file(file_1mb)
        provided = FileMetadata(
            filename="test_1mb.bin",
            size=SIZE_1MB,
            md5=md5,
            sha256=sha256,
            mtime="2026-01-01T00:00:00+00:00",
            ctime="2026-01-01T00:00:00+00:00",
            atime="2026-01-01T00:00:00+00:00",
        )
        enc_path = str(tmp_work_dir / "with_meta.enc")
        result = encrypt_file(
            file_1mb, aes_key, enc_path, chunk_size=_1GB,
            metadata=provided,
        )

        assert result.metadata is provided
        _, meta = _read_enc_parts(enc_path)
        assert meta["hash_before_md5"] == md5
        assert meta["hash_before_sha256"] == sha256
        # Sentinel timestamps prove the provided metadata was used
        assert meta["mtime"] == "2026-01-01T00:00:00+00:00"

    def test_metadata_skips_collect_metadata(
        self,
        file_1mb: str,
        aes_key: bytes,
        tmp_work_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Neither collect_metadata nor an extra pass may run."""
        from desktop.crypto import aes_gcm_encrypt as enc_mod

        def _boom(_filepath: str) -> None:
            raise AssertionError("collect_metadata must not be called")

        monkeypatch.setattr(enc_mod, "collect_metadata", _boom)

        md5, sha256 = _hashes_of_file(file_1mb)
        provided = FileMetadata(
            filename="test_1mb.bin", size=SIZE_1MB, md5=md5, sha256=sha256,
            mtime="", ctime="", atime="",
        )
        enc_path = str(tmp_work_dir / "no_collect.enc")
        encrypt_file(
            file_1mb, aes_key, enc_path, chunk_size=_1GB, metadata=provided,
        )

    def test_inline_hashes_match_direct_computation(
        self, file_10mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """Without metadata, the single-pass inline hashes must be exact."""
        expected_md5, expected_sha256 = _hashes_of_file(file_10mb)
        enc_path = str(tmp_work_dir / "inline_hash.enc")
        result = encrypt_file(file_10mb, aes_key, enc_path, chunk_size=_1GB)

        assert result.metadata.md5 == expected_md5
        assert result.metadata.sha256 == expected_sha256
        _, meta = _read_enc_parts(enc_path)
        assert meta["hash_before_md5"] == expected_md5
        assert meta["hash_before_sha256"] == expected_sha256


# ---------------------------------------------------------------------------
# Byte-level progress / cancellation
# ---------------------------------------------------------------------------

class TestByteLevelProgress:
    """progress_cb must fire per 8 MiB buffer, not per 64 GB chunk."""

    def test_encrypt_progress_calls_per_buffer(
        self, file_10mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        calls: list[tuple[int, int]] = []
        enc_path = str(tmp_work_dir / "prog.enc")
        encrypt_file(
            file_10mb, aes_key, enc_path, chunk_size=_1GB,
            progress_cb=lambda done, total: calls.append((done, total)),
        )

        # 10 MB with 8 MiB buffers -> at least 2 calls (8 MiB, 10 MB)
        assert len(calls) >= 2
        completed = [c[0] for c in calls]
        assert completed == sorted(completed)
        assert calls[0][0] == _8MB
        assert calls[-1] == (SIZE_10MB, SIZE_10MB)

    def test_decrypt_progress_calls_per_buffer(
        self, file_10mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "prog_dec.enc")
        dec_dir = tmp_work_dir / "prog_dec_out"
        dec_dir.mkdir()
        encrypt_file(file_10mb, aes_key, enc_path, chunk_size=_1GB)

        calls: list[tuple[int, int]] = []
        decrypt_file(
            enc_path, aes_key, str(dec_dir),
            progress_cb=lambda done, total: calls.append((done, total)),
        )

        assert len(calls) >= 2
        completed = [c[0] for c in calls]
        assert completed == sorted(completed)
        assert calls[-1] == (SIZE_10MB, SIZE_10MB)

    def test_encrypt_cancellation_mid_chunk(
        self, file_10mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """Raising from the first (mid-chunk) callback must cancel."""
        enc_path = str(tmp_work_dir / "cancel.enc")

        def _cancel(done: int, total: int) -> None:
            raise RuntimeError("user cancelled")

        with pytest.raises(EncryptionError):
            encrypt_file(
                file_10mb, aes_key, enc_path, chunk_size=_1GB,
                progress_cb=_cancel,
            )

    def test_decrypt_cancellation_cleans_partial_output(
        self, file_10mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        from desktop.crypto import DecryptionError

        enc_path = str(tmp_work_dir / "cancel_dec.enc")
        dec_dir = tmp_work_dir / "cancel_dec_out"
        dec_dir.mkdir()
        encrypt_file(file_10mb, aes_key, enc_path, chunk_size=_1GB)

        def _cancel(done: int, total: int) -> None:
            raise RuntimeError("user cancelled")

        with pytest.raises(DecryptionError):
            decrypt_file(
                enc_path, aes_key, str(dec_dir), progress_cb=_cancel,
            )

        assert not (dec_dir / "test_10mb.bin").exists()


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

class TestTamperDetection:
    """Modified ciphertext must raise TamperDetectedError."""

    def test_flipped_ciphertext_byte_detected(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "tamper.enc")
        dec_dir = tmp_work_dir / "tamper_dec"
        dec_dir.mkdir()
        encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)

        # Flip one byte in the middle of the ciphertext section
        with open(enc_path, "r+b") as f:
            f.seek(8 + 1000)
            original = f.read(1)
            f.seek(8 + 1000)
            f.write(bytes([original[0] ^ 0xFF]))

        with pytest.raises(TamperDetectedError):
            decrypt_file(enc_path, aes_key, str(dec_dir))

        assert not (dec_dir / "test_1mb.bin").exists()


# ---------------------------------------------------------------------------
# Empty file edge case
# ---------------------------------------------------------------------------

class TestEmptyFile:
    """Zero-byte files must round-trip through the streaming path."""

    def test_empty_file_roundtrip(
        self, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        src = tmp_work_dir / "empty.bin"
        src.write_bytes(b"")
        enc_path = str(tmp_work_dir / "empty.enc")
        dec_dir = tmp_work_dir / "empty_dec"
        dec_dir.mkdir()

        result = encrypt_file(str(src), aes_key, enc_path, chunk_size=_1GB)
        assert result.chunk_count == 1

        dec_result = decrypt_file(enc_path, aes_key, str(dec_dir))
        assert dec_result.hash_verified is True
        assert (dec_dir / "empty.bin").read_bytes() == b""
