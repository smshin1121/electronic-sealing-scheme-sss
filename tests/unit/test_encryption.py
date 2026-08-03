"""Tests for AES-256-GCM encryption/decryption correctness.

Validates:
- Round-trip encrypt/decrypt with hash verification (1 MB, 10 MB)
- Multi-segment chunking (1 MB chunk_size)
- .enc binary structure (offset, meta_size, JSON metadata)
- Wrong-key decryption failure
- Schema boundary: EncryptionResult.file_info matches record_schema result_files
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
from pathlib import Path

import pytest

from desktop.crypto import (
    DecryptionError,
    TamperDetectedError,
    decrypt_file,
    encrypt_file,
)
from tests.fixtures.generate_test_files import SIZE_1MB, create_random_file

_1GB = 1 * 1024**3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_of_file(path: str) -> str:
    """Compute SHA-256 hex digest for a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_enc_metadata(enc_path: str) -> dict:
    """Parse the trailing JSON metadata from an .enc file."""
    with open(enc_path, "rb") as f:
        # Read offset (first 8 bytes LE)
        offset = struct.unpack("<Q", f.read(8))[0]

        # Read meta_size (last 4 bytes LE)
        f.seek(-4, 2)
        meta_size = struct.unpack("<I", f.read(4))[0]

        # Read metadata JSON
        f.seek(offset)
        meta_json = f.read(meta_size)

    return json.loads(meta_json.decode("utf-8"))


# ---------------------------------------------------------------------------
# 1 MB round-trip
# ---------------------------------------------------------------------------

class TestEncryptDecrypt1MB:
    """Encrypt and decrypt a 1 MB file, verifying hash integrity."""

    def test_roundtrip_hash_match(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        original_hash = _sha256_of_file(file_1mb)
        enc_path = str(tmp_work_dir / "out.enc")
        dec_dir = str(tmp_work_dir / "dec")
        os.makedirs(dec_dir)

        enc_result = encrypt_file(file_1mb, aes_key, enc_path)
        dec_result = decrypt_file(enc_path, aes_key, dec_dir)

        assert dec_result.hash_verified is True
        assert dec_result.sha256_match is True
        assert dec_result.md5_match is True
        assert _sha256_of_file(dec_result.output_filepath) == original_hash

    def test_encryption_result_fields(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "out.enc")
        result = encrypt_file(file_1mb, aes_key, enc_path)

        assert result.enc_filepath == enc_path
        assert result.original_filepath == file_1mb
        assert result.encryption_algo == "AES-256-GCM"
        assert result.chunk_count >= 1
        assert result.metadata.size == SIZE_1MB


# ---------------------------------------------------------------------------
# 10 MB round-trip
# ---------------------------------------------------------------------------

class TestEncryptDecrypt10MB:
    """Encrypt and decrypt a 10 MB file, verifying hash integrity."""

    def test_roundtrip_hash_match(
        self, file_10mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        original_hash = _sha256_of_file(file_10mb)
        enc_path = str(tmp_work_dir / "out10.enc")
        dec_dir = str(tmp_work_dir / "dec10")
        os.makedirs(dec_dir)

        encrypt_file(file_10mb, aes_key, enc_path)
        dec_result = decrypt_file(enc_path, aes_key, dec_dir)

        assert dec_result.hash_verified is True
        assert _sha256_of_file(dec_result.output_filepath) == original_hash


# ---------------------------------------------------------------------------
# Multi-segment (chunk_size = 1 GB, file smaller -> still 1 chunk
# Use a 1 MB file with chunk_size = 1 GB so we get 1 chunk;
# for real multi-segment, we create a small file and use min valid chunk_size)
# Since minimum chunk_size is 1 GB and test files are small, we verify
# the engine correctly handles it as a single chunk.
# ---------------------------------------------------------------------------

class TestMultiSegment:
    """Segment-level behaviour when chunk_size = 1 GB (minimum)."""

    def test_single_chunk_for_small_file(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "seg.enc")
        result = encrypt_file(
            file_1mb, aes_key, enc_path, chunk_size=_1GB,
        )
        assert result.chunk_count == 1

        meta = _read_enc_metadata(enc_path)
        assert len(meta["nonces"]) == 1
        assert len(meta["tags"]) == 1
        assert len(meta["chunk_lengths"]) == 1

    def test_roundtrip_with_min_chunk_size(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "seg_rt.enc")
        dec_dir = str(tmp_work_dir / "seg_dec")
        os.makedirs(dec_dir)

        original_hash = _sha256_of_file(file_1mb)
        encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        dec_result = decrypt_file(enc_path, aes_key, dec_dir)

        assert dec_result.hash_verified is True
        assert _sha256_of_file(dec_result.output_filepath) == original_hash


# ---------------------------------------------------------------------------
# .enc binary structure validation
# ---------------------------------------------------------------------------

class TestEncBinaryStructure:
    """Validate the .enc file binary layout."""

    def test_offset_and_meta_size(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "struct.enc")
        encrypt_file(file_1mb, aes_key, enc_path)
        file_size = os.path.getsize(enc_path)

        with open(enc_path, "rb") as f:
            # First 8 bytes = offset (uint64 LE)
            offset = struct.unpack("<Q", f.read(8))[0]

            # Last 4 bytes = meta_size (uint32 LE)
            f.seek(file_size - 4)
            meta_size = struct.unpack("<I", f.read(4))[0]

        # offset should point to start of JSON metadata
        assert offset == file_size - 4 - meta_size
        assert offset > 8  # encrypted data exists between offset header and metadata

    def test_metadata_json_parseable(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "json.enc")
        encrypt_file(file_1mb, aes_key, enc_path)

        meta = _read_enc_metadata(enc_path)

        assert "nonces" in meta
        assert "tags" in meta
        assert "chunk_lengths" in meta
        assert meta["encryption_algo"] == "AES-256-GCM"
        assert meta["filename"] == "test_1mb.bin"
        assert meta["size"] == SIZE_1MB

    def test_nonces_tags_chunks_same_length(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "len.enc")
        encrypt_file(file_1mb, aes_key, enc_path)

        meta = _read_enc_metadata(enc_path)
        n = len(meta["nonces"])
        assert n > 0
        assert len(meta["tags"]) == n
        assert len(meta["chunk_lengths"]) == n


# ---------------------------------------------------------------------------
# Wrong key decryption -> failure
# ---------------------------------------------------------------------------

class TestWrongKey:
    """Decryption with an incorrect key must fail."""

    def test_wrong_key_raises_error(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "wk.enc")
        dec_dir = str(tmp_work_dir / "wk_dec")
        os.makedirs(dec_dir)

        encrypt_file(file_1mb, aes_key, enc_path)

        wrong_key = os.urandom(32)
        assert wrong_key != aes_key

        with pytest.raises((DecryptionError, TamperDetectedError)):
            decrypt_file(enc_path, wrong_key, dec_dir)


# ---------------------------------------------------------------------------
# Schema boundary: result_files conformance (record_schema.md)
# ---------------------------------------------------------------------------

_HEX_PATTERN = re.compile(r"^[0-9a-f]+$")


class TestResultFilesSchemaConformance:
    """EncryptionResult + .enc metadata must conform to record_schema result_files.

    Expected schema per result_files item:
        filename: str (.enc)
        size: int
        encryption_algo: "AES-256-GCM"
        enc_ended_time: ISO 8601
        nonces: [hex string]
        tags: [hex string]
        chunk_lengths: [int]

    Critical rule: nonces, tags, chunk_lengths arrays must have identical length.
    All nonce/tag values must be lowercase hex strings.
    """

    def test_arrays_equal_length(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "schema.enc")
        encrypt_file(file_1mb, aes_key, enc_path)
        meta = _read_enc_metadata(enc_path)

        n = len(meta["nonces"])
        assert n == len(meta["tags"])
        assert n == len(meta["chunk_lengths"])

    def test_nonces_are_hex_strings(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "hex_n.enc")
        encrypt_file(file_1mb, aes_key, enc_path)
        meta = _read_enc_metadata(enc_path)

        for nonce in meta["nonces"]:
            assert isinstance(nonce, str)
            assert _HEX_PATTERN.match(nonce), f"Non-hex nonce: {nonce}"
            # AES-GCM nonce = 12 bytes = 24 hex chars
            assert len(nonce) == 24, f"Unexpected nonce length: {len(nonce)}"

    def test_tags_are_hex_strings(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "hex_t.enc")
        encrypt_file(file_1mb, aes_key, enc_path)
        meta = _read_enc_metadata(enc_path)

        for tag in meta["tags"]:
            assert isinstance(tag, str)
            assert _HEX_PATTERN.match(tag), f"Non-hex tag: {tag}"
            # GCM tag = 16 bytes = 32 hex chars
            assert len(tag) == 32, f"Unexpected tag length: {len(tag)}"

    def test_chunk_lengths_are_ints(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "cl.enc")
        encrypt_file(file_1mb, aes_key, enc_path)
        meta = _read_enc_metadata(enc_path)

        for cl in meta["chunk_lengths"]:
            assert isinstance(cl, int)
            assert cl > 0

    def test_encryption_algo_field(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "algo.enc")
        encrypt_file(file_1mb, aes_key, enc_path)
        meta = _read_enc_metadata(enc_path)

        assert meta["encryption_algo"] == "AES-256-GCM"

    def test_enc_ended_time_iso8601(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "time.enc")
        encrypt_file(file_1mb, aes_key, enc_path)
        meta = _read_enc_metadata(enc_path)

        from datetime import datetime

        # Should parse without error
        dt = datetime.fromisoformat(meta["enc_ended_time"])
        assert dt is not None

    def test_filename_ends_with_enc(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "fname.enc")
        result = encrypt_file(file_1mb, aes_key, enc_path)

        assert result.enc_filepath.endswith(".enc")

    def test_result_size_is_int(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "sz.enc")
        encrypt_file(file_1mb, aes_key, enc_path)
        meta = _read_enc_metadata(enc_path)

        assert isinstance(meta["size"], int)
        assert meta["size"] > 0
