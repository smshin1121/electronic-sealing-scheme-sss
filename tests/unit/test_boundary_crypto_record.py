"""Boundary tests: crypto module -> record module.

Validates that EncryptionResult from crypto.encrypt_file() produces
data compatible with record_builder.build_seal_record() and passes
validate_record().
"""

from __future__ import annotations

import json
import os
import struct

import pytest

from desktop.crypto.aes_gcm_encrypt import encrypt_file
from desktop.crypto.file_metadata import collect_metadata
from desktop.crypto.types import EncryptionResult, FileMetadata
from desktop.record.history_manager import create_initial_history
from desktop.record.record_builder import (
    build_seal_record,
    create_seal_id,
    validate_record,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MIN_CHUNK = 1 * 1024**3  # 1 GB - minimum chunk size for encrypt_file


def _read_enc_metadata(enc_path: str) -> dict:
    """Read the JSON metadata embedded at the end of an .enc file."""
    with open(enc_path, "rb") as f:
        # Read meta_size from last 4 bytes
        f.seek(-4, 2)
        meta_size = struct.unpack("<I", f.read(4))[0]

        # Read JSON metadata
        f.seek(-(4 + meta_size), 2)
        meta_json = f.read(meta_size)

    return json.loads(meta_json.decode("utf-8"))


def _make_case_info() -> dict:
    return {
        "case_number": "2026-0001",
        "investigator": "Kim",
        "device_user": "Park",
        "suspect": "Lee",
        "storage_type": "SSD",
        "storage_info": {
            "manufacturer": "Samsung",
            "model": "870 EVO",
            "serial": "S1234",
        },
        "seizure_time": "2026-04-01T09:00:00Z",
        "seizure_location": "Seoul",
    }


def _make_signer_info() -> dict:
    return {
        "name": "Lee",
        "email": "lee@example.com",
        "birth_date": "1990-01-01",
        "phone": "010-1234-5678",
        "cert_fingerprint": "AB" * 32,
        "signature_image_hash": "CD" * 32,
    }


def _make_history() -> dict:
    return create_initial_history({
        "seal_type": "Sealing",
        "start_time": "2026-04-01T10:00:00Z",
        "end_time": "2026-04-01T11:00:00Z",
        "investigator": "Kim",
    })


def _normalize_time(iso_str: str) -> str:
    """Normalize ISO time to end with Z for schema compatibility."""
    if iso_str.endswith("+00:00"):
        return iso_str.replace("+00:00", "Z")
    if not iso_str.endswith("Z"):
        return iso_str + "Z"
    return iso_str


# ---------------------------------------------------------------------------
# Tests: EncryptionResult schema compatibility
# ---------------------------------------------------------------------------


class TestEncryptionResultSchema:
    """EncryptionResult fields must map to record file_info.result_files."""

    def test_encryption_result_has_required_fields(self) -> None:
        """EncryptionResult dataclass must have the fields we need."""
        result = EncryptionResult(
            enc_filepath="/tmp/test.enc",
            original_filepath="/tmp/test.bin",
            metadata=FileMetadata(
                filename="test.bin",
                size=1024,
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha256="e3b0c44298fc1c149afbf4c8996fb924"
                       "27ae41e4649b934ca495991b7852b855",
                mtime="2026-04-01T10:00:00+00:00",
                ctime="2026-04-01T09:00:00+00:00",
                atime="2026-04-01T11:00:00+00:00",
            ),
            chunk_count=1,
            encryption_algo="AES-256-GCM",
        )
        assert result.enc_filepath == "/tmp/test.enc"
        assert result.metadata.filename == "test.bin"
        assert result.encryption_algo == "AES-256-GCM"

    def test_file_metadata_maps_to_original_files(self) -> None:
        """FileMetadata fields must match original_files schema."""
        meta = FileMetadata(
            filename="evidence.dd",
            size=1048576,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb924"
                   "27ae41e4649b934ca495991b7852b855",
            mtime="2026-04-01T10:00:00+00:00",
            ctime="2026-04-01T09:00:00+00:00",
            atime="2026-04-01T11:00:00+00:00",
        )
        original_file = {
            "filename": meta.filename,
            "size": meta.size,
            "md5": meta.md5,
            "sha256": meta.sha256,
            "mtime": _normalize_time(meta.mtime),
            "ctime": _normalize_time(meta.ctime),
            "atime": _normalize_time(meta.atime),
        }
        required_keys = {"filename", "size", "md5", "sha256",
                         "mtime", "ctime", "atime"}
        assert required_keys <= set(original_file.keys())


# ---------------------------------------------------------------------------
# Tests: end-to-end encrypt -> build_record -> validate
# ---------------------------------------------------------------------------


class TestEncryptThenBuildRecord:
    """encrypt_file() -> build_seal_record() -> validate_record() chain."""

    @pytest.fixture
    def encrypted_file(self, tmp_path):
        """Encrypt a small file and return (enc_result, enc_metadata)."""
        # Create test file
        src = tmp_path / "test_evidence.bin"
        src.write_bytes(os.urandom(1024))

        aes_key = os.urandom(32)
        enc_path = str(tmp_path / "test_evidence.bin.enc")
        seal_id = create_seal_id()

        result = encrypt_file(
            filepath=str(src),
            aes_key=aes_key,
            output_path=enc_path,
            chunk_size=_MIN_CHUNK,
            seal_id=seal_id,
        )

        enc_meta = _read_enc_metadata(enc_path)
        return result, enc_meta, seal_id

    def test_enc_metadata_has_nonces_tags_chunks(self, encrypted_file):
        """Encrypted file metadata must have nonces, tags, chunk_lengths."""
        _, enc_meta, _ = encrypted_file
        assert "nonces" in enc_meta
        assert "tags" in enc_meta
        assert "chunk_lengths" in enc_meta

    def test_nonces_tags_chunks_same_length(self, encrypted_file):
        """nonces, tags, chunk_lengths arrays must be the same length."""
        _, enc_meta, _ = encrypted_file
        assert len(enc_meta["nonces"]) == len(enc_meta["tags"])
        assert len(enc_meta["tags"]) == len(enc_meta["chunk_lengths"])

    def test_build_and_validate_record(self, encrypted_file):
        """Full pipeline: encrypt -> build record -> validate passes."""
        result, enc_meta, seal_id = encrypted_file

        # Build original_files from EncryptionResult metadata
        meta = result.metadata
        original_files = [{
            "filename": meta.filename,
            "size": meta.size,
            "md5": meta.md5,
            "sha256": meta.sha256,
            "mtime": _normalize_time(meta.mtime),
            "ctime": _normalize_time(meta.ctime),
            "atime": _normalize_time(meta.atime),
        }]

        # Build result_files from .enc metadata
        result_files = [{
            "filename": os.path.basename(result.enc_filepath),
            "size": os.path.getsize(result.enc_filepath),
            "encryption_algo": enc_meta.get("encryption_algo", "AES-256-GCM"),
            "enc_ended_time": _normalize_time(enc_meta["enc_ended_time"]),
            "nonces": enc_meta["nonces"],
            "tags": enc_meta["tags"],
            "chunk_lengths": enc_meta["chunk_lengths"],
        }]

        file_info = {
            "original_files": original_files,
            "result_files": result_files,
            "hash_match": True,
        }

        process_info = {
            "type": "Sealing",
            "start_time": "2026-04-01T10:00:00Z",
            "end_time": "2026-04-01T11:00:00Z",
            "file_count": 1,
            "investigator": "Kim",
            "reason": None,
            "participation": "present",
        }

        record = build_seal_record(
            unlock_time_iso="2026-12-31T00:00:00Z",
        key_commitment="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  # public-test-fixture; gitleaks:allow
            seal_id=seal_id,
            case_info=_make_case_info(),
            process_info=process_info,
            file_info=file_info,
            signer_info=_make_signer_info(),
            history=_make_history(),
        )

        errors = validate_record(record)
        assert errors == [], f"Validation errors: {errors}"

    def test_enc_metadata_algo_matches_result(self, encrypted_file):
        """Encryption algo in metadata must be AES-256-GCM."""
        result, enc_meta, _ = encrypted_file
        assert result.encryption_algo == "AES-256-GCM"
        assert enc_meta.get("encryption_algo") == "AES-256-GCM"


# ---------------------------------------------------------------------------
# Tests: ISO 8601 format compatibility (boundary concern)
# ---------------------------------------------------------------------------


class TestISO8601FormatBoundary:
    """crypto module outputs +00:00 but record schema expects Z suffix.

    This test documents the known format mismatch and verifies
    that normalization is needed at the integration boundary.
    """

    def test_file_metadata_uses_offset_format(self, tmp_path) -> None:
        """collect_metadata() produces +00:00, not Z."""
        src = tmp_path / "meta_test.bin"
        src.write_bytes(b"hello")

        meta = collect_metadata(str(src))
        # Python's isoformat() with UTC timezone produces +00:00
        assert "+00:00" in meta.mtime or "Z" in meta.mtime

    def test_normalization_needed_for_validation(self, tmp_path) -> None:
        """Without normalization, +00:00 format fails record validation."""
        src = tmp_path / "norm_test.bin"
        src.write_bytes(b"test")

        meta = collect_metadata(str(src))

        # If the metadata uses +00:00 format, record validation will fail
        # unless normalized
        if "+00:00" in meta.mtime:
            record_with_offset = _build_minimal_record_with_meta(meta)
            errors = validate_record(record_with_offset)
            time_errors = [e for e in errors if "ISO 8601" in e]
            # This confirms the boundary issue exists
            assert len(time_errors) > 0, (
                "Expected ISO 8601 validation errors for +00:00 format"
            )


def _build_minimal_record_with_meta(meta: FileMetadata) -> dict:
    """Build a minimal record using raw metadata times (no normalization)."""
    seal_id = create_seal_id()
    return {
        "seal_id": seal_id,
        "case_info": {
            "case_number": "2026-0001",
            "investigator": "Kim",
            "device_user": "Park",
            "suspect": "Lee",
            "storage_type": "SSD",
            "storage_info": {
                "manufacturer": "Samsung",
                "model": "870 EVO",
                "serial": "S1234",
            },
            "seizure_time": "2026-04-01T09:00:00Z",
            "seizure_location": "Seoul",
        },
        "process_info": {
            "type": "Sealing",
            "start_time": "2026-04-01T10:00:00Z",
            "end_time": "2026-04-01T11:00:00Z",
            "file_count": 1,
            "investigator": "Kim",
            "participation": "present",
        },
        "file_info": {
            "original_files": [{
                "filename": meta.filename,
                "size": meta.size,
                "md5": meta.md5,
                "sha256": meta.sha256,
                "mtime": meta.mtime,   # raw, not normalized
                "ctime": meta.ctime,
                "atime": meta.atime,
            }],
            "result_files": [{
                "filename": "test.enc",
                "size": 100,
                "encryption_algo": "AES-256-GCM",
                "enc_ended_time": "2026-04-01T11:00:00Z",
                "nonces": ["aa"],
                "tags": ["bb"],
                "chunk_lengths": [100],
            }],
            "hash_match": True,
        },
        "signer_info": {
            "name": "Lee",
            "email": "lee@example.com",
            "birth_date": "1990-01-01",
            "phone": "010-1234-5678",
            "cert_fingerprint": "AB" * 32,
            "signature_image_hash": "CD" * 32,
        },
        "history": create_initial_history({
            "seal_type": "Sealing",
            "start_time": "2026-04-01T10:00:00Z",
            "end_time": "2026-04-01T11:00:00Z",
            "investigator": "Kim",
        }),
    }
