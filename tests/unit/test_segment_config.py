"""Tests for segment (chunk) size configuration.

Validates:
- Default chunk_size is 1 GiB (fastest at the largest measured input and
  the finest resume granularity; see the segment-size sweep in the paper)
- Maximum chunk_size is 64 GiB - 16 MiB (GCM plaintext limit margin)
- Minimum chunk_size (1 GiB) works correctly
- Sub-minimum chunk_size raises EncryptionError
- Super-maximum chunk_size raises EncryptionError
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

from desktop.crypto import EncryptionError, encrypt_file
from desktop.crypto.aes_gcm_encrypt import (
    _DEFAULT_CHUNK_SIZE,
    _MAX_CHUNK_SIZE,
    _MIN_CHUNK_SIZE,
)
from tests.fixtures.generate_test_files import SIZE_1MB, create_random_file

_1GB = 1 * 1024**3
_64GB = 64 * 1024**3
_16MB = 16 * 1024**2
# GCM authenticates at most 2^39 - 256 bits (64 GiB - 32 B) of plaintext
# per (key, nonce); the max chunk keeps a 16 MiB margin below that.
_GCM_PLAINTEXT_LIMIT = _64GB - 32
_EXPECTED_MAX = _64GB - _16MB


# ---------------------------------------------------------------------------
# Default value verification
# ---------------------------------------------------------------------------

class TestDefaultChunkSize:
    """The default chunk_size must be 1 GiB.

    The manuscript recommends 1 GiB as the default segment size (fastest
    at the largest measured input, finest resume granularity), so the
    implementation default must match that recommendation.
    """

    def test_default_constant_is_1gb(self) -> None:
        assert _DEFAULT_CHUNK_SIZE == _1GB

    def test_default_below_gcm_plaintext_limit(self) -> None:
        assert _DEFAULT_CHUNK_SIZE < _GCM_PLAINTEXT_LIMIT

    def test_function_signature_default(self) -> None:
        sig = inspect.signature(encrypt_file)
        default = sig.parameters["chunk_size"].default
        assert default == _1GB

    def test_gui_wizard_defaults_match(self) -> None:
        """The wizards must offer the same default the paper reports."""
        from desktop.gui.seal_wizard import DEFAULT_CHUNK_GB as SEAL_DEFAULT
        from desktop.gui.reseal_wizard import (
            DEFAULT_CHUNK_GB as RESEAL_DEFAULT,
        )

        assert SEAL_DEFAULT == 1
        assert RESEAL_DEFAULT == 1

    def test_min_constant_is_1gb(self) -> None:
        assert _MIN_CHUNK_SIZE == _1GB

    def test_max_constant_is_64gb_minus_margin(self) -> None:
        assert _MAX_CHUNK_SIZE == _EXPECTED_MAX
        assert _MAX_CHUNK_SIZE < _GCM_PLAINTEXT_LIMIT


# ---------------------------------------------------------------------------
# Minimum chunk_size (1 GB)
# ---------------------------------------------------------------------------

class TestMinChunkSize:
    """Encryption with chunk_size = 1 GB on a small file."""

    def test_encrypt_with_1gb_chunk(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "min_chunk.enc")
        result = encrypt_file(
            file_1mb, aes_key, enc_path, chunk_size=_1GB,
        )
        assert result.chunk_count == 1
        assert os.path.isfile(enc_path)


# ---------------------------------------------------------------------------
# Below minimum -> error
# ---------------------------------------------------------------------------

class TestBelowMinChunkSize:
    """chunk_size below 1 GB must be rejected."""

    def test_512mb_raises_error(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "too_small.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=512 * 1024**2,  # 512 MB
            )

    def test_1mb_raises_error(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "1mb_chunk.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=1 * 1024**2,  # 1 MB
            )

    def test_zero_raises_error(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "zero_chunk.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=0,
            )

    def test_negative_raises_error(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "neg_chunk.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=-1,
            )


# ---------------------------------------------------------------------------
# Above maximum -> error
# ---------------------------------------------------------------------------

class TestAboveMaxChunkSize:
    """chunk_size above 64 GiB - 16 MiB must be rejected."""

    def test_full_64gb_raises_error(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """A full 64 GiB chunk exceeds the GCM plaintext limit."""
        enc_path = str(tmp_work_dir / "full_64gb.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=64 * 1024**3,
            )

    def test_65gb_raises_error(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "too_large.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=65 * 1024**3,
            )

    def test_128gb_raises_error(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "128gb_chunk.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(
                file_1mb, aes_key, enc_path,
                chunk_size=128 * 1024**3,
            )


# ---------------------------------------------------------------------------
# Invalid key size
# ---------------------------------------------------------------------------

class TestInvalidKeySize:
    """AES key must be exactly 32 bytes."""

    def test_16byte_key_raises(
        self, file_1mb: str, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "bad_key.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(file_1mb, os.urandom(16), enc_path)

    def test_empty_key_raises(
        self, file_1mb: str, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "empty_key.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(file_1mb, b"", enc_path)

    def test_64byte_key_raises(
        self, file_1mb: str, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "long_key.enc")
        with pytest.raises(EncryptionError):
            encrypt_file(file_1mb, os.urandom(64), enc_path)
