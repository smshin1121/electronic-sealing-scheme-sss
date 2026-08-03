"""Tests for local KMS envelope encryption/decryption.

Validates:
- Master key generation, envelope encrypt, then decrypt -> original match
- Different master key -> decryption failure
- Missing master key file -> error
- Master key file already exists -> error on re-init
- Environment variable helper
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from desktop.crypto import (
    KMSError,
    decrypt_envelope,
    encrypt_envelope,
    get_master_key_path,
    init_master_key,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key_path(tmp_path: Path) -> str:
    """Create a master key file and return its path."""
    path = str(tmp_path / "master.key")
    init_master_key(path)
    return path


@pytest.fixture
def second_master_key_path(tmp_path: Path) -> str:
    """Create a second, distinct master key file."""
    path = str(tmp_path / "master2.key")
    init_master_key(path)
    return path


# ---------------------------------------------------------------------------
# Happy path: generate -> encrypt -> decrypt
# ---------------------------------------------------------------------------

class TestEnvelopeRoundTrip:
    """Envelope encryption then decryption must return original plaintext."""

    def test_roundtrip_small_payload(self, master_key_path: str) -> None:
        plaintext = b"digital-evidence-aes-key-material"
        ciphertext = encrypt_envelope(plaintext, master_key_path)

        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)  # nonce + tag overhead

        recovered = decrypt_envelope(ciphertext, master_key_path)
        assert recovered == plaintext

    def test_roundtrip_empty_payload(self, master_key_path: str) -> None:
        plaintext = b""
        ciphertext = encrypt_envelope(plaintext, master_key_path)
        recovered = decrypt_envelope(ciphertext, master_key_path)
        assert recovered == plaintext

    def test_roundtrip_large_payload(self, master_key_path: str) -> None:
        plaintext = os.urandom(10_000)
        ciphertext = encrypt_envelope(plaintext, master_key_path)
        recovered = decrypt_envelope(ciphertext, master_key_path)
        assert recovered == plaintext

    def test_ciphertext_differs_each_call(self, master_key_path: str) -> None:
        """Nonce randomness means repeated encryptions differ."""
        plaintext = b"same-input"
        ct1 = encrypt_envelope(plaintext, master_key_path)
        ct2 = encrypt_envelope(plaintext, master_key_path)
        assert ct1 != ct2


# ---------------------------------------------------------------------------
# Wrong master key -> failure
# ---------------------------------------------------------------------------

class TestWrongMasterKey:
    """Decryption with a different master key must fail."""

    def test_different_key_raises(
        self, master_key_path: str, second_master_key_path: str
    ) -> None:
        plaintext = b"secret-data"
        ciphertext = encrypt_envelope(plaintext, master_key_path)

        with pytest.raises(KMSError):
            decrypt_envelope(ciphertext, second_master_key_path)


# ---------------------------------------------------------------------------
# Missing master key file -> error
# ---------------------------------------------------------------------------

class TestMissingMasterKey:
    """Operations with a non-existent master key file must fail."""

    def test_encrypt_missing_key_raises(self, tmp_path: Path) -> None:
        fake_path = str(tmp_path / "nonexistent.key")
        with pytest.raises(KMSError):
            encrypt_envelope(b"data", fake_path)

    def test_decrypt_missing_key_raises(self, tmp_path: Path) -> None:
        fake_path = str(tmp_path / "nonexistent.key")
        # ciphertext must be > 12 bytes to pass length check
        with pytest.raises(KMSError):
            decrypt_envelope(b"x" * 32, fake_path)


# ---------------------------------------------------------------------------
# init_master_key validation
# ---------------------------------------------------------------------------

class TestInitMasterKey:
    """Master key initialization constraints."""

    def test_creates_32byte_file(self, tmp_path: Path) -> None:
        path = str(tmp_path / "new.key")
        init_master_key(path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) == 32

    def test_double_init_raises(self, master_key_path: str) -> None:
        """Re-initializing an existing key file must fail."""
        with pytest.raises(KMSError):
            init_master_key(master_key_path)

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        path = str(tmp_path / "deep" / "nested" / "dir" / "master.key")
        init_master_key(path)
        assert os.path.isfile(path)


# ---------------------------------------------------------------------------
# Ciphertext too short
# ---------------------------------------------------------------------------

class TestCiphertextTooShort:
    """Ciphertext shorter than nonce (12 bytes) must be rejected."""

    def test_empty_ciphertext_raises(self, master_key_path: str) -> None:
        with pytest.raises(KMSError):
            decrypt_envelope(b"", master_key_path)

    def test_11byte_ciphertext_raises(self, master_key_path: str) -> None:
        with pytest.raises(KMSError):
            decrypt_envelope(b"x" * 11, master_key_path)

    def test_12byte_ciphertext_raises(self, master_key_path: str) -> None:
        """Exactly 12 bytes = nonce only, no data -> should fail."""
        with pytest.raises(KMSError):
            decrypt_envelope(b"x" * 12, master_key_path)


# ---------------------------------------------------------------------------
# get_master_key_path environment variable
# ---------------------------------------------------------------------------

class TestGetMasterKeyPath:
    """get_master_key_path prefers env var and falls back to default path."""

    def test_env_var_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MASTER_KEY_PATH", "/some/path/master.key")
        assert get_master_key_path() == "/some/path/master.key"

    def test_env_var_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MASTER_KEY_PATH", raising=False)
        monkeypatch.setattr(
            "desktop.crypto.local_kms._DEFAULT_MASTER_KEY_PATH",
            Path("/nonexistent/master.key"),
        )
        with pytest.raises(KMSError):
            get_master_key_path()

    def test_env_var_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MASTER_KEY_PATH", "")
        monkeypatch.setattr(
            "desktop.crypto.local_kms._DEFAULT_MASTER_KEY_PATH",
            Path("/nonexistent/master.key"),
        )
        with pytest.raises(KMSError):
            get_master_key_path()

    def test_default_path_used_when_present(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("MASTER_KEY_PATH", raising=False)
        monkeypatch.setattr(
            "desktop.crypto.local_kms._DEFAULT_MASTER_KEY_PATH",
            tmp_path / "master.key",
        )
        init_master_key(str(tmp_path / "master.key"))
        assert get_master_key_path() == str(tmp_path / "master.key")
