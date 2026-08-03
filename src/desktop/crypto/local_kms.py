"""Local KMS: master key envelope encryption/decryption."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import KMSError

_NONCE_SIZE = 12
_KEY_SIZE = 32
_ENV_MASTER_KEY_PATH = "MASTER_KEY_PATH"
_DEFAULT_MASTER_KEY_PATH = Path.home() / ".enc_envelope" / "master.key"


def init_master_key(path: str) -> None:
    """Generate and save a new AES-256 master key.

    Args:
        path: File path where the master key will be stored.

    Raises:
        KMSError: If key generation or file write fails.
    """
    if os.path.exists(path):
        raise KMSError(f"Master key file already exists: {path}")

    try:
        master_key = os.urandom(_KEY_SIZE)
        parent_dir = os.path.dirname(path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(path, "wb") as f:
            f.write(master_key)
    except OSError as exc:
        raise KMSError(f"Failed to write master key: {exc}") from exc


def encrypt_envelope(plaintext: bytes, master_key_path: str) -> bytes:
    """Encrypt plaintext using master key (AES-256-GCM envelope encryption).

    Returns nonce (12 bytes) prepended to ciphertext+tag.

    Args:
        plaintext: Data to encrypt.
        master_key_path: Path to the master key file.

    Returns:
        bytes: nonce(12B) + ciphertext_with_tag

    Raises:
        KMSError: If encryption fails.
    """
    master_key = _load_master_key(master_key_path)

    try:
        nonce = os.urandom(_NONCE_SIZE)
        aesgcm = AESGCM(master_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext_with_tag
    except Exception as exc:
        raise KMSError(f"Envelope encryption failed: {exc}") from exc


def decrypt_envelope(ciphertext: bytes, master_key_path: str) -> bytes:
    """Decrypt envelope-encrypted data using master key.

    Expects nonce (first 12 bytes) + ciphertext_with_tag.

    Args:
        ciphertext: nonce(12B) + encrypted data with auth tag.
        master_key_path: Path to the master key file.

    Returns:
        bytes: Decrypted plaintext.

    Raises:
        KMSError: If decryption fails or data is tampered.
    """
    if len(ciphertext) <= _NONCE_SIZE:
        raise KMSError("Ciphertext too short to contain nonce")

    master_key = _load_master_key(master_key_path)

    nonce = ciphertext[:_NONCE_SIZE]
    encrypted_data = ciphertext[_NONCE_SIZE:]

    try:
        aesgcm = AESGCM(master_key)
        return aesgcm.decrypt(nonce, encrypted_data, None)
    except Exception as exc:
        raise KMSError(f"Envelope decryption failed: {exc}") from exc


def get_master_key_path() -> str:
    """Resolve the active master key path.

    Returns:
        The file path string.

    Raises:
        KMSError: If no configured or default path is available.
    """
    path = os.environ.get(_ENV_MASTER_KEY_PATH)
    if path:
        return path

    if _DEFAULT_MASTER_KEY_PATH.is_file():
        return str(_DEFAULT_MASTER_KEY_PATH)

    raise KMSError(
        "Master key path is unavailable: set MASTER_KEY_PATH or initialize "
        f"the default key at {_DEFAULT_MASTER_KEY_PATH}"
    )


def _load_master_key(path: str) -> bytes:
    """Load master key from file.

    Raises:
        KMSError: If file cannot be read or key size is invalid.
    """
    if not os.path.isfile(path):
        raise KMSError(f"Master key file not found: {path}")

    try:
        with open(path, "rb") as f:
            key = f.read()
    except OSError as exc:
        raise KMSError(f"Failed to read master key: {exc}") from exc

    if len(key) != _KEY_SIZE:
        raise KMSError(
            f"Invalid master key size: expected {_KEY_SIZE} bytes, got {len(key)}"
        )

    return key
