"""Fail-closed contract for container plaintext-hash verification.

``encrypt_file`` always records both plaintext hashes in the container
metadata. An .enc whose metadata lacks them was truncated or rewritten,
so verification must fail rather than pass vacuously — otherwise an
attacker disables integrity checking by deleting two JSON fields.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from desktop.crypto.aes_gcm_decrypt import _compare_hashes, decrypt_file
from desktop.crypto.exceptions import TamperDetectedError

PLAINTEXT = b"sealed evidence payload" * 512


def _build_enc(path: Path, aes_key: bytes, *, drop_hashes: bool) -> None:
    """Write a minimal one-segment container, optionally without hashes."""
    nonce = os.urandom(12)
    ct_with_tag = AESGCM(aes_key).encrypt(nonce, PLAINTEXT, None)

    meta: dict[str, Any] = {
        "filename": "evidence.bin",
        "size": len(PLAINTEXT),
        "encryption_algo": "AES-256-GCM",
        "mtime": "2026-01-01T00:00:00+00:00",
        "ctime": "2026-01-01T00:00:00+00:00",
        "atime": "2026-01-01T00:00:00+00:00",
        "enc_ended_time": "2026-01-01T00:00:00+00:00",
        "seal_id": "",
        "nonces": [nonce.hex()],
        "tags": [ct_with_tag[-16:].hex()],
        "chunk_lengths": [len(PLAINTEXT)],
    }
    if not drop_hashes:
        meta["hash_before_sha256"] = hashlib.sha256(PLAINTEXT).hexdigest()
        meta["hash_before_md5"] = hashlib.md5(PLAINTEXT).hexdigest()

    meta_json = json.dumps(meta).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", 8 + len(ct_with_tag)))
        f.write(ct_with_tag)
        f.write(meta_json)
        f.write(struct.pack("<I", len(meta_json)))


class TestCompareHashesFailClosed:
    """_compare_hashes treats an absent expected value as a mismatch."""

    def test_both_present_and_equal_passes(self) -> None:
        assert _compare_hashes("a", "b", "a", "b") == (True, True)

    def test_absent_md5_is_a_mismatch(self) -> None:
        assert _compare_hashes("a", "b", None, "b") == (False, True)

    def test_absent_sha256_is_a_mismatch(self) -> None:
        assert _compare_hashes("a", "b", "a", None) == (True, False)

    def test_both_absent_is_a_mismatch(self) -> None:
        assert _compare_hashes("a", "b", None, None) == (False, False)

    def test_present_but_different_is_a_mismatch(self) -> None:
        assert _compare_hashes("a", "b", "x", "y") == (False, False)


class TestStrippedMetadataIsRejected:
    """End-to-end: deleting the hash fields must not yield plaintext."""

    def test_intact_container_decrypts(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        enc = tmp_path / "intact.enc"
        _build_enc(enc, key, drop_hashes=False)
        out = tmp_path / "out_intact"
        out.mkdir()

        result = decrypt_file(str(enc), key, str(out))

        assert result.hash_verified is True
        assert (out / "evidence.bin").read_bytes() == PLAINTEXT

    def test_container_without_hashes_is_refused(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        enc = tmp_path / "stripped.enc"
        _build_enc(enc, key, drop_hashes=True)
        out = tmp_path / "out_stripped"
        out.mkdir()

        with pytest.raises(TamperDetectedError):
            decrypt_file(str(enc), key, str(out))

        # And no plaintext is left behind at the final path.
        assert not (out / "evidence.bin").exists()
        assert list(out.iterdir()) == []
