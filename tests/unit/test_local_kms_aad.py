"""Context-bound envelope encryption for the wrapped s3 share (stage D, D2).

``encrypt_envelope`` / ``decrypt_envelope`` accept an optional keyword-only
``aad`` (the local analogue of a KMS encryption context). The wrapped s3
is bound to its seal and authenticated policy, so a ciphertext moved to
another seal or policy fails to unwrap. Calls without ``aad`` behave
exactly as before.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from desktop.crypto import KMSError, decrypt_envelope, encrypt_envelope
from desktop.crypto.local_kms import init_master_key


@pytest.fixture()
def master_key(tmp_path: Path) -> str:
    path = str(tmp_path / "master.key")
    init_master_key(path)
    return path


class TestEnvelopeAad:
    def test_round_trip_with_aad(self, master_key: str) -> None:
        blob = encrypt_envelope(b"3-abcdef", master_key, aad=b"context-A")
        assert decrypt_envelope(blob, master_key, aad=b"context-A") == b"3-abcdef"

    def test_wrong_aad_fails(self, master_key: str) -> None:
        blob = encrypt_envelope(b"3-abcdef", master_key, aad=b"context-A")
        with pytest.raises(KMSError):
            decrypt_envelope(blob, master_key, aad=b"context-B")

    def test_bound_ciphertext_needs_its_aad(self, master_key: str) -> None:
        blob = encrypt_envelope(b"3-abcdef", master_key, aad=b"context-A")
        with pytest.raises(KMSError):
            decrypt_envelope(blob, master_key)

    def test_unbound_ciphertext_rejects_an_aad(self, master_key: str) -> None:
        blob = encrypt_envelope(b"3-abcdef", master_key)
        with pytest.raises(KMSError):
            decrypt_envelope(blob, master_key, aad=b"context-A")

    def test_legacy_calls_are_unchanged(self, master_key: str) -> None:
        blob = encrypt_envelope(b"3-abcdef", master_key)
        assert decrypt_envelope(blob, master_key) == b"3-abcdef"

    def test_aad_is_keyword_only(self) -> None:
        for func in (encrypt_envelope, decrypt_envelope):
            param = inspect.signature(func).parameters["aad"]
            assert param.kind is inspect.Parameter.KEYWORD_ONLY
            assert param.default is None
