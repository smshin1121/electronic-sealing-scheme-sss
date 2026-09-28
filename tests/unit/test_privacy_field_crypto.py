"""Per-seal data keys and field encryption (stage E, E3a).

Each seal gets one random 256-bit data key, stored only wrapped with
AES-256-GCM under the privacy master key (associated data: a domain and
the seal ID, through the local KMS emulation). A protected field is
AES-256-GCM under the seal's data key with associated data naming the
table, the seal ID and the column, so a ciphertext moved to another row or
column, or a wrapped key moved to another seal, fails to decrypt.
Synthetic values; keys are generated per test.
"""

from __future__ import annotations

import base64

import pytest

from desktop.crypto.local_kms import init_master_key, load_master_key
from web.privacy.field_crypto import (
    DATA_KEY_BYTES,
    FieldCryptoError,
    decrypt_field,
    encrypt_field,
    new_data_key,
    unwrap_data_key,
    wrap_data_key,
)

SEAL = "S-20260928-FC0001"
OTHER_SEAL = "S-20260928-FC0002"


@pytest.fixture()
def master_path(tmp_path) -> str:
    path = str(tmp_path / "privacy_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def data_key() -> bytes:
    return new_data_key()


class TestDataKeys:
    def test_new_data_keys_are_random_256_bit(self) -> None:
        first, second = new_data_key(), new_data_key()
        assert len(first) == DATA_KEY_BYTES == 32
        assert first != second

    def test_wrap_and_unwrap(self, master_path, data_key) -> None:
        wrapped = wrap_data_key(data_key, master_path, SEAL)

        assert data_key not in wrapped
        assert unwrap_data_key(wrapped, load_master_key(master_path), SEAL) == data_key

    def test_wrapped_key_is_bound_to_its_seal(self, master_path, data_key) -> None:
        wrapped = wrap_data_key(data_key, master_path, SEAL)

        with pytest.raises(FieldCryptoError):
            unwrap_data_key(wrapped, load_master_key(master_path), OTHER_SEAL)

    def test_another_master_key_cannot_unwrap(self, tmp_path, master_path, data_key) -> None:
        other = str(tmp_path / "other_master.key")
        init_master_key(other)
        wrapped = wrap_data_key(data_key, master_path, SEAL)

        with pytest.raises(FieldCryptoError):
            unwrap_data_key(wrapped, load_master_key(other), SEAL)

    def test_tampered_or_truncated_wrap_fails(self, master_path, data_key) -> None:
        wrapped = bytearray(wrap_data_key(data_key, master_path, SEAL))
        wrapped[-1] ^= 1
        master = load_master_key(master_path)

        for bad in (bytes(wrapped), bytes(wrapped[:20]), b""):
            with pytest.raises(FieldCryptoError):
                unwrap_data_key(bad, master, SEAL)

    def test_unusable_master_key_path_fails_to_wrap(self, tmp_path, data_key) -> None:
        with pytest.raises(FieldCryptoError):
            wrap_data_key(data_key, str(tmp_path / "absent.key"), SEAL)


class TestFieldEncryption:
    def test_round_trip(self, data_key) -> None:
        stored = encrypt_field(data_key, "cases", SEAL, "suspect_name_enc", "홍길동")

        assert stored.startswith("e1:")
        assert "홍길동" not in stored
        assert decrypt_field(data_key, "cases", SEAL, "suspect_name_enc", stored) == "홍길동"

    def test_each_encryption_uses_a_fresh_nonce(self, data_key) -> None:
        first = encrypt_field(data_key, "cases", SEAL, "suspect_email_enc", "hong@example.org")
        second = encrypt_field(data_key, "cases", SEAL, "suspect_email_enc", "hong@example.org")
        assert first != second

    @pytest.mark.parametrize("table,seal,column", [
        ("cases", OTHER_SEAL, "suspect_name_enc"),
        ("cases", SEAL, "suspect_email_enc"),
        ("seal_records", SEAL, "suspect_name_enc"),
    ])
    def test_moved_ciphertext_fails(self, data_key, table, seal, column) -> None:
        stored = encrypt_field(data_key, "cases", SEAL, "suspect_name_enc", "홍길동")

        with pytest.raises(FieldCryptoError):
            decrypt_field(data_key, table, seal, column, stored)

    def test_another_data_key_fails(self, data_key) -> None:
        stored = encrypt_field(data_key, "cases", SEAL, "suspect_name_enc", "홍길동")

        with pytest.raises(FieldCryptoError):
            decrypt_field(new_data_key(), "cases", SEAL, "suspect_name_enc", stored)

    def test_malformed_values_fail(self, data_key) -> None:
        stored = encrypt_field(data_key, "cases", SEAL, "suspect_name_enc", "홍길동")
        raw = bytearray(base64.b64decode(stored[3:]))
        raw[15] ^= 1
        tampered = "e1:" + base64.b64encode(bytes(raw)).decode("ascii")

        for bad in (tampered, stored[3:], "e2:" + stored[3:], "e1:!!!", "e1:",
                    "e1:" + base64.b64encode(b"\x00" * 20).decode("ascii"), "", None):
            with pytest.raises(FieldCryptoError):
                decrypt_field(data_key, "cases", SEAL, "suspect_name_enc", bad)

    def test_framing_is_unambiguous(self, data_key) -> None:
        # Shifting a character between table and column must not collide.
        stored = encrypt_field(data_key, "cases", SEAL, "xsuspect", "v")

        with pytest.raises(FieldCryptoError):
            decrypt_field(data_key, "casesx", SEAL, "suspect", stored)
