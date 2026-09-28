"""Encryption of synced seal records at rest (stage E, E3b).

``record_json`` and ``record_pdf`` of a ``seal_records`` row are
AES-256-GCM ciphertexts under the seal's data key (E3a's per-seal key),
with associated data naming the table, the seal ID, the event ID and the
column. A ciphertext moved to another seal, another event of the same seal
or the other column fails to decrypt; decryption returns exactly the bytes
that were encrypted. Synthetic values; keys are generated per test.
"""

from __future__ import annotations

import base64

import pytest

from web.privacy.field_crypto import FieldCryptoError, encrypt_field, new_data_key
from web.privacy.record_crypto import (
    COLUMN_JSON,
    COLUMN_PDF,
    SEALED_PREFIX,
    open_record_json,
    open_record_pdf,
    record_aad,
    seal_record_json,
    seal_record_pdf,
)

SEAL = "S-20260928-RC0001"
OTHER_SEAL = "S-20260928-RC0002"
# Key order, spacing and non-ASCII text are part of the received bytes.
RECORD_TEXT = '{"seal_id": "S-20260928-RC0001",  "signer_info": {"name": "박서준"}}\n'
PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n(park.sj@example.org)\n%%EOF\n"


@pytest.fixture()
def data_key() -> bytes:
    return new_data_key()


class TestRecordJson:
    def test_round_trip_returns_the_exact_text(self, data_key) -> None:
        sealed = seal_record_json(data_key, SEAL, 3, RECORD_TEXT)

        assert sealed.startswith(SEALED_PREFIX)
        assert "박서준" not in sealed and "signer_info" not in sealed
        assert open_record_json(data_key, SEAL, 3, sealed) == RECORD_TEXT

    def test_each_encryption_uses_a_fresh_nonce(self, data_key) -> None:
        assert (seal_record_json(data_key, SEAL, 1, RECORD_TEXT)
                != seal_record_json(data_key, SEAL, 1, RECORD_TEXT))

    @pytest.mark.parametrize("seal_id,event_id", [
        (OTHER_SEAL, 3),   # another seal
        (SEAL, 4),         # another event of the same seal (same data key)
        (SEAL, 30),
    ])
    def test_a_moved_ciphertext_fails(self, data_key, seal_id, event_id) -> None:
        sealed = seal_record_json(data_key, SEAL, 3, RECORD_TEXT)

        with pytest.raises(FieldCryptoError):
            open_record_json(data_key, seal_id, event_id, sealed)

    def test_the_json_ciphertext_does_not_open_as_the_pdf(self, data_key) -> None:
        sealed = seal_record_json(data_key, SEAL, 3, RECORD_TEXT)

        with pytest.raises(FieldCryptoError):
            open_record_pdf(data_key, SEAL, 3, sealed.encode("ascii"))

    def test_another_data_key_fails(self, data_key) -> None:
        sealed = seal_record_json(data_key, SEAL, 3, RECORD_TEXT)

        with pytest.raises(FieldCryptoError):
            open_record_json(new_data_key(), SEAL, 3, sealed)

    def test_an_identity_field_ciphertext_is_not_a_record(self, data_key) -> None:
        # E3a's field format under the same data key never opens here.
        field = encrypt_field(data_key, "seal_records", SEAL, COLUMN_JSON, RECORD_TEXT)

        with pytest.raises(FieldCryptoError):
            open_record_json(data_key, SEAL, 3, field)

    def test_malformed_values_fail(self, data_key) -> None:
        sealed = seal_record_json(data_key, SEAL, 3, RECORD_TEXT)
        raw = bytearray(base64.b64decode(sealed[len(SEALED_PREFIX):]))
        raw[20] ^= 1
        tampered = SEALED_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")

        for bad in (tampered, sealed[len(SEALED_PREFIX):], RECORD_TEXT, "",
                    SEALED_PREFIX, SEALED_PREFIX + "!!!", sealed[:-8], None,
                    SEALED_PREFIX + base64.b64encode(b"\x00" * 20).decode("ascii")):
            with pytest.raises(FieldCryptoError):
                open_record_json(data_key, SEAL, 3, bad)

    def test_text_that_is_not_utf8_is_refused(self, data_key) -> None:
        # The stored plaintext is the UTF-8 of the received text, strictly.
        with pytest.raises(FieldCryptoError):
            seal_record_json(data_key, SEAL, 3, '{"x": "\ud800"}')

    @pytest.mark.parametrize("event_id", [0, -1, True, "3", 3.0, None, 2 ** 31])
    def test_the_event_id_must_be_a_positive_int(self, data_key, event_id) -> None:
        with pytest.raises(FieldCryptoError):
            seal_record_json(data_key, SEAL, event_id, RECORD_TEXT)


class TestRecordPdf:
    def test_round_trip_returns_the_exact_bytes(self, data_key) -> None:
        sealed = seal_record_pdf(data_key, SEAL, 2, PDF_BYTES)

        assert isinstance(sealed, bytes) and sealed.startswith(SEALED_PREFIX.encode())
        assert PDF_BYTES not in sealed and b"park.sj" not in sealed
        assert open_record_pdf(data_key, SEAL, 2, sealed) == PDF_BYTES

    def test_empty_bytes_round_trip(self, data_key) -> None:
        assert open_record_pdf(data_key, SEAL, 2, seal_record_pdf(data_key, SEAL, 2, b"")) == b""

    @pytest.mark.parametrize("seal_id,event_id", [(OTHER_SEAL, 2), (SEAL, 1)])
    def test_a_moved_ciphertext_fails(self, data_key, seal_id, event_id) -> None:
        sealed = seal_record_pdf(data_key, SEAL, 2, PDF_BYTES)

        with pytest.raises(FieldCryptoError):
            open_record_pdf(data_key, seal_id, event_id, sealed)

    def test_the_pdf_ciphertext_does_not_open_as_the_json(self, data_key) -> None:
        sealed = seal_record_pdf(data_key, SEAL, 2, b'{"a": 1}')
        as_text = SEALED_PREFIX + base64.b64encode(sealed[len(SEALED_PREFIX):]).decode("ascii")

        with pytest.raises(FieldCryptoError):
            open_record_json(data_key, SEAL, 2, as_text)

    def test_malformed_values_fail(self, data_key) -> None:
        sealed = bytearray(seal_record_pdf(data_key, SEAL, 2, PDF_BYTES))
        sealed[-1] ^= 1

        for bad in (bytes(sealed), PDF_BYTES, b"", SEALED_PREFIX.encode(),
                    bytes(sealed[:20]), None, "text"):
            with pytest.raises(FieldCryptoError):
                open_record_pdf(data_key, SEAL, 2, bad)

    def test_memoryview_from_a_driver_is_accepted(self, data_key) -> None:
        sealed = seal_record_pdf(data_key, SEAL, 2, PDF_BYTES)

        assert open_record_pdf(data_key, SEAL, 2, memoryview(sealed)) == PDF_BYTES


class TestAssociatedData:
    def test_every_part_is_bound_and_framed(self) -> None:
        base = record_aad(SEAL, 12, COLUMN_JSON)

        assert base != record_aad(OTHER_SEAL, 12, COLUMN_JSON)
        assert base != record_aad(SEAL, 1, COLUMN_JSON)
        assert base != record_aad(SEAL, 12, COLUMN_PDF)
        # Shifting a digit between the seal ID and the event must not collide.
        assert record_aad("S-1", 23, COLUMN_JSON) != record_aad("S-12", 3, COLUMN_JSON)
