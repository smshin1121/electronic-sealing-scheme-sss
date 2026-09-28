"""Encryption of synced seal records at rest (stage E, E3b).

``seal_records.record_json`` and ``seal_records.record_pdf`` are stored as
AES-256-GCM ciphertexts under the seal's data key (the per-seal key of
:mod:`web.privacy.field_crypto`, stored wrapped in ``seal_data_keys``)::

    AAD = lp("ESS-RECORD-v1") || lp("seal_records") || lp(seal_id)
          || lp(decimal event_id) || lp(column)

``lp(x)`` frames each part by its 4-byte big-endian length, so no two
different (seal, event, column) triples give the same associated data. A
ciphertext copied to another seal, to another event of the same seal (which
shares the data key) or to the other column fails the GCM tag check. The
domain differs from E3a's identity fields (``ESS-FIELD-v1``), so neither
format opens as the other.

Stored forms (``SEALED_PREFIX`` = ``"r1:"``):

  - ``record_json`` (a text column): ``"r1:" + base64(nonce || ct || tag)``;
    the plaintext is the strict UTF-8 encoding of the received text, and
    decryption returns that exact text;
  - ``record_pdf`` (a binary column): ``b"r1:" + nonce || ct || tag``, so a
    large PDF is not inflated by base64; decryption returns the exact bytes.

The nonce is 96 random bits per encryption. Every failure raises
:class:`web.privacy.field_crypto.FieldCryptoError` with a message that holds
no key material and no plaintext. This module does no I/O.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .field_crypto import DATA_KEY_BYTES, FieldCryptoError
from .framing import frame, utf8

RECORDS_TABLE = "seal_records"
COLUMN_JSON = "record_json"
COLUMN_PDF = "record_pdf"
SEALED_PREFIX = "r1:"

_SEALED_PREFIX_BYTES = SEALED_PREFIX.encode("ascii")
_DOMAIN = b"ESS-RECORD-v1"
_NONCE_BYTES = 12
_TAG_BYTES = 16
_MAX_EVENT_ID = 2 ** 31 - 1  # the INT column of both schema variants


def record_aad(seal_id: str, event_id: int, column: str) -> bytes:
    """Associated data of one stored record column (see the module doc)."""
    return frame(_DOMAIN, utf8(RECORDS_TABLE), utf8(seal_id),
                 str(_event_number(event_id)).encode("ascii"), utf8(column))


def seal_record_json(data_key: bytes, seal_id: str, event_id: int, text: str) -> str:
    """Encrypt the received record text for (seal, event); returns the stored text."""
    if not isinstance(text, str):
        raise FieldCryptoError("the record must be text")
    try:
        plaintext = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FieldCryptoError("the record is not valid UTF-8 text") from exc
    sealed = _seal(data_key, record_aad(seal_id, event_id, COLUMN_JSON), plaintext)
    return SEALED_PREFIX + base64.b64encode(sealed).decode("ascii")


def open_record_json(data_key: bytes, seal_id: str, event_id: int, stored: object) -> str:
    """Decrypt a stored ``record_json`` value; returns the exact received text."""
    if not isinstance(stored, str) or not stored.startswith(SEALED_PREFIX):
        raise FieldCryptoError("not a protected record value")
    try:
        sealed = base64.b64decode(stored[len(SEALED_PREFIX):], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FieldCryptoError("not a protected record value") from exc
    plaintext = _open(data_key, record_aad(seal_id, event_id, COLUMN_JSON), sealed)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FieldCryptoError("the record did not decrypt to text") from exc


def seal_record_pdf(data_key: bytes, seal_id: str, event_id: int, pdf: bytes) -> bytes:
    """Encrypt the received PDF bytes for (seal, event); returns the stored bytes."""
    if not isinstance(pdf, (bytes, bytearray, memoryview)):
        raise FieldCryptoError("the PDF must be bytes")
    sealed = _seal(data_key, record_aad(seal_id, event_id, COLUMN_PDF), bytes(pdf))
    return _SEALED_PREFIX_BYTES + sealed


def open_record_pdf(data_key: bytes, seal_id: str, event_id: int, stored: object) -> bytes:
    """Decrypt a stored ``record_pdf`` value; returns the exact received bytes."""
    if not isinstance(stored, (bytes, bytearray, memoryview)):
        raise FieldCryptoError("not a protected record value")
    raw = bytes(stored)
    if not raw.startswith(_SEALED_PREFIX_BYTES):
        raise FieldCryptoError("not a protected record value")
    return _open(data_key, record_aad(seal_id, event_id, COLUMN_PDF),
                 raw[len(_SEALED_PREFIX_BYTES):])


def _event_number(event_id: object) -> int:
    if type(event_id) is not int or not 1 <= event_id <= _MAX_EVENT_ID:
        raise FieldCryptoError("the event id must be an integer from 1 to 2^31 - 1")
    return event_id


def _seal(data_key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    _check_key(data_key)
    nonce = os.urandom(_NONCE_BYTES)
    try:
        return nonce + AESGCM(data_key).encrypt(nonce, plaintext, aad)
    except (OverflowError, TypeError, ValueError) as exc:
        raise FieldCryptoError("the record could not be encrypted") from exc


def _open(data_key: bytes, aad: bytes, sealed: bytes) -> bytes:
    _check_key(data_key)
    if len(sealed) < _NONCE_BYTES + _TAG_BYTES:
        raise FieldCryptoError("the protected record value is truncated")
    try:
        return AESGCM(data_key).decrypt(sealed[:_NONCE_BYTES], sealed[_NONCE_BYTES:], aad)
    except (InvalidTag, TypeError, ValueError) as exc:
        raise FieldCryptoError("the record could not be decrypted") from exc


def _check_key(data_key: object) -> None:
    if not isinstance(data_key, bytes) or len(data_key) != DATA_KEY_BYTES:
        raise FieldCryptoError("a data key must be 32 bytes")
