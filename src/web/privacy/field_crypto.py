"""Per-seal data keys and field encryption (stage E, E3a; reused by E3b).

Key hierarchy::

    privacy master key  (file PRIVACY_KMS_MASTER_KEY_PATH, 32 bytes; a
     |                   local stand-in for a KMS/HSM key)
     |  wraps, AES-256-GCM through desktop.crypto.local_kms,
     |  AAD = lp("ESS-DATA-KEY-v1") || lp(seal_id)
     v
    data key            (one random 256-bit key per seal; table
     |                   seal_data_keys holds only the wrapped form)
     |  encrypts, AES-256-GCM,
     |  AAD = lp("ESS-FIELD-v1") || lp(table) || lp(seal_id) || lp(column)
     v
    protected field     "e1:" + base64(nonce(12) || ciphertext || tag(16))

``lp(x)`` frames each part by its 4-byte big-endian length, so no two
different (table, seal ID, column) triples give the same associated data.
A ciphertext copied to another seal's row, another column or another
table, or a wrapped key copied to another seal, fails the GCM tag check.
Every failure surfaces as :class:`FieldCryptoError`, without key material
or plaintext in the message.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from desktop.crypto.exceptions import KMSError
from desktop.crypto.local_kms import decrypt_envelope_with_key, encrypt_envelope

from .framing import frame, utf8

DATA_KEY_BYTES = 32
FIELD_PREFIX = "e1:"

_NONCE_BYTES = 12
_TAG_BYTES = 16
_WRAP_DOMAIN = b"ESS-DATA-KEY-v1"
_FIELD_DOMAIN = b"ESS-FIELD-v1"


class FieldCryptoError(Exception):
    """A data key could not be wrapped or unwrapped, or a field not decrypted."""


def new_data_key() -> bytes:
    """A fresh random 256-bit data key."""
    return os.urandom(DATA_KEY_BYTES)


def wrap_data_key(data_key: bytes, master_key_path: str, seal_id: str) -> bytes:
    """Wrap a seal's data key under the master key (bound to the seal ID)."""
    if len(data_key) != DATA_KEY_BYTES:
        raise FieldCryptoError("a data key must be 32 bytes")
    try:
        return encrypt_envelope(data_key, master_key_path, aad=_wrap_aad(seal_id))
    except KMSError as exc:
        raise FieldCryptoError("the data key could not be wrapped") from exc


def unwrap_data_key(wrapped: bytes, master_key: bytes, seal_id: str) -> bytes:
    """Unwrap a seal's data key; fails if it was wrapped for another seal."""
    try:
        data_key = decrypt_envelope_with_key(
            bytes(wrapped), master_key, aad=_wrap_aad(seal_id)
        )
    except (KMSError, TypeError, ValueError) as exc:
        raise FieldCryptoError("the data key could not be unwrapped") from exc
    if len(data_key) != DATA_KEY_BYTES:
        raise FieldCryptoError("the unwrapped data key has the wrong size")
    return data_key


def encrypt_field(
    data_key: bytes, table: str, seal_id: str, column: str, plaintext: str
) -> str:
    """Encrypt one field value for (table, seal ID, column)."""
    nonce = os.urandom(_NONCE_BYTES)
    try:
        sealed = AESGCM(data_key).encrypt(
            nonce, utf8(plaintext), _field_aad(table, seal_id, column),
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise FieldCryptoError("the field could not be encrypted") from exc
    return FIELD_PREFIX + base64.b64encode(nonce + sealed).decode("ascii")


def decrypt_field(
    data_key: bytes, table: str, seal_id: str, column: str, stored: object
) -> str:
    """Decrypt a value written by :func:`encrypt_field` for the same place."""
    raw = _decode(stored)
    try:
        plaintext = AESGCM(data_key).decrypt(
            raw[:_NONCE_BYTES], raw[_NONCE_BYTES:],
            _field_aad(table, seal_id, column),
        )
        return plaintext.decode("utf-8", "surrogatepass")
    except (InvalidTag, TypeError, ValueError) as exc:
        raise FieldCryptoError("the field could not be decrypted") from exc


def _decode(stored: object) -> bytes:
    if not isinstance(stored, str) or not stored.startswith(FIELD_PREFIX):
        raise FieldCryptoError("not a protected field value")
    try:
        raw = base64.b64decode(stored[len(FIELD_PREFIX):], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FieldCryptoError("not a protected field value") from exc
    if len(raw) < _NONCE_BYTES + _TAG_BYTES:
        raise FieldCryptoError("the protected field value is truncated")
    return raw


def _wrap_aad(seal_id: str) -> bytes:
    return frame(_WRAP_DOMAIN, utf8(seal_id))


def _field_aad(table: str, seal_id: str, column: str) -> bytes:
    return frame(_FIELD_DOMAIN, utf8(table), utf8(seal_id), utf8(column))
