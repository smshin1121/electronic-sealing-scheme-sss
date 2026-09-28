"""Keyed identity digests: normalisation and HMAC-SHA256 (stage E, E3a).

A digest is::

    HMAC-SHA256(pepper, lp("ESS-IDENTITY-DIGEST-v1") || lp(field)
                        || lp(seal_id) || lp(normalised value))

where ``lp(x)`` is the 4-byte big-endian length of the UTF-8 bytes of ``x``
followed by those bytes, so the framing is unambiguous. It is stored as 64
lowercase hex characters. The field name separates the digests of the
three fields; the seal ID binds a digest to its case, so a digest copied
into another case's row does not match there, and one subject's digests
are not linkable across cases without the pepper.

Normalisation (applied to the registered and to the submitted value):
  - name: Unicode NFC; leading and trailing whitespace removed and inner
    runs of whitespace collapsed to one space; letter case is kept;
  - birth date: the ASCII digits after NFKC (``1990-01-01`` and
    ``19900101`` are the same ``YYYYMMDD`` value);
  - phone: the ASCII digits after NFKC, so formatting is ignored
    (``010-1234-5678`` equals ``01012345678``; a country prefix such as
    ``+82`` is not rewritten).

A value with nothing left after normalisation has no digest (``''``), and
:func:`digest_matches` never matches an empty or malformed digest.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
from typing import Callable

from .framing import frame, utf8

FIELD_NAME = "name"
FIELD_BIRTH = "birth_date"
FIELD_PHONE = "phone"

MIN_KEY_BYTES = 32

_DOMAIN = b"ESS-IDENTITY-DIGEST-v1"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")  # SHA-256, lowercase hex
_ASCII_DIGITS = frozenset("0123456789")


def normalize_name(value: object) -> str:
    """NFC, trimmed, inner whitespace collapsed to one space ('' for non-text)."""
    if not isinstance(value, str):
        return ""
    return unicodedata.normalize("NFC", " ".join(value.split()))


def normalize_birth_date(value: object) -> str:
    """Canonical ``YYYYMMDD`` form: the ASCII digits of the value after NFKC.

    Accepts the legacy (``19900101``) and the HTML ``<input type="date">``
    (``1990-01-01``) forms alike, so stored and submitted values compare
    equal regardless of formatting.
    """
    return _ascii_digits(value)


def normalize_phone(value: object) -> str:
    """The ASCII digits of the value after NFKC (separators are ignored)."""
    return _ascii_digits(value)


_NORMALIZERS: dict[str, Callable[[object], str]] = {
    FIELD_NAME: normalize_name,
    FIELD_BIRTH: normalize_birth_date,
    FIELD_PHONE: normalize_phone,
}


def identity_digest(key: bytes, field: str, seal_id: str, raw: object) -> str:
    """The keyed digest of one identity field of one seal ('' if no value).

    Raises:
        ValueError: An unknown field, or a key shorter than 32 bytes.
    """
    normalizer = _NORMALIZERS.get(field)
    if normalizer is None:
        raise ValueError(f"not a digested identity field: {field!r}")
    if not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES:
        raise ValueError("the identity digest key must be at least 32 bytes")
    value = normalizer(raw)
    if not value:
        return ""
    message = frame(_DOMAIN, utf8(field), utf8(seal_id), utf8(value))
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def digest_matches(stored: object, candidate: object) -> bool:
    """Whether two digests are equal and both well formed (constant time).

    Both are compared as bytes with :func:`hmac.compare_digest`, and the
    well-formedness of both is checked, in every case; an empty value
    (no registered or no submitted value) therefore never matches.
    """
    well_formed = is_digest(stored) and is_digest(candidate)
    equal = hmac.compare_digest(_as_bytes(stored), _as_bytes(candidate))
    return well_formed and equal


def is_digest(value: object) -> bool:
    """Whether ``value`` is 64 lowercase hex characters."""
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _ascii_digits(value: object) -> str:
    if not isinstance(value, str):
        return ""
    folded = unicodedata.normalize("NFKC", value)
    return "".join(ch for ch in folded if ch in _ASCII_DIGITS)


def _as_bytes(value: object) -> bytes:
    return utf8(value) if isinstance(value, str) else b""
