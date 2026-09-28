"""Synced seal records at rest: encrypt on write, decrypt on read (stage E, E3b).

The model functions of :mod:`web.models.release_models` call this module,
so sync admission and the release gate keep their logic and see the same
text they saw before E3b.

Writing (:func:`protect_record`): the privacy keys are loaded, the seal's
data key is unwrapped -- or, when the seal's case exists but has none, a
new one is created, wrapped under the privacy master key and inserted in
the caller's transaction (:func:`data_key_for_write`) -- and ``record_json``
and ``record_pdf`` are encrypted (:mod:`web.privacy.record_crypto`). A seal
without a case is refused (:class:`CaseNotRegistered`): its record could not
be stored anyway (foreign key), and a data key cannot exist without a case.
A key is created only for a genuinely unprotected legacy case: a seal that
already holds protected identity fields or records but has lost its key
row is refused (:class:`DataKeyMissing`), never given a replacement key.

Reading, fail-closed:

  - no privacy keys, or an unreadable key file: :class:`PrivacyUnavailable`
    (never a plaintext fallback);
  - a row stored before E3b (``record_scheme = ''``): :class:`LegacyRecordError`
    with a WARNING naming the conversion command. Such a row is refused
    rather than read or skipped: skipping it would let a release or the
    generation mark decide on part of the seal's records;
  - a protected row that does not decrypt (moved or tampered ciphertext,
    missing or foreign data key): :func:`record_text` raises
    :class:`FieldCryptoError`; :func:`readable_record_text`, used by the
    system readers, returns :data:`UNREADABLE_RECORD` instead, which every
    reader that parses the record treats as unreadable, never as absent.

Nothing here logs or raises with record content or key material.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from flask import g

from ..models.privacy_models import (
    find_data_key_use,
    find_wrapped_data_key,
    insert_data_key_uncommitted,
)
from ..models.record_models import StoredRecord
from .case_identity import load_seal_data_key, utc_now_iso
from .field_crypto import FieldCryptoError, new_data_key, unwrap_data_key, wrap_data_key
from .keys import PrivacyError, PrivacyKeys, PrivacyUnavailable, load_privacy_keys
from .record_crypto import (
    open_record_json,
    open_record_pdf,
    seal_record_json,
    seal_record_pdf,
)

logger = logging.getLogger(__name__)

MIGRATION_COMMAND = "python -m src.web.privacy.migrate --apply"
_LOG_ID_LIMIT = 200
_READ_KEYS = "_seal_record_read_keys"  # flask.g attribute, per application context


class LegacyRecordError(PrivacyError):
    """A stored record predates E3b and is still plaintext (run the migration)."""


class CaseNotRegistered(LookupError):
    """No case exists for the seal, so its record cannot be stored."""


class DataKeyMissing(PrivacyError):
    """A seal with protected data has lost its data key row; no new key is made."""


class UnreadableRecord(str):
    """Stands for a stored record that does not decrypt (system reads only).

    Its value is ``''``, which is not JSON: every reader that parses the
    record classifies it as unreadable. It is never ``None``, so no reader
    mistakes it for a missing record.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "<unreadable record>"


UNREADABLE_RECORD = UnreadableRecord("")


@dataclass(frozen=True)
class SealedRecord:
    """The stored (encrypted) form of one record's two columns."""

    sealed_json: str = field(repr=False)
    sealed_pdf: Optional[bytes] = field(default=None, repr=False)


def protect_record(
    seal_id: str, event_id: int, record_json: str, record_pdf: Optional[bytes]
) -> SealedRecord:
    """Encrypt a record for storage (may insert the seal's data key, no commit).

    Raises:
        PrivacyUnavailable: The privacy keys are not configured or unreadable.
        CaseNotRegistered: The seal has no data key and no case.
        DataKeyMissing: The seal holds protected data but its key row is gone.
        FieldCryptoError: The stored data key does not unwrap, or the record
            text is not valid UTF-8.
    """
    keys = load_privacy_keys()
    data_key, _created = data_key_for_write(seal_id, keys)
    sealed_pdf = (None if record_pdf is None
                  else seal_record_pdf(data_key, seal_id, event_id, record_pdf))
    return SealedRecord(seal_record_json(data_key, seal_id, event_id, record_json),
                        sealed_pdf)


def data_key_for_write(seal_id: str, keys: PrivacyKeys) -> tuple[bytes, bool]:
    """The seal's data key and whether it was created now (inserted, no commit).

    Call under the seal's write lock (``seal_write_transaction``). The key
    of a seal registered since E3a is reused. A new key is created only for
    a genuinely unprotected legacy case: one whose identity and records
    hold nothing under a data key (:func:`find_data_key_use`). A seal that
    does hold protected data but has lost its key row is refused
    (:class:`DataKeyMissing`): a new key would leave ciphertexts that need
    the lost one, and only one key per seal can be stored. The identity
    conversion (E3a) uses this function too.

    Raises:
        CaseNotRegistered: The seal has no key and no case.
        DataKeyMissing: The seal holds protected data but no key row.
        PrivacyUnavailable: The master key cannot be read to wrap a new key.
        FieldCryptoError: The stored key does not unwrap.
    """
    wrapped = find_wrapped_data_key(seal_id)
    if wrapped is not None:
        return unwrap_data_key(wrapped, keys.master_key, seal_id), False
    use = find_data_key_use(seal_id)
    if use is None:
        raise CaseNotRegistered("no case is registered for this seal")
    if use.protected:
        logger.error("Data key missing for a seal with protected data; no new key "
                     "is created (seal_id=%r, protected identity=%s, protected "
                     "records=%d); restore its seal_data_keys row from a backup",
                     seal_id[:_LOG_ID_LIMIT], use.identity_protected,
                     use.protected_records)
        raise DataKeyMissing("the seal's data key is missing and is not replaced")
    data_key = new_data_key()
    try:
        # local_kms wraps from the key file, which is read again here.
        wrapped = wrap_data_key(data_key, keys.master_key_path, seal_id)
    except FieldCryptoError as exc:
        raise PrivacyUnavailable("the privacy master key became unreadable") from exc
    insert_data_key_uncommitted(seal_id, wrapped, utc_now_iso())
    logger.info("Data key created for a seal's records: seal_id=%r",
                seal_id[:_LOG_ID_LIMIT])
    return data_key, True


def require_protected(stored: StoredRecord) -> None:
    """Refuse a row stored before E3b (it is never read as plaintext).

    Raises:
        LegacyRecordError: ``record_scheme`` is not ``'v1'``.
    """
    if stored.protected:
        return
    logger.warning("Seal record refused: stored before E3b and not converted "
                   "(seal_id=%r event_id=%s); convert it with %s",
                   stored.seal_id[:_LOG_ID_LIMIT], stored.event_id, MIGRATION_COMMAND)
    raise LegacyRecordError("the stored record is not protected yet")


def record_text(stored: StoredRecord) -> str:
    """The exact received record text of a stored row.

    Raises:
        LegacyRecordError: The row predates E3b.
        PrivacyUnavailable: The privacy keys are unavailable.
        FieldCryptoError: The row does not decrypt.
    """
    require_protected(stored)
    return open_record_json(_read_key(stored.seal_id), stored.seal_id,
                            stored.event_id, stored.record_json)


def _read_key(seal_id: str) -> bytes:
    """The seal's data key for reading, loaded once per application context.

    The first read of a seal in a request loads the privacy key files and
    unwraps the seal's key, so missing or unreadable keys still fail that
    request (``PrivacyUnavailable``); later reads of the same seal in the
    same request (a release reading several records) reuse it. The cache
    lives in ``flask.g`` and ends with the application context, never
    across requests. A key that does not unwrap is not cached.
    """
    cache = g.get(_READ_KEYS)
    if cache is None:
        cache = {}
        setattr(g, _READ_KEYS, cache)
    data_key = cache.get(seal_id)
    if data_key is None:
        data_key = load_seal_data_key(seal_id, load_privacy_keys())
        cache[seal_id] = data_key
    return data_key


def readable_record_text(stored: StoredRecord) -> str:
    """:func:`record_text`, or :data:`UNREADABLE_RECORD` if it does not decrypt.

    For the system readers (sync admission, the release gate): a record
    that does not decrypt is logged at ERROR and read as unreadable.
    """
    try:
        return record_text(stored)
    except FieldCryptoError:
        logger.error("Seal record did not decrypt; read as unreadable "
                     "(seal_id=%r event_id=%s)", stored.seal_id[:_LOG_ID_LIMIT],
                     stored.event_id)
        return UNREADABLE_RECORD


def record_pdf_bytes(stored: StoredRecord) -> Optional[bytes]:
    """The exact received PDF bytes of a stored row, or ``None`` without a PDF.

    Raises:
        LegacyRecordError: The row predates E3b.
        PrivacyUnavailable: The privacy keys are unavailable.
        FieldCryptoError: The PDF does not decrypt.
    """
    require_protected(stored)
    if stored.record_pdf is None:
        return None
    return open_record_pdf(_read_key(stored.seal_id), stored.seal_id,
                           stored.event_id, stored.record_pdf)


def is_unreadable(value: Any) -> bool:
    """Whether ``value`` is the stand-in for a record that did not decrypt."""
    return isinstance(value, UnreadableRecord)
