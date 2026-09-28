"""Audited reads of synced seal records for a person (stage E, E3b).

The only path by which a record's content or PDF leaves the web app
decrypted to a person. The caller (a route) authenticates first; these
functions then decrypt and append one ``identity_access_audit`` row per
decryption:

    seal_id, field (record_json | record_pdf), purpose (record_view |
    record_download), actor_role, actor, client_address, outcome
    (revealed | failed), created_at -- never the content.

The row is written (and committed) before the content is returned; if it
cannot be written, :class:`IdentityAuditError` is raised and the content
is withheld. A record that does not decrypt is audited as ``failed`` (best
effort) and :class:`FieldCryptoError` propagates. Nothing is decrypted, and
nothing audited, for a record or PDF that does not exist, a record stored
before E3b (:class:`web.privacy.record_store.LegacyRecordError`) or missing
privacy keys (:class:`web.privacy.keys.PrivacyUnavailable`).

System reads -- sync admission and the release gate, through
:mod:`web.models.release_models` -- are not audited here per read: they
return no content to anyone, and the release gate already writes one
``release_audit`` row per attempt.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Optional

from ..models.privacy_models import (
    ACTOR_ROLES,
    OUTCOME_FAILED,
    OUTCOME_REVEALED,
    IdentityAccessEntry,
    insert_identity_access,
)
from ..models.record_models import find_stored_record
from .case_identity import IdentityAuditError, utc_now_iso
from .field_crypto import FieldCryptoError
from .record_crypto import COLUMN_JSON, COLUMN_PDF
from .record_store import record_pdf_bytes, record_text

logger = logging.getLogger(__name__)

PURPOSE_RECORD_VIEW = "record_view"
PURPOSE_RECORD_DOWNLOAD = "record_download"
_LOG_ID_LIMIT = 200


def reveal_record_json(
    seal_id: str, event_id: int, *, actor_role: str, actor: str = "",
    client_address: str = "",
) -> Optional[str]:
    """The record text of (seal, event) for a person, audited; None if absent.

    Raises:
        ValueError: An unknown actor role.
        LegacyRecordError: The record predates E3b (nothing decrypted).
        PrivacyUnavailable: The privacy keys are unavailable.
        FieldCryptoError: The record does not decrypt (audited as failed).
        IdentityAuditError: The audit row could not be written; withheld.
    """
    entry = _entry(seal_id, COLUMN_JSON, PURPOSE_RECORD_VIEW, actor_role, actor,
                   client_address)
    stored = find_stored_record(seal_id, event_id)
    if stored is None:
        return None
    try:
        text = record_text(stored)
    except FieldCryptoError:
        _audit_failed(entry, event_id)
        raise
    _audit_or_withhold(entry, event_id)
    return text


def reveal_record_pdf(
    seal_id: str, event_id: int, *, actor_role: str, actor: str = "",
    client_address: str = "",
) -> Optional[bytes]:
    """The PDF of (seal, event) for a person, audited; None if there is none.

    Raises: as :func:`reveal_record_json`.
    """
    entry = _entry(seal_id, COLUMN_PDF, PURPOSE_RECORD_DOWNLOAD, actor_role, actor,
                   client_address)
    stored = find_stored_record(seal_id, event_id, with_pdf=True)
    if stored is None or stored.record_pdf is None:
        return None
    try:
        pdf = record_pdf_bytes(stored)
    except FieldCryptoError:
        _audit_failed(entry, event_id)
        raise
    _audit_or_withhold(entry, event_id)
    return pdf


def _entry(seal_id: str, field_name: str, purpose: str, actor_role: str,
           actor: str, client_address: str) -> IdentityAccessEntry:
    if actor_role not in ACTOR_ROLES:
        raise ValueError(f"not an actor role: {actor_role!r}")
    return IdentityAccessEntry(
        seal_id=seal_id, field_name=field_name, purpose=purpose,
        actor_role=actor_role, outcome=OUTCOME_REVEALED, created_at=utc_now_iso(),
        actor=actor, client_address=client_address,
    )


def _audit_or_withhold(entry: IdentityAccessEntry, event_id: int) -> None:
    try:
        insert_identity_access(replace(entry, created_at=utc_now_iso()))
    except Exception as exc:
        logger.error("Record access audit write failed; content withheld: "
                     "seal_id=%r event_id=%s field=%s", entry.seal_id[:_LOG_ID_LIMIT],
                     event_id, entry.field_name)
        raise IdentityAuditError("the record access could not be audited") from exc
    logger.info("Seal record revealed: seal_id=%r event_id=%s field=%s purpose=%s "
                "actor_role=%s", entry.seal_id[:_LOG_ID_LIMIT], event_id,
                entry.field_name, entry.purpose, entry.actor_role)


def _audit_failed(entry: IdentityAccessEntry, event_id: int) -> None:
    logger.warning("Seal record did not decrypt for a person: seal_id=%r "
                   "event_id=%s field=%s", entry.seal_id[:_LOG_ID_LIMIT], event_id,
                   entry.field_name)
    try:
        insert_identity_access(replace(entry, outcome=OUTCOME_FAILED,
                                       created_at=utc_now_iso()))
    except Exception:
        logger.exception("Record access audit write failed for a failed decryption")
