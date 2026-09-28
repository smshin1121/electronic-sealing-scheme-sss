"""Synchronization endpoint.

Receives seal records from the desktop SQLite DB and stores them
in the web MariaDB (or SQLite fallback). A resubmission is never dropped
silently (see below).

A Sealing/Resealing payload may carry ``wrapped_s3``: the base64 envelope
ciphertext of the time-locked system share, bound on the desktop to the
record's seal_id and signed policy. It is accepted only when the record
names the same seal, and stored in the same transaction as the record.

Sync authentication (stage E, E2a; :mod:`web.sync_auth`): a submission may
carry ``sync_auth``, an envelope over the seal, event, exact record, PDF and
wrapped-s3 bytes, policy generation, time and nonce, signed by the
institutional seal-policy key. Its signature and time are checked before
the payload is decoded, its binding to the request after. A present but
invalid ``sync_auth`` is always refused (401; 503 when no CA is pinned to
verify it). With ``SYNC_REQUIRE_SIGNATURE`` on, unsigned submissions are
refused (401); off (the default), they are admitted as before, so the
properties that rest on who submitted a record hold only with the switch
on. The nonce of a verified envelope is claimed first under the seal's
write lock, in the same transaction as the store; a reused nonce is
refused (409). A submission refused with 409 after that claim still
consumes its nonce, except a copy (below); that refusal, like the storage
refusals under "Storage at rest", rolls the claim back.

Records are admitted by their seal policy (unsigned submissions are not
authenticated, so this is what keeps a policy from being stripped):

  - a policy that verifies against a pinned CA (or whose certificate has
    only expired) is stored and enrolls the seal (``policy_enrollment``);
  - a policy that fails verification (tampered, unsigned, another seal)
    is refused with 422 and nothing is stored;
  - a record without a policy, or one that cannot be checked because no CA
    is pinned, is stored as before -- unless the seal is enrolled, which
    refuses it with 409.

Policy generations (stage E, E2a): a verified policy that would be stored
(a new event, or a displacement) is refused with 409 when its generation is
below the seal's high-water mark (``policy_high_water``; rollback), or
equal to it with another policy digest. Storing it sets or raises the mark
in the same transaction. A seal without a mark first gets the one its
stored records imply (the highest authenticated generation among them), so
a lower generation arriving first cannot become the mark. An identical
resubmission is answered as before whatever its generation (it changes
nothing).

The enrollment check, the conflict decision below and the writes of one
submission run in a single transaction serialized per seal
(``seal_write_transaction``), so concurrent submissions cannot
interleave; the incoming policy and envelope are verified before that lock
is taken.

A second submission for the same (seal_id, event_id) is never dropped
silently:

  - an identical record (same event type and JSON, value types included)
    adds a missing wrapped s3 or enrollment and otherwise changes nothing
    (200); a different wrapped s3 for it is refused (409);
  - an authenticated record displaces an unauthenticated one that
    occupied the event first, provided the event still holds the record
    that decision was made on;
  - any other difference is refused (409).

Copies (Fable gate, finding 1): an authenticated record that is an exact
copy (the comparison above) of a record the seal stores under another
event id is refused with 409, before it would be stored under a new event
or displace an unauthenticated one. The desktop appends every event to
the record's history, so it never sends one; with the switch off, anyone
holding a signed record could otherwise take a future event id of the
seal with it, and the genuine record for that event would meet a 409.
The refusal rolls the transaction back: a signed copy's nonce stays
unused (a replay is refused the same way) and a mark bootstrapped for it
is not kept. A stored record that does not decrypt never matches.
Unauthenticated copies follow the rules above.

Storage at rest (stage E, E3b; :mod:`web.privacy.record_store`): the
record and its PDF are stored encrypted under the seal's data key, and
the model functions decrypt them for the decisions above, which compare
the decrypted text exactly as before. Without the privacy keys the route
answers 503 after the authentication, binding and policy checks and stores
nothing (no nonce is claimed); a key file that cannot be read at request
time is 503 too (the transaction, nonce included, rolls back). A seal whose case is not registered is refused
with 404. A seal that holds protected data but has lost its data key row
is refused with 503 and never given a new key (the transaction, nonce and
generation mark included, rolls back). A seal with a stored record from before E3b that this
submission would have to read (same event, the mark bootstrap, or the
copy check of an authenticated record, which reads every record of the
seal) is refused with 503 until the conversion runs.

Endpoint
--------
POST /sync/upload-record  -- SQLite -> MariaDB record sync
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

from flask import Blueprint, current_app, jsonify, request

from desktop.signature.seal_policy import (
    POLICY_EXPIRED,
    POLICY_INVALID,
    POLICY_VERIFIED,
    assess_record_policy,
)
from desktop.signature.sync_envelope import VerifiedSyncEnvelope

from ..models.release_models import (
    SYNC_COMPLETED,
    SYNC_ENVELOPE_CONFLICT,
    DuplicateEventError,
    complete_synced_record,
    find_record_at,
    find_record_jsons_newest_first,
    is_policy_enrolled,
    replace_synced_record,
    seal_write_transaction,
    store_synced_record,
)
from ..models.sync_models import (
    claim_sync_nonce,
    find_high_water,
    prune_sync_nonces,
    raise_high_water,
    seed_high_water,
)
from ..privacy.keys import PrivacyUnavailable, privacy_keys_configured
from ..privacy.record_store import (
    MIGRATION_COMMAND,
    CaseNotRegistered,
    DataKeyMissing,
    LegacyRecordError,
)
from ..release_selection import stored_maximum
from ..sync_auth import (
    AuthFailure,
    SubmittedEvent,
    check_generation_claim,
    check_request_binding,
    nonce_expiry,
    unsigned_refusal,
    utc_now,
    validate_sync_config,
    verify_submission_signature,
)

logger = logging.getLogger(__name__)

bp = Blueprint("sync", __name__, url_prefix="/sync")

# Maximum accepted base64-encoded PDF length (~30 MB decoded)
MAX_PDF_B64_LENGTH = 40 * 1024 * 1024
# wrapped_s3 = 12-byte nonce + share ciphertext + 16-byte GCM tag; a
# share string is ~66 bytes, so a few KiB is a generous bound.
MAX_WRAPPED_S3_B64_LENGTH = 4096
_MIN_WRAPPED_S3_BYTES = 12 + 16 + 3
_WRAPPED_S3_EVENTS = ("Sealing", "Resealing")
_EVENT_TYPES = ("Sealing", "Unsealing", "Resealing")
_MAX_EVENT_ID = 2 ** 31 - 1  # the INT column of both schema variants
_EVENT_ID_TEXT = re.compile(r"[0-9]{1,10}")
_MAX_LOG_ID_LEN = 200

_MSG_KEYS_MISSING = (
    "개인정보 보호 키가 설정되지 않았거나 쓸 수 없어 기록을 저장할 수 없습니다. "
    "관리자에게 문의해 주세요."
)
_MSG_NOT_CONVERTED = (
    "이 봉인의 기존 기록이 아직 보호 형식으로 이관되지 않아 동기화할 수 없습니다. "
    "관리자에게 문의해 주세요."
)
_MSG_NO_CASE = "등록된 사건이 없어 기록을 저장할 수 없습니다. 먼저 사건을 등록해 주세요."
_MSG_KEY_MISSING = (
    "이 봉인의 데이터 키를 찾을 수 없어 기록을 저장할 수 없습니다. "
    "관리자에게 문의해 주세요."
)


_MSG_RECORD_COPY = (
    "같은 기록이 이미 다른 event_id에 저장되어 있어 동기화를 거부합니다."
)


class SyncNonceReused(Exception):
    """The envelope's nonce was used before; the transaction rolls back."""


class SyncRecordCopied(Exception):
    """The record is a copy of one stored under another event id; the
    transaction rolls back (the nonce claim included)."""

    def __init__(self, stored_event_id: int) -> None:
        super().__init__(stored_event_id)
        self.stored_event_id = stored_event_id


@dataclass(frozen=True)
class _Admission:
    """The incoming record's policy: digest (None unless it authenticates)
    and generation (0 without a policy or for a version-1 policy)."""

    digest: Optional[str]
    generation: int = 0


@bp.record_once
def _validate_config(state: Any) -> None:
    """A switch or window that cannot work refuses start-up."""
    validate_sync_config(state.app.config)


@bp.route("/upload-record", methods=["POST"])
def upload_record() -> tuple[Any, int]:
    """Receive and store a seal record (idempotent).

    Expected JSON body::

        {
            "seal_id":     "S-20251104-ABA82E",
            "event_id":    1,
            "event_type":  "Sealing",
            "record_json": "{ ... }",
            "record_pdf":  "<base64-encoded PDF or null>",
            "wrapped_s3":  "<base64 envelope of s3, optional>",
            "sync_auth":   {"envelope": {...}, "signature": "...",
                            "cert": "<PEM>"}   (optional, E2a)
        }

    Returns:
        JSON response with status.
    """
    if not request.is_json:
        return _sync_error("JSON 요청이 필요합니다.", 400)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _sync_error("잘못된 JSON 형식입니다.", 400)
    fields, error = _read_fields(data)
    if error is not None:
        return error
    config = current_app.config
    refusal = unsigned_refusal(data, config)
    if refusal is not None:
        return _auth_error(refusal, fields)
    envelope, failure = verify_submission_signature(data, config,
                                                    now=utc_now())
    if failure is not None:
        return _auth_error(failure, fields)
    record_obj, event, error = _decode_submission(data, fields)
    if error is not None:
        return error
    failure = check_request_binding(envelope, event)
    if failure is not None:
        return _auth_error(failure, fields)
    admission, error = _assess_policy(fields["seal_id"], record_obj)
    if error is not None:
        return error
    failure = check_generation_claim(envelope, admission.generation)
    if failure is not None:
        return _auth_error(failure, fields)
    return _keys_refusal(fields) or _store(event, record_obj, admission, envelope)


def _read_fields(data: dict) -> tuple[dict[str, Any], Optional[tuple[Any, int]]]:
    """The identifying fields, validated (400 with every problem named)."""
    seal_id = data.get("seal_id")
    event_type = data.get("event_type")
    record_json = data.get("record_json", "")
    seal_id = seal_id.strip() if isinstance(seal_id, str) else ""
    event_type = event_type.strip() if isinstance(event_type, str) else ""
    event_id = _event_id(data.get("event_id"))
    errors: list[str] = []
    if not seal_id:
        errors.append("seal_id는 필수입니다.")
    if event_id is None:
        errors.append("event_id는 1 이상의 정수여야 합니다.")
    if event_type not in _EVENT_TYPES:
        errors.append("event_type은 Sealing, Unsealing, Resealing 중 하나여야 합니다.")
    if not record_json:
        errors.append("record_json은 필수입니다.")
    fields = {"seal_id": seal_id, "event_id": event_id,
              "event_type": event_type, "record_json": record_json}
    if errors:
        return fields, _sync_error(" / ".join(errors), 400)
    return fields, None


def _keys_refusal(fields: dict[str, Any]) -> Optional[tuple[Any, int]]:
    """503 when the privacy keys are not configured (checked after the
    request's authentication, so an unauthenticated caller learns nothing
    about the server's keys, and before anything is stored)."""
    if privacy_keys_configured():
        return None
    logger.warning("Sync refused (503): identity protection keys not "
                   "configured (seal_id=%r event_id=%s)",
                   _clip(fields["seal_id"]), fields["event_id"])
    return _sync_error(_MSG_KEYS_MISSING, 503)


def _event_id(value: Any) -> Optional[int]:
    """A positive event id that fits the INT column (an int, or its digits)."""
    if isinstance(value, str) and _EVENT_ID_TEXT.fullmatch(value):
        value = int(value)
    if type(value) is not int or not 1 <= value <= _MAX_EVENT_ID:
        return None
    return value


def _decode_submission(
    data: dict, fields: dict[str, Any]
) -> tuple[Any, Optional[SubmittedEvent], Optional[tuple[Any, int]]]:
    """The parsed record and the submitted event, bytes decoded (or 400/413)."""
    record_obj, error = _parse_record(fields["record_json"])
    if error is not None:
        return None, None, error
    wrapped_s3, error = _decode_wrapped_s3(
        data.get("wrapped_s3"), fields["event_type"], fields["seal_id"],
        record_obj)
    if error is not None:
        return None, None, error
    record_pdf, error = _decode_record_pdf(data.get("record_pdf"))
    if error is not None:
        return None, None, error
    event = SubmittedEvent(fields["seal_id"], fields["event_id"],
                           fields["event_type"], fields["record_json"],
                           record_pdf, wrapped_s3)
    return record_obj, event, None


def _parse_record(record_json: Any) -> tuple[Any, Optional[tuple[Any, int]]]:
    """The record as an object (a string is parsed; 400 if unreadable)."""
    if not isinstance(record_json, str):
        return record_json, None
    try:
        return json.loads(record_json), None
    except (json.JSONDecodeError, TypeError):
        return None, _sync_error("record_json이 올바른 JSON이 아닙니다.", 400)


def _store(
    event: SubmittedEvent, record_obj: Any, admission: _Admission,
    envelope: Optional[VerifiedSyncEnvelope],
) -> tuple[Any, int]:
    """Run admission and the writes under the seal's write lock."""
    record_json = event.record_json
    if not isinstance(record_json, str):
        record_json = json.dumps(record_json, ensure_ascii=False)
    stored = {
        "seal_id": event.seal_id, "event_id": event.event_id,
        "event_type": event.event_type, "record_json": record_json,
        "record_pdf": event.record_pdf, "wrapped_s3": event.wrapped_s3,
    }
    try:
        with seal_write_transaction(event.seal_id):
            response = _store_serialized(stored, record_obj, admission,
                                         envelope)
    except SyncNonceReused:
        logger.warning("Sync refused: nonce already used (seal_id=%r "
                       "event_id=%s)", _clip(event.seal_id), event.event_id)
        return _sync_error("이미 사용된 동기화 요청입니다 (nonce 재사용).", 409)
    except SyncRecordCopied as exc:
        logger.warning("Sync refused: a copy of the record stored under "
                       "event_id=%s (seal_id=%r event_id=%s); nothing stored",
                       exc.stored_event_id, _clip(event.seal_id), event.event_id)
        return _sync_error(_MSG_RECORD_COPY, 409)
    except (PrivacyUnavailable, LegacyRecordError, CaseNotRegistered,
            DataKeyMissing) as exc:
        return _storage_refusal(exc, event)
    except Exception:
        logger.exception("동기화 실패: seal_id=%r event_id=%s",
                         _clip(event.seal_id), event.event_id)
        return _sync_error("기록 저장에 실패했습니다.", 500)
    if envelope is not None:
        _prune_nonces()
    return response


def _store_serialized(
    stored: dict[str, Any], record_obj: Any, admission: _Admission,
    envelope: Optional[VerifiedSyncEnvelope],
) -> tuple[Any, int]:
    """Admission and storage under the seal's write lock (nothing commits here)."""
    seal_id, event_id = stored["seal_id"], stored["event_id"]
    if envelope is not None:
        _claim_nonce(envelope, seal_id, event_id)
    if admission.digest is None and is_policy_enrolled(seal_id):
        logger.warning("Sync refused: record without an authenticated policy "
                       "for an enrolled seal (seal_id=%s)", seal_id)
        return _sync_error(
            "인증된 봉인 정책이 등록된 봉인에는 검증되는 정책이 없는 기록을 "
            "동기화할 수 없습니다.", 409
        )
    if admission.digest is not None:
        _bootstrap_mark(seal_id)
    existing = find_record_at(seal_id, event_id)
    if existing is not None:
        return _resubmission(stored, record_obj, admission, existing)
    _refuse_copy(seal_id, event_id, record_obj, admission)
    refusal = _generation_refusal(seal_id, event_id, admission)
    if refusal is not None:
        return refusal
    try:
        store_synced_record(**stored, enrolled_digest=admission.digest)
    except DuplicateEventError:
        return _event_conflict(seal_id, event_id)
    _raise_mark(seal_id, event_id, admission)
    return jsonify({"status": "ok", "message": "동기화 완료"}), 200


def _storage_refusal(exc: Exception, event: SubmittedEvent) -> tuple[Any, int]:
    """503/404 for a submission the protected store cannot take (rolled back)."""
    seal_id, event_id = _clip(event.seal_id), event.event_id
    if isinstance(exc, CaseNotRegistered):
        logger.warning("Sync refused (404): no case registered (seal_id=%r "
                       "event_id=%s)", seal_id, event_id)
        return _sync_error(_MSG_NO_CASE, 404)
    if isinstance(exc, LegacyRecordError):
        logger.warning("Sync refused (503): a stored record of the seal is not "
                       "converted yet (seal_id=%r event_id=%s); run %s",
                       seal_id, event_id, MIGRATION_COMMAND)
        return _sync_error(_MSG_NOT_CONVERTED, 503)
    if isinstance(exc, DataKeyMissing):
        logger.error("Sync refused (503): the seal holds protected data but its "
                     "data key row is missing; no new key was created "
                     "(seal_id=%r event_id=%s)", seal_id, event_id)
        return _sync_error(_MSG_KEY_MISSING, 503)
    logger.error("Sync refused (503): identity protection keys unreadable "
                 "(seal_id=%r event_id=%s)", seal_id, event_id)
    return _sync_error(_MSG_KEYS_MISSING, 503)


def _claim_nonce(envelope: VerifiedSyncEnvelope, seal_id: str,
                 event_id: int) -> None:
    """Record the envelope's nonce; a used one rolls everything back."""
    if not claim_sync_nonce(
        nonce=envelope.nonce, seal_id=seal_id, event_id=event_id,
        sent_at=envelope.sent_at_iso, expires_at=nonce_expiry(envelope),
        received_at=utc_now().isoformat(),
    ):
        raise SyncNonceReused(envelope.nonce)


def _resubmission(
    stored: dict[str, Any], record_obj: Any, admission: _Admission,
    existing: tuple[str, str],
) -> tuple[Any, int]:
    """Decide on a second submission for an event that already has a record."""
    seal_id, event_id = stored["seal_id"], stored["event_id"]
    existing_type, existing_json = existing
    if existing_type == stored["event_type"] and _same_record(
        existing_json, record_obj
    ):
        return _identical_resubmission(stored, admission)
    if admission.digest and not _authenticated(existing_json, seal_id):
        _refuse_copy(seal_id, event_id, record_obj, admission)
        refusal = _generation_refusal(seal_id, event_id, admission)
        if refusal is not None:
            return refusal
        return _displacement(stored, admission, existing_json)
    return _event_conflict(seal_id, event_id)


def _refuse_copy(seal_id: str, event_id: int, record_obj: Any,
                 admission: _Admission) -> None:
    """Raise :class:`SyncRecordCopied` for an authenticated record that is an
    exact copy of one the seal stores under another event id.

    Called before a new event is stored and before a displacement (under
    the lock). An exact copy carries the same policy, so comparing with
    every stored record finds the same matches as comparing with those of
    the same digest, without parsing their policies. A stored record that
    does not decrypt (``''``) never matches; one from before E3b raises
    :class:`LegacyRecordError` (503).
    """
    if admission.digest is None:
        return
    incoming = _canonical_json(record_obj)
    for stored_event_id, stored_json in find_record_jsons_newest_first(seal_id):
        if stored_event_id != event_id and _canonical_text(stored_json) == incoming:
            raise SyncRecordCopied(stored_event_id)


def _identical_resubmission(
    stored: dict[str, Any], admission: _Admission
) -> tuple[Any, int]:
    """Add a missing wrapped s3 or enrollment; refuse a different wrapped s3."""
    outcome = complete_synced_record(
        seal_id=stored["seal_id"], event_id=stored["event_id"],
        wrapped_s3=stored["wrapped_s3"], enrolled_digest=admission.digest,
    )
    if outcome == SYNC_ENVELOPE_CONFLICT:
        logger.warning("Sync refused: a different wrapped_s3 is already stored "
                       "for seal_id=%s event_id=%s",
                       stored["seal_id"], stored["event_id"])
        return _sync_error(
            "같은 기록에 다른 wrapped_s3가 이미 있어 동기화를 거부합니다.", 409
        )
    _raise_mark(stored["seal_id"], stored["event_id"], admission)
    message = ("동기화 완료" if outcome == SYNC_COMPLETED
               else "이미 동기화된 기록입니다.")
    return jsonify({"status": "ok", "message": message}), 200


def _displacement(
    stored: dict[str, Any], admission: _Admission, existing_json: str
) -> tuple[Any, int]:
    """Replace an unauthenticated record, if it is still the one assessed."""
    seal_id, event_id = stored["seal_id"], stored["event_id"]
    if not replace_synced_record(**stored, enrolled_digest=admission.digest,
                                 expected_record_json=existing_json):
        return _event_conflict(seal_id, event_id)
    _raise_mark(seal_id, event_id, admission)
    logger.warning("Sync replaced an unauthenticated record with an "
                   "authenticated one: seal_id=%s event_id=%s",
                   seal_id, event_id)
    return jsonify({"status": "ok", "message": "동기화 완료"}), 200


def _generation_refusal(
    seal_id: str, event_id: int, admission: _Admission
) -> Optional[tuple[Any, int]]:
    """409 for a verified policy below the mark, or at it with another digest."""
    if admission.digest is None:
        return None
    mark = find_high_water(seal_id)
    if mark is None:
        return None
    if admission.generation < mark.generation:
        logger.warning("Sync refused: policy generation %d is below the "
                       "seal's high-water mark %d (rollback): seal_id=%s "
                       "event_id=%s", admission.generation, mark.generation,
                       seal_id, event_id)
        return _sync_error(
            "이 봉인에 이미 등록된 것보다 낮은 세대의 봉인 정책이라 동기화를 "
            "거부합니다 (롤백).", 409)
    if admission.generation == mark.generation and (
        admission.digest != mark.policy_digest
    ):
        logger.warning("Sync refused: another policy of generation %d is "
                       "already registered: seal_id=%s event_id=%s",
                       admission.generation, seal_id, event_id)
        return _sync_error(
            "같은 세대의 다른 봉인 정책이 이미 등록되어 있어 동기화를 "
            "거부합니다.", 409)
    return None


def _bootstrap_mark(seal_id: str) -> None:
    """Give a seal without a mark the one its stored records imply.

    Records stored before E2a, while no CA was pinned, or out of band have
    no mark. Before the first decision on a verified policy, the stored
    records are read (under the lock) and the mark is set to the highest
    authenticated generation among them, so a lower generation arriving
    first cannot become the mark.
    """
    if find_high_water(seal_id) is not None:
        return
    ca_path = (current_app.config.get("POLICY_CA_CERT_PATH") or "").strip()
    top = stored_maximum(seal_id, find_record_jsons_newest_first,
                         ca_path=ca_path or None)
    if top is None:
        return
    generation, digest, event_id = top
    seed_high_water(seal_id=seal_id, generation=generation,
                    policy_digest=digest, event_id=event_id,
                    updated_at=utc_now().isoformat())
    logger.info("Sync set the high-water mark from stored records: "
                "seal_id=%s generation=%d event_id=%d",
                seal_id, generation, event_id)


def _raise_mark(seal_id: str, event_id: int, admission: _Admission) -> None:
    """Set or raise the seal's generation mark (inside the transaction)."""
    if admission.digest is None:
        return
    raise_high_water(seal_id=seal_id, generation=admission.generation,
                     policy_digest=admission.digest, event_id=event_id,
                     updated_at=utc_now().isoformat())


def _prune_nonces() -> None:
    """Drop expired nonces (best effort, after the submission committed)."""
    try:
        prune_sync_nonces(int(utc_now().timestamp()))
    except Exception:
        logger.warning("Sync nonce pruning failed", exc_info=True)


def _event_conflict(seal_id: str, event_id: int) -> tuple[Any, int]:
    logger.warning("Sync refused: a different record already exists for "
                   "seal_id=%s event_id=%s", seal_id, event_id)
    return _sync_error(
        "같은 event_id에 다른 기록이 이미 있어 동기화를 거부합니다.", 409
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _canonical_text(record_json: str) -> Optional[str]:
    """The canonical form of a stored record, or ``None`` if it is not JSON."""
    try:
        return _canonical_json(json.loads(record_json))
    except (TypeError, ValueError):
        return None


def _same_record(existing_json: str, record_obj: Any) -> bool:
    """Whether the stored and the resubmitted record are the same JSON.

    Key order and whitespace do not matter; value types do: ``true``,
    ``1`` and ``1.0`` differ, as they do for the policy schema.
    """
    existing = _canonical_text(existing_json)
    try:
        return existing is not None and existing == _canonical_json(record_obj)
    except (TypeError, ValueError):
        return False


def _authenticated(record_json: str, seal_id: str) -> bool:
    """Whether a stored record carries a verified (or only expired) policy."""
    try:
        record = json.loads(record_json)
    except (TypeError, ValueError):
        return False
    if not isinstance(record, dict):
        return False
    ca_path = (current_app.config.get("POLICY_CA_CERT_PATH") or "").strip()
    assessment = assess_record_policy(
        record, ca_cert_path=ca_path or None, expected_seal_id=seal_id,
    )
    return assessment.status in (POLICY_VERIFIED, POLICY_EXPIRED)


def _assess_policy(
    seal_id: str, record_obj: Any
) -> tuple[_Admission, Optional[tuple[Any, int]]]:
    """Verify the incoming record's policy (before the seal's lock is taken).

    Returns:
        ``(admission, None)`` when the record may go on to admission, or
        ``(admission, error_response)`` when its policy fails verification.
        Whether an unauthenticated record is admitted depends on
        enrollment, which is checked under the lock.
    """
    record = record_obj if isinstance(record_obj, dict) else {}
    ca_path = (current_app.config.get("POLICY_CA_CERT_PATH") or "").strip()
    assessment = assess_record_policy(
        record, ca_cert_path=ca_path or None, expected_seal_id=seal_id,
    )
    if assessment.status in (POLICY_VERIFIED, POLICY_EXPIRED) and (
        assessment.policy is not None
    ):
        policy = assessment.policy
        return _Admission(policy.digest_hex, policy.generation), None
    if assessment.status == POLICY_INVALID:
        logger.warning("Sync refused: seal policy fails verification "
                       "(seal_id=%s): %s", seal_id, assessment.detail)
        return _Admission(None), _sync_error(
            "record_json의 봉인 정책을 검증할 수 없어 동기화를 거부합니다.", 422
        )
    return _Admission(None), None


def _auth_error(failure: AuthFailure, fields: dict[str, Any]) -> tuple[Any, int]:
    """Refuse an unauthenticated submission; the cause goes to the log only."""
    logger.warning("Sync refused (%d): %s (seal_id=%r event_id=%s)",
                   failure.status, failure.cause, _clip(fields["seal_id"]),
                   fields["event_id"])
    return _sync_error(failure.message, failure.status)


def _clip(text: str) -> str:
    return text[:_MAX_LOG_ID_LEN]


def _sync_error(message: str, status: int) -> tuple[Any, int]:
    return jsonify({"status": "error", "message": message}), status


def _decode_record_pdf(
    value: Any,
) -> tuple[Optional[bytes], Optional[tuple[Any, int]]]:
    """Decode the optional PDF (type/length validated before decoding)."""
    if not value:
        return None, None
    if not isinstance(value, str):
        return None, _sync_error("record_pdf는 base64 문자열이어야 합니다.", 400)
    if len(value) > MAX_PDF_B64_LENGTH:
        return None, _sync_error("record_pdf가 허용 크기를 초과했습니다.", 413)
    try:
        return base64.b64decode(value, validate=True), None
    except Exception:
        return None, _sync_error("record_pdf의 base64 디코딩에 실패했습니다.", 400)


def _decode_wrapped_s3(
    value: Any, event_type: str, seal_id: str, record_obj: Any
) -> tuple[Optional[bytes], Optional[tuple[Any, int]]]:
    """Validate the optional ``wrapped_s3`` field.

    Returns:
        ``(ciphertext, None)`` when present and valid, ``(None, None)``
        when absent, or ``(None, error_response)``.
    """
    if value is None or value == "":
        return None, None
    if not isinstance(value, str):
        return None, _sync_error("wrapped_s3는 base64 문자열이어야 합니다.", 400)
    if len(value) > MAX_WRAPPED_S3_B64_LENGTH:
        return None, _sync_error("wrapped_s3가 허용 크기를 초과했습니다.", 413)
    if event_type not in _WRAPPED_S3_EVENTS:
        return None, _sync_error(
            "wrapped_s3는 Sealing/Resealing 기록에만 첨부할 수 있습니다.", 400
        )
    if not isinstance(record_obj, dict) or record_obj.get("seal_id") != seal_id:
        return None, _sync_error(
            "wrapped_s3를 첨부한 record_json의 seal_id가 요청과 일치하지 "
            "않습니다.", 400
        )
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None, _sync_error("wrapped_s3의 base64 디코딩에 실패했습니다.", 400)
    if len(decoded) < _MIN_WRAPPED_S3_BYTES:
        return None, _sync_error("wrapped_s3의 길이가 올바르지 않습니다.", 400)
    return decoded, None
