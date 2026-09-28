"""Conversion of stored seal records to the encrypted form (stage E, E3b).

Run by ``python -m src.web.privacy.migrate`` (:mod:`web.privacy.migrate`)
after the identity conversion of the ``cases`` rows and before the SQLite
scrub. Each ``seal_records`` row stored before E3b (``record_scheme <>
'v1'``) is converted in one transaction under the seal's write lock
(:func:`web.models.release_models.seal_write_transaction`):

  1. re-read the row inside the lock (skip it if converted meanwhile);
  2. take the seal's data key: the stored one unwrapped, or -- when the
     seal's case exists but has none (a case registered before E3a whose
     identity is not converted yet) -- a new one, wrapped and inserted in
     the same transaction; the identity conversion later reuses it. A row
     whose seal has no case is reported and skipped: ``seal_data_keys``
     refers to ``cases``, so no key can be stored for it. A seal that
     already holds protected data (identity or records) but has lost its
     key row gets no new key: its rows are refused, keep their plaintext,
     and are reported (:func:`write_missing_keys`);
  3. encrypt ``record_json`` (the UTF-8 of the stored text) and
     ``record_pdf`` and write both ciphertexts with ``record_scheme = 'v1'``;
  4. read the row back and decrypt each column; the result must equal the
     stored plaintext byte for byte. Each verification decryption appends
     an ``identity_access_audit`` row (purpose ``migration_verify``, actor
     role ``system``, actor ``privacy-migrate``) in the same transaction;
  5. commit, which replaces the plaintext. Any failure rolls the row back
     (plaintext, data key and audit rows together) and reports it.

A converted row is never touched again. No record content is printed or
logged: only counts, seal IDs and event numbers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, TextIO

from ..models.privacy_models import (
    OUTCOME_REVEALED,
    IdentityAccessEntry,
    find_data_key_use,
    find_wrapped_data_key,
    insert_identity_access_uncommitted,
)
from ..models.record_models import (
    RECORD_SCHEME_V1,
    StoredRecord,
    count_plaintext_record_rows,
    find_stored_record_by_id,
    survey_record_rows,
    write_sealed_record,
)
from ..models.release_models import seal_write_transaction
from .case_identity import PURPOSE_MIGRATION_CHECK, utc_now_iso
from .keys import PrivacyKeys
from .record_crypto import (
    COLUMN_JSON,
    COLUMN_PDF,
    open_record_json,
    open_record_pdf,
    seal_record_json,
    seal_record_pdf,
)
from .record_store import CaseNotRegistered, DataKeyMissing, data_key_for_write

logger = logging.getLogger(__name__)

ACTOR = "privacy-migrate"
CONVERTED = "converted"
UNCHANGED = "unchanged"
NO_CASE = "no_case"
KEY_MISSING = "key_missing"
FAILED = "failed"
_LOG_ID_LIMIT = 200


class RecordRoundTripError(Exception):
    """A converted row does not read back as its plaintext (no values here)."""


@dataclass(frozen=True)
class RecordOutcome:
    """What the conversion of one row did (no content)."""

    seal_id: str
    event_id: int
    status: str
    key_created: bool = False


def write_survey(out: TextIO) -> int:
    """Print the record counts; returns how many rows are still plaintext."""
    rows = survey_record_rows()
    pending = sum(1 for row in rows if row.scheme != RECORD_SCHEME_V1)
    out.write(f"봉인 기록 {len(rows)}건: 보호됨 {len(rows) - pending}건, "
              f"암호화 대상 {pending}건\n")
    return pending


def convert_records(keys: PrivacyKeys) -> list[RecordOutcome]:
    """Convert every row stored before E3b; one outcome per such row."""
    pending = [row for row in survey_record_rows() if row.scheme != RECORD_SCHEME_V1]
    return [_convert(row.row_id, row.seal_id, row.event_id, keys) for row in pending]


def write_results(outcomes: list[RecordOutcome], out: TextIO) -> bool:
    """Print the results (seal IDs and events only); True when none remain."""
    count = {status: sum(1 for o in outcomes if o.status == status)
             for status in (CONVERTED, FAILED, NO_CASE, KEY_MISSING)}
    out.write(f"봉인 기록: 암호화 {count[CONVERTED]}건, 실패 {count[FAILED]}건, "
              f"사건 없어 건너뜀 {count[NO_CASE]}건, "
              f"데이터 키 없어 거부 {count[KEY_MISSING]}건\n")
    created = len({o.seal_id for o in outcomes if o.key_created})
    if created:
        out.write(f"기록 암호화를 위해 데이터 키를 새로 만든 봉인: {created}건\n")
    for outcome in outcomes:
        if outcome.status == FAILED:
            out.write(f"  봉인 기록 실패 (평문 유지): {outcome.seal_id!r} "
                      f"이벤트 {outcome.event_id}\n")
        elif outcome.status == NO_CASE:
            out.write(f"  봉인 기록 건너뜀 (등록된 사건 없음, 평문 유지): "
                      f"{outcome.seal_id!r} 이벤트 {outcome.event_id}\n")
        elif outcome.status == KEY_MISSING:
            out.write(f"  봉인 기록 거부 (보호된 봉인의 데이터 키 없음, 평문 유지): "
                      f"{outcome.seal_id!r} 이벤트 {outcome.event_id}\n")
    remaining = count_plaintext_record_rows()
    out.write(f"평문이 남은 봉인 기록 행: {remaining}건\n")
    return (remaining == 0 and not count[FAILED] and not count[NO_CASE]
            and not count[KEY_MISSING])


def write_missing_keys(seal_ids: Iterable[str], out: TextIO) -> int:
    """Name the seals that hold protected data but have lost their key row.

    Checked against the database, for the seals the run could not convert
    (identity or records). No new key was created for them; returns how
    many there are.
    """
    missing = [seal_id for seal_id in dict.fromkeys(seal_ids) if _key_lost(seal_id)]
    if missing:
        out.write(f"데이터 키가 없는 보호된 봉인 {len(missing)}건: 새 키를 만들지 "
                  "않았습니다. seal_data_keys 행을 백업에서 복구한 뒤 다시 실행해 "
                  "주세요.\n")
    for seal_id in missing:
        out.write(f"  데이터 키 없음: {seal_id!r}\n")
    return len(missing)


def _key_lost(seal_id: str) -> bool:
    if find_wrapped_data_key(seal_id) is not None:
        return False
    use = find_data_key_use(seal_id)
    return use is not None and use.protected


def _convert(row_id: int, seal_id: str, event_id: int, keys: PrivacyKeys) -> RecordOutcome:
    """Convert one row in one transaction; rolled back on any failure."""
    try:
        with seal_write_transaction(seal_id):
            stored = find_stored_record_by_id(row_id)
            if stored is None or stored.protected:
                return RecordOutcome(seal_id, event_id, UNCHANGED)
            data_key, created = data_key_for_write(seal_id, keys)
            _encrypt_row(stored, data_key)
            _verify_round_trip(stored, data_key)
    except CaseNotRegistered:
        logger.warning("Seal record not converted: no case for seal_id=%r "
                       "(event_id=%s); it keeps its plaintext",
                       seal_id[:_LOG_ID_LIMIT], event_id)
        return RecordOutcome(seal_id, event_id, NO_CASE)
    except DataKeyMissing:  # logged at ERROR by data_key_for_write
        return RecordOutcome(seal_id, event_id, KEY_MISSING)
    except Exception as exc:
        logger.error("Seal record migration failed for seal_id=%r event_id=%s "
                     "(%s); the row keeps its plaintext", seal_id[:_LOG_ID_LIMIT],
                     event_id, type(exc).__name__)
        return RecordOutcome(seal_id, event_id, FAILED)
    logger.info("Seal record migrated: seal_id=%r event_id=%s",
                seal_id[:_LOG_ID_LIMIT], event_id)
    return RecordOutcome(seal_id, event_id, CONVERTED, created)


def _encrypt_row(stored: StoredRecord, data_key: bytes) -> None:
    sealed_json = seal_record_json(data_key, stored.seal_id, stored.event_id,
                                   stored.record_json)
    sealed_pdf = (None if stored.record_pdf is None else
                  seal_record_pdf(data_key, stored.seal_id, stored.event_id,
                                  stored.record_pdf))
    if write_sealed_record(stored.row_id, sealed_json, sealed_pdf) != 1:
        raise RecordRoundTripError("the row changed while it was converted")


def _verify_round_trip(original: StoredRecord, data_key: bytes) -> None:
    """Read the row back; each column must decrypt to the original bytes."""
    stored = find_stored_record_by_id(original.row_id)
    if stored is None or not stored.protected:
        raise RecordRoundTripError("the converted row did not read back")
    text = open_record_json(data_key, stored.seal_id, stored.event_id,
                            stored.record_json)
    _audit_verification(stored, COLUMN_JSON)
    if text.encode("utf-8") != original.record_json.encode("utf-8"):
        raise RecordRoundTripError("a record does not decrypt to its plaintext")
    if original.record_pdf is None:
        if stored.record_pdf is not None:
            raise RecordRoundTripError("a PDF was stored for a record without one")
        return
    pdf = open_record_pdf(data_key, stored.seal_id, stored.event_id, stored.record_pdf)
    _audit_verification(stored, COLUMN_PDF)
    if pdf != bytes(original.record_pdf):
        raise RecordRoundTripError("a PDF does not decrypt to its plaintext")


def _audit_verification(stored: StoredRecord, column: str) -> None:
    insert_identity_access_uncommitted(IdentityAccessEntry(
        seal_id=stored.seal_id, field_name=column, purpose=PURPOSE_MIGRATION_CHECK,
        actor_role="system", outcome=OUTCOME_REVEALED, created_at=utc_now_iso(),
        actor=ACTOR,
    ))
