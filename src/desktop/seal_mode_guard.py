"""Seal-mode and seal-ID guards for resealing and unsealing (stage E, E1).

Resealing keeps the mode of the previous record and never falls back to
standard: the mode is read with :func:`desktop.record.seal_mode_of`
(unknown, or different from the record's signed policy: refused) and
compared with the record this desktop stored for the seal. A strict record
always carries a signed policy. Unsealing replaces that stored record (U7),
so U3 and U7 require the fields an unsealing carries unchanged (mode, time
lock, key commitment, policy) to equal the stored ones, and U3 refuses a
record older than the stored one: the stored history must be the start of
the loaded record's (U7 checks it again under the write lock; E2e). R1
applies the same history rule before a reseal starts (E2f); R8 checks it
again under the write lock. A seal_id read from a record file must be a
plain token before output file names are built from it.

These are guards against a wrong, stripped or edited record *file*. The
desktop holds no trust anchor to authenticate a record: a policy's
signature is not verified here, and an insider who controls the desktop
(including its policy key and database) is out of scope.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from typing import Any, Optional

logger = logging.getLogger(__name__)


def require_safe_seal_id(seal_id: Any, label: str) -> None:
    """Refuse a seal_id that is not a plain file-name token.

    Args:
        seal_id: The ID read from a record file.
        label: What was read, for the message (e.g. "기록지", "봉인지").

    Raises:
        ValueError: When the ID contains anything but letters, digits and
            hyphens, or is longer than 64 characters.
    """
    from .record import is_safe_seal_id

    if not is_safe_seal_id(seal_id):
        raise ValueError(f"{label}의 seal_id 형식이 올바르지 않습니다: {seal_id!r}")


def carried_seal_mode(record: dict[str, Any]) -> str:
    """The seal mode a reseal of ``record`` must keep.

    Raises:
        ValueError: When the mode is unknown or differs from the record's
            signed policy (see :func:`desktop.record.seal_mode_of`).
    """
    from .record import RecordValidationError, seal_mode_of

    try:
        return seal_mode_of(record)
    except RecordValidationError as exc:
        raise ValueError(f"봉인 모드를 확인할 수 없습니다: {exc}") from exc


def stored_record(db_path: str, seal_id: str) -> Optional[dict[str, Any]]:
    """The record this desktop stored for ``seal_id``, if any.

    None only when there is nothing to compare: no database file (it is
    not created by asking), a database without the table, no row, or a
    case registered but not yet sealed (its placeholder has no seal_id). A
    database or stored record that cannot be read refuses instead of
    skipping the comparison.

    Raises:
        ValueError: When the stored record cannot be read.
    """
    from .db import get_seal_record

    if db_path != ":memory:" and not os.path.exists(db_path):
        logger.warning("No stored records to compare for %s (no database)", seal_id)
        return None
    try:
        row = get_seal_record(db_path, seal_id)
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc):
            raise ValueError(
                f"이 PC의 기록 DB를 읽을 수 없어 봉인 모드를 확인할 수 "
                f"없습니다 ({seal_id}): {exc}"
            ) from exc
        logger.warning("No stored records to compare for %s", seal_id)
        return None
    except (sqlite3.Error, ValueError) as exc:  # incl. JSONDecodeError
        raise ValueError(
            f"이 PC에 저장된 기록을 읽을 수 없어 봉인 모드를 확인할 수 "
            f"없습니다 ({seal_id}): {exc}"
        ) from exc
    record = row.get("record_json") if row else None
    if not isinstance(record, dict) or record.get("seal_id") != seal_id:
        return None
    return record


def stored_seal_mode(db_path: str, seal_id: str) -> Optional[str]:
    """Mode of the record this desktop stored for ``seal_id``, if any.

    None when there is nothing to compare (see :func:`stored_record`).

    Raises:
        ValueError: When the stored record cannot be read, or its own mode
            cannot be determined.
    """
    record = stored_record(db_path, seal_id)
    return None if record is None else carried_seal_mode(record)


# Fixed when a seal or reseal is signed; an unsealing carries them unchanged.
GOVERNING_FIELDS = (
    "seal_mode", "unlock_time_iso", "key_commitment",
    "policy", "policy_signature", "policy_cert",
)


def governing_fields(record: dict[str, Any]) -> dict[str, Any]:
    """The :data:`GOVERNING_FIELDS` of ``record``, normalized for comparison.

    ``seal_mode`` is read with :func:`carried_seal_mode` (a legacy record
    without one is standard); a missing time lock or commitment is "".

    Raises:
        ValueError: When the mode is unknown or differs from the record's
            signed policy.
    """
    return {
        "seal_mode": carried_seal_mode(record),
        "unlock_time_iso": record.get("unlock_time_iso") or "",
        "key_commitment": record.get("key_commitment") or "",
        "policy": record.get("policy"),
        "policy_signature": record.get("policy_signature"),
        "policy_cert": record.get("policy_cert"),
    }


def _require_same_governing_fields(
    reference: dict[str, Any], record: dict[str, Any], problem: str
) -> None:
    """Refuse ``record`` unless its governing fields equal ``reference``'s."""
    before, after = governing_fields(reference), governing_fields(record)
    changed = [name for name in GOVERNING_FIELDS if before[name] != after[name]]
    if not changed:
        return
    detail = ", ".join(changed)
    if "seal_mode" in changed:
        detail += f"; 모드 '{before['seal_mode']}' → '{after['seal_mode']}'"
    raise ValueError(f"{problem} ({detail}).")


def check_unseal_record(db_path: str, record: dict[str, Any]) -> Optional[str]:
    """U3: the record loaded for an unsealing, checked as at R1 and more.

    The mode must be readable and agree with the record's signed policy.
    When this desktop stored a record for the seal, the loaded record's
    :data:`GOVERNING_FIELDS` must equal the stored ones: U7 replaces the
    stored record, which the reseal (R1) downgrade guard trusts. An edited
    or stripped file is refused, as is an older record that the stored one
    has since replaced (e.g. the sealing record after a reseal, or after an
    unsealing on this desktop: its history lacks the stored events).

    Returns:
        ``"stored"`` (compared with this desktop's record) or None (nothing
        stored for the seal: the file is checked on its own).

    Raises:
        ValueError: On an unreadable or inconsistent mode, or a mismatch.
    """
    governing_fields(record)
    stored = stored_record(db_path, record["seal_id"])
    if stored is None:
        return None
    _require_same_governing_fields(
        stored, record,
        "불러온 봉인지가 이 PC에 저장된 봉인 기록과 다릅니다. 수정된 파일이거나 "
        "이후 재봉인으로 대체된 이전 기록입니다",
    )
    _require_latest_history(stored, record)
    return "stored"


def _history_events(record: dict[str, Any]) -> Optional[list]:
    """History events; [] without a history; None when malformed."""
    history = record.get("history")
    if history is None:
        return []
    events = history.get("events", []) if isinstance(history, dict) else None
    return events if isinstance(events, list) else None


def _require_latest_history(
    stored: dict[str, Any], record: dict[str, Any], label: str = "봉인지"
) -> None:
    """U3 and R1: the loaded record is the stored one, or a later one.

    The stored history events must be the first events of the loaded
    record's (stage E, E2e for U3, E2f for R1). An older record (for
    example the sealing record after an unsealing on this desktop) would
    produce an event the stored record already has; U7 and R8 check the
    same rule again under the write lock.

    Raises:
        ValueError: On an older, diverged or unreadable history.
    """
    stored_events = _history_events(stored)
    loaded_events = _history_events(record)
    if stored_events is not None and loaded_events is not None and (
        loaded_events[: len(stored_events)] == stored_events
    ):
        return
    raise ValueError(
        f"불러온 {label}가 이 PC에 저장된 이 봉인의 최신 기록보다 이전 것이거나 "
        f"이력이 다릅니다 (저장된 이력 {_count(stored_events)}건, 불러온 {label} "
        f"{_count(loaded_events)}건). 이 봉인의 마지막 작업(봉인해제·재봉인)에서 "
        "만든 기록지 JSON으로 다시 진행하세요."
    )


def check_reseal_lineage(db_path: str, record: dict[str, Any]) -> None:
    """R1: the record to reseal is this desktop's stored record or a later one.

    The history rule of U3 (stage E, E2f). Without it a reseal from an
    older record was refused only when R8 saved it (``StaleRecordError``),
    after R5 had re-encrypted the files and R7 had handed out new shares.
    With nothing stored for the seal the file is checked on its own.

    Raises:
        ValueError: On an older, diverged or unreadable history, or an
            unreadable stored record.
    """
    stored = stored_record(db_path, record["seal_id"])
    if stored is not None:
        _require_latest_history(stored, record, label="기록지")


def _count(events: Optional[list]) -> str:
    return "?" if events is None else str(len(events))


def check_unseal_save(
    db_path: str, loaded: dict[str, Any], unseal_record: dict[str, Any]
) -> None:
    """U7: the unseal record may replace the stored one only unchanged.

    Its :data:`GOVERNING_FIELDS` must equal those of the record loaded at
    U3 and, read again now, those of this desktop's stored record.

    Raises:
        ValueError: On a mismatch; nothing is saved.
    """
    _require_same_governing_fields(
        loaded, unseal_record,
        "봉인해제 기록이 불러온 봉인지와 다르게 만들어져 저장하지 않았습니다",
    )
    stored = stored_record(db_path, unseal_record["seal_id"])
    if stored is not None:
        _require_same_governing_fields(
            stored, unseal_record,
            "U3 이후 이 PC에 저장된 봉인 기록이 바뀌어 봉인해제 기록을 저장하지 "
            "않았습니다",
        )


def resolve_reseal_mode(
    db_path: str, record: dict[str, Any]
) -> tuple[str, Optional[str]]:
    """The mode a reseal of ``record`` keeps, and what confirmed it.

    Returns:
        ``(mode, source)``; source is ``"stored"`` (this desktop's stored
        record), ``"policy"`` (the record's consistency-checked policy) or
        None (nothing but the file).

    Raises:
        ValueError: On an unreadable, inconsistent or downgraded mode.
    """
    mode = carried_seal_mode(record)
    stored = stored_seal_mode(db_path, record["seal_id"])
    if stored is not None and stored != mode:
        raise ValueError(
            f"봉인 모드 불일치: 불러온 기록은 '{mode}', 이 PC에 저장된 "
            f"기록은 '{stored}'입니다. 모드를 바꾸는 재봉인은 허용하지 "
            f"않습니다 (seal_mode mismatch)."
        )
    if stored is not None:
        return mode, "stored"
    return mode, ("policy" if "policy" in record else None)


def require_policy_for_strict(record: dict[str, Any], policy_digest: Any) -> None:
    """As at sealing (S4): a strict reseal record carries a signed policy.

    Raises:
        ValueError: When the record is strict and no policy was signed.
    """
    if record.get("seal_mode") == "strict" and policy_digest is None:
        raise ValueError(
            "strict 봉인을 재봉인하려면 서명된 봉인 정책(policy)이 "
            "필요합니다: 기관 정책 키(ENC_ENVELOPE_POLICY_KEY_PATH / "
            "ENC_ENVELOPE_POLICY_CERT_PATH)를 설정하세요."
        )


def split_mode(prev_record: dict[str, Any], new_record: dict[str, Any]) -> str:
    """The mode R7 splits by: the new (R6) record's, equal to the carried one.

    Raises:
        ValueError: When either mode is unreadable or they differ.
    """
    carried = carried_seal_mode(prev_record)
    mode = carried_seal_mode(new_record)
    if mode != carried:
        raise ValueError(
            f"R7 봉인 모드 불일치: 이전 기록 '{carried}', 재봉인 기록 "
            f"'{mode}' (seal_mode mismatch)"
        )
    return mode
