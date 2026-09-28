"""Which stored record a release decision rests on (stage E, E2a).

Split from :mod:`web.release_gate` (whose ``_resolve_policy`` calls
:func:`select_record` with its own record reader). The rule is described
under "Record selection" in that module's docstring:

  - candidates are the records whose policy authenticates (verified, or
    only expired); records without one are ignored;
  - with a high-water mark (``policy_high_water``), the decision rests on
    the newest record carrying exactly the mark's policy (its digest).
    Records are read newest first and the reading stops there. Any other
    authenticated record -- below the mark (an older generation replayed
    later) or at or above it with another policy (written outside sync
    admission) -- is ignored and counted in the audit detail;
  - without a mark, every record is read and the decision rests on the
    highest generation (version-1 policies count as 0), the newest event
    among equals. That record then seeds the mark (:func:`_backfill_mark`),
    so later releases read only down to it.

The mark equals the highest generation among the seal's stored
authenticated records: sync admission bootstraps it from the stored
records (:func:`stored_maximum`) before its first decision, refuses a
policy below it or another digest at it, and raises it with every store.
A seal with a mark or an enrollment and no record carrying a usable
policy is denied on every path; only a seal with neither falls back to
the newest record (v1.0.1).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

from desktop.signature.seal_policy import (
    POLICY_EXPIRED,
    POLICY_INVALID,
    POLICY_UNVERIFIABLE,
    POLICY_VERIFIED,
    VerifiedPolicy,
    assess_record_policy,
)

from .models.release_models import enroll_seal, is_policy_enrolled
from .models.sync_models import HighWaterMark, find_high_water, seed_high_water

logger = logging.getLogger(__name__)

STATUS_NO_RECORD = "record_missing"
STATUS_UNREADABLE = "record_unreadable"

_AUTHENTIC_STATUSES = frozenset({POLICY_VERIFIED, POLICY_EXPIRED})

RecordReader = Callable[[str], Iterable[tuple[int, str]]]


@dataclass(frozen=True)
class Selection:
    """The classified record a decision rests on."""

    status: str
    policy: Optional[VerifiedPolicy] = None
    detail: str = ""
    enrolled: bool = False


@dataclass(frozen=True)
class _Scan:
    """What one pass over the records found."""

    chosen: Optional[tuple[int, Selection]] = None
    newest: Optional[Selection] = None
    unauthenticated: tuple[int, ...] = ()   # their event ids
    lower_generation: int = 0
    below_mark: int = 0
    other_policy: int = 0


def select_record(
    seal_id: str, read_records: RecordReader, *, ca_path: Optional[str]
) -> Selection:
    """The record a release decision on ``seal_id`` rests on.

    Args:
        seal_id: The seal.
        read_records: Yields ``(event_id, record_json)`` newest first.
        ca_path: The pinned CA bundle, or None when none is configured.
    """
    mark = find_high_water(seal_id)
    records = read_records(seal_id)
    if mark is None:
        scan = _scan_all(records, seal_id, ca_path)
    else:
        scan = _scan_to_mark(records, seal_id, ca_path, mark)
    if scan.chosen is not None:
        event_id, found = scan.chosen
        _enroll(seal_id, event_id, found)
        if mark is None:
            _backfill_mark(seal_id, event_id, found)
        return Selection(found.status, found.policy,
                         _join(found.detail, _note(scan, mark)))
    if mark is not None or is_policy_enrolled(seal_id):
        return _enrolled_denial(ca_path, _note(scan, mark))
    return scan.newest or Selection(STATUS_NO_RECORD)


def stored_maximum(
    seal_id: str, read_records: RecordReader, *, ca_path: Optional[str]
) -> Optional[tuple[int, str, int]]:
    """``(generation, policy digest, event id)`` of the stored record with
    the highest authenticated generation (newest among equals), if any.

    Used by sync admission to bootstrap a missing mark.
    """
    scan = _scan_all(read_records(seal_id), seal_id, ca_path)
    if scan.chosen is None:
        return None
    event_id, found = scan.chosen
    return found.policy.generation, found.policy.digest_hex, event_id


def classify_record(
    record_json: Any, seal_id: str, ca_path: Optional[str]
) -> Selection:
    """Parse one stored record and classify its policy."""
    try:
        record = json.loads(record_json)
    except (TypeError, ValueError):
        return Selection(STATUS_UNREADABLE, detail="record_json unreadable")
    if not isinstance(record, dict):
        return Selection(STATUS_UNREADABLE,
                         detail="record_json is not an object")
    assessment = assess_record_policy(
        record, ca_cert_path=ca_path, expected_seal_id=seal_id,
    )
    return Selection(assessment.status, assessment.policy, assessment.detail)


def _authentic(found: Selection) -> bool:
    return found.status in _AUTHENTIC_STATUSES and found.policy is not None


def _scan_all(
    records: Iterable[tuple[int, str]], seal_id: str, ca_path: Optional[str],
) -> _Scan:
    """Read every record; keep the highest generation, newest among equals."""
    chosen: Optional[tuple[int, Selection]] = None
    newest: Optional[Selection] = None
    unauthenticated: list[int] = []
    generations: list[int] = []
    for event_id, record_json in records:
        found = classify_record(record_json, seal_id, ca_path)
        newest = newest or found
        if not _authentic(found):
            unauthenticated.append(event_id)
            continue
        generations.append(found.policy.generation)
        if chosen is None or found.policy.generation > chosen[1].policy.generation:
            chosen = (event_id, found)
    top = chosen[1].policy.generation if chosen else 0
    return _Scan(chosen, newest, tuple(unauthenticated),
                 lower_generation=sum(1 for g in generations if g < top))


def _scan_to_mark(
    records: Iterable[tuple[int, str]], seal_id: str, ca_path: Optional[str],
    mark: HighWaterMark,
) -> _Scan:
    """Read newest first until the record carrying the mark's policy."""
    unauthenticated: list[int] = []
    below = other = 0
    newest: Optional[Selection] = None
    for event_id, record_json in records:
        found = classify_record(record_json, seal_id, ca_path)
        newest = newest or found
        if not _authentic(found):
            unauthenticated.append(event_id)
        elif found.policy.digest_hex == mark.policy_digest:
            return _Scan((event_id, found), newest, tuple(unauthenticated),
                         below_mark=below, other_policy=other)
        elif found.policy.generation < mark.generation:
            below += 1
        else:
            other += 1
    return _Scan(None, newest, tuple(unauthenticated), below_mark=below,
                 other_policy=other)


def _note(scan: _Scan, mark: Optional[HighWaterMark]) -> str:
    """The audit detail on what the selection ignored."""
    notes = []
    newer = (sum(1 for e in scan.unauthenticated if e > scan.chosen[0])
             if scan.chosen else 0)
    if newer:
        notes.append(f"{newer} newer record(s) without an authenticated "
                     "policy ignored")
    if scan.lower_generation:
        notes.append(f"{scan.lower_generation} authenticated record(s) of a "
                     "lower generation ignored")
    if scan.below_mark and mark is not None:
        notes.append(f"{scan.below_mark} authenticated record(s) below the "
                     f"high-water mark (generation {mark.generation}) ignored")
    if scan.other_policy:
        notes.append(f"{scan.other_policy} authenticated record(s) at or "
                     "above the high-water mark with another policy ignored")
    return "; ".join(notes)


def _enrolled_denial(ca_path: Optional[str], note: str) -> Selection:
    """An enrolled seal (or one with a mark) never falls back to v1.0.1."""
    if not ca_path:
        return Selection(
            POLICY_UNVERIFIABLE, enrolled=True,
            detail=_join("seal enrolled with an authenticated policy; no "
                         "pinned CA configured to verify it", note),
        )
    return Selection(
        POLICY_INVALID, enrolled=True,
        detail=_join("seal enrolled with an authenticated policy, but no "
                     "stored record carrying it verifies", note),
    )


def _enroll(seal_id: str, event_id: int, found: Selection) -> None:
    """Enroll a seal whose stored record authenticates (backfill).

    Records stored before enrollment existed, or while no CA was pinned,
    are enrolled the first time a release authenticates them, so removing
    the CA later cannot reopen the unauthenticated fallback. A failed
    write is logged and does not decide the release.
    """
    if found.policy is None:
        return
    try:
        enroll_seal(seal_id, event_id, found.policy.digest_hex)
    except Exception:
        logger.warning("Enrollment write failed: seal_id=%r",
                       seal_id[:200], exc_info=True)


def _backfill_mark(seal_id: str, event_id: int, found: Selection) -> None:
    """Seed the mark from a full scan (the one mark write outside the lock).

    It only inserts when the seal has no mark, and every sync admission of
    a verified policy creates or raises the mark itself under the seal's
    write lock, so a concurrent admission is never lowered. A failed write
    is logged and does not decide the release.
    """
    try:
        seed_high_water(
            seal_id=seal_id, generation=found.policy.generation,
            policy_digest=found.policy.digest_hex, event_id=event_id,
            updated_at=datetime.now(tz=timezone.utc).isoformat(),
            commit=True,
        )
    except Exception:
        logger.warning("High-water mark backfill failed: seal_id=%r",
                       seal_id[:200], exc_info=True)


def _join(first: str, second: str) -> str:
    return "; ".join(part for part in (first, second) if part)
