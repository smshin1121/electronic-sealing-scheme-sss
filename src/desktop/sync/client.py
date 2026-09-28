"""The desktop sync client: one outbox, two backends (stage E, E2a, E2d, E2e).

Sealing (S7), Unsealing (U7) and Resealing (R8) prepare a delivery intent
(:func:`prepare_sync`) before they save the record locally. The intent
holds the immutable event snapshot (the record exactly as saved, the PDF
bytes, the wrapped s3) and the backends configured at that moment
(:mod:`desktop.sync.backends`). Its rows are written to the desktop SQLite
outbox (:mod:`desktop.sync.outbox`) inside the transaction that saves the
record (:meth:`SyncIntent.write`), so the local event and its delivery
intent are committed together or not at all: a crash after the save
leaves a pending row, and a failed outbox insert fails the save (the step
reports the error and can be run again). The network push follows the
commit (:meth:`SyncIntent.deliver`), never raises into the process, and a
failed push stays pending (WARNING) until ``python -m desktop.sync retry``
sends it; every attempt is signed anew. An unconfigured backend is skipped
with one INFO line and nothing is queued for it.

One row per (seal, event, backend), and it is never replaced: when the
event is queued already, the save goes ahead only if the queued snapshot
is exactly the new one (event type, record JSON, PDF bytes and wrapped s3;
a re-run of the same step). Any other snapshot raises
:class:`SyncConflictError`, and the local save rolls back with it (E2e):
a record saved locally always has its own delivery queued or sent.

Order: the pending pushes of one seal and backend go out by event id, and
a failure stops the rest of that group, because the release host refuses
a policy generation below one it already admitted (an Unsealing record of
generation 1 sent after a Resealing record of generation 2 would be
refused as a rollback).

The event id and type come from the record itself: the last event of its
``history`` (``id`` 1, 2, ... and ``seal_type``). Logs name the seal, the
event, the backend and the error; never the record, identity values or
share material.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import groupby
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from . import outbox
from .backends import (
    DEFAULT_TIMEOUT,
    PortalBackend,
    SyncBackend,
    WebBackend,
)
from .outbox import (
    OutboxEntry,
    all_entries,
    pending_entries,
    record_failure,
    record_success,
)

logger = logging.getLogger(__name__)

_EVENT_TYPES = frozenset({"Sealing", "Unsealing", "Resealing"})


class SyncItemError(ValueError):
    """A completed record does not name its seal and current event."""


class SyncConflictError(ValueError):
    """The outbox holds another snapshot of this event; nothing was saved.

    The message is for the operator (Korean) and names the seal, the event,
    the backend and the queue state; never the record.
    """


@dataclass(frozen=True)
class SyncItem:
    """A completed event to push; payload fields are left out of ``repr``."""

    seal_id: str
    event_id: int
    event_type: str
    record_json: str = field(repr=False)
    record_pdf: Optional[bytes] = field(default=None, repr=False)
    wrapped_s3_b64: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class PushSummary:
    """One push run: delivered, failed, and still pending afterwards."""

    sent: int
    failed: int
    pending: int


def build_sync_item(
    *,
    event_type: str,
    record_json: str,
    pdf_path: Optional[str],
    wrapped_s3_b64: Optional[str] = None,
) -> SyncItem:
    """The item for a record the process has just saved.

    Raises:
        SyncItemError: When the record is not JSON, names no seal, or its
            last history event is not an ``event_type`` with an id >= 1.
    """
    if event_type not in _EVENT_TYPES:
        raise SyncItemError(f"unknown event type {event_type!r}")
    try:
        record = json.loads(record_json)
    except (TypeError, ValueError) as exc:
        raise SyncItemError("record_json is not JSON") from exc
    if not isinstance(record, dict) or not isinstance(
        record.get("seal_id"), str
    ) or not record["seal_id"]:
        raise SyncItemError("the record names no seal_id")
    return SyncItem(
        seal_id=record["seal_id"],
        event_id=_current_event_id(record, event_type),
        event_type=event_type, record_json=record_json,
        record_pdf=_read_pdf(pdf_path), wrapped_s3_b64=wrapped_s3_b64,
    )


def _current_event_id(record: Mapping[str, Any], event_type: str) -> int:
    """The id of the record's last history event, which must be this one."""
    history = record.get("history")
    events = history.get("events") if isinstance(history, Mapping) else None
    last = events[-1] if isinstance(events, list) and events else None
    event_id = last.get("id") if isinstance(last, Mapping) else None
    if type(event_id) is not int or event_id < 1:
        raise SyncItemError("the record's last history event has no id")
    if last.get("seal_type") != event_type:
        raise SyncItemError(
            f"the record's last history event is not a {event_type} event")
    return event_id


def _read_pdf(pdf_path: Optional[str]) -> Optional[bytes]:
    """The record PDF's bytes; a missing or empty file is sent without one."""
    if not pdf_path:
        return None
    try:
        data = Path(pdf_path).read_bytes()
    except OSError as exc:
        logger.warning("Record PDF unreadable, synced without it: %s",
                       exc.strerror or type(exc).__name__)
        return None
    if not data:
        logger.warning("Record PDF is empty, synced without it")
        return None
    return data


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


class SyncClient:
    """Queue completed records and push them to the configured backends."""

    def __init__(self, db_path: str, backends: Sequence[SyncBackend]) -> None:
        self._db_path = db_path
        self._backends = {backend.name: backend for backend in backends}

    @classmethod
    def from_env(cls, db_path: str, *, signer: Any = None,
                 timeout: float = DEFAULT_TIMEOUT) -> "SyncClient":
        """Both backends, configured from the environment.

        ``signer`` is the institutional seal-policy key the process used;
        without one the web backend loads it from the environment.
        """
        return cls(db_path, [WebBackend.from_env(signer=signer, timeout=timeout),
                             PortalBackend.from_env(timeout=timeout)])

    def announce_backends(self) -> bool:
        """Log one INFO line per unconfigured backend; any configured?"""
        return bool(self.configured_backends())

    def configured_backends(self) -> tuple[str, ...]:
        """Names of the configured backends; one INFO line for each other."""
        for backend in self._backends.values():
            if not backend.configured():
                logger.info("Sync backend '%s' not configured (%s): skipped, "
                            "nothing queued", backend.name,
                            backend.config_hint())
        return tuple(b.name for b in self._backends.values() if b.configured())

    def push_pending(self, *, seal_id: Optional[str] = None) -> PushSummary:
        """Push pending records per seal and backend, in event order."""
        sent = failed = 0
        entries = pending_entries(self._db_path, seal_id=seal_id)
        for (_seal, name), group in groupby(
            entries, key=lambda e: (e.seal_id, e.backend)
        ):
            delivered, broke = self._push_group(name, list(group))
            sent += delivered
            failed += broke
        remaining = len(pending_entries(self._db_path, seal_id=seal_id))
        return PushSummary(sent=sent, failed=failed, pending=remaining)

    def entries(self) -> list[OutboxEntry]:
        """Every queued record (for ``status``)."""
        return all_entries(self._db_path)

    def _push_group(self, name: str,
                    entries: list[OutboxEntry]) -> tuple[int, int]:
        """Push one seal's records for one backend until one fails."""
        backend = self._backends.get(name)
        if backend is None or not backend.configured():
            logger.warning("Sync backend '%s' is not configured now: %d "
                           "record(s) of seal_id=%s stay pending", name,
                           len(entries), entries[0].seal_id)
            return 0, 0
        for position, entry in enumerate(entries):
            if not self._push_one(backend, entry):
                return position, 1
        return len(entries), 0

    def _push_one(self, backend: SyncBackend, entry: OutboxEntry) -> bool:
        attempt = entry.attempts + 1
        try:
            backend.push(entry)
        except Exception as exc:  # any failure keeps the record queued
            record_failure(self._db_path, entry.id, str(exc), now=_now())
            logger.warning("Sync push failed, record kept in the outbox: "
                           "seal_id=%s event_id=%s backend=%s attempt=%d: %s",
                           entry.seal_id, entry.event_id, backend.name,
                           attempt, exc)
            return False
        record_success(self._db_path, entry.id, now=_now())
        logger.info("Sync push delivered: seal_id=%s event_id=%s backend=%s "
                    "attempt=%d", entry.seal_id, entry.event_id, backend.name,
                    attempt)
        return True


@dataclass(frozen=True)
class SyncIntent:
    """What a completed event hands to sync: rows to write, then a push.

    Empty (``item`` None) when no backend is configured or the record
    cannot be queued; then both methods do nothing.
    """

    item: Optional[SyncItem] = None
    backends: tuple[str, ...] = ()
    client: Optional[SyncClient] = field(default=None, repr=False)

    def write(self, conn: sqlite3.Connection) -> None:
        """Queue the item on ``conn``, inside the caller's transaction.

        A row already queued for (seal, event, backend) is kept only when
        it holds exactly this snapshot (see :func:`_same_snapshot`).

        Raises:
            SyncConflictError: The outbox holds another snapshot of this
                event (pending or sent); the caller's transaction must roll
                back, the local save with it.
            sqlite3.Error: Likewise; also when the insert was ignored for a
                reason other than a queued row (a constraint).
        """
        if self.item is None:
            return
        item, now = self.item, _now()
        for backend in self.backends:
            if outbox.enqueue_on(
                conn, seal_id=item.seal_id, event_id=item.event_id,
                event_type=item.event_type, backend=backend,
                record_json=item.record_json, record_pdf=item.record_pdf,
                wrapped_s3_b64=item.wrapped_s3_b64, now=now,
            ):
                continue
            queued = outbox.find_entry_on(conn, item.seal_id, item.event_id,
                                          backend)
            if queued is None:
                raise sqlite3.IntegrityError(
                    f"sync outbox row not written: seal_id={item.seal_id} "
                    f"event_id={item.event_id} backend={backend}")
            if not _same_snapshot(queued, item):
                logger.warning("Sync outbox holds another snapshot of "
                               "seal_id=%s event_id=%s backend=%s (%s); the "
                               "save is refused", item.seal_id, item.event_id,
                               backend, queued.status)
                raise SyncConflictError(
                    _conflict_message(item, backend, queued.status))

    def deliver(self) -> None:
        """Push the seal's pending records (after the commit); never raises."""
        if self.item is None or self.client is None:
            return
        try:
            self.client.push_pending(seal_id=self.item.seal_id)
        except Exception as exc:
            logger.warning("Sync push of seal_id=%s not completed (its records "
                           "stay in the outbox): %s: %s", self.item.seal_id,
                           type(exc).__name__, exc)


def _same_snapshot(queued: OutboxEntry, item: SyncItem) -> bool:
    """Every immutable queued field agrees; status and attempts do not count."""
    return (queued.event_type == item.event_type
            and queued.record_json == item.record_json
            and (queued.record_pdf or None) == (item.record_pdf or None)
            and (queued.wrapped_s3_b64 or None) == (item.wrapped_s3_b64 or None))


def _conflict_message(item: SyncItem, backend: str, status: str) -> str:
    state = "보냄" if status == outbox.STATUS_SENT else "보내기 대기"
    return (
        "동기화 대기열에 이 봉인의 같은 이벤트가 다른 내용으로 이미 있어 "
        f"저장하지 않았습니다 (seal_id {item.seal_id}, 이벤트 {item.event_id}, "
        f"전송 대상 {backend}, 대기열 상태: {state}). 이전 기록지로 같은 작업을 "
        "다시 하면 생깁니다. 이 봉인의 마지막 작업에서 만든 기록지로 다시 "
        "진행하세요.")


def prepare_sync(
    db_path: str,
    *,
    event_type: str,
    record_json: str,
    pdf_path: Optional[str],
    wrapped_s3_b64: Optional[str] = None,
    signer: Any = None,
    client: Optional[SyncClient] = None,
) -> SyncIntent:
    """The delivery intent of a record a process is about to save.

    Call before the local save's transaction; pass :meth:`SyncIntent.write`
    to it, and call :meth:`SyncIntent.deliver` after the commit.

    Returns:
        An empty intent when no backend is configured, or when the record
        does not name its seal and current event (WARNING; such a record
        cannot be delivered as this event).

    Raises:
        sqlite3.Error: The outbox table cannot be created; the save must not
            go ahead without its intent.
    """
    active = client or SyncClient.from_env(db_path, signer=signer)
    backends = active.configured_backends()
    if not backends:
        return SyncIntent()
    try:
        item = build_sync_item(event_type=event_type, record_json=record_json,
                               pdf_path=pdf_path, wrapped_s3_b64=wrapped_s3_b64)
    except SyncItemError as exc:
        logger.warning("The %s record cannot be queued for sync: %s",
                       event_type, exc)
        return SyncIntent()
    outbox.ensure_outbox(db_path)
    return SyncIntent(item=item, backends=backends, client=active)


def sync_after_completion(
    db_path: str,
    *,
    event_type: str,
    record_json: str,
    pdf_path: Optional[str],
    wrapped_s3_b64: Optional[str] = None,
    signer: Any = None,
    client: Optional[SyncClient] = None,
) -> None:
    """Queue (own transaction) and push a record that is already saved.

    For a caller that saved the record without an intent: tests and tools;
    no process uses it (they use :func:`prepare_sync`). Queueing follows
    the conflict rule of :meth:`SyncIntent.write`, but it runs after the
    caller's save and cannot undo it: a conflicting snapshot is not queued
    and the refusal is logged (WARNING). Never raises.
    """
    try:
        intent = prepare_sync(db_path, event_type=event_type,
                              record_json=record_json, pdf_path=pdf_path,
                              wrapped_s3_b64=wrapped_s3_b64, signer=signer,
                              client=client)
        if intent.item is None:
            return
        with outbox.transaction(db_path) as conn:
            intent.write(conn)
        intent.deliver()
    except Exception as exc:
        logger.warning("Sync after %s not completed (the local record is "
                       "saved; queued records stay in the outbox): %s: %s",
                       event_type, type(exc).__name__, exc)
