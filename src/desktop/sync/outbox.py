"""The desktop's sync outbox (``sync_outbox`` in the desktop SQLite; stage E, E2a).

One row per (seal, event, backend). A row keeps what a push needs -- the
record JSON exactly as stored, the record PDF bytes and the base64 wrapped
s3 -- so a retry does not depend on the output folder or on the desktop's
``seal_records`` row, which keeps only the latest record of a seal. The
envelope of the reference web, and the portal's HMAC headers, are made at
each attempt, never stored.

Status is ``pending`` until a push succeeds (``sent``). Every attempt
counts in ``attempts`` and leaves ``last_error`` (empty after a success),
``last_attempt_at`` and, once sent, ``sent_at`` (ISO UTC).

The processes write their rows with :func:`enqueue_on`, on the connection
of the transaction that saves the local record (stage E, E2d), so a
completed event and its delivery intent are committed together.
:func:`ensure_outbox` must run before that transaction: it creates the
table with ``executescript``, which commits whatever is open.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

STATUS_PENDING = "pending"
STATUS_SENT = "sent"
_MAX_ERROR_LEN = 500

_CREATE_OUTBOX = """
CREATE TABLE IF NOT EXISTS sync_outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id         TEXT    NOT NULL,
    event_id        INTEGER NOT NULL,
    event_type      TEXT    NOT NULL,
    backend         TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'sent')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT '',
    record_json     TEXT    NOT NULL,
    record_pdf      BLOB,
    wrapped_s3      TEXT,
    created_at      TEXT    NOT NULL,
    last_attempt_at TEXT    NOT NULL DEFAULT '',
    sent_at         TEXT    NOT NULL DEFAULT '',
    UNIQUE (seal_id, event_id, backend)
);
CREATE INDEX IF NOT EXISTS idx_sync_outbox_status
    ON sync_outbox (status, seal_id, backend, event_id);
"""

_COLUMNS = ("id, seal_id, event_id, event_type, backend, status, attempts, "
            "last_error, created_at, last_attempt_at, sent_at, record_json, "
            "record_pdf, wrapped_s3")


@dataclass(frozen=True)
class OutboxEntry:
    """One queued push; the payload fields are left out of ``repr``."""

    id: int
    seal_id: str
    event_id: int
    event_type: str
    backend: str
    status: str
    attempts: int
    last_error: str
    created_at: str
    last_attempt_at: str
    sent_at: str
    record_json: str = field(repr=False)
    record_pdf: Optional[bytes] = field(default=None, repr=False)
    wrapped_s3_b64: Optional[str] = field(default=None, repr=False)


@contextmanager
def _connect(db_path: str) -> Iterator[sqlite3.Connection]:
    """A connection that commits on success and rolls back on error."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def transaction(db_path: str) -> Any:
    """A connection whose writes commit together (or roll back) on exit."""
    return _connect(db_path)


def ensure_outbox(db_path: str) -> None:
    """Create the table if missing (the desktop DB file is created too)."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.executescript(_CREATE_OUTBOX)


def enqueue_on(
    conn: sqlite3.Connection,
    *,
    seal_id: str,
    event_id: int,
    event_type: str,
    backend: str,
    record_json: str,
    record_pdf: Optional[bytes],
    wrapped_s3_b64: Optional[str],
    now: str,
) -> bool:
    """Queue a push on ``conn``, inside the caller's transaction.

    Returns:
        ``False`` when (seal, event, backend) is already queued (nothing
        written).
    """
    cursor = conn.execute(
        """INSERT OR IGNORE INTO sync_outbox
           (seal_id, event_id, event_type, backend, record_json,
            record_pdf, wrapped_s3, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (seal_id, event_id, event_type, backend, record_json, record_pdf,
         wrapped_s3_b64, now),
    )
    return cursor.rowcount == 1


def find_entry_on(conn: sqlite3.Connection, seal_id: str, event_id: int,
                  backend: str) -> Optional[OutboxEntry]:
    """The queued push for (seal, event, backend) on ``conn``, if any."""
    row = conn.execute(
        f"""SELECT {_COLUMNS} FROM sync_outbox
            WHERE seal_id = ? AND event_id = ? AND backend = ?""",
        (seal_id, event_id, backend),
    ).fetchone()
    return None if row is None else _entry(row)


def pending_entries(db_path: str, *,
                    seal_id: Optional[str] = None) -> list[OutboxEntry]:
    """Pending pushes in sending order: per seal and backend, by event."""
    ensure_outbox(db_path)
    sql = f"SELECT {_COLUMNS} FROM sync_outbox WHERE status = ?"
    params: tuple = (STATUS_PENDING,)
    if seal_id is not None:
        sql += " AND seal_id = ?"
        params = (STATUS_PENDING, seal_id)
    with _connect(db_path) as conn:
        rows = conn.execute(
            sql + " ORDER BY seal_id, backend, event_id", params).fetchall()
    return [_entry(row) for row in rows]


def all_entries(db_path: str) -> list[OutboxEntry]:
    """Every queued push, oldest first."""
    ensure_outbox(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM sync_outbox ORDER BY id").fetchall()
    return [_entry(row) for row in rows]


def record_success(db_path: str, entry_id: int, *, now: str) -> None:
    """Mark a push as delivered."""
    with _connect(db_path) as conn:
        conn.execute(
            """UPDATE sync_outbox SET status = ?, attempts = attempts + 1,
               last_error = '', last_attempt_at = ?, sent_at = ?
               WHERE id = ?""",
            (STATUS_SENT, now, now, entry_id),
        )


def record_failure(db_path: str, entry_id: int, error: str, *,
                   now: str) -> None:
    """Count a failed attempt; the push stays pending."""
    with _connect(db_path) as conn:
        conn.execute(
            """UPDATE sync_outbox SET attempts = attempts + 1,
               last_error = ?, last_attempt_at = ? WHERE id = ?""",
            (error[:_MAX_ERROR_LEN], now, entry_id),
        )


def _entry(row: sqlite3.Row) -> OutboxEntry:
    pdf = row["record_pdf"]
    return OutboxEntry(
        id=row["id"], seal_id=row["seal_id"], event_id=row["event_id"],
        event_type=row["event_type"], backend=row["backend"],
        status=row["status"], attempts=row["attempts"],
        last_error=row["last_error"], created_at=row["created_at"],
        last_attempt_at=row["last_attempt_at"], sent_at=row["sent_at"],
        record_json=row["record_json"],
        record_pdf=None if pdf is None else bytes(pdf),
        wrapped_s3_b64=row["wrapped_s3"],
    )
