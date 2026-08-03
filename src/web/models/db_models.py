"""Database connection and parameterized query helpers.

Supports MariaDB (primary) with SQLite fallback.
All queries use parameterized placeholders to prevent SQL injection.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from typing import Any, Generator

from flask import Flask, g

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MariaDB optional import
# ---------------------------------------------------------------------------
try:
    import mariadb

    _HAS_MARIADB = True
except ImportError:
    _HAS_MARIADB = False

# ---------------------------------------------------------------------------
# Schema DDL (compatible with both SQLite and MariaDB)
# ---------------------------------------------------------------------------
_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL UNIQUE,
    case_number TEXT    NOT NULL,
    investigator TEXT   NOT NULL,
    suspect_name TEXT   NOT NULL,
    suspect_email TEXT  NOT NULL DEFAULT '',
    suspect_birth TEXT  NOT NULL DEFAULT '',
    suspect_phone TEXT  NOT NULL DEFAULT '',
    auth_level  TEXT    NOT NULL DEFAULT 'basic',
    password_hash TEXT  NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    role        TEXT    NOT NULL CHECK(role IN ('suspect','investigator','admin')),
    name        TEXT    NOT NULL,
    email       TEXT    NOT NULL DEFAULT '',
    birth_date  TEXT    NOT NULL DEFAULT '',
    phone       TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id)
);

CREATE TABLE IF NOT EXISTS key_shares (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    share_index INTEGER NOT NULL CHECK(share_index BETWEEN 1 AND 4),
    share_data  TEXT    NOT NULL,
    uploaded_by TEXT    NOT NULL,
    uploaded_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE(seal_id, share_index)
);

CREATE TABLE IF NOT EXISTS seal_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    event_id    INTEGER NOT NULL,
    event_type  TEXT    NOT NULL CHECK(event_type IN ('Sealing','Unsealing','Resealing')),
    record_json TEXT    NOT NULL,
    record_pdf  BLOB,
    synced_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE(seal_id, event_id)
);

CREATE TABLE IF NOT EXISTS auth_failures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    ip_address  TEXT    NOT NULL DEFAULT '',
    failed_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_auth_failures_lookup
    ON auth_failures (seal_id, ip_address, failed_at);

CREATE INDEX IF NOT EXISTS idx_key_shares_index_uploaded
    ON key_shares (share_index, uploaded_at);
"""

_MARIADB_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    seal_id      VARCHAR(64)  NOT NULL UNIQUE,
    case_number  VARCHAR(128) NOT NULL,
    investigator VARCHAR(128) NOT NULL,
    suspect_name VARCHAR(128) NOT NULL,
    suspect_email VARCHAR(256) NOT NULL DEFAULT '',
    suspect_birth VARCHAR(16)  NOT NULL DEFAULT '',
    suspect_phone VARCHAR(32)  NOT NULL DEFAULT '',
    auth_level   VARCHAR(32)  NOT NULL DEFAULT 'basic',
    password_hash VARCHAR(256) NOT NULL DEFAULT '',
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS users (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    seal_id    VARCHAR(64)  NOT NULL,
    role       ENUM('suspect','investigator','admin') NOT NULL,
    name       VARCHAR(128) NOT NULL,
    email      VARCHAR(256) NOT NULL DEFAULT '',
    birth_date VARCHAR(16)  NOT NULL DEFAULT '',
    phone      VARCHAR(32)  NOT NULL DEFAULT '',
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS key_shares (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    seal_id      VARCHAR(64) NOT NULL,
    share_index  TINYINT     NOT NULL,
    share_data   TEXT        NOT NULL,
    uploaded_by  VARCHAR(128) NOT NULL,
    uploaded_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE KEY uq_seal_share (seal_id, share_index)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS seal_records (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    seal_id      VARCHAR(64) NOT NULL,
    event_id     INT         NOT NULL,
    event_type   ENUM('Sealing','Unsealing','Resealing') NOT NULL,
    record_json  LONGTEXT    NOT NULL,
    record_pdf   LONGBLOB,
    synced_at    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE KEY uq_seal_event (seal_id, event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_failures (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    seal_id    VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    failed_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_auth_failures_lookup
    ON auth_failures (seal_id, ip_address, failed_at);

CREATE INDEX IF NOT EXISTS idx_key_shares_index_uploaded
    ON key_shares (share_index, uploaded_at);
"""


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def _connect_mariadb(app: Flask) -> mariadb.Connection:
    """Create a MariaDB connection from app config."""
    if not _HAS_MARIADB:
        raise RuntimeError("mariadb package is not installed")

    conn = mariadb.connect(
        host=app.config["DB_HOST"],
        port=app.config["DB_PORT"],
        user=app.config["DB_USER"],
        password=app.config["DB_PASSWORD"],
        database=app.config["DB_NAME"],
        pool_size=app.config.get("DB_POOL_SIZE", 5),
    )
    return conn


def _connect_sqlite(app: Flask) -> sqlite3.Connection:
    """Create a SQLite connection from app config."""
    import os

    db_path = app.config["SQLITE_PATH"]
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_db() -> Any:
    """Get or create a database connection for the current request.

    Returns:
        A database connection (MariaDB or SQLite).
    """
    from flask import current_app

    if "db" not in g:
        use_sqlite = current_app.config.get("USE_SQLITE", False)
        if use_sqlite or not _HAS_MARIADB:
            if not use_sqlite:
                logger.warning(
                    "MariaDB driver not installed, falling back to SQLite"
                )
            g.db = _connect_sqlite(current_app)
            g.db_type = "sqlite"
        else:
            try:
                g.db = _connect_mariadb(current_app)
                g.db_type = "mariadb"
            except Exception:
                logger.warning(
                    "MariaDB connection failed, falling back to SQLite"
                )
                g.db = _connect_sqlite(current_app)
                g.db_type = "sqlite"
    return g.db


def close_db(exc: BaseException | None = None) -> None:
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    g.pop("db_type", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass


def init_db(app: Flask) -> None:
    """Initialize database tables.

    Args:
        app: The Flask application instance.
    """
    with app.app_context():
        db = get_db()
        db_type = g.get("db_type", "sqlite")

        if db_type == "sqlite":
            db.executescript(_SQLITE_SCHEMA)
        else:
            cursor = db.cursor()
            for statement in _MARIADB_SCHEMA.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    cursor.execute(stmt)
            db.commit()
            cursor.close()

        close_db()


# ---------------------------------------------------------------------------
# Query helpers (parameterized queries only)
# ---------------------------------------------------------------------------

def execute_query(
    sql: str,
    params: tuple[Any, ...] = (),
    *,
    fetch_one: bool = False,
    fetch_all: bool = False,
) -> Any:
    """Execute a parameterized SQL query.

    Args:
        sql: SQL statement with ? placeholders (SQLite) or %s (MariaDB).
        params: Query parameters.
        fetch_one: Return a single row.
        fetch_all: Return all rows.

    Returns:
        Query result or None.
    """
    db = get_db()
    db_type = g.get("db_type", "sqlite")

    # Normalize placeholders: internal code uses ? (SQLite style)
    # MariaDB uses %s
    if db_type == "mariadb":
        sql = sql.replace("?", "%s")

    cursor = db.cursor()
    try:
        cursor.execute(sql, params)

        if fetch_one:
            return cursor.fetchone()
        if fetch_all:
            return cursor.fetchall()

        db.commit()
        return cursor.lastrowid
    finally:
        cursor.close()


def insert_case(
    seal_id: str,
    case_number: str,
    investigator: str,
    suspect_name: str,
    suspect_email: str = "",
    suspect_birth: str = "",
    suspect_phone: str = "",
    auth_level: str = "basic",
    password_hash: str = "",
) -> int | None:
    """Insert a new case record.

    Returns:
        The inserted row ID, or None on failure.
    """
    return execute_query(
        """INSERT INTO cases
           (seal_id, case_number, investigator, suspect_name,
            suspect_email, suspect_birth, suspect_phone,
            auth_level, password_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            seal_id, case_number, investigator, suspect_name,
            suspect_email, suspect_birth, suspect_phone,
            auth_level, password_hash,
        ),
    )


def find_case_by_seal_id(seal_id: str) -> Any:
    """Find a case by seal_id.

    Returns:
        Row dict/tuple or None.
    """
    return execute_query(
        "SELECT * FROM cases WHERE seal_id = ?",
        (seal_id,),
        fetch_one=True,
    )


def insert_key_share(
    seal_id: str,
    share_index: int,
    share_data: str,
    uploaded_by: str,
) -> int | None:
    """Insert or ignore a key share.

    Returns:
        The inserted row ID, or None if duplicate.
    """
    db = get_db()
    db_type = g.get("db_type", "sqlite")

    if db_type == "sqlite":
        sql = """INSERT OR IGNORE INTO key_shares
                 (seal_id, share_index, share_data, uploaded_by)
                 VALUES (?, ?, ?, ?)"""
    else:
        sql = """INSERT IGNORE INTO key_shares
                 (seal_id, share_index, share_data, uploaded_by)
                 VALUES (%s, %s, %s, %s)"""

    cursor = db.cursor()
    try:
        cursor.execute(sql, (seal_id, share_index, share_data, uploaded_by))
        db.commit()
        return cursor.lastrowid
    finally:
        cursor.close()


def find_key_shares_by_seal_id(seal_id: str) -> list[Any]:
    """Find all key shares for a given seal_id.

    Returns:
        List of row dicts/tuples.
    """
    return execute_query(
        "SELECT * FROM key_shares WHERE seal_id = ? ORDER BY share_index",
        (seal_id,),
        fetch_all=True,
    ) or []


def insert_seal_record(
    seal_id: str,
    event_id: int,
    event_type: str,
    record_json: str,
    record_pdf: bytes | None = None,
) -> int | None:
    """Insert a seal record (idempotent: ignores duplicates).

    Returns:
        The inserted row ID, or None if duplicate.
    """
    db = get_db()
    db_type = g.get("db_type", "sqlite")

    if db_type == "sqlite":
        sql = """INSERT OR IGNORE INTO seal_records
                 (seal_id, event_id, event_type, record_json, record_pdf)
                 VALUES (?, ?, ?, ?, ?)"""
    else:
        sql = """INSERT IGNORE INTO seal_records
                 (seal_id, event_id, event_type, record_json, record_pdf)
                 VALUES (%s, %s, %s, %s, %s)"""

    cursor = db.cursor()
    try:
        cursor.execute(sql, (seal_id, event_id, event_type, record_json, record_pdf))
        db.commit()
        return cursor.lastrowid
    finally:
        cursor.close()


def find_seal_records_by_seal_id(seal_id: str) -> list[Any]:
    """Find all seal records for a given seal_id ordered by event_id.

    Returns:
        List of row dicts/tuples.
    """
    return execute_query(
        "SELECT * FROM seal_records WHERE seal_id = ? ORDER BY event_id",
        (seal_id,),
        fetch_all=True,
    ) or []


def find_seal_record_summaries_by_seal_id(seal_id: str) -> list[Any]:
    """Find seal record summaries (list view) for a given seal_id.

    Excludes the heavy ``record_json`` / ``record_pdf`` columns so that
    listing pages do not load large payloads. Use
    :func:`find_seal_record_json` for the detail view.

    Returns:
        List of row dicts/tuples with
        (id, seal_id, event_id, event_type, synced_at).
    """
    return execute_query(
        """SELECT id, seal_id, event_id, event_type, synced_at
           FROM seal_records WHERE seal_id = ? ORDER BY event_id""",
        (seal_id,),
        fetch_all=True,
    ) or []


def find_seal_record_json(seal_id: str, event_id: int) -> str | None:
    """Fetch the record_json payload of a single seal record.

    Returns:
        The record JSON string, or None if not found.
    """
    row = execute_query(
        "SELECT record_json FROM seal_records WHERE seal_id = ? AND event_id = ?",
        (seal_id, event_id),
        fetch_one=True,
    )
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get("record_json")
    if hasattr(row, "keys"):
        return row["record_json"]
    return row[0]


def find_latest_seal_mode(seal_id: str) -> str | None:
    """Resolve the recovery regime of a seal from its latest synced record.

    Returns:
        ``"standard"`` or ``"strict"``; ``None`` when no sealing record
        has been synced for this seal (legacy / pre-sync case — callers
        decide whether to permit a documented legacy default).

    Raises:
        ValueError: When a record exists but its JSON is unreadable or
            carries an unrecognized ``seal_mode`` value. Callers must
            treat this as a recovery denial (fail-closed): a present but
            unverifiable mode must never silently degrade to standard.
    """
    import json as _json

    records = find_seal_records_by_seal_id(seal_id)
    if not records:
        return None

    latest = records[-1]
    if isinstance(latest, dict) or hasattr(latest, "keys"):
        record_json = latest["record_json"]
    else:
        record_json = latest[4]

    try:
        record = _json.loads(record_json)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"seal_records.record_json unreadable for {seal_id}"
        ) from exc

    mode = record.get("seal_mode", "standard")
    if mode not in ("standard", "strict"):
        raise ValueError(
            f"Unrecognized seal_mode {mode!r} for {seal_id}"
        )
    return mode


def find_latest_unlock_time(seal_id: str) -> str | None:
    """Resolve the unlock time anchored at sealing from the latest synced record.

    The sealing process stores ``unlock_time_iso`` at the top level of the
    record JSON (legacy records may use ``unlock_time``); the portal's
    unlock-time policy gate compares it against server time.

    Returns:
        The ISO 8601 unlock time, or ``None`` when no sealing record has
        been synced or the record predates the unlock-time field (legacy
        case --- callers treat this as ungated).

    Raises:
        ValueError: When a record exists but its JSON is unreadable.
    """
    import json as _json

    records = find_seal_records_by_seal_id(seal_id)
    if not records:
        return None

    latest = records[-1]
    if isinstance(latest, dict) or hasattr(latest, "keys"):
        record_json = latest["record_json"]
    else:
        record_json = latest[4]

    try:
        record = _json.loads(record_json)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"seal_records.record_json unreadable for {seal_id}"
        ) from exc

    unlock = record.get("unlock_time_iso") or record.get("unlock_time")
    return unlock if isinstance(unlock, str) and unlock else None


def find_latest_key_commitment(seal_id: str) -> str | None:
    """Resolve the recovery-key commitment from the latest synced record.

    Returns:
        ``SHA-256(key)`` as 64 lowercase hex chars, or ``None`` when no
        record has been synced or the record predates the field (legacy
        case --- callers then cannot verify the reconstruction).

    Raises:
        ValueError: When a record exists but its JSON is unreadable, or
            the commitment is present but malformed. A malformed
            commitment must never be treated as "absent": that would let
            a rewritten record silently disable verification.
    """
    import json as _json
    import re as _re

    records = find_seal_records_by_seal_id(seal_id)
    if not records:
        return None

    latest = records[-1]
    if isinstance(latest, dict) or hasattr(latest, "keys"):
        record_json = latest["record_json"]
    else:
        record_json = latest[4]

    try:
        record = _json.loads(record_json)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"seal_records.record_json unreadable for {seal_id}"
        ) from exc

    commitment = record.get("key_commitment")
    if commitment in (None, ""):
        return None
    if not isinstance(commitment, str) or not _re.fullmatch(
        r"[0-9a-f]{64}", commitment
    ):
        raise ValueError(
            f"Malformed key_commitment for {seal_id}"
        )
    return commitment


def find_admin_share_summaries() -> list[Any]:
    """List admin key shares (share_index = 4) without share_data payload.

    Returns:
        List of row dicts/tuples with
        (id, seal_id, share_index, uploaded_by, uploaded_at).
    """
    return execute_query(
        """SELECT id, seal_id, share_index, uploaded_by, uploaded_at
           FROM key_shares WHERE share_index = 4
           ORDER BY uploaded_at DESC""",
        fetch_all=True,
    ) or []


def record_auth_failure(seal_id: str, ip_address: str) -> None:
    """Record an authentication failure."""
    execute_query(
        "INSERT INTO auth_failures (seal_id, ip_address) VALUES (?, ?)",
        (seal_id, ip_address),
    )


def count_recent_auth_failures(
    seal_id: str,
    ip_address: str,
    window_seconds: int = 600,
) -> int:
    """Count authentication failures within the given time window.

    Args:
        seal_id: The seal identifier.
        ip_address: Client IP address.
        window_seconds: Lookback window in seconds.

    Returns:
        Number of recent failures.
    """
    db = get_db()
    db_type = g.get("db_type", "sqlite")

    if db_type == "sqlite":
        sql = """SELECT COUNT(*) FROM auth_failures
                 WHERE seal_id = ? AND ip_address = ?
                 AND failed_at > datetime('now', ?)"""
        params = (seal_id, ip_address, f"-{window_seconds} seconds")
    else:
        sql = """SELECT COUNT(*) FROM auth_failures
                 WHERE seal_id = %s AND ip_address = %s
                 AND failed_at > DATE_SUB(NOW(), INTERVAL %s SECOND)"""
        params = (seal_id, ip_address, window_seconds)

    cursor = db.cursor()
    try:
        cursor.execute(sql, params)
        row = cursor.fetchone()
        if row is None:
            return 0
        return row[0] if isinstance(row, (tuple, list)) else row["COUNT(*)"]
    finally:
        cursor.close()
