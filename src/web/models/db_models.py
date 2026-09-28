"""Database connection and parameterized query helpers.

Supports MariaDB (primary) with SQLite fallback.
All queries use parameterized placeholders to prevent SQL injection.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from typing import TYPE_CHECKING, Any

from flask import Flask, g

from .migrations import apply_migrations
from .privacy_schema import MARIADB_PRIVACY_SCHEMA, SQLITE_PRIVACY_SCHEMA

if TYPE_CHECKING:
    from .share_models import ShareWrite

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
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    suspect_name_digest  TEXT NOT NULL DEFAULT '',
    suspect_birth_digest TEXT NOT NULL DEFAULT '',
    suspect_phone_digest TEXT NOT NULL DEFAULT '',
    suspect_name_enc     TEXT NOT NULL DEFAULT '',
    suspect_email_enc    TEXT NOT NULL DEFAULT '',
    identity_scheme      TEXT NOT NULL DEFAULT '',
    registered_by        TEXT NOT NULL DEFAULT ''
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
    generation  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE(seal_id, share_index, generation)
);

CREATE TABLE IF NOT EXISTS seal_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    event_id    INTEGER NOT NULL,
    event_type  TEXT    NOT NULL CHECK(event_type IN ('Sealing','Unsealing','Resealing')),
    record_json TEXT    NOT NULL,
    record_pdf  BLOB,
    synced_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    record_scheme TEXT  NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS wrapped_s3_shares (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    event_id    INTEGER NOT NULL,
    wrapped_s3  BLOB    NOT NULL,
    synced_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE(seal_id, event_id)
);

CREATE TABLE IF NOT EXISTS release_audit (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id          TEXT    NOT NULL,
    path             TEXT    NOT NULL CHECK(path IN ('standard','timelock','admin')),
    policy_status    TEXT    NOT NULL,
    policy_digest    TEXT    NOT NULL,
    outcome          TEXT    NOT NULL CHECK(outcome IN ('released','denied')),
    reason           TEXT    NOT NULL,
    detail           TEXT    NOT NULL,
    operator_reason  TEXT    NOT NULL,
    tsa_token_sha256 TEXT    NOT NULL,
    tsa_token        TEXT    NOT NULL,
    tsa_challenge    TEXT    NOT NULL,
    tsa_gen_time     TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    operator         TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_release_audit_seal
    ON release_audit (seal_id, id);

CREATE TABLE IF NOT EXISTS policy_enrollment (
    seal_id        TEXT    PRIMARY KEY,
    event_id       INTEGER NOT NULL,
    policy_digest  TEXT    NOT NULL,
    enrolled_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id)
);

CREATE TABLE IF NOT EXISTS admin_accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0, 1)),
    created_at    TEXT    NOT NULL,
    disabled_at   TEXT    NOT NULL DEFAULT ''
);
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
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    suspect_name_digest  VARCHAR(64) NOT NULL DEFAULT '',
    suspect_birth_digest VARCHAR(64) NOT NULL DEFAULT '',
    suspect_phone_digest VARCHAR(64) NOT NULL DEFAULT '',
    suspect_name_enc     TEXT        NOT NULL DEFAULT '',
    suspect_email_enc    TEXT        NOT NULL DEFAULT '',
    identity_scheme      VARCHAR(16) NOT NULL DEFAULT '',
    registered_by        VARCHAR(64) NOT NULL DEFAULT ''
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
    generation   INT         NOT NULL DEFAULT 0,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE KEY uq_seal_share_generation (seal_id, share_index, generation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS seal_records (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    seal_id      VARCHAR(64) NOT NULL,
    event_id     INT         NOT NULL,
    event_type   ENUM('Sealing','Unsealing','Resealing') NOT NULL,
    record_json  LONGTEXT    NOT NULL,
    record_pdf   LONGBLOB,
    synced_at    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    record_scheme VARCHAR(16) NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS wrapped_s3_shares (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    seal_id     VARCHAR(64) NOT NULL,
    event_id    INT         NOT NULL,
    wrapped_s3  BLOB        NOT NULL,
    synced_at   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE KEY uq_wrapped_s3_event (seal_id, event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS release_audit (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    seal_id          VARCHAR(64)  NOT NULL,
    path             ENUM('standard','timelock','admin') NOT NULL,
    policy_status    VARCHAR(32)  NOT NULL,
    policy_digest    VARCHAR(64)  NOT NULL,
    outcome          ENUM('released','denied') NOT NULL,
    reason           VARCHAR(64)  NOT NULL,
    detail           VARCHAR(512) NOT NULL,
    operator_reason  TEXT         NOT NULL,
    tsa_token_sha256 VARCHAR(64)  NOT NULL,
    tsa_token        TEXT         NOT NULL,
    tsa_challenge    VARCHAR(64)  NOT NULL,
    tsa_gen_time     VARCHAR(40)  NOT NULL,
    created_at       VARCHAR(40)  NOT NULL,
    operator         VARCHAR(64)  NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_release_audit_seal
    ON release_audit (seal_id, id);

CREATE TABLE IF NOT EXISTS policy_enrollment (
    seal_id        VARCHAR(64)  NOT NULL PRIMARY KEY,
    event_id       INT          NOT NULL,
    policy_digest  VARCHAR(64)  NOT NULL,
    enrolled_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS admin_accounts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64)  COLLATE utf8mb4_bin NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    disabled      TINYINT      NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at    VARCHAR(40)  NOT NULL,
    disabled_at   VARCHAR(40)  NOT NULL DEFAULT '',
    UNIQUE KEY uq_admin_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
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
        create_schema(get_db(), g.get("db_type", "sqlite"))
        close_db()


def create_schema(db: Any, db_type: str) -> None:
    """Create any missing table, then migrate existing ones (idempotent).

    Split out of :func:`init_db` so that a caller that must first check
    which backend it reached (the account CLI) can use one connection.
    The identity-protection tables (:mod:`web.models.privacy_schema`) are
    created after the main tables they refer to.
    """
    if db_type == "sqlite":
        db.executescript(_SQLITE_SCHEMA + SQLITE_PRIVACY_SCHEMA)
    else:
        cursor = db.cursor()
        try:
            for statement in (_MARIADB_SCHEMA + MARIADB_PRIVACY_SCHEMA).strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    cursor.execute(stmt)
            db.commit()
        finally:
            cursor.close()
    apply_migrations(db, db_type)


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
    """Insert a new case; the subject's identity is stored protected (E3a).

    The v1.0.1 signature is kept for existing callers, but the four
    identity arguments are only inputs to
    :func:`web.privacy.case_identity.register_protected_case`, which stores
    keyed digests (name, birth date, phone) and ciphertexts (name, e-mail)
    under a new per-seal data key and leaves the plaintext columns ''.
    It therefore needs the identity-protection keys. ``password_hash`` is
    stored as given. ``registered_by`` stays '': the two registration
    paths of stage F, F2 (an administrator's form, a signed record) record
    who registered the case; this helper is neither.

    Returns:
        The inserted row ID.

    Raises:
        PrivacyUnavailable: The identity-protection keys are not configured.
    """
    from ..privacy.case_identity import CaseRegistration, register_protected_case

    return register_protected_case(CaseRegistration(
        seal_id=seal_id, case_number=case_number, investigator=investigator,
        name=suspect_name, email=suspect_email, birth=suspect_birth,
        phone=suspect_phone, auth_level=auth_level, password_hash=password_hash,
    ))


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
    *,
    generation: int = 0,
) -> ShareWrite:
    """Store a key share for one policy generation (stage F, F1).

    A slot holds one share per generation. The v1.x call shape (no
    ``generation``) stores generation 0, the generation every share stored
    before F1 was given. The upload routes pass the seal's current
    generation (:mod:`web.share_upload`); a share stored out of band after
    a reseal (for example s4) needs ``generation=G`` of the resealing
    policy. Nothing is ignored silently any more.

    Returns:
        A :class:`web.models.share_models.ShareWrite`: ``outcome`` is
        ``"stored"`` (with ``row_id``), ``"identical"`` (the same share is
        already stored for that generation) or ``"conflict"`` (another
        share is); nothing is written in the last two cases.

    Raises:
        ValueError: ``share_index`` is not 1 to 4, or ``generation`` is
            not an int from 0 to 2^31 - 1.
    """
    from .share_models import store_key_share

    return store_key_share(seal_id, share_index, share_data, uploaded_by,
                           generation=generation)


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
    """Insert a seal record, encrypted (idempotent: ignores duplicates).

    Since stage E, E3b the record is stored through
    :func:`web.models.release_models.insert_protected_record`: both columns
    encrypted under the seal's data key; it needs the privacy keys.

    Returns:
        The cursor's last row id.
    """
    from .release_models import insert_protected_record

    return insert_protected_record(seal_id, event_id, event_type, record_json,
                                   record_pdf)


def find_seal_records_by_seal_id(seal_id: str) -> list[dict[str, Any]]:
    """All records of a seal by event, decrypted (a system read, not audited;
    person-facing reads go through :mod:`web.privacy.record_access`).

    Returns:
        Dicts with ``id, seal_id, event_id, event_type, record_json,
        record_pdf, synced_at`` (see
        :func:`web.models.release_models.find_seal_records`).
    """
    from .release_models import find_seal_records

    return find_seal_records(seal_id)


def find_seal_record_summaries_by_seal_id(seal_id: str) -> list[Any]:
    """Find seal record summaries (list view) for a given seal_id.

    Reads no record content (nothing is decrypted): the list page shows
    the event, its type and time, and whether a PDF is stored. A person
    sees the content only through :mod:`web.privacy.record_access`.

    Returns:
        List of row dicts/tuples with
        (id, seal_id, event_id, event_type, synced_at, has_pdf).
    """
    return execute_query(
        """SELECT id, seal_id, event_id, event_type, synced_at,
                  CASE WHEN record_pdf IS NULL THEN 0 ELSE 1 END AS has_pdf
           FROM seal_records WHERE seal_id = ? ORDER BY event_id""",
        (seal_id,),
        fetch_all=True,
    ) or []


def _latest_record(seal_id: str) -> dict | None:
    """The newest synced record of a seal, parsed; None when none is stored.

    Raises:
        ValueError: The record is unreadable (not JSON, or it does not
            decrypt). A record stored before E3b, or missing privacy keys,
            raise the privacy errors instead (fail-closed).
    """
    from .release_models import find_latest_record_json

    record_json = find_latest_record_json(seal_id)
    if record_json is None:
        return None
    try:
        return json.loads(record_json)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"seal_records.record_json unreadable for {seal_id}"
        ) from exc


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
    record = _latest_record(seal_id)
    if record is None:
        return None

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
    record = _latest_record(seal_id)
    if record is None:
        return None

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
    record = _latest_record(seal_id)
    if record is None:
        return None

    commitment = record.get("key_commitment")
    if commitment in (None, ""):
        return None
    if not isinstance(commitment, str) or not re.fullmatch(
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
        (id, seal_id, share_index, uploaded_by, uploaded_at, generation);
        ``generation`` (stage F, F1) is the policy generation the share
        was stored for.
    """
    return execute_query(
        """SELECT id, seal_id, share_index, uploaded_by, uploaded_at,
                  generation
           FROM key_shares WHERE share_index = 4
           ORDER BY uploaded_at DESC, id DESC""",
        fetch_all=True,
    ) or []


def record_auth_failure(seal_id: str, ip_address: str) -> int | None:
    """Record (and commit) an authentication failure; returns its row id."""
    return execute_query(
        "INSERT INTO auth_failures (seal_id, ip_address) VALUES (?, ?)",
        (seal_id, ip_address),
    )


def delete_auth_failure(row_id: int) -> None:
    """Remove one recorded failure by row id (a withdrawn reservation)."""
    execute_query("DELETE FROM auth_failures WHERE id = ?", (row_id,))


def relabel_auth_failure(row_id: int, seal_id: str) -> None:
    """Move one row to another key (a reservation that became a failure)."""
    execute_query("UPDATE auth_failures SET seal_id = ? WHERE id = ?",
                  (seal_id, row_id))


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
