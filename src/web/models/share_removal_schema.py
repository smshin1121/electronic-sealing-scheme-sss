"""The audit table of share removals by an administrator (stage F, gate fix).

``share_removal_audit`` keeps one row per ``key_shares`` row an
administrator removed (:mod:`web.models.share_removal_models`): the seal,
the slot and policy generation, who uploaded the share and when, the SHA-256
of the removed share (lowercase hex over its stripped, lower-cased value;
the value itself is not kept), the administrator's username, the stated
reason and the time of the removal. ``seal_id`` is the seal id stored with
the share. ``uploaded_at`` is copied as the share row stores it: on SQLite
the UTC text of ``datetime('now')``; on MariaDB the ``DATETIME`` of
``CURRENT_TIMESTAMP``, in the server's session time zone and without an
offset. ``removed_at`` is UTC in ISO 8601 with its offset.

Both schema variants are created when missing at every start-up
(:func:`web.models.migrations.apply_migrations`), as the sync tables are,
so a new database and one created by an earlier version get the table
alike. Like ``release_audit`` it has no foreign key, and nothing in this
codebase updates or deletes its rows; the database itself does not enforce
that (application-level audit).
"""

from __future__ import annotations

from typing import Any

SQLITE_SHARE_REMOVAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS share_removal_audit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id       TEXT    NOT NULL,
    share_index   INTEGER NOT NULL,
    generation    INTEGER NOT NULL,
    uploaded_by   TEXT    NOT NULL,
    uploaded_at   TEXT    NOT NULL,
    share_sha256  TEXT    NOT NULL,
    operator      TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    removed_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_share_removal_audit_seal
    ON share_removal_audit (seal_id, id);
"""

MARIADB_SHARE_REMOVAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS share_removal_audit (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    seal_id       VARCHAR(64)  NOT NULL,
    share_index   TINYINT      NOT NULL,
    generation    INT          NOT NULL,
    uploaded_by   VARCHAR(128) NOT NULL,
    uploaded_at   VARCHAR(40)  NOT NULL,
    share_sha256  VARCHAR(64)  NOT NULL,
    operator      VARCHAR(64)  NOT NULL,
    reason        TEXT         NOT NULL,
    removed_at    VARCHAR(40)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_share_removal_audit_seal
    ON share_removal_audit (seal_id, id)
"""


def create_share_removal_audit(db: Any, db_type: str) -> None:
    """Create the table and its index if missing, on an open connection."""
    if db_type == "sqlite":
        db.executescript(SQLITE_SHARE_REMOVAL_SCHEMA)
        return
    cursor = db.cursor()
    try:
        for statement in MARIADB_SHARE_REMOVAL_SCHEMA.strip().split(";"):
            if statement.strip():
                cursor.execute(statement.strip())
        db.commit()
    finally:
        cursor.close()
