"""Tables of sync authentication and policy generations (stage E, E2a).

Both schema variants of two tables, created by the migration step at every
start-up (:func:`web.models.migrations.apply_migrations`), so a new
database and one created by an earlier version get them alike:

  - ``sync_nonces`` -- every nonce of an authenticated sync submission,
    claimed in the same transaction as the store under the seal's write
    lock. ``expires_at`` (Unix seconds) is ``sent_at`` plus the largest
    window the configuration allows, so pruning expired rows can never let
    a replay back in, whatever window is configured.
  - ``policy_high_water`` -- per seal, the highest policy generation among
    its stored authenticated records, with that policy's digest and event:
    sync admission bootstraps it from the stored records and raises it with
    every store; the release gate seeds a missing one after a full scan.

They live here, not in :mod:`web.models.db_models`, to keep that module
under the size limit; ``CREATE ... IF NOT EXISTS`` makes the step
idempotent.
"""

from __future__ import annotations

from typing import Any

SQLITE_SYNC_SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_nonces (
    nonce        TEXT    PRIMARY KEY,
    seal_id      TEXT    NOT NULL,
    event_id     INTEGER NOT NULL,
    sent_at      TEXT    NOT NULL,
    expires_at   INTEGER NOT NULL,
    received_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sync_nonces_expiry
    ON sync_nonces (expires_at);

CREATE TABLE IF NOT EXISTS policy_high_water (
    seal_id        TEXT    PRIMARY KEY,
    generation     INTEGER NOT NULL,
    policy_digest  TEXT    NOT NULL,
    event_id       INTEGER NOT NULL,
    updated_at     TEXT    NOT NULL,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id)
);
"""

MARIADB_SYNC_SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_nonces (
    nonce        VARCHAR(128) COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
    seal_id      VARCHAR(64)  NOT NULL,
    event_id     INT          NOT NULL,
    sent_at      VARCHAR(40)  NOT NULL,
    expires_at   BIGINT       NOT NULL,
    received_at  VARCHAR(40)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_sync_nonces_expiry
    ON sync_nonces (expires_at);

CREATE TABLE IF NOT EXISTS policy_high_water (
    seal_id        VARCHAR(64)  NOT NULL PRIMARY KEY,
    generation     INT          NOT NULL,
    policy_digest  VARCHAR(64)  NOT NULL,
    event_id       INT          NOT NULL,
    updated_at     VARCHAR(40)  NOT NULL,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def create_sync_tables(db: Any, db_type: str) -> None:
    """Create the two tables if missing, on an open connection."""
    if db_type == "sqlite":
        db.executescript(SQLITE_SYNC_SCHEMA)
        return
    cursor = db.cursor()
    try:
        for statement in MARIADB_SYNC_SCHEMA.strip().split(";"):
            if statement.strip():
                cursor.execute(statement.strip())
        db.commit()
    finally:
        cursor.close()
