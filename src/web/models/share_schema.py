"""The policy generation of stored key shares: migration (stage F, F1).

Since F1 a share slot is versioned by the seal's policy generation:
``key_shares`` has ``generation`` (an integer, ``NOT NULL DEFAULT 0``,
appended as the last column) and the unique key
``(seal_id, share_index, generation)`` in place of v1.x's
``(seal_id, share_index)``, in both DDL variants of
:mod:`web.models.db_models`. :func:`migrate_key_shares` brings a table
created before F1 to that shape. It is idempotent and runs at every
start-up (:func:`web.models.migrations.apply_migrations`). Every existing
row keeps its id and values and gets generation 0, the generation of
version-1 policies and of seals without an authenticated policy.

SQLite cannot change a table's constraints in place, so the table is
rebuilt, following SQLite's procedure for schema changes: foreign keys are
switched off on this connection (``PRAGMA foreign_keys`` is a no-op inside
a transaction, so before it starts), then one ``BEGIN IMMEDIATE``
transaction creates the new table, copies every row with its id, carries
the AUTOINCREMENT sequence over (new rows never reuse an id the old table
gave out), drops the old table, renames the new one and recreates
``idx_key_shares_index_uploaded``; ``PRAGMA foreign_key_check`` runs before
the commit, and foreign keys are switched back on afterwards. Rows whose
case is missing (possible only if they were written with foreign keys off)
are kept as they were and reported at WARNING. The column is checked again
inside the transaction, so a second process starting at the same time
finds the table rebuilt and changes nothing. Any error rolls the whole
rebuild back.

MariaDB: the column is added if missing (existing rows get 0); the new
unique key, which starts with ``seal_id``, is added before the old key
``uq_seal_share`` is dropped, because the foreign key on ``seal_id`` needs
an index that starts with it at every moment.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_REBUILD_TABLE = "key_shares_f1_rebuild"
# The F1 table (the key_shares DDL of web.models.db_models, other name).
_SQLITE_REBUILD_DDL = f"""
CREATE TABLE {_REBUILD_TABLE} (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    share_index INTEGER NOT NULL CHECK(share_index BETWEEN 1 AND 4),
    share_data  TEXT    NOT NULL,
    uploaded_by TEXT    NOT NULL,
    uploaded_at TEXT    NOT NULL DEFAULT (datetime('now')),
    generation  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE(seal_id, share_index, generation)
)"""
_SQLITE_COPY_ROWS = f"""
INSERT INTO {_REBUILD_TABLE}
    (id, seal_id, share_index, share_data, uploaded_by, uploaded_at, generation)
SELECT id, seal_id, share_index, share_data, uploaded_by, uploaded_at, 0
FROM key_shares"""
_SQLITE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_key_shares_index_uploaded
    ON key_shares (share_index, uploaded_at)"""

_MARIADB_STEPS = (
    "ALTER TABLE key_shares ADD COLUMN IF NOT EXISTS "
    "generation INT NOT NULL DEFAULT 0",
    "ALTER TABLE key_shares ADD UNIQUE KEY IF NOT EXISTS "
    "uq_seal_share_generation (seal_id, share_index, generation)",
    "ALTER TABLE key_shares DROP INDEX IF EXISTS uq_seal_share",
)


def migrate_key_shares(db: Any, db_type: str) -> None:
    """Give a ``key_shares`` table from before F1 its generation (idempotent)."""
    if db_type == "sqlite":
        _rebuild_sqlite(db)
    else:
        _alter_mariadb(db)


def _has_generation(db: Any) -> bool:
    return "generation" in {row[1] for row in db.execute("PRAGMA table_info(key_shares)")}


def _rebuild_sqlite(db: Any) -> None:
    """Rebuild ``key_shares`` with the generation (SQLite; see the module)."""
    if _has_generation(db):
        return
    db.commit()  # PRAGMA foreign_keys has no effect inside a transaction
    foreign_keys = db.execute("PRAGMA foreign_keys").fetchone()[0]
    db.execute("PRAGMA foreign_keys=OFF")
    try:
        _rebuild_in_transaction(db)
    finally:
        if foreign_keys:
            db.execute("PRAGMA foreign_keys=ON")


def _rebuild_in_transaction(db: Any) -> None:
    db.execute("BEGIN IMMEDIATE")
    try:
        if _has_generation(db):  # rebuilt meanwhile by another process
            db.rollback()
            return
        copied = _copy_into_rebuilt_table(db)
        orphans = db.execute("PRAGMA foreign_key_check(key_shares)").fetchall()
        db.commit()
    except BaseException:
        db.rollback()
        raise
    logger.info("Schema migrated: key_shares rebuilt with the generation column "
                "(%d row(s) kept, generation 0)", copied)
    if orphans:
        logger.warning("Schema migration: key_shares keeps %d row(s) whose case "
                       "is missing (written with foreign keys off); they were "
                       "copied as they were", len(orphans))


def _copy_into_rebuilt_table(db: Any) -> int:
    """New table, rows with their ids, sequence; swap names; the index."""
    sequence = db.execute(
        "SELECT seq FROM sqlite_sequence WHERE name = 'key_shares'").fetchone()
    db.execute(_SQLITE_REBUILD_DDL)
    copied = db.execute(_SQLITE_COPY_ROWS).rowcount
    if sequence is not None:
        _carry_sequence(db, int(sequence[0]))
    db.execute("DROP TABLE key_shares")
    db.execute(f"ALTER TABLE {_REBUILD_TABLE} RENAME TO key_shares")
    db.execute(_SQLITE_INDEX)
    return copied


def _carry_sequence(db: Any, last_id: int) -> None:
    """Keep the old table's AUTOINCREMENT position for the new table."""
    current = db.execute("SELECT seq FROM sqlite_sequence WHERE name = ?",
                         (_REBUILD_TABLE,)).fetchone()
    if current is None:
        db.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)",
                   (_REBUILD_TABLE, last_id))
    elif int(current[0]) < last_id:
        db.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = ?",
                   (last_id, _REBUILD_TABLE))


def _alter_mariadb(db: Any) -> None:
    """Column, then the new unique key, then drop the old one (MariaDB)."""
    cursor = db.cursor()
    try:
        # Each is a no-op (a note, not an error) once applied.
        for statement in _MARIADB_STEPS:
            cursor.execute(statement)
        db.commit()
    finally:
        cursor.close()
