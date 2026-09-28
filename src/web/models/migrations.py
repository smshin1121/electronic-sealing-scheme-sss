"""In-place additions for databases created by earlier versions.

``CREATE TABLE IF NOT EXISTS`` leaves an existing table as it is, so a
column added to a table's DDL must also be added to databases that already
have the table. Each step here is idempotent and runs at every start-up,
right after the schema script (:func:`web.models.db_models.create_schema`).

Steps:
  - ``release_audit.operator`` (stage E, E4): the administrator's username
    on admin-path rows. Existing rows get ``''``, the value that also marks
    rows of the standard and time-locked paths.
  - the protected identity columns of ``cases`` (stage E, E3a):
    ``suspect_{name,birth,phone}_digest``, ``suspect_{name,email}_enc`` and
    ``identity_scheme``, appended in this order, as in the ``cases`` DDL.
    Existing rows get ``''`` (``identity_scheme = ''`` marks a row whose
    identity is still in the plaintext columns); converting them is an
    explicit step, ``python -m src.web.privacy.migrate``. The new tables
    ``seal_data_keys`` and ``identity_access_audit`` need no step here: the
    schema script creates them when missing.
  - ``sync_nonces`` and ``policy_high_water`` (stage E, E2a): the nonce
    store of authenticated sync submissions and the per-seal policy
    generation mark (:mod:`web.models.sync_schema`), created when missing.
  - ``seal_records.record_scheme`` (stage E, E3b), appended last as in the
    DDL. Existing rows get ``''``: their ``record_json``/``record_pdf``
    still hold plaintext, which no reader returns at run time, until the
    explicit conversion (``python -m src.web.privacy.migrate --apply``)
    encrypts them and sets ``'v1'``.
  - ``cases.registered_by`` (stage F, F2), appended last, after the E3a
    columns, as in the DDL: who registered the case (an administrator's
    username, or ``sync:`` for a case its signed record created; see
    :mod:`web.sync_registration`). Existing rows get ``''``: nothing
    recorded who registered them.
  - ``key_shares.generation`` (stage F, F1) and the unique key
    ``(seal_id, share_index, generation)``: a table rebuild on SQLite, an
    added column and key on MariaDB (:mod:`web.models.share_schema`).
    Existing rows keep their ids and get generation 0. This step runs last.
  - ``share_removal_audit`` (stage F, Fable gate finding 1): one row per
    share an administrator removed (:mod:`web.models.share_removal_schema`),
    created when missing, before the ``key_shares`` step.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

logger = logging.getLogger(__name__)

_SQLITE_ADD_OPERATOR = (
    "ALTER TABLE release_audit ADD COLUMN operator TEXT NOT NULL DEFAULT ''"
)
_MARIADB_ADD_OPERATOR = (
    "ALTER TABLE release_audit ADD COLUMN IF NOT EXISTS "
    "operator VARCHAR(64) NOT NULL DEFAULT ''"
)

# (column, SQLite type, MariaDB type), in DDL order.
_CASES_IDENTITY_COLUMNS = (
    ("suspect_name_digest", "TEXT NOT NULL DEFAULT ''", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("suspect_birth_digest", "TEXT NOT NULL DEFAULT ''", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("suspect_phone_digest", "TEXT NOT NULL DEFAULT ''", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("suspect_name_enc", "TEXT NOT NULL DEFAULT ''", "TEXT NOT NULL DEFAULT ''"),
    ("suspect_email_enc", "TEXT NOT NULL DEFAULT ''", "TEXT NOT NULL DEFAULT ''"),
    ("identity_scheme", "TEXT NOT NULL DEFAULT ''", "VARCHAR(16) NOT NULL DEFAULT ''"),
)
# (column, SQLite type, MariaDB type) of seal_records (stage E, E3b).
_RECORD_SCHEME_COLUMN = (
    "record_scheme", "TEXT NOT NULL DEFAULT ''", "VARCHAR(16) NOT NULL DEFAULT ''",
)
# (column, SQLite type, MariaDB type) of cases (stage F, F2); 64 characters
# hold any administrator username.
_REGISTERED_BY_COLUMN = (
    "registered_by", "TEXT NOT NULL DEFAULT ''", "VARCHAR(64) NOT NULL DEFAULT ''",
)


def apply_migrations(db: Any, db_type: str) -> None:
    """Bring an existing schema up to date on an open connection."""
    if db_type == "sqlite":
        _add_sqlite_column(db, "release_audit", "operator", _SQLITE_ADD_OPERATOR)
        for table, (column, sqlite_type, _) in _added_columns():
            _add_sqlite_column(
                db, table, column,
                f"ALTER TABLE {table} ADD COLUMN {column} {sqlite_type}",
            )
    else:
        _add_mariadb_columns(db)
    _add_sync_tables(db, db_type)
    _add_case_registrar(db, db_type)
    _add_share_removal_audit(db, db_type)
    _version_key_shares(db, db_type)


def _added_columns() -> list[tuple[str, tuple[str, str, str]]]:
    """(table, column spec) of E3a's ``cases`` and E3b's ``seal_records`` columns."""
    return ([("cases", spec) for spec in _CASES_IDENTITY_COLUMNS]
            + [("seal_records", _RECORD_SCHEME_COLUMN)])


def _add_mariadb_columns(db: Any) -> None:
    """E4's ``release_audit.operator``, E3a's ``cases`` identity columns and
    E3b's ``seal_records.record_scheme``."""
    cursor = db.cursor()
    try:
        # A no-op (with a note, not an error) when the column exists.
        cursor.execute(_MARIADB_ADD_OPERATOR)
        for table, (column, _, mariadb_type) in _added_columns():
            cursor.execute(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {mariadb_type}"
            )
        db.commit()
    finally:
        cursor.close()


def _add_sync_tables(db: Any, db_type: str) -> None:
    """Stage E, E2a: the sync nonce store and the policy generation mark."""
    from .sync_schema import create_sync_tables

    create_sync_tables(db, db_type)


def _add_case_registrar(db: Any, db_type: str) -> None:
    """Stage F, F2: ``cases.registered_by``, appended after the E3a columns
    (this step runs after them)."""
    column, sqlite_type, mariadb_type = _REGISTERED_BY_COLUMN
    if db_type == "sqlite":
        _add_sqlite_column(db, "cases", column,
                           f"ALTER TABLE cases ADD COLUMN {column} {sqlite_type}")
        return
    cursor = db.cursor()
    try:
        # A no-op (with a note, not an error) when the column exists.
        cursor.execute(f"ALTER TABLE cases ADD COLUMN IF NOT EXISTS {column} {mariadb_type}")
        db.commit()
    finally:
        cursor.close()


def _add_share_removal_audit(db: Any, db_type: str) -> None:
    """Stage F (Fable gate, finding 1): the audit table of share removals."""
    from .share_removal_schema import create_share_removal_audit

    create_share_removal_audit(db, db_type)


def _version_key_shares(db: Any, db_type: str) -> None:
    """Stage F, F1: share slots versioned by policy generation."""
    from .share_schema import migrate_key_shares

    migrate_key_shares(db, db_type)


def _add_sqlite_column(db: Any, table: str, column: str, statement: str) -> None:
    columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    if column in columns:
        return
    try:
        db.execute(statement)
        db.commit()
    except sqlite3.OperationalError as exc:
        # Another process may have added it between the check and the ALTER.
        if "duplicate column" not in str(exc).lower():
            raise
        return
    logger.info("Schema migrated: added %s.%s", table, column)
