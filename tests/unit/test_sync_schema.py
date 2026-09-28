"""Schema of sync authentication and policy generations (stage E, E2a).

Both schema variants declare ``sync_nonces`` and ``policy_high_water``;
the migration step creates them in a database made by an earlier version
(here: the stage D / E4 schema without them), idempotently. The MariaDB
DDL is executed for real only in the throwaway-container run
(``tests/integration/test_sync_auth_mariadb.py``); here it is checked as
text and through a recording connection.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

import pytest

from web.models import db_models
from web.models.migrations import apply_migrations
from web.models.sync_schema import MARIADB_SYNC_SCHEMA, SQLITE_SYNC_SCHEMA

_TABLES = {
    "sync_nonces": ("nonce", "seal_id", "event_id", "sent_at", "expires_at",
                    "received_at"),
    "policy_high_water": ("seal_id", "generation", "policy_digest",
                          "event_id", "updated_at"),
}


def _table_block(schema: str, table: str) -> str:
    match = re.search(rf"CREATE TABLE IF NOT EXISTS {table} \((.*?)\)[^)]*;",
                      schema, re.S)
    assert match, f"{table} not declared"
    return match.group(1)


@pytest.mark.parametrize("schema", [SQLITE_SYNC_SCHEMA, MARIADB_SYNC_SCHEMA],
                         ids=["sqlite", "mariadb"])
def test_both_variants_declare_the_tables_and_columns(schema: str) -> None:
    for table, columns in _TABLES.items():
        block = _table_block(schema, table)
        for column in columns:
            assert re.search(rf"^\s*{column}\s", block, re.M), (table, column)
    assert "idx_sync_nonces_expiry" in schema
    assert "REFERENCES cases(seal_id)" in _table_block(schema,
                                                       "policy_high_water")


def test_the_mariadb_nonce_is_compared_byte_for_byte() -> None:
    block = _table_block(MARIADB_SYNC_SCHEMA, "sync_nonces")
    assert re.search(r"nonce\s+VARCHAR\(128\)\s+COLLATE utf8mb4_bin", block)
    assert re.search(r"expires_at\s+BIGINT", block)


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_the_migration_adds_the_tables_to_an_existing_database(
    tmp_path,
) -> None:
    path = tmp_path / "pre_e2a.db"
    conn = sqlite3.connect(path)
    conn.executescript(db_models._SQLITE_SCHEMA)  # the schema before E2a
    conn.execute("INSERT INTO cases (seal_id, case_number, investigator, "
                 "suspect_name) VALUES ('S-20260928-OLD001', 'c', 'i', 's')")
    conn.commit()
    added = {"sync_nonces", "policy_high_water", "share_removal_audit"}
    assert not added & _tables(conn)

    db_models.create_schema(conn, "sqlite")
    db_models.create_schema(conn, "sqlite")  # idempotent

    assert added <= _tables(conn)  # the audit table since stage F (Fable re-check)
    assert conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 1
    conn.execute("INSERT INTO policy_high_water VALUES "
                 "('S-20260928-OLD001', 1, ?, 1, 't')", ("ab" * 32,))
    conn.close()


class _RecordingConnection:
    """Stands in for a MariaDB connection; records executed statements."""

    def __init__(self) -> None:
        self.statements: list[str] = []
        self.commits = 0

    def cursor(self) -> "_RecordingConnection":
        return self

    def execute(self, statement: str, *_args: Any) -> None:
        self.statements.append(" ".join(statement.split()))

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        return None


def test_the_mariadb_migration_creates_the_tables_after_the_operator_step() -> None:
    conn = _RecordingConnection()

    apply_migrations(conn, "mariadb")

    assert conn.statements[0].startswith(
        "ALTER TABLE release_audit ADD COLUMN IF NOT EXISTS operator")
    created = [s.split()[5] for s in conn.statements if s.startswith("CREATE")]
    # Since stage F (Fable gate, finding 1) the share-removal audit table and
    # its index follow the sync tables.
    assert created == ["sync_nonces", "idx_sync_nonces_expiry",
                       "policy_high_water", "share_removal_audit",
                       "idx_share_removal_audit_seal"]
    # Every step is idempotent; since stage F (F1) one of them drops the
    # v1.x key of key_shares (DROP INDEX IF EXISTS).
    assert all("IF NOT EXISTS" in s or s.startswith("ALTER TABLE key_shares "
                                                    "DROP INDEX IF EXISTS ")
               for s in conn.statements[1:])
