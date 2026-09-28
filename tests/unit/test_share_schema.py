"""The key_shares migration statements on MariaDB, as text (stage F, F1).

The MariaDB migration is executed for real only in the throwaway-container
run (``tests/integration/test_share_generations_mariadb.py``). Here the
order is checked through a recording connection: the column first, then the
new unique key (it starts with ``seal_id``, so the foreign key on
``seal_id`` keeps an index), and only then the drop of ``uq_seal_share``;
every statement is a no-op once applied.
"""

from __future__ import annotations

from typing import Any

from web.models import db_models
from web.models.migrations import apply_migrations
from web.models.share_schema import migrate_key_shares


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


EXPECTED = [
    "ALTER TABLE key_shares ADD COLUMN IF NOT EXISTS generation INT NOT NULL "
    "DEFAULT 0",
    "ALTER TABLE key_shares ADD UNIQUE KEY IF NOT EXISTS "
    "uq_seal_share_generation (seal_id, share_index, generation)",
    "ALTER TABLE key_shares DROP INDEX IF EXISTS uq_seal_share",
]


def test_the_new_key_is_added_before_the_old_one_is_dropped() -> None:
    conn = _RecordingConnection()

    migrate_key_shares(conn, "mariadb")

    assert conn.statements == EXPECTED
    assert conn.commits == 1


def test_the_step_runs_last_at_every_start_up() -> None:
    conn = _RecordingConnection()

    apply_migrations(conn, "mariadb")

    assert conn.statements[-3:] == EXPECTED


def test_both_ddl_variants_declare_the_versioned_slot() -> None:
    sqlite_ddl = " ".join(db_models._SQLITE_SCHEMA.split())
    mariadb_ddl = " ".join(db_models._MARIADB_SCHEMA.split())

    assert "generation INTEGER NOT NULL DEFAULT 0" in sqlite_ddl
    assert "UNIQUE(seal_id, share_index, generation)" in sqlite_ddl
    assert "UNIQUE(seal_id, share_index)" not in sqlite_ddl
    assert "generation INT NOT NULL DEFAULT 0" in mariadb_ddl
    assert ("UNIQUE KEY uq_seal_share_generation (seal_id, share_index, "
            "generation)") in mariadb_ddl
    assert "uq_seal_share " not in mariadb_ddl
