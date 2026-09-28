"""The generation column of ``key_shares``: migrating a v1.1 SQLite database
(stage F, F1).

A database created by v1.1 has ``key_shares`` with the unique key
``(seal_id, share_index)``. At start-up the table is rebuilt in one
transaction with ``generation INTEGER NOT NULL DEFAULT 0`` and the unique key
``(seal_id, share_index, generation)``: every row keeps its id and values and
gets generation 0, the index ``idx_key_shares_index_uploaded`` is recreated,
the AUTOINCREMENT sequence continues where it stood, and foreign keys stay
enforced. A second start-up changes nothing. The MariaDB variant is in
``test_share_generations_mariadb.py``.

Synthetic data only.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.record_protection import V101_CASES_DDL
from tests.fixtures.release_web import make_release_app

pytestmark = pytest.mark.integration

SEAL = "S-20260929-F1M001"
ORPHAN = "S-20260929-F1M099"
# key_shares as v1.0.1 to v1.1 created it (SQLite), with its index.
V11_KEY_SHARES_DDL = """
CREATE TABLE key_shares (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    share_index INTEGER NOT NULL CHECK(share_index BETWEEN 1 AND 4),
    share_data  TEXT    NOT NULL,
    uploaded_by TEXT    NOT NULL,
    uploaded_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE(seal_id, share_index)
);
CREATE INDEX IF NOT EXISTS idx_key_shares_index_uploaded
    ON key_shares (share_index, uploaded_at);
"""
ROWS = (
    (3, SEAL, 1, "1-" + "a1" * 32, "suspect", "2026-09-01 10:00:00"),
    (7, SEAL, 2, "2-" + "b2" * 32, "investigator", "2026-09-02 11:00:00"),
    (8, SEAL, 4, "4-" + "c4" * 32, "admin", "2026-09-03 12:00:00"),
)
LAST_ID = 11  # rows 9 to 11 were written and removed before the upgrade


def _write_v11_database(path: Path, *, orphan: bool = False) -> None:
    """A v1.1-shaped ``cases`` and ``key_shares`` with three share rows."""
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(V101_CASES_DDL + V11_KEY_SHARES_DDL)
        conn.execute("""INSERT INTO cases (seal_id, case_number, investigator,
                        suspect_name) VALUES (?, '2026-F1', 'old', 'old')""",
                     (SEAL,))
        conn.executemany("""INSERT INTO key_shares (id, seal_id, share_index,
                            share_data, uploaded_by, uploaded_at)
                            VALUES (?, ?, ?, ?, ?, ?)""", ROWS)
        conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = 'key_shares'",
                     (LAST_ID,))
        conn.commit()
        if orphan:  # a row whose case is gone (written with foreign keys off)
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("""INSERT INTO key_shares (id, seal_id, share_index,
                            share_data, uploaded_by) VALUES (5, ?, 2, ?, 'x')""",
                         (ORPHAN, "2-" + "d5" * 32))
            conn.commit()
    finally:
        conn.close()


def _query(path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        return [tuple(row) for row in conn.execute(sql, params)]
    finally:
        conn.close()


def _columns(path: Path) -> list[tuple]:
    """(name, type, not null, default, primary key) of every column."""
    return [row[1:] for row in _query(path, "PRAGMA table_info(key_shares)")]


def _index_columns(path: Path, name: str) -> list[str]:
    return [row[2] for row in _query(path, f"PRAGMA index_info({name})")]


def _unique_keys(path: Path) -> list[list[str]]:
    return [_index_columns(path, row[1])
            for row in _query(path, "PRAGMA index_list(key_shares)") if row[2]]


def _foreign_keys(path: Path) -> list[tuple]:
    return [(row[2], row[3], row[4])
            for row in _query(path, "PRAGMA foreign_key_list(key_shares)")]


def _rows(path: Path) -> list[tuple]:
    return _query(path, """SELECT id, seal_id, share_index, share_data,
                           uploaded_by, uploaded_at, generation
                           FROM key_shares ORDER BY id""")


def _sequence(path: Path) -> int:
    [(seq,)] = _query(path, "SELECT seq FROM sqlite_sequence WHERE name = 'key_shares'")
    return int(seq)


def _snapshot(path: Path) -> tuple[Any, ...]:
    return (_query(path, """SELECT type, name, sql FROM sqlite_master
                            WHERE tbl_name = 'key_shares' ORDER BY name"""),
            _rows(path), _sequence(path))


@pytest.fixture()
def v11_database(tmp_path: Path) -> Path:
    path = tmp_path / "release_web.db"  # the file make_release_app opens
    _write_v11_database(path)
    return path


class TestSqliteMigration:
    def test_the_v1_1_table_gains_the_generation_and_keeps_its_rows(
        self, tmp_path, monkeypatch, v11_database
    ) -> None:
        make_release_app(tmp_path, monkeypatch)  # start-up migrates

        assert [column[0] for column in _columns(v11_database)] == [
            "id", "seal_id", "share_index", "share_data", "uploaded_by",
            "uploaded_at", "generation"]
        assert _rows(v11_database) == [(*row, 0) for row in ROWS]
        assert _unique_keys(v11_database) == [
            ["seal_id", "share_index", "generation"]]
        assert _index_columns(v11_database, "idx_key_shares_index_uploaded") == [
            "share_index", "uploaded_at"]
        assert _foreign_keys(v11_database) == [("cases", "seal_id", "seal_id")]
        assert _sequence(v11_database) == LAST_ID

    def test_a_second_start_up_changes_nothing(
        self, tmp_path, monkeypatch, v11_database
    ) -> None:
        make_release_app(tmp_path, monkeypatch)
        before = _snapshot(v11_database)

        make_release_app(tmp_path, monkeypatch)

        assert _snapshot(v11_database) == before

    def test_new_rows_continue_the_sequence_and_versions_share_a_slot(
        self, tmp_path, monkeypatch, v11_database
    ) -> None:
        app = make_release_app(tmp_path, monkeypatch)
        with app.app_context():
            from web.models.db_models import insert_key_share

            newer = insert_key_share(SEAL, 1, "1-" + "e1" * 32, "suspect",
                                     generation=2)
            clash = insert_key_share(SEAL, 1, "1-" + "e1" * 32, "suspect")

        assert (newer.outcome, newer.row_id) == ("stored", LAST_ID + 1)
        assert clash.outcome == "conflict"
        with pytest.raises(sqlite3.IntegrityError):
            conn = sqlite3.connect(v11_database)
            try:
                conn.execute("""INSERT INTO key_shares (seal_id, share_index,
                                share_data, uploaded_by, generation)
                                VALUES (?, 1, '1-ff', 'x', 0)""", (SEAL,))
            finally:
                conn.close()

    def test_the_rebuilt_table_matches_a_new_one(
        self, tmp_path, monkeypatch, v11_database
    ) -> None:
        make_release_app(tmp_path, monkeypatch)
        fresh_dir = tmp_path / "fresh"
        fresh_dir.mkdir()
        make_release_app(fresh_dir, monkeypatch)
        fresh = fresh_dir / "release_web.db"

        assert _columns(v11_database) == _columns(fresh)
        assert _unique_keys(v11_database) == _unique_keys(fresh)
        assert _foreign_keys(v11_database) == _foreign_keys(fresh)
        assert _index_columns(v11_database, "idx_key_shares_index_uploaded") == (
            _index_columns(fresh, "idx_key_shares_index_uploaded"))

    def test_foreign_keys_stay_on_and_enforced(self, tmp_path, v11_database) -> None:
        from web.models.db_models import create_schema

        conn = sqlite3.connect(v11_database)
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            create_schema(conn, "sqlite")

            [(enabled,)] = conn.execute("PRAGMA foreign_keys").fetchall()
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute("""INSERT INTO key_shares (seal_id, share_index,
                                share_data, uploaded_by) VALUES (?, 1, '1-ab', 'x')""",
                             (ORPHAN,))
        finally:
            conn.close()
        assert enabled == 1
        assert "generation" in [column[0] for column in _columns(v11_database)]

    def test_rows_without_a_case_are_kept_and_reported(
        self, tmp_path, monkeypatch, caplog
    ) -> None:
        path = tmp_path / "release_web.db"
        _write_v11_database(path, orphan=True)
        caplog.set_level(logging.WARNING)

        make_release_app(tmp_path, monkeypatch)

        assert (5, ORPHAN, 2, 0) in [(r[0], r[1], r[2], r[6]) for r in _rows(path)]
        assert len(_rows(path)) == len(ROWS) + 1
        assert any("key_shares" in record.getMessage()
                   and "1 row(s)" in record.getMessage()
                   for record in caplog.records)


def test_a_failed_rebuild_leaves_the_v1_1_table_as_it_was(tmp_path, monkeypatch) -> None:
    """Codex stage F review: an error inside the rebuild (here after the rows
    were copied) rolls the whole rebuild back, and foreign keys are on again."""
    from web.models import share_schema

    path = tmp_path / "v11_failed.db"
    _write_v11_database(path)
    before = (_columns(path), _query(path, "SELECT * FROM key_shares ORDER BY id"),
              _unique_keys(path))

    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("injected failure after the rows were copied")

    monkeypatch.setattr(share_schema, "_carry_sequence", fail)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        with pytest.raises(RuntimeError, match="injected failure"):
            share_schema.migrate_key_shares(conn, "sqlite")
        foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    finally:
        conn.close()

    assert foreign_keys == 1
    assert (_columns(path), _query(path, "SELECT * FROM key_shares ORDER BY id"),
            _unique_keys(path)) == before
    assert _query(path, "SELECT name FROM sqlite_master WHERE name = ?",
                  ("key_shares_f1_rebuild",)) == []
    assert _query(path, "SELECT seq FROM sqlite_sequence WHERE name = 'key_shares'") == [
        (LAST_ID,)]
