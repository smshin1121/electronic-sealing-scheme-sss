"""Share slots versioned by policy generation (stage F, F1) on MariaDB.

The F1 tests run on SQLite; this module runs the MariaDB-only code on a
real MariaDB server: the ``key_shares`` DDL (``generation`` and the unique
key ``uq_seal_share_generation``), the migration of a v1.1 table (column
added, the new unique key added before ``uq_seal_share`` is dropped, the
foreign key on ``seal_id`` kept, rows and ids kept at generation 0), the
share store's outcomes under the case-row lock with a plain ``INSERT`` on
tuple rows, both upload routes, the releases after a reseal on the
standard, strict time-locked and admin paths, and the administrator's
share list on tuple rows.

It is skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must
be a throwaway test instance: the module drops and recreates two databases
whose names start with ``enc_release_test``. Synthetic data only.
Environment as in ``test_release_mariadb.py``: RELEASE_TEST_MARIADB_HOST,
_PORT, _USER, _PASSWORD, _DB.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    login_admin,
    post_form,
    recover_standard,
    recovered_key,
    store_share,
    sync_seal,
)
from tests.fixtures.share_uploads import (
    MSG_IDENTICAL,
    share_rows,
    take_flashes,
    upload_investigator_share,
    upload_owner_share,
)

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = os.environ.get("RELEASE_TEST_MARIADB_DB", "enc_release_test") + "_f1"
MIGRATION_DB = DB + "_migr"
TIMELOCK_URL = "/investigator/recover-key-timelock"
ADMIN_URL = "/admin/emergency-recover"
OLD_SEAL = "S-20260929-F1MM01"

# cases and key_shares as v1.0.1 to v1.1 created them on MariaDB.
_V11_CASES = """
CREATE TABLE cases (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""
_V11_KEY_SHARES = """
CREATE TABLE key_shares (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    seal_id      VARCHAR(64) NOT NULL,
    share_index  TINYINT     NOT NULL,
    share_data   TEXT        NOT NULL,
    uploaded_by  VARCHAR(128) NOT NULL,
    uploaded_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE KEY uq_seal_share (seal_id, share_index)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""
_OLD_ROWS = ((3, 1, "1-" + "a1" * 32, "suspect"), (7, 2, "2-" + "b2" * 32, "investigator"),
             (8, 4, "4-" + "c4" * 32, "admin"))


def _server(database: str | None = None) -> Any:
    import mariadb

    return mariadb.connect(host=HOST, port=PORT, user=USER, password=PASSWORD,
                           database=database)


def _recreate(name: str) -> None:
    assert name.startswith("enc_release_test"), "refusing to drop a non-test database"
    conn = _server()
    try:
        cur = conn.cursor()
        cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
        cur.execute(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        conn.close()


def _query(database: str, sql: str, params: tuple = ()) -> list[tuple]:
    conn = _server(database)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = list(cur.fetchall()) if cur.description else []
        conn.commit()
        return rows
    finally:
        conn.close()


def _columns(database: str) -> list[tuple]:
    return _query(database, """SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
                               FROM information_schema.COLUMNS
                               WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'key_shares'
                               ORDER BY ORDINAL_POSITION""", (database,))


def _indexes(database: str) -> dict[str, tuple[int, list[str]]]:
    """index name -> (non_unique, columns in order) of key_shares."""
    found: dict[str, tuple[int, list[str]]] = {}
    for name, non_unique, column in _query(database, """
            SELECT INDEX_NAME, NON_UNIQUE, COLUMN_NAME FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'key_shares'
            ORDER BY INDEX_NAME, SEQ_IN_INDEX""", (database,)):
        found.setdefault(name, (int(non_unique), []))[1].append(column)
    return found


def _foreign_keys(database: str) -> list[tuple]:
    return _query(database, """SELECT k.COLUMN_NAME, k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME
                               FROM information_schema.REFERENTIAL_CONSTRAINTS r
                               JOIN information_schema.KEY_COLUMN_USAGE k
                                 ON k.CONSTRAINT_SCHEMA = r.CONSTRAINT_SCHEMA
                                AND k.CONSTRAINT_NAME = r.CONSTRAINT_NAME
                                AND k.TABLE_NAME = r.TABLE_NAME
                               WHERE r.CONSTRAINT_SCHEMA = %s AND r.TABLE_NAME = 'key_shares'""",
                  (database,))


def _make_app(monkeypatch: pytest.MonkeyPatch, database: str = DB, **release: Any) -> Any:
    """A testing app on the MariaDB server; fails if the app fell back to SQLite."""
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT), ("DB_USER", USER),
                        ("DB_PASSWORD", PASSWORD), ("DB_NAME", database)):
        monkeypatch.setattr(TestingConfig, name, value)
    monkeypatch.setenv("USE_SQLITE", "false")
    from web.app import create_app

    app = create_app("testing")
    app.config.update(**release)
    with app.app_context():
        from flask import g

        from web.models.db_models import get_db

        get_db()
        assert g.db_type == "mariadb", "the app fell back to SQLite; the MariaDB path was not exercised"
    return app


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    _recreate(DB)


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(monkeypatch, release_pki, release_tsa, master_key):
    return _make_app(
        monkeypatch,
        POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path),
        RELEASE_KMS_MASTER_KEY_PATH=master_key,
        RELEASE_TSA_URL=release_tsa,
        RELEASE_TSA_CERT_PATH=str(release_pki.tsa_cert_path),
        RELEASE_TSA_CA_CERT_PATH=str(release_pki.ca_cert_path),
        RELEASE_TSA_POLICY_OID=DEFAULT_TSA_POLICY_OID,
    )


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _pair(seal_id: str, master_key: str, signer: Any, **kwargs: Any):
    return tuple(make_seal_material(seal_id=seal_id, master_key_path=master_key,
                                    signer=signer, generation=generation, **kwargs)
                 for generation in (1, 2))


def _last(app: Any, seal_id: str, path: str) -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row"
    return rows[-1]


class TestMariadbSchema:
    def test_a_new_table_has_the_versioned_slot(self, app) -> None:
        columns = _columns(DB)
        indexes = _indexes(DB)

        assert [c[0] for c in columns][-1] == "generation"
        assert (columns[-1][1].lower(), columns[-1][2], str(columns[-1][3])) == ("int", "NO", "0")
        assert indexes["uq_seal_share_generation"] == (0, ["seal_id", "share_index", "generation"])
        assert "uq_seal_share" not in indexes
        assert _foreign_keys(DB) == [("seal_id", "cases", "seal_id")]

    def test_a_v1_1_table_is_migrated_once_and_keeps_its_rows(self, monkeypatch) -> None:
        _recreate(MIGRATION_DB)
        _query(MIGRATION_DB, _V11_CASES)
        _query(MIGRATION_DB, _V11_KEY_SHARES)
        _query(MIGRATION_DB, """INSERT INTO cases (seal_id, case_number, investigator, suspect_name)
                                VALUES (%s, '2026-F1', 'old', 'old')""", (OLD_SEAL,))
        for row_id, index, data, by in _OLD_ROWS:
            _query(MIGRATION_DB, """INSERT INTO key_shares (id, seal_id, share_index, share_data,
                                    uploaded_by) VALUES (%s, %s, %s, %s, %s)""",
                   (row_id, OLD_SEAL, index, data, by))

        app = _make_app(monkeypatch, MIGRATION_DB)
        after_first = (_columns(MIGRATION_DB), _indexes(MIGRATION_DB))
        _make_app(monkeypatch, MIGRATION_DB)  # the migration is idempotent

        indexes = _indexes(MIGRATION_DB)
        assert (_columns(MIGRATION_DB), indexes) == after_first
        assert [c[0] for c in _columns(MIGRATION_DB)][-1] == "generation"
        assert indexes["uq_seal_share_generation"] == (0, ["seal_id", "share_index", "generation"])
        assert "uq_seal_share" not in indexes
        assert indexes["idx_key_shares_index_uploaded"][1] == ["share_index", "uploaded_at"]
        assert _foreign_keys(MIGRATION_DB) == [("seal_id", "cases", "seal_id")]
        assert _query(MIGRATION_DB, """SELECT id, share_index, share_data, uploaded_by, generation
                                       FROM key_shares ORDER BY id""") == [
            (row_id, index, data, by, 0) for row_id, index, data, by in _OLD_ROWS]
        with app.app_context():
            from web.models.db_models import insert_key_share

            newer = insert_key_share(OLD_SEAL, 1, "1-" + "e1" * 32, "suspect", generation=2)
            clash = insert_key_share(OLD_SEAL, 1, "1-" + "e1" * 32, "suspect")
            same = insert_key_share(OLD_SEAL, 1, "1-" + "A1" * 32, "suspect")
        assert (newer.outcome, clash.outcome, same.outcome) == ("stored", "conflict", "identical")
        assert newer.row_id is not None and newer.row_id > 8
        import mariadb

        with pytest.raises(mariadb.IntegrityError):
            _query(MIGRATION_DB, """INSERT INTO key_shares (seal_id, share_index, share_data,
                                    uploaded_by, generation) VALUES (%s, 1, '1-ff', 'x', 0)""",
                   (OLD_SEAL,))
        with pytest.raises(mariadb.IntegrityError):  # the foreign key still holds
            _query(MIGRATION_DB, """INSERT INTO key_shares (seal_id, share_index, share_data,
                                    uploaded_by, generation) VALUES ('S-NO-CASE', 1, '1-ff', 'x', 5)""")


class TestMariadbUploadsAndReleases:
    def test_uploads_are_tagged_and_a_conflict_is_refused(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1MM10", master_key, signer)
        sync_seal(client, app, sealed)

        stored = upload_owner_share(client, sealed.seal_id, sealed.shares[0])
        early = upload_owner_share(client, sealed.seal_id, resealed.shares[0])
        sync_seal(client, app, resealed, event_id=2, event_type="Resealing")
        later = upload_owner_share(client, sealed.seal_id, resealed.shares[0])
        take_flashes(client)
        again = upload_owner_share(client, sealed.seal_id, resealed.shares[0])
        investigator = upload_investigator_share(client, sealed.seal_id, resealed.shares[1])

        assert (stored.status_code, early.status_code, later.status_code) == (302, 409, 302)
        assert "세대 1" in early.get_data(as_text=True)
        assert again.status_code == 302
        assert investigator.status_code == 302
        assert share_rows(app, sealed.seal_id) == [
            (1, 1, sealed.shares[0]), (1, 2, resealed.shares[0]), (2, 2, resealed.shares[1])]

    def test_the_identical_share_again_adds_no_row(self, app, client, master_key, signer) -> None:
        seal = make_seal_material(seal_id="S-20260929-F1MM11", master_key_path=master_key,
                                  signer=signer, generation=1)
        sync_seal(client, app, seal)
        upload_investigator_share(client, seal.seal_id, seal.shares[1])
        take_flashes(client)

        again = upload_investigator_share(client, seal.seal_id, seal.shares[1].upper())

        assert again.status_code == 302
        assert any(MSG_IDENTICAL in text for _, text in take_flashes(client))
        assert share_rows(app, seal.seal_id) == [(2, 1, seal.shares[1])]

    def test_standard_release_after_a_reseal(self, app, client, master_key, signer) -> None:
        sealed, resealed = _pair("S-20260929-F1MM20", master_key, signer)
        sync_seal(client, app, sealed)
        upload_owner_share(client, sealed.seal_id, sealed.shares[0])
        sync_seal(client, app, resealed, event_id=2, event_type="Resealing")
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])

        resp = recover_standard(client, resealed)

        assert resp.status_code == 302
        assert recovered_key(client, resealed.seal_id) == resealed.key_hex
        assert _last(app, resealed.seal_id, "standard")["detail"] == (
            "shares=1+2; share 1 of generation 2")

    def test_strict_time_locked_release_after_a_reseal(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1MM30", master_key, signer, mode="strict")
        sync_seal(client, app, sealed)
        upload_owner_share(client, sealed.seal_id, sealed.shares[0])
        sync_seal(client, app, resealed, event_id=2, event_type="Resealing")
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])

        resp = post_form(client, TIMELOCK_URL, {"seal_id": resealed.seal_id,
                                                "share_data": resealed.shares[1]})

        assert resp.status_code == 302
        assert recovered_key(client, resealed.seal_id) == resealed.key_hex
        assert _last(app, resealed.seal_id, "timelock")["detail"].startswith(
            "shares=1+2+3; share 1 of generation 2; ")

    def test_admin_release_with_a_versioned_admin_share_and_the_list(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1MM40", master_key, signer)
        sync_seal(client, app, sealed)
        store_share(app, sealed.seal_id, 4, sealed.shares[3], generation=1)
        sync_seal(client, app, resealed, event_id=2, event_type="Resealing")
        store_share(app, sealed.seal_id, 4, resealed.shares[3], generation=2)
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])
        login_admin(client)

        resp = post_form(client, ADMIN_URL, {"seal_id": sealed.seal_id, "reason": "court order"})
        listing = client.get("/admin/shares").get_data(as_text=True)

        assert resp.status_code == 200
        assert resealed.key_hex in resp.get_data(as_text=True)
        assert _last(app, sealed.seal_id, "admin")["detail"] == (
            "shares=1+4; share 1 of generation 2, share 4 of generation 2")
        assert listing.count(sealed.seal_id) == 2 and "봉인 정책 세대" in listing
        for share in (sealed.shares[3], resealed.shares[3]):
            assert share.split("-")[1] not in listing

    def test_an_unknown_case_is_404_and_nothing_is_stored(self, app, client) -> None:
        ensure_case(app, "S-20260929-F1MM50")

        missing = upload_investigator_share(client, "S-20260929-F1MM5X", "2-" + "ab" * 32)

        assert missing.status_code == 404
        assert share_rows(app, "S-20260929-F1MM5X") == []
