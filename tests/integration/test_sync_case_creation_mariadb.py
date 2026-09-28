"""The signed record creates its case (stage F, F2) on the MariaDB variant.

  - ``cases.registered_by`` (``VARCHAR(64) NOT NULL DEFAULT ''``) is the
    last column, and the ``ADD COLUMN IF NOT EXISTS`` step adds it to a
    v1.1 ``cases`` table (idempotent; existing rows get ``''``);
  - a signed first sync creates the case on tuple rows (digests,
    ciphertexts, ``registered_by``) and the subject then authenticates; an
    administrator's registration records the username; a refused creation
    (missing identity value) leaves nothing, its nonce included;
  - two simultaneous first syncs of one seal: ``SELECT ... FOR UPDATE`` on
    the missing case row takes only a gap lock, so both reach the insert
    and one of them fails (deadlock or duplicate key). It is rolled back
    entirely, nonce included, and answered 503 with ``Retry-After``; one
    case, one record and one data key remain, and its retry succeeds;
  - two new seals whose IDs fall in the same index gap collide the same way.

Skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must be a
throwaway test instance: the module drops and recreates databases whose
names start with ``enc_release_test``. Synthetic data only; keys and
passwords are generated per run. Environment as in
``test_release_mariadb.py``: RELEASE_TEST_MARIADB_HOST, _PORT, _USER,
_PASSWORD, _DB.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from tests.fixtures.case_registration import (
    CASE_NUMBER,
    INVESTIGATOR,
    SUBJECT,
    SYNC_URL,
    creatable_record,
    register_as_admin,
    registration_form,
    slow_case_creation,
)
from tests.fixtures.concurrency import run_concurrently
from tests.fixtures.privacy_keys import read_pepper
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import post_form
from tests.fixtures.sync_web import signed_payload

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = os.environ.get("RELEASE_TEST_MARIADB_DB", "enc_release_test") + "_f2"
MIGRATION_DB = DB + "_migr"

# ``cases`` as v1.1.0 (5c9891b) created it on MariaDB, and one protected row.
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
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    suspect_name_digest  VARCHAR(64) NOT NULL DEFAULT '',
    suspect_birth_digest VARCHAR(64) NOT NULL DEFAULT '',
    suspect_phone_digest VARCHAR(64) NOT NULL DEFAULT '',
    suspect_name_enc     TEXT        NOT NULL DEFAULT '',
    suspect_email_enc    TEXT        NOT NULL DEFAULT '',
    identity_scheme      VARCHAR(16) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""
_V11_ROW = """
INSERT INTO cases (seal_id, case_number, investigator, suspect_name, auth_level,
                   suspect_name_digest, suspect_name_enc, identity_scheme)
VALUES ('S-20260901-MV1101', '2026-V11-M', '수사관V', '', 'basic', 'aa', 'e1:synthetic', 'v1')
"""


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


def _count(table: str, seal_id: str) -> int:
    [(count,)] = _query(DB, f"SELECT COUNT(*) FROM {table} WHERE seal_id = %s", (seal_id,))
    return int(count)


def _columns(database: str) -> list[tuple[str, str, str]]:
    return [(name, str(ctype).lower(), nullable) for name, ctype, nullable in _query(
        database, """SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE FROM information_schema.COLUMNS
                     WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'cases'
                     ORDER BY ORDINAL_POSITION""", (database,))]


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    _recreate(DB)


def _make_app(monkeypatch: pytest.MonkeyPatch, database: str = DB, **release: str) -> Any:
    """A testing app on the MariaDB server; fails if it fell back to SQLite."""
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT),
                        ("DB_USER", USER), ("DB_PASSWORD", PASSWORD), ("DB_NAME", database)):
        monkeypatch.setattr(TestingConfig, name, value)
    monkeypatch.setenv("USE_SQLITE", "false")
    from web.app import create_app

    app = create_app("testing")
    app.config.update(release)
    with app.app_context():
        from flask import g

        from web.models.db_models import get_db

        get_db()
        assert g.db_type == "mariadb", "the app fell back to SQLite; the MariaDB path was not exercised"
    return app


@pytest.fixture()
def master_key(tmp_path) -> str:
    from desktop.crypto.local_kms import init_master_key

    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


@pytest.fixture()
def app(monkeypatch, release_pki, master_key):
    return _make_app(monkeypatch, POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path),
                     RELEASE_KMS_MASTER_KEY_PATH=master_key)


def _seal(seal_id: str, master_key: str, signer: Any) -> Any:
    return make_seal_material(seal_id=seal_id, master_key_path=master_key, signer=signer,
                              case_no=CASE_NUMBER, generation=1)


def _answer(app: Any, body: dict) -> tuple[int, str]:
    resp = app.test_client().post(SYNC_URL, json=body)
    return resp.status_code, resp.headers.get("Retry-After", "")


def _nonce(body: dict) -> str:
    return body["sync_auth"]["envelope"]["nonce"]


def _nonces(seal_id: str) -> list[str]:
    """The stored sync nonces of one seal (the database is shared by the module)."""
    return [nonce for (nonce,) in _query(
        DB, "SELECT nonce FROM sync_nonces WHERE seal_id = %s ORDER BY nonce", (seal_id,))]


class TestMariadbSchema:
    def test_registered_by_is_the_last_cases_column(self, app) -> None:
        assert _columns(DB)[-1] == ("registered_by", "varchar(64)", "NO")

    def test_a_v11_cases_table_gains_it(self, monkeypatch) -> None:
        _recreate(MIGRATION_DB)
        _query(MIGRATION_DB, _V11_CASES)
        _query(MIGRATION_DB, _V11_ROW)

        _make_app(monkeypatch, MIGRATION_DB)
        _make_app(monkeypatch, MIGRATION_DB)  # the step is idempotent

        columns = _columns(MIGRATION_DB)
        assert [name for name, _, _ in columns[-2:]] == ["identity_scheme", "registered_by"]
        assert columns[-1] == ("registered_by", "varchar(64)", "NO")
        assert len(columns) == 18 + 1
        assert _query(MIGRATION_DB, "SELECT seal_id, registered_by FROM cases") == [
            ("S-20260901-MV1101", "")]


class TestMariadbCreation:
    def test_a_signed_first_sync_creates_the_case(self, app, master_key, signer) -> None:
        from cryptography.hazmat.primitives import hashes

        from web.privacy.digests import identity_digest

        seal = _seal("S-20260928-F2MC01", master_key, signer)

        status, _ = _answer(app, signed_payload(seal, signer, record=creatable_record(seal)))

        assert status == 200
        [row] = _query(DB, """SELECT case_number, investigator, suspect_name, suspect_email,
                                     suspect_birth, suspect_phone, auth_level, password_hash,
                                     suspect_name_digest, suspect_phone_digest, identity_scheme,
                                     registered_by FROM cases WHERE seal_id = %s""",
                       (seal.seal_id,))
        fingerprint = signer.cert.fingerprint(hashes.SHA256()).hex()
        pepper = read_pepper(app)
        assert row == (CASE_NUMBER, INVESTIGATOR, "", "", "", "", "basic", "",
                       identity_digest(pepper, "name", seal.seal_id, SUBJECT["name"]),
                       identity_digest(pepper, "phone", seal.seal_id, SUBJECT["phone"]),
                       "v1", "sync:" + fingerprint[:16])
        assert (_count("seal_data_keys", seal.seal_id), _count("seal_records", seal.seal_id)) == (1, 1)
        auth = post_form(app.test_client(), f"/suspect/auth/{seal.seal_id}",
                         {"name": SUBJECT["name"], "birth_date": SUBJECT["birth_date"],
                          "phone": SUBJECT["phone"]})
        assert auth.status_code == 302

    def test_a_refused_creation_leaves_nothing(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2MC02", master_key, signer)
        record = creatable_record(seal, signer_info={"phone": ""})

        status, _ = _answer(app, signed_payload(seal, signer, record=record))

        assert status == 422
        for table in ("cases", "seal_records", "seal_data_keys", "policy_high_water"):
            assert _count(table, seal.seal_id) == 0, table
        assert _nonces(seal.seal_id) == []

    def test_a_data_key_row_without_its_case_is_a_fault_not_a_race(
        self, app, master_key, signer
    ) -> None:
        # Only a conflict on the case row's own insert is a race (503); a
        # duplicate on the data key's insert (an orphan row, possible only
        # with foreign key checks off) is a fault: 500, nothing kept.
        seal = _seal("S-20260928-F2MC04", master_key, signer)
        conn = _server(DB)
        try:
            cur = conn.cursor()
            cur.execute("SET FOREIGN_KEY_CHECKS = 0")
            cur.execute("INSERT INTO seal_data_keys (seal_id, wrapped_key, created_at) "
                        "VALUES (%s, %s, %s)",
                        (seal.seal_id, b"\x00" * 60, "2026-09-28T00:00:00+00:00"))
            conn.commit()
        finally:
            conn.close()

        answer = _answer(app, signed_payload(seal, signer, record=creatable_record(seal)))

        assert answer == (500, "")
        assert _count("cases", seal.seal_id) == 0
        assert _nonces(seal.seal_id) == []

    def test_an_administrators_registration_records_the_username(self, app) -> None:
        resp = register_as_admin(app, registration_form("S-20260928-F2MC03"),
                                 username="admin-f2m")

        assert resp.status_code == 302
        assert _query(DB, "SELECT registered_by FROM cases WHERE seal_id = %s",
                      ("S-20260928-F2MC03",)) == [("admin-f2m",)]


class TestMariadbSimultaneousFirstSyncs:
    def test_one_seal_one_case_and_the_loser_is_asked_to_retry(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        seal = _seal("S-20260928-F2MR01", master_key, signer)
        record = creatable_record(seal)
        bodies = [signed_payload(seal, signer, record=record) for _ in range(2)]
        slow_case_creation(monkeypatch, 0.5)

        answers = run_concurrently(lambda body: _answer(app, body), bodies)

        assert sorted(status for status, _ in answers) == [200, 503], answers
        loser = [status for status, _ in answers].index(503)
        assert answers[loser][1] == "1"
        for table in ("cases", "seal_records", "seal_data_keys", "wrapped_s3_shares"):
            assert _count(table, seal.seal_id) == 1, table
        assert _nonces(seal.seal_id) == [_nonce(bodies[1 - loser])]
        # The loser's nonce was rolled back, so its retry is admitted and
        # completes as an identical resubmission.
        assert _answer(app, bodies[loser]) == (200, "")
        assert _nonces(seal.seal_id) == sorted(_nonce(body) for body in bodies)
        assert _count("cases", seal.seal_id) == 1

    def test_two_new_seals_in_one_index_gap_collide_and_the_retry_succeeds(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        # Without a case row the lock is a gap lock, shared by every missing
        # seal ID between two existing ones: the first syncs of two new
        # seals can collide like two of one seal.
        seals = [_seal(f"S-20260928-F2MG0{i}", master_key, signer) for i in (1, 2)]
        bodies = [signed_payload(seal, signer, record=creatable_record(seal))
                  for seal in seals]
        slow_case_creation(monkeypatch, 0.5)

        answers = run_concurrently(lambda body: _answer(app, body), bodies)

        assert sorted(status for status, _ in answers) == [200, 503], answers
        loser = [status for status, _ in answers].index(503)
        assert _count("cases", seals[loser].seal_id) == 0
        assert _answer(app, bodies[loser])[0] == 200
        assert [_count("cases", seal.seal_id) for seal in seals] == [1, 1]
