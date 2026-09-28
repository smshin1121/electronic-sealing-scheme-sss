"""Identity protection (stage E, E3a) on the MariaDB variant.

The E3a tests run on SQLite; this module runs the MariaDB-only paths on a
real server: the DDL of the protected ``cases`` columns and of
``seal_data_keys`` and ``identity_access_audit``, registration, basic
authentication and OTP delivery on tuple rows, the legacy password
upgrade, the ``ADD COLUMN IF NOT EXISTS`` migration of a v1.0.1 ``cases``
table, and the conversion CLI under ``SELECT ... FOR UPDATE``.

Skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must be a
throwaway test instance: the module drops and recreates databases whose
names start with ``enc_release_test``. Synthetic data only; keys and
passwords are generated per run. Environment as in
``test_release_mariadb.py``: RELEASE_TEST_MARIADB_HOST, _PORT, _USER,
_PASSWORD, _DB.
"""

from __future__ import annotations

import hashlib
import io
import os
import secrets
from typing import Any

import pytest

from tests.fixtures.release_web import CSRF_TOKEN, post_form

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = os.environ.get("RELEASE_TEST_MARIADB_DB", "enc_release_test") + "_e3a"
MIGRATION_DB = DB + "_migr"

NAME, EMAIL = "홍길동", "hong.gildong@example.org"
BIRTH, PHONE = "1990-01-01", "010-2468-1357"
PLAINTEXTS = (NAME, EMAIL, "hong.gildong", BIRTH, "19900101", PHONE, "01024681357")
NEW_CASE_COLUMNS = [
    ("suspect_name_digest", "varchar(64)"), ("suspect_birth_digest", "varchar(64)"),
    ("suspect_phone_digest", "varchar(64)"), ("suspect_name_enc", "text"),
    ("suspect_email_enc", "text"), ("identity_scheme", "varchar(16)"),
]

# ``cases`` as v1.0.1 (a2dc8e6) created it on MariaDB, and one plaintext row.
_V101_CASES = """
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
_V101_ROW = """
INSERT INTO cases (seal_id, case_number, investigator, suspect_name, suspect_email,
                   suspect_birth, suspect_phone, auth_level)
VALUES ('S-20260101-MOLD01', '2026-OLD', '수사관B', '김철수', 'kim.cs@example.org',
        '19850505', '010-9876-5432', 'basic')
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


def _columns(database: str, table: str) -> list[tuple[str, str]]:
    return [(name, str(ctype)) for name, ctype in _query(database, """
        SELECT COLUMN_NAME, COLUMN_TYPE FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION""",
        (database, table))]


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    _recreate(DB)


def _use_mariadb(monkeypatch: pytest.MonkeyPatch, database: str) -> None:
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT),
                        ("DB_USER", USER), ("DB_PASSWORD", PASSWORD), ("DB_NAME", database)):
        monkeypatch.setattr(TestingConfig, name, value)
    monkeypatch.setenv("USE_SQLITE", "false")


def _make_app(monkeypatch: pytest.MonkeyPatch, database: str = DB) -> Any:
    """A testing app on the MariaDB server; fails if it fell back to SQLite."""
    _use_mariadb(monkeypatch, database)
    from web.app import create_app

    app = create_app("testing")
    with app.app_context():
        from flask import g

        from web.models.db_models import get_db

        get_db()
        assert g.db_type == "mariadb", "the app fell back to SQLite; the MariaDB path was not exercised"
    return app


@pytest.fixture()
def app(monkeypatch):
    return _make_app(monkeypatch)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def sent(monkeypatch) -> list[tuple[str, str]]:
    from web.auth.otp_service import OTPService

    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(OTPService, "send_otp",
                        lambda self, email, otp: calls.append((email, otp)) or True)
    return calls


def _register(client: Any, seal_id: str, **overrides: str) -> Any:
    form = {"seal_id": seal_id, "case_number": "2026-E3A-M", "investigator": "수사관A",
            "suspect_name": NAME, "suspect_email": EMAIL, "suspect_birth": BIRTH,
            "suspect_phone": PHONE, "auth_level": "basic", **overrides}
    return post_form(client, "/investigator/register-case", form)


def _auth(client: Any, seal_id: str, **overrides: str) -> Any:
    form = {"name": NAME, "birth_date": BIRTH, "phone": PHONE, **overrides}
    return post_form(client, f"/suspect/auth/{seal_id}", form)


class TestMariadbSchema:
    def test_protected_columns_and_tables(self, app) -> None:
        cases = _columns(DB, "cases")
        keys = _columns(DB, "seal_data_keys")
        audit = _columns(DB, "identity_access_audit")

        assert [(n, t.lower()) for n, t in cases[-6:]] == NEW_CASE_COLUMNS
        assert [n for n, _ in keys] == ["seal_id", "wrapped_key", "created_at"]
        assert [n for n, _ in audit] == ["id", "seal_id", "field", "purpose", "actor_role",
                                         "actor", "client_address", "outcome", "created_at"]
        fks = _query(DB, """SELECT REFERENCED_TABLE_NAME FROM information_schema.KEY_COLUMN_USAGE
                            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'seal_data_keys'
                            AND REFERENCED_TABLE_NAME IS NOT NULL""", (DB,))
        assert fks == [("cases",)]


class TestMariadbRegistrationAndLogin:
    def test_registration_stores_no_plaintext(self, app, client) -> None:
        resp = _register(client, "S-20260928-MREG01")

        assert resp.status_code == 302
        [row] = _query(DB, "SELECT * FROM cases WHERE seal_id = %s", ("S-20260928-MREG01",))
        for value in row:
            for plaintext in PLAINTEXTS:
                assert plaintext not in str(value), plaintext
        [key] = _query(DB, "SELECT LENGTH(wrapped_key) FROM seal_data_keys WHERE seal_id = %s",
                       ("S-20260928-MREG01",))
        assert key == (60,)

    def test_basic_authentication_on_tuple_rows(self, app, client) -> None:
        _register(client, "S-20260928-MREG02")

        wrong = _auth(app.test_client(), "S-20260928-MREG02", phone="010-2468-1358")
        right = _auth(client, "S-20260928-MREG02", birth_date="19900101", phone="01024681357")

        assert (wrong.status_code, right.status_code) == (401, 302)

    def test_otp_delivery_is_audited(self, app, client, sent) -> None:
        _register(client, "S-20260928-MREG03", auth_level="basic+otp")
        with client.session_transaction() as sess:
            sess["csrf_token"] = CSRF_TOKEN

        def send() -> Any:
            return client.post("/suspect/send-otp/S-20260928-MREG03",
                               data={"name": NAME, "birth_date": BIRTH, "phone": PHONE,
                                     "csrf_token": CSRF_TOKEN},
                               headers={"Accept": "application/json"})

        resp = send()
        app.config["OTP_MAX_DELIVERIES_PER_SEAL"] = 1  # the audit row counts
        capped = send()

        assert resp.status_code == 200 and [e for e, _ in sent] == [EMAIL]
        assert capped.status_code == 429 and len(sent) == 1
        rows = _query(DB, """SELECT field, purpose, actor_role, outcome FROM identity_access_audit
                             WHERE seal_id = %s""", ("S-20260928-MREG03",))
        assert rows == [("suspect_email", "otp_delivery", "subject", "revealed")]

    def test_legacy_case_password_is_upgraded(self, app, client) -> None:
        password = secrets.token_urlsafe(6)
        with app.app_context():
            from web.models.db_models import insert_case

            insert_case(seal_id="S-20260928-MREG04", case_number="C-L", investigator="수사관",
                        suspect_name=NAME, suspect_birth=BIRTH, suspect_phone=PHONE,
                        auth_level="basic+password",
                        password_hash=hashlib.sha256(password.encode()).hexdigest())

        resp = _auth(client, "S-20260928-MREG04", password=password)

        assert resp.status_code == 302
        [(stored,)] = _query(DB, "SELECT password_hash FROM cases WHERE seal_id = %s",
                             ("S-20260928-MREG04",))
        assert stored.startswith("scrypt$")


class TestMariadbMigration:
    def test_v101_table_is_extended_and_converted(self, monkeypatch) -> None:
        _recreate(MIGRATION_DB)
        _query(MIGRATION_DB, _V101_CASES)
        _query(MIGRATION_DB, _V101_ROW)

        _make_app(monkeypatch, MIGRATION_DB)
        _make_app(monkeypatch, MIGRATION_DB)  # the column step is idempotent
        cases = _columns(MIGRATION_DB, "cases")
        assert [(n, t.lower()) for n, t in cases[-6:]] == NEW_CASE_COLUMNS
        assert len(cases) == 12 + 6

        from web.cli_support import build_cli_app
        from web.privacy.migrate import main

        def run(*argv: str) -> tuple[int, str]:
            out, err = io.StringIO(), io.StringIO()
            code = main(list(argv), app=build_cli_app("testing"), stdout=out, stderr=err)
            return code, out.getvalue() + err.getvalue()

        dry = run("--dry-run")
        applied = run("--apply")
        before = _query(MIGRATION_DB, "SELECT * FROM cases")
        again = run("--apply")

        assert dry[0] == 0 and "변환 대상 1건" in dry[1] and "mariadb (" in dry[1]
        assert applied[0] == 0 and "변환 1건, 실패 0건" in applied[1]
        assert "OPTIMIZE TABLE" in applied[1]
        assert again[0] == 0 and "변환 대상 0건" in again[1]
        assert _query(MIGRATION_DB, "SELECT * FROM cases") == before
        for text in (dry[1], applied[1], again[1]):
            assert "김철수" not in text and "kim.cs" not in text
        [row] = _query(MIGRATION_DB, """SELECT suspect_name, suspect_email, suspect_birth,
                                               suspect_phone, identity_scheme FROM cases""")
        assert row == ("", "", "", "", "v1")
        audit = _query(MIGRATION_DB, "SELECT field, actor_role FROM identity_access_audit")
        assert sorted(audit) == [("suspect_email", "system"), ("suspect_name", "system")]

        migrated = _make_app(monkeypatch, MIGRATION_DB)
        resp = post_form(migrated.test_client(), "/suspect/auth/S-20260101-MOLD01",
                         {"name": "김철수", "birth_date": "1985-05-05", "phone": "01098765432"})
        assert resp.status_code == 302
