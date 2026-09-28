"""Administrator identity (stage E, E4) on the MariaDB variant.

The E4 tests run on SQLite; this module runs the MariaDB-only code on a
real MariaDB server: the ``admin_accounts`` DDL (binary username
collation, unique key), the account helpers on tuple rows, the account
CLI against MariaDB, login and session revocation, the ``operator`` column
of ``release_audit`` written by the admin path, and the migration of a
``release_audit`` table created without it (``ADD COLUMN IF NOT EXISTS``).

It is skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must
be a throwaway test instance: the module drops and recreates two databases
whose names start with ``enc_release_test``. Synthetic data only; every
password is generated per test. Environment as in
``test_release_mariadb.py``: RELEASE_TEST_MARIADB_HOST, _PORT, _USER,
_PASSWORD, _DB.
"""

from __future__ import annotations

import io
import os
import secrets
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    SlowDerivations,
    admin_login_failures,
    admin_login_pending,
    audit_rows,
    create_admin,
    login_burst,
    login_from,
    login_with_password,
    post_form,
    store_share,
    sync_seal,
)

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = os.environ.get("RELEASE_TEST_MARIADB_DB", "enc_release_test") + "_e4"
MIGRATION_DB = DB + "_migr"
ADMIN_URL = "/admin/emergency-recover"
SHARES_URL = "/admin/shares"
MSG_LOCKED = "로그인 실패 횟수 초과로 10분간 차단되었습니다"
MSG_BURST = "동시에 처리 중인 로그인 요청이 많습니다"

# release_audit as stage D (276af94) created it on MariaDB, before E4.
_STAGE_D_RELEASE_AUDIT = """
CREATE TABLE release_audit (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    seal_id          VARCHAR(64)  NOT NULL,
    path             ENUM('standard','timelock','admin') NOT NULL,
    policy_status    VARCHAR(32)  NOT NULL,
    policy_digest    VARCHAR(64)  NOT NULL,
    outcome          ENUM('released','denied') NOT NULL,
    reason           VARCHAR(64)  NOT NULL,
    detail           VARCHAR(512) NOT NULL,
    operator_reason  TEXT         NOT NULL,
    tsa_token_sha256 VARCHAR(64)  NOT NULL,
    tsa_token        TEXT         NOT NULL,
    tsa_challenge    VARCHAR(64)  NOT NULL,
    tsa_gen_time     VARCHAR(40)  NOT NULL,
    created_at       VARCHAR(40)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""
_OLD_ROW = """
INSERT INTO release_audit (seal_id, path, policy_status, policy_digest, outcome,
    reason, detail, operator_reason, tsa_token_sha256, tsa_token, tsa_challenge,
    tsa_gen_time, created_at)
VALUES ('S-20260927-OLD002', 'admin', 'legacy', '', 'released', 'released',
    'shares=2+4', 'pre-E4 row (synthetic)', '', '', '', '', '2026-09-27T00:00:00+00:00')
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
        return list(cur.fetchall())
    finally:
        conn.close()


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    _recreate(DB)


def _make_app(monkeypatch: pytest.MonkeyPatch, database: str = DB, **config: Any) -> Any:
    """A testing app on the MariaDB server; fails if it fell back to SQLite."""
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT), ("DB_USER", USER),
                        ("DB_PASSWORD", PASSWORD), ("DB_NAME", database)):
        monkeypatch.setattr(TestingConfig, name, value)
    monkeypatch.setenv("USE_SQLITE", "false")
    from web.app import create_app

    app = create_app("testing")
    app.config.update(**config)
    with app.app_context():
        from flask import g

        from web.models.db_models import get_db

        get_db()
        assert g.db_type == "mariadb", "the app fell back to SQLite; the MariaDB path was not exercised"
    return app


@pytest.fixture()
def app(monkeypatch, release_pki):
    return _make_app(monkeypatch, POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path))


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


class TestMariadbAccountSchema:
    def test_accounts_table_and_operator_column(self, app) -> None:
        columns = _query(DB, """SELECT COLUMN_NAME, COLLATION_NAME FROM information_schema.COLUMNS
                                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'admin_accounts'
                                ORDER BY ORDINAL_POSITION""", (DB,))
        unique = _query(DB, """SELECT NON_UNIQUE, COLUMN_NAME FROM information_schema.STATISTICS
                               WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'admin_accounts'
                               AND INDEX_NAME = 'uq_admin_username'""", (DB,))
        audit = _query(DB, """SELECT COLUMN_NAME, COLUMN_TYPE, COLUMN_DEFAULT, IS_NULLABLE
                              FROM information_schema.COLUMNS
                              WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'release_audit'
                              ORDER BY ORDINAL_POSITION""", (DB,))

        assert [name for name, _ in columns] == [
            "id", "username", "password_hash", "disabled", "created_at", "disabled_at"]
        assert dict(columns)["username"] == "utf8mb4_bin"
        assert [(int(non_unique), column) for non_unique, column in unique] == [(0, "username")]
        name, column_type, default, nullable = audit[-1]
        assert (name, column_type, nullable) == ("operator", "varchar(64)", "NO")
        assert default in ("''", "")

    def test_no_default_account_exists(self, monkeypatch) -> None:
        empty = DB + "_empty"
        _recreate(empty)

        fresh = _make_app(monkeypatch, empty)

        with fresh.app_context():
            from web.models.admin_models import list_admin_accounts

            assert list_admin_accounts() == []


class TestMariadbAccountsAndLogin:
    def test_cli_creates_lists_and_disables(self, app) -> None:
        from web.admin_accounts import main
        from web.auth.passwords import verify_password

        password = secrets.token_urlsafe(18)

        def run(*argv: str, stdin: str = "") -> tuple[int, str, str]:
            out, err = io.StringIO(), io.StringIO()
            code = main(list(argv), app=app, stdin=io.StringIO(stdin), stdout=out, stderr=err)
            return code, out.getvalue(), err.getvalue()

        created = run("create", "cli.admin", "--password-stdin", stdin=password + "\n")
        duplicate = run("create", "CLI.Admin", "--password-stdin", stdin=secrets.token_urlsafe(18) + "\n")
        listed = run("list")
        disabled = run("disable", "cli.admin")

        assert created[0] == 0, created[2]
        assert "mariadb (" in created[2]
        assert duplicate[0] == 1
        assert listed[0] == 0 and "cli.admin" in listed[1]
        assert disabled[0] == 0
        for _code, out, err in (created, duplicate, listed, disabled):
            assert password not in out and password not in err
        with app.app_context():
            from web.models.admin_models import find_admin_account_by_username

            account = find_admin_account_by_username("cli.admin")
        assert account is not None and account.disabled and account.disabled_at
        assert verify_password(password, account.password_hash)

    def test_login_and_revocation(self, app, client) -> None:
        password = create_admin(app, "maria.login")

        wrong = login_with_password(client, "maria.login", secrets.token_urlsafe(18))
        right = login_with_password(client, "maria.login", password)
        opened = client.get(SHARES_URL)
        with app.app_context():
            from web.auth.admin_auth import disable_admin_account

            disable_admin_account("maria.login")
        after = client.get(SHARES_URL)

        assert (wrong.status_code, right.status_code, opened.status_code) == (401, 302, 200)
        assert after.status_code == 302 and after.headers["Location"].endswith("/admin/login")

    def test_login_lockout_counts_recent_failures(self, app, client) -> None:
        # count_recent_auth_failures has its own MariaDB branch (DATE_SUB).
        app.config["AUTH_MAX_FAILURES"] = 2
        password = create_admin(app, "maria.lock")

        codes = [login_from(client, "192.0.2.99", "maria.lock", secrets.token_urlsafe(18)).status_code
                 for _ in range(2)]
        locked = login_from(client, "192.0.2.99", "maria.lock", password)
        elsewhere = login_from(client, "198.51.100.99", "maria.lock", password)

        assert codes == [401, 401]
        assert (locked.status_code, elsewhere.status_code) == (429, 302)
        assert MSG_LOCKED in locked.get_data(as_text=True)  # a real lockout

    def test_login_burst_stays_within_the_address_budget(self, app, monkeypatch) -> None:
        # Each request runs on its own connection; under REPEATABLE READ each
        # counts in a snapshot taken after its own reservation was committed.
        from web.auth import passwords

        app.config.update(AUTH_MAX_FAILURES=3, ADMIN_LOGIN_MAX_CONCURRENT=16)
        create_admin(app, "maria.burst")
        slow = SlowDerivations(passwords._derive, delay=1.0)
        monkeypatch.setattr(passwords, "_derive", slow)

        replies = login_burst(app, [("192.0.2.98", "maria.burst", secrets.token_urlsafe(18))] * 8)

        statuses = [status for status, _ in replies]
        assert slow.calls <= 3, statuses
        assert statuses.count(401) == slow.calls
        assert statuses.count(429) == 8 - slow.calls
        for status, body in replies:
            if status == 429:  # refused for attempts in progress, not locked
                assert MSG_BURST in body and MSG_LOCKED not in body
        assert admin_login_failures(app, "192.0.2.98") == slow.calls
        assert admin_login_pending(app, "192.0.2.98") == 0


class TestMariadbOperator:
    def test_emergency_release_records_the_operator(self, app, client, master_key, release_pki) -> None:
        seal = make_seal_material(seal_id="S-20260928-ME4001", master_key_path=master_key,
                                  signer=load_test_signer(release_pki))
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])
        password = create_admin(app, "maria.ops")
        assert login_with_password(client, "maria.ops", password).status_code == 302

        resp = post_form(client, ADMIN_URL, {"seal_id": seal.seal_id, "reason": "court order (synthetic)"})
        blank = post_form(client, ADMIN_URL, {"seal_id": seal.seal_id, "reason": ""})

        assert (resp.status_code, blank.status_code) == (200, 400)
        rows = [r for r in audit_rows(app, seal.seal_id) if r["path"] == "admin"]
        assert [(r["outcome"], r["reason"], r["operator"]) for r in rows] == [
            ("released", "released", "maria.ops"), ("denied", "reason_required", "maria.ops")]

    def test_migration_adds_operator_to_an_existing_table(self, monkeypatch) -> None:
        _recreate(MIGRATION_DB)
        conn = _server(MIGRATION_DB)
        try:
            cur = conn.cursor()
            cur.execute(_STAGE_D_RELEASE_AUDIT)
            cur.execute(_OLD_ROW)
            conn.commit()
        finally:
            conn.close()

        app = _make_app(monkeypatch, MIGRATION_DB)
        _make_app(monkeypatch, MIGRATION_DB)  # idempotent

        columns = [row[0] for row in _query(MIGRATION_DB, """
            SELECT COLUMN_NAME FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'release_audit'
            ORDER BY ORDINAL_POSITION""", (MIGRATION_DB,))]
        assert columns[-1] == "operator" and columns.count("operator") == 1
        [old] = audit_rows(app, "S-20260927-OLD002")
        assert (old["operator"], old["operator_reason"]) == ("", "pre-E4 row (synthetic)")
