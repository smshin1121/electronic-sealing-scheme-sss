"""The registration form needs a signed-in administrator (stage F, F2).

In v1.1 anyone could register a case, and with it the identity binding
and data key of a seal ID (Fable gate, finding 4). Since F2:

  - GET and POST of ``/investigator/register-case`` without a valid
    administrator session (E4) are redirected to the admin login; nothing
    is read from the form or stored, and no budget place is reserved. A
    session whose account was disabled ends there;
  - an administrator's registration behaves as in v1.1 and records the
    account's username in ``cases.registered_by``;
  - ``cases.registered_by`` is the last column of both schema variants and
    is added (``''``) to the ``cases`` table of an existing database.

That a registration attempted without a session leaves the seal ID free
for its signed record is tested with the case creation
(``test_sync_case_creation.py``, ``TestPreemption``).

Synthetic data only.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from tests.fixtures.case_registration import (
    REGISTER_URL,
    admin_client,
    register_as_admin,
    registration_form,
)
from tests.fixtures.privacy_keys import read_pepper
from tests.fixtures.release_web import (
    ADMIN_USERNAME,
    CSRF_TOKEN,
    make_release_app,
    post_form,
)

pytestmark = pytest.mark.integration

LOGIN_REQUIRED = "관리자 인증이 필요합니다."


@pytest.fixture()
def app(tmp_path, monkeypatch):
    return make_release_app(tmp_path, monkeypatch)


def _rows(app: Any, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute(sql, params))
    finally:
        conn.close()


def _cases(app: Any, seal_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in _rows(app, "SELECT * FROM cases WHERE seal_id = ?",
                                       (seal_id,))]


def _digest(app: Any, field: str, seal_id: str, value: str) -> str:
    from web.privacy.digests import identity_digest

    return identity_digest(read_pepper(app), field, seal_id, value)


def _to_login(resp: Any) -> bool:
    return resp.status_code == 302 and resp.headers["Location"].endswith("/admin/login")


# ===================================================================
# The form needs an administrator session
# ===================================================================

class TestAdministratorRequired:
    def test_get_without_a_session_is_sent_to_the_admin_login(self, app) -> None:
        client = app.test_client()

        resp = client.get(REGISTER_URL)
        page = client.get(resp.headers["Location"])

        assert _to_login(resp)
        assert LOGIN_REQUIRED in page.get_data(as_text=True)

    @pytest.mark.parametrize("auth_level", ["basic", "basic+password"])
    def test_post_without_a_session_stores_nothing(self, app, auth_level) -> None:
        import secrets

        form = registration_form("S-20260928-F2A001", auth_level=auth_level,
                                 password=secrets.token_urlsafe(16))

        resp = post_form(app.test_client(), REGISTER_URL, form)

        assert _to_login(resp)
        assert _rows(app, "SELECT * FROM cases") == []
        assert _rows(app, "SELECT * FROM seal_data_keys") == []
        # Refused before the budget: no reservation row, no password work.
        assert _rows(app, "SELECT * FROM auth_failures") == []

    def test_the_v101_admin_flag_is_not_a_session(self, app) -> None:
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["is_admin"] = True

        resp = post_form(client, REGISTER_URL, registration_form("S-20260928-F2A002"))

        assert _to_login(resp)
        assert _rows(app, "SELECT * FROM cases") == []

    def test_a_disabled_accounts_session_ends(self, app) -> None:
        client = admin_client(app)
        with app.app_context():
            from web.auth.admin_auth import disable_admin_account

            disable_admin_account(ADMIN_USERNAME)

        resp = post_form(client, REGISTER_URL, registration_form("S-20260928-F2A003"))

        assert _to_login(resp)
        assert _rows(app, "SELECT * FROM cases") == []
        with client.session_transaction() as sess:
            assert "admin_id" not in sess and "admin_username" not in sess

    def test_an_administrator_registers_and_is_recorded(self, app) -> None:
        form = registration_form("S-20260928-F2A004")

        resp = register_as_admin(app, form, username="admin-f2")

        assert resp.status_code == 302
        assert resp.headers["Location"].endswith(REGISTER_URL)
        [case] = _cases(app, "S-20260928-F2A004")
        assert case["registered_by"] == "admin-f2"
        assert case["suspect_name"] == "" and case["identity_scheme"] == "v1"
        assert case["suspect_phone_digest"] == _digest(
            app, "phone", "S-20260928-F2A004", form["suspect_phone"])

    def test_the_page_names_the_signed_in_administrator(self, app) -> None:
        resp = admin_client(app, "admin-f2").get(REGISTER_URL)

        assert resp.status_code == 200
        assert "admin-f2" in resp.get_data(as_text=True)

    def test_an_existing_seal_id_is_still_refused_with_409(self, app) -> None:
        form = registration_form("S-20260928-F2A005")

        first = register_as_admin(app, form)
        second = register_as_admin(app, {**form, "suspect_name": "다른사람"})

        assert (first.status_code, second.status_code) == (302, 409)
        assert "이미 등록된 봉인 ID" in second.get_data(as_text=True)
        assert len(_cases(app, "S-20260928-F2A005")) == 1

    def test_a_form_post_without_fields_is_400_for_an_administrator(self, app) -> None:
        client = admin_client(app)
        with client.session_transaction() as sess:
            sess["csrf_token"] = CSRF_TOKEN

        assert client.post(REGISTER_URL, data={"csrf_token": CSRF_TOKEN}).status_code == 400

    def test_a_case_created_after_the_check_is_still_409(self, app, monkeypatch) -> None:
        # A signed record's first sync may create the case after the form
        # found the seal id free and before its insert: the answer is the
        # form's 409, not a 500, and the existing case is kept.
        import web.routes.investigator as investigator

        seal_id = "S-20260928-F2A007"
        with app.app_context():
            from web.models.db_models import insert_case

            insert_case(seal_id=seal_id, case_number="2026-F2-SYNC", investigator="수사관S",
                        suspect_name="정하늘")
        checks: list[str] = []
        real = investigator.find_case_by_seal_id

        def free_at_first(candidate: str) -> Any:
            checks.append(candidate)
            return None if len(checks) == 1 else real(candidate)

        monkeypatch.setattr(investigator, "find_case_by_seal_id", free_at_first)

        resp = register_as_admin(app, registration_form(seal_id))

        assert resp.status_code == 409
        assert "이미 등록된 봉인 ID" in resp.get_data(as_text=True)
        [case] = _cases(app, seal_id)
        assert (case["case_number"], case["registered_by"]) == ("2026-F2-SYNC", "")

    @pytest.mark.parametrize("csrf", [True, False])
    def test_only_a_post_registers(self, app, csrf) -> None:
        # Flask answers HEAD on GET routes and the CSRF check skips HEAD, so
        # a HEAD with a form body must not reach the registration.
        client = admin_client(app)
        form = registration_form("S-20260928-F2A006")
        if csrf:
            with client.session_transaction() as sess:
                sess["csrf_token"] = CSRF_TOKEN
            form = {**form, "csrf_token": CSRF_TOKEN}

        resp = client.open(REGISTER_URL, method="HEAD", data=form)

        assert resp.status_code == 200
        assert _rows(app, "SELECT * FROM cases") == []
        assert _rows(app, "SELECT * FROM auth_failures") == []


# ===================================================================
# cases.registered_by in the schema and the migration
# ===================================================================

class TestRegisteredByColumn:
    def test_both_variants_declare_it_as_the_last_cases_column(self) -> None:
        from web.models import db_models

        for ddl, declared in ((db_models._SQLITE_SCHEMA, "registered_by TEXT NOT NULL DEFAULT ''"),
                              (db_models._MARIADB_SCHEMA,
                               "registered_by VARCHAR(64) NOT NULL DEFAULT ''")):
            cases = ddl.split("CREATE TABLE IF NOT EXISTS cases", 1)[1].split(";", 1)[0]
            columns = [line.strip() for line in cases.splitlines()
                       if line.strip() and not line.strip().startswith(("(", ")"))]
            assert " ".join(columns[-1].split()).rstrip(",") == declared

    def test_a_new_database_has_it_last(self, app) -> None:
        columns = _rows(app, "PRAGMA table_info(cases)")

        last = columns[-1]
        assert (last["name"], last["type"], last["notnull"], last["dflt_value"]) == (
            "registered_by", "TEXT", 1, "''")

    def test_an_existing_v11_cases_table_gains_it_at_start_up(
        self, tmp_path, monkeypatch
    ) -> None:
        db_path = tmp_path / "release_web.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(V11_CASES_DDL)
        conn.execute(V11_CASE_ROW)
        conn.commit()
        conn.close()

        app = make_release_app(tmp_path, monkeypatch)
        make_release_app(tmp_path, monkeypatch)  # the step is idempotent

        names = [row["name"] for row in _rows(app, "PRAGMA table_info(cases)")]
        assert names[-2:] == ["identity_scheme", "registered_by"]
        assert names.count("registered_by") == 1
        [old] = _cases(app, "S-20260901-V11001")
        assert old["registered_by"] == "" and old["identity_scheme"] == "v1"


# ``cases`` as v1.1.0 (5c9891b) created it on SQLite, and one protected row
# (synthetic digest and ciphertext stand-ins).
V11_CASES_DDL = """
CREATE TABLE cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL UNIQUE,
    case_number TEXT    NOT NULL,
    investigator TEXT   NOT NULL,
    suspect_name TEXT   NOT NULL,
    suspect_email TEXT  NOT NULL DEFAULT '',
    suspect_birth TEXT  NOT NULL DEFAULT '',
    suspect_phone TEXT  NOT NULL DEFAULT '',
    auth_level  TEXT    NOT NULL DEFAULT 'basic',
    password_hash TEXT  NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    suspect_name_digest  TEXT NOT NULL DEFAULT '',
    suspect_birth_digest TEXT NOT NULL DEFAULT '',
    suspect_phone_digest TEXT NOT NULL DEFAULT '',
    suspect_name_enc     TEXT NOT NULL DEFAULT '',
    suspect_email_enc    TEXT NOT NULL DEFAULT '',
    identity_scheme      TEXT NOT NULL DEFAULT ''
);
"""
V11_CASE_ROW = """
INSERT INTO cases (seal_id, case_number, investigator, suspect_name, auth_level,
                   suspect_name_digest, suspect_name_enc, identity_scheme)
VALUES ('S-20260901-V11001', '2026-V11-01', '수사관V', '', 'basic',
        'aa', 'e1:synthetic', 'v1')
"""
