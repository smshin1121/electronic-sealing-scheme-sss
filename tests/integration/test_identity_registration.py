"""Identity protection at case registration (stage E, E3a).

Registering a case stores keyed digests of the subject's name, birth date
and phone and AES-256-GCM ciphertexts of the name and e-mail under a new
per-seal data key (stored wrapped), all in one transaction; the plaintext
columns of ``cases`` hold ''. Without the keys, registration answers 503.
New case passwords are scrypt hashes and follow the 12-character policy;
a password is stored only when the authentication level uses it. Both
schema variants declare the new columns and tables, and an existing
``cases`` table gains the columns at start-up. Synthetic data only.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.privacy_keys import clear_privacy_keys, read_pepper
from tests.fixtures.release_web import CSRF_TOKEN, make_release_app, post_form

pytestmark = pytest.mark.integration

REGISTER_URL = "/investigator/register-case"
NAME, EMAIL = "홍길동", "hong.gildong@example.org"
BIRTH, PHONE = "1990-01-01", "010-1234-5678"
# Every representation of the synthetic identity that must not be stored.
PLAINTEXTS = (NAME, EMAIL, "hong.gildong", BIRTH, "19900101", PHONE, "01012345678")
NEW_CASE_COLUMNS = [
    "suspect_name_digest", "suspect_birth_digest", "suspect_phone_digest",
    "suspect_name_enc", "suspect_email_enc", "identity_scheme",
]


@pytest.fixture()
def app(tmp_path, monkeypatch):
    return make_release_app(tmp_path, monkeypatch)


@pytest.fixture()
def client(app):
    return app.test_client()


def _form(seal_id: str, **overrides: str) -> dict[str, str]:
    form = {
        "seal_id": seal_id, "case_number": "2026-E3A-001", "investigator": "수사관A",
        "suspect_name": NAME, "suspect_email": EMAIL, "suspect_birth": BIRTH,
        "suspect_phone": PHONE, "auth_level": "basic",
    }
    form.update(overrides)
    return form


def _register(client: Any, seal_id: str, **overrides: str) -> Any:
    return post_form(client, REGISTER_URL, _form(seal_id, **overrides))


def _db_path(app: Any) -> str:
    return app.config["SQLITE_PATH"]


def _rows(app: Any, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn = sqlite3.connect(_db_path(app))
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute(sql, params))
    finally:
        conn.close()


def _case(app: Any, seal_id: str) -> dict[str, Any]:
    [row] = _rows(app, "SELECT * FROM cases WHERE seal_id = ?", (seal_id,))
    return dict(row)


def _expected_digest(app: Any, field: str, seal_id: str, value: str) -> str:
    from web.privacy.digests import identity_digest

    return identity_digest(read_pepper(app), field, seal_id, value)


def _database_bytes(app: Any) -> bytes:
    base = Path(_db_path(app))
    return b"".join(p.read_bytes() for p in (base, Path(f"{base}-wal")) if p.exists())


class TestProtectedRegistration:
    def test_no_column_holds_the_plaintext_identity(self, app, client) -> None:
        seal_id = "S-20260928-REG001"

        resp = _register(client, seal_id)

        assert resp.status_code == 302
        row = _case(app, seal_id)
        for column, value in row.items():
            for plaintext in PLAINTEXTS:
                assert plaintext not in str(value), (column, plaintext)
        for column in ("suspect_name", "suspect_email", "suspect_birth", "suspect_phone"):
            assert row[column] == ""
        stored = _database_bytes(app)
        for plaintext in PLAINTEXTS:
            assert plaintext.encode("utf-8") not in stored, plaintext

    def test_digests_and_ciphertexts_are_stored(self, app, client) -> None:
        seal_id = "S-20260928-REG002"

        _register(client, seal_id)

        row = _case(app, seal_id)
        assert row["identity_scheme"] == "v1"
        assert row["suspect_name_digest"] == _expected_digest(app, "name", seal_id, NAME)
        assert row["suspect_birth_digest"] == _expected_digest(app, "birth_date", seal_id, "19900101")
        assert row["suspect_phone_digest"] == _expected_digest(app, "phone", seal_id, "01012345678")
        assert row["suspect_name_enc"].startswith("e1:")
        assert row["suspect_email_enc"].startswith("e1:")
        [key_row] = _rows(app, "SELECT * FROM seal_data_keys WHERE seal_id = ?", (seal_id,))
        assert len(bytes(key_row["wrapped_key"])) == 12 + 32 + 16
        assert _rows(app, "SELECT * FROM identity_access_audit") == []

    def test_ciphertexts_decrypt_with_the_seal_data_key(self, app, client) -> None:
        seal_id = "S-20260928-REG003"
        _register(client, seal_id)

        row = _case(app, seal_id)
        with app.app_context():
            from web.privacy.case_identity import load_seal_data_key
            from web.privacy.field_crypto import decrypt_field

            key = load_seal_data_key(seal_id)
        assert decrypt_field(key, "cases", seal_id, "suspect_name_enc",
                             row["suspect_name_enc"]) == NAME
        assert decrypt_field(key, "cases", seal_id, "suspect_email_enc",
                             row["suspect_email_enc"]) == EMAIL

    def test_optional_fields_left_empty_have_no_digest_or_ciphertext(self, app, client) -> None:
        seal_id = "S-20260928-REG004"

        resp = _register(client, seal_id, suspect_email="", suspect_birth="", suspect_phone="")

        assert resp.status_code == 302
        row = _case(app, seal_id)
        assert (row["suspect_birth_digest"], row["suspect_phone_digest"],
                row["suspect_email_enc"]) == ("", "", "")
        assert row["suspect_name_digest"] and row["suspect_name_enc"]

    def test_a_failed_data_key_insert_leaves_no_case_row(self, app, client) -> None:
        conn = sqlite3.connect(_db_path(app))
        conn.execute("""CREATE TRIGGER e3a_fail_data_key BEFORE INSERT ON seal_data_keys
                        BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END""")
        conn.commit()
        conn.close()

        resp = _register(client, "S-20260928-REG005")

        assert resp.status_code == 500
        assert _rows(app, "SELECT * FROM cases WHERE seal_id = ?", ("S-20260928-REG005",)) == []

    def test_insert_case_keeps_its_signature_and_protects_the_identity(self, app) -> None:
        seal_id = "S-20260928-REG006"
        with app.app_context():
            from web.models.db_models import insert_case

            insert_case(seal_id=seal_id, case_number="C-1", investigator="수사관",
                        suspect_name=NAME, suspect_email=EMAIL,
                        suspect_birth=BIRTH, suspect_phone=PHONE)

        row = _case(app, seal_id)
        assert row["suspect_name"] == "" and row["identity_scheme"] == "v1"
        assert row["suspect_phone_digest"] == _expected_digest(app, "phone", seal_id, PHONE)


class TestRegistrationRules:
    @pytest.mark.parametrize("unset", ["pepper", "master_key", "both"])
    def test_missing_keys_refuse_registration_with_503(self, app, client, unset) -> None:
        # An app does not start without the keys (Fable gate, finding 5);
        # clearing them on a running app stands for a key lost later.
        clear_privacy_keys(app, unset)

        resp = _register(client, "S-20260928-REG101")

        assert resp.status_code == 503
        assert "개인정보 보호 키" in resp.get_data(as_text=True)
        assert _rows(app, "SELECT * FROM cases") == []

    def test_a_master_key_unreadable_when_wrapping_is_503(self, app, client, monkeypatch) -> None:
        from web.privacy.field_crypto import FieldCryptoError

        def unreadable(*args: Any) -> bytes:
            raise FieldCryptoError("the data key could not be wrapped")

        monkeypatch.setattr("web.privacy.case_identity.wrap_data_key", unreadable)
        resp = _register(client, "S-20260928-REG108")

        assert resp.status_code == 503
        assert _rows(app, "SELECT * FROM cases") == []

    def test_insert_case_without_keys_raises(self, app) -> None:
        clear_privacy_keys(app)

        with app.app_context():
            from web.models.db_models import insert_case
            from web.privacy.keys import PrivacyUnavailable

            with pytest.raises(PrivacyUnavailable):
                insert_case(seal_id="S-20260928-REG102", case_number="C-1",
                            investigator="수사관", suspect_name=NAME)
        assert _rows(app, "SELECT * FROM cases") == []

    def test_short_case_password_is_refused(self, app, client) -> None:
        resp = _register(client, "S-20260928-REG103", auth_level="basic+password",
                         password="a" * 11)

        assert resp.status_code == 400
        assert "12자 이상" in resp.get_data(as_text=True)
        assert _rows(app, "SELECT * FROM cases") == []

    def test_new_case_password_is_a_scrypt_hash(self, app, client) -> None:
        import secrets

        password = secrets.token_urlsafe(12)
        resp = _register(client, "S-20260928-REG104", auth_level="basic+password",
                         password=password)

        assert resp.status_code == 302
        stored = _case(app, "S-20260928-REG104")["password_hash"]
        assert stored.startswith("scrypt$")
        from web.auth.passwords import verify_password

        assert verify_password(password, stored)

    def test_password_is_not_stored_when_the_level_does_not_use_it(self, app, client) -> None:
        import secrets

        resp = _register(client, "S-20260928-REG105", auth_level="basic",
                         password=secrets.token_urlsafe(12))

        assert resp.status_code == 302
        assert _case(app, "S-20260928-REG105")["password_hash"] == ""

    def test_unknown_auth_level_is_refused(self, app, client) -> None:
        resp = _register(client, "S-20260928-REG106", auth_level="otp")

        assert resp.status_code == 400
        assert _rows(app, "SELECT * FROM cases") == []

    @pytest.mark.parametrize("field,length", [
        ("suspect_name", 129), ("suspect_email", 257),
        ("suspect_birth", 17), ("suspect_phone", 33),
        # seal_id is also the associated data of the ciphertexts: a value
        # MariaDB would truncate could never be decrypted or matched again.
        ("seal_id", 65), ("case_number", 129), ("investigator", 129),
    ])
    def test_overlong_identity_fields_are_refused(self, app, client, field, length) -> None:
        form = {**_form("S-20260928-REG107"), field: "1" * length}

        resp = post_form(client, REGISTER_URL, form)

        assert resp.status_code == 400
        assert _rows(app, "SELECT * FROM cases") == []

    def test_registration_form_post_without_fields_is_400(self, client) -> None:
        with client.session_transaction() as sess:
            sess["csrf_token"] = CSRF_TOKEN
        resp = client.post(REGISTER_URL, data={"csrf_token": CSRF_TOKEN})
        assert resp.status_code == 400


class TestSchema:
    def test_both_variants_declare_the_new_columns_and_tables(self) -> None:
        from web.models import db_models, privacy_schema

        for ddl in (db_models._SQLITE_SCHEMA, db_models._MARIADB_SCHEMA):
            cases = ddl.split("CREATE TABLE IF NOT EXISTS cases", 1)[1].split(";", 1)[0]
            for column in NEW_CASE_COLUMNS:
                assert f"\n    {column} " in cases, column
        for ddl in (privacy_schema.SQLITE_PRIVACY_SCHEMA, privacy_schema.MARIADB_PRIVACY_SCHEMA):
            assert "CREATE TABLE IF NOT EXISTS seal_data_keys" in ddl
            assert "CREATE TABLE IF NOT EXISTS identity_access_audit" in ddl

    def test_new_sqlite_database_has_the_columns_last_and_the_tables(self, app) -> None:
        cases = [r["name"] for r in _rows(app, "PRAGMA table_info(cases)")]
        keys = [r["name"] for r in _rows(app, "PRAGMA table_info(seal_data_keys)")]
        audit = [r["name"] for r in _rows(app, "PRAGMA table_info(identity_access_audit)")]

        assert cases[-len(NEW_CASE_COLUMNS):] == NEW_CASE_COLUMNS
        assert keys == ["seal_id", "wrapped_key", "created_at"]
        assert audit == ["id", "seal_id", "field", "purpose", "actor_role", "actor",
                         "client_address", "outcome", "created_at"]

    def test_existing_cases_table_gains_the_columns_at_start_up(self, tmp_path, monkeypatch) -> None:
        db_path = tmp_path / "release_web.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(V101_CASES_DDL)
        conn.execute(V101_CASE_ROW)
        conn.commit()
        conn.close()

        app = make_release_app(tmp_path, monkeypatch)
        make_release_app(tmp_path, monkeypatch)  # idempotent

        columns = [r["name"] for r in _rows(app, "PRAGMA table_info(cases)")]
        assert columns[-len(NEW_CASE_COLUMNS):] == NEW_CASE_COLUMNS
        assert all(columns.count(c) == 1 for c in NEW_CASE_COLUMNS)
        old = _case(app, "S-20260101-OLD001")
        assert old["suspect_name"] == "김철수" and old["identity_scheme"] == ""
        assert old["suspect_name_digest"] == ""


# ``cases`` as v1.0.1 (a2dc8e6) created it on SQLite, with one plaintext row.
V101_CASES_DDL = """
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
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""
V101_CASE_ROW = """
INSERT INTO cases (seal_id, case_number, investigator, suspect_name,
                   suspect_email, suspect_birth, suspect_phone, auth_level)
VALUES ('S-20260101-OLD001', '2026-OLD-01', '수사관B', '김철수',
        'kim.cs@example.org', '19850505', '010-9876-5432', 'basic')
"""
