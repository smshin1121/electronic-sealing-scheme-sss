"""Synced seal records at rest (stage E, E3b) on the MariaDB variant.

Runs the MariaDB-only paths on a real server: the ``record_scheme`` DDL and
its ``ADD COLUMN IF NOT EXISTS`` migration, encrypted ``LONGTEXT`` and
``LONGBLOB`` values written through ``INSERT IGNORE`` and read back as
tuple rows, the conditional displacement (``BINARY`` comparison of the
stored ciphertext), the refusals (no case, unconverted row), the audited
subject views, and the conversion CLI under ``SELECT ... FOR UPDATE``.

Skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must be a
throwaway test instance: the module drops and recreates databases whose
names start with ``enc_release_test``. Synthetic data only. Environment as
in ``test_release_mariadb.py``.
"""

from __future__ import annotations

import base64
import io
import json
import os
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import (
    IDENTITY_VALUES,
    PDF_MARKER,
    SIGNER_INFO,
    identity_record,
    leaks,
    needles,
    synthetic_pdf,
)
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    recover_standard,
    store_share,
    sync_payload,
)
from tests.fixtures.sync_web import signed_payload

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = "enc_release_test_e3b"
OLD_DB = DB + "_old"
URL = "/sync/upload-record"


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


def _rows(database: str, sql: str, params: tuple = ()) -> list[dict]:
    conn = _server(database)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        names = [d[0] for d in cur.description] if cur.description else []
        rows = [dict(zip(names, row)) for row in cur.fetchall()] if names else []
        conn.commit()
        return rows
    finally:
        conn.close()


def _row(seal_id: str, event_id: int, database: str = DB) -> dict:
    [row] = _rows(database, "SELECT * FROM seal_records WHERE seal_id = %s AND event_id = %s",
                  (seal_id, event_id))
    return row


def _columns(database: str, table: str) -> list[tuple[str, str]]:
    return [(r["COLUMN_NAME"], str(r["COLUMN_TYPE"])) for r in _rows(database, """
        SELECT COLUMN_NAME, COLUMN_TYPE FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION""",
        (database, table))]


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    _recreate(DB)


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


def _make_app(monkeypatch: pytest.MonkeyPatch, database: str, **config: Any) -> Any:
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT),
                        ("DB_USER", USER), ("DB_PASSWORD", PASSWORD), ("DB_NAME", database)):
        monkeypatch.setattr(TestingConfig, name, value)
    monkeypatch.setenv("USE_SQLITE", "false")
    from web.app import create_app

    application = create_app("testing")
    application.config.update(**config)
    with application.app_context():
        from flask import g

        from web.models.db_models import get_db

        get_db()
        assert g.db_type == "mariadb", "the app fell back to SQLite; the MariaDB path was not exercised"
    return application


@pytest.fixture()
def app(monkeypatch, release_pki, master_key):
    return _make_app(monkeypatch, DB, POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path),
                     RELEASE_KMS_MASTER_KEY_PATH=master_key)


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _seal(seal_id: str, master_key: str, signer: Any):
    return make_seal_material(seal_id=seal_id, master_key_path=master_key, signer=signer,
                              generation=1 if signer is not None else None)


def _post(app: Any, body: dict, *, case: bool = True) -> Any:
    if case:
        ensure_case(app, body["seal_id"])
    return app.test_client().post(URL, json=body)


def _unsigned(seal: Any, record: dict, *, event_id: int = 1, event_type: str = "Sealing",
              pdf: bytes | None = None) -> dict:
    body = sync_payload(seal, record=record, event_id=event_id, event_type=event_type,
                        include_wrapped=False)
    if pdf is not None:
        body["record_pdf"] = base64.b64encode(pdf).decode("ascii")
    return body


class TestMariadbSchema:
    def test_the_record_scheme_column(self, app) -> None:
        assert _columns(DB, "seal_records")[-1] == ("record_scheme", "varchar(16)")

    def test_a_pre_e3b_table_gains_the_column(self, monkeypatch, master_key) -> None:
        _recreate(OLD_DB)
        conn = _server(OLD_DB)
        try:
            cur = conn.cursor()
            cur.execute(_V101_CASES)
            cur.execute(_PRE_E3B_RECORDS)
            conn.commit()
        finally:
            conn.close()

        for _ in range(2):  # idempotent
            _make_app(monkeypatch, OLD_DB, RELEASE_KMS_MASTER_KEY_PATH=master_key)

        columns = [name for name, _ in _columns(OLD_DB, "seal_records")]
        assert columns[-1] == "record_scheme" and columns.count("record_scheme") == 1


class TestMariadbStorage:
    def test_a_synced_record_is_stored_encrypted(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-E3BD01", master_key, signer)
        pdf = synthetic_pdf("mariadb")
        # Event 2 is another record (an exact copy of event 1 is refused
        # since the Fable gate fix for finding 1), sent as indented text.
        later = identity_record(seal, process_info={"type": "Unsealing"})
        text = json.dumps(later, ensure_ascii=False, indent=2) + "\n"
        body = signed_payload(seal, signer, record=identity_record(seal), record_pdf=pdf)

        assert _post(app, body).status_code == 200
        unsigned = _unsigned(seal, later, event_id=2, event_type="Unsealing", pdf=pdf)
        unsigned["record_json"] = text
        assert _post(app, unsigned).status_code == 200

        for event_id, sent in ((1, body["record_json"]), (2, text)):
            row = _row(seal.seal_id, event_id)
            assert row["record_scheme"] == "v1"
            assert leaks(row, needles(sent, pdf)) == []
        with app.app_context():
            from web.models.release_models import find_record_json_at, find_record_pdf_at

            assert find_record_json_at(seal.seal_id, 2) == text
            assert find_record_pdf_at(seal.seal_id, 2) == pdf

    def test_resubmissions_and_displacement_behave_as_before(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-E3BD02", master_key, signer)
        stripped = {k: v for k, v in identity_record(seal).items()
                    if k not in ("policy", "policy_signature", "policy_cert")}
        assert _post(app, _unsigned(seal, stripped)).status_code == 200
        first = _row(seal.seal_id, 1)
        again = _unsigned(seal, dict(reversed(list(stripped.items()))))
        conflict = _unsigned(seal, {**stripped, "signer_info": {**SIGNER_INFO, "phone": "x"}})

        assert app.test_client().post(URL, json=again).status_code == 200
        assert app.test_client().post(URL, json=conflict).status_code == 409
        assert _row(seal.seal_id, 1) == first
        with app.app_context():
            from web.models.release_models import (
                find_record_json_at,
                replace_synced_record,
                seal_write_transaction,
            )

            before = find_record_json_at(seal.seal_id, 1)
            change = dict(seal_id=seal.seal_id, event_id=1, event_type="Sealing",
                          record_json=json.dumps(seal.record), record_pdf=None,
                          wrapped_s3=seal.wrapped_s3,
                          enrolled_digest=seal.policy_digest.hex())
            with seal_write_transaction(seal.seal_id):
                assert replace_synced_record(**change,
                                             expected_record_json=before.upper()) is False
            with seal_write_transaction(seal.seal_id):
                assert replace_synced_record(**change, expected_record_json=before) is True
            assert json.loads(find_record_json_at(seal.seal_id, 1)) == seal.record
        assert _row(seal.seal_id, 1)["record_json"] != first["record_json"]

    def test_a_moved_ciphertext_is_unreadable_and_the_gate_denies(
        self, app, master_key
    ) -> None:
        seal = _seal("S-20260928-E3BD03", master_key, None)
        for event_id, event_type in ((1, "Sealing"), (2, "Unsealing")):
            assert _post(app, _unsigned(seal, identity_record(seal, note=str(event_id)),
                                        event_id=event_id, event_type=event_type)
                         ).status_code == 200
        store_share(app, seal.seal_id, 1, seal.shares[0])
        moved = _row(seal.seal_id, 1)["record_json"]
        _rows(DB, "UPDATE seal_records SET record_json = %s WHERE seal_id = %s AND event_id = 2",
              (moved, seal.seal_id))

        with app.app_context():
            from web.models.release_models import find_record_json_at
            from web.privacy.record_store import is_unreadable

            assert is_unreadable(find_record_json_at(seal.seal_id, 2))
        client = app.test_client()
        resp = recover_standard(client, seal)

        assert resp.status_code == 500
        [row] = audit_rows(app, seal.seal_id)
        assert (row["outcome"], row["reason"]) == ("denied", "record_unreadable")

    def test_refusals_no_case_and_unconverted_rows(self, app, master_key) -> None:
        orphan = _seal("S-20260928-E3BD04", master_key, None)
        assert _post(app, _unsigned(orphan, orphan.record), case=False).status_code == 404
        assert _rows(DB, "SELECT id FROM seal_records WHERE seal_id = %s",
                     (orphan.seal_id,)) == []

        legacy = _seal("S-20260928-E3BD05", master_key, None)
        ensure_case(app, legacy.seal_id)
        _rows(DB, """INSERT INTO seal_records (seal_id, event_id, event_type, record_json)
                     VALUES (%s, 1, 'Sealing', %s)""",
              (legacy.seal_id, json.dumps(legacy.record)))
        store_share(app, legacy.seal_id, 1, legacy.shares[0])

        resp = app.test_client().post(URL, json=_unsigned(legacy, legacy.record))
        released = recover_standard(app.test_client(), legacy)

        assert resp.status_code == 503
        assert released.status_code == 500
        [row] = audit_rows(app, legacy.seal_id)
        assert row["outcome"] == "denied" and row["policy_status"] != "record_missing"


class TestMariadbSchemeIsExact:
    @pytest.mark.parametrize("scheme", ["V1", "v1 "])
    def test_a_scheme_not_exactly_v1_counts_as_unconverted(
        self, app, master_key, scheme
    ) -> None:
        # MariaDB's default collation ignores case and trailing spaces; the
        # SQL count must agree with the application's exact comparison.
        seal = _seal(f"S-20260928-E3BD2{len(scheme)}{scheme[0]}", master_key, None)
        assert _post(app, _unsigned(seal, identity_record(seal))).status_code == 200
        with app.app_context():
            from web.models.record_models import count_plaintext_record_rows

            before = count_plaintext_record_rows()
        _rows(DB, "UPDATE seal_records SET record_scheme = %s WHERE seal_id = %s",
              (scheme, seal.seal_id))

        with app.app_context():
            from web.models.record_models import count_plaintext_record_rows
            from web.models.release_models import find_record_json_at
            from web.privacy.record_store import LegacyRecordError

            assert count_plaintext_record_rows() == before + 1
            with pytest.raises(LegacyRecordError):
                find_record_json_at(seal.seal_id, 1)


class TestMariadbSubjectViews:
    def test_views_are_audited_and_a_failed_audit_withholds(
        self, app, master_key, monkeypatch
    ) -> None:
        seal = _seal("S-20260928-E3BD06", master_key, None)
        pdf = synthetic_pdf("view")
        body = _unsigned(seal, identity_record(seal), pdf=pdf)
        assert _post(app, body).status_code == 200
        client = app.test_client()
        with client.session_transaction() as sess:
            sess[f"auth_{seal.seal_id}"] = True

        detail = client.get(f"/suspect/records/{seal.seal_id}/detail/1",
                            headers={"Accept": "application/json"})
        download = client.get(f"/suspect/records/{seal.seal_id}/pdf/1")

        def broken(*_args: Any, **_kwargs: Any) -> int:
            raise RuntimeError("synthetic audit store failure")

        monkeypatch.setattr("web.privacy.record_access.insert_identity_access", broken)
        withheld = client.get(f"/suspect/records/{seal.seal_id}/detail/1",
                              headers={"Accept": "application/json"})

        assert detail.status_code == 200 and detail.get_json()["record_json"] == body["record_json"]
        assert download.status_code == 200 and download.get_data() == pdf
        assert withheld.status_code == 503
        assert body["record_json"].encode("utf-8") not in withheld.get_data()
        audit = _rows(DB, """SELECT field, purpose, actor_role, outcome FROM identity_access_audit
                             WHERE seal_id = %s ORDER BY id""", (seal.seal_id,))
        assert [tuple(a.values()) for a in audit] == [
            ("record_json", "record_view", "subject", "revealed"),
            ("record_pdf", "record_download", "subject", "revealed")]


# ``cases`` as v1.0.1 created it, and ``seal_records`` as stage D/E2a did.
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
_PRE_E3B_RECORDS = """
CREATE TABLE seal_records (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    seal_id      VARCHAR(64) NOT NULL,
    event_id     INT         NOT NULL,
    event_type   ENUM('Sealing','Unsealing','Resealing') NOT NULL,
    record_json  LONGTEXT    NOT NULL,
    record_pdf   LONGBLOB,
    synced_at    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE KEY uq_seal_event (seal_id, event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""
OLD_SEAL = "S-20260928-E3BD09"
OLD_TEXT = json.dumps({"seal_id": OLD_SEAL, "signer_info": SIGNER_INFO}, ensure_ascii=False)
OLD_PDF = synthetic_pdf("old-mariadb")


def _old_database(database: str) -> None:
    """A v1.0.1 ``cases`` row and a pre-E3b plaintext record in a new database."""
    _recreate(database)
    conn = _server(database)
    try:
        cur = conn.cursor()
        cur.execute(_V101_CASES)
        cur.execute(_PRE_E3B_RECORDS)
        cur.execute("""INSERT INTO cases (seal_id, case_number, investigator, suspect_name)
                       VALUES (%s, '2026-OLD', 'old', %s)""", (OLD_SEAL, SIGNER_INFO["name"]))
        cur.execute("""INSERT INTO seal_records (seal_id, event_id, event_type, record_json,
                       record_pdf) VALUES (%s, 1, 'Sealing', %s, %s)""",
                    (OLD_SEAL, OLD_TEXT, OLD_PDF))
        conn.commit()
    finally:
        conn.close()


class TestMariadbMigration:
    def test_pre_e3b_records_are_converted_once(self, monkeypatch, master_key) -> None:
        database = DB + "_migr"
        _old_database(database)
        app = _make_app(monkeypatch, database, RELEASE_KMS_MASTER_KEY_PATH=master_key)

        from web.cli_support import build_cli_app
        from web.privacy.migrate import main

        def run(*argv: str) -> tuple[int, str]:
            out, err = io.StringIO(), io.StringIO()
            code = main(list(argv), app=build_cli_app("testing"), stdout=out, stderr=err)
            return code, out.getvalue() + err.getvalue()

        dry = run("--dry-run")
        applied = run("--apply")
        before = _rows(database, "SELECT * FROM seal_records")
        again = run("--apply")

        assert dry[0] == 0 and "봉인 기록 1건: 보호됨 0건, 암호화 대상 1건" in dry[1]
        assert applied[0] == 0, applied[1]
        assert "봉인 기록: 암호화 1건, 실패 0건, 사건 없어 건너뜀 0건" in applied[1]
        assert "OPTIMIZE TABLE cases, seal_records" in applied[1]
        assert again[0] == 0 and "암호화 대상 0건" in again[1]
        assert _rows(database, "SELECT * FROM seal_records") == before
        for text in (dry[1], applied[1], again[1]):
            for value in IDENTITY_VALUES:
                assert value not in text
            assert PDF_MARKER.decode("ascii") not in text
        [row] = before
        assert row["record_scheme"] == "v1" and leaks(row, needles(OLD_TEXT, OLD_PDF)) == []
        with app.app_context():
            from web.models.release_models import find_record_json_at, find_record_pdf_at

            assert find_record_json_at(OLD_SEAL, 1) == OLD_TEXT
            assert find_record_pdf_at(OLD_SEAL, 1) == OLD_PDF
        audit = _rows(database, "SELECT field, actor_role FROM identity_access_audit "
                                "WHERE field IN (%s, %s) ORDER BY id",
                      ("record_json", "record_pdf"))
        assert [tuple(a.values()) for a in audit] == [("record_json", "system"),
                                                      ("record_pdf", "system")]
