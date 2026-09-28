"""A missing per-seal data key is never silently replaced, on MariaDB (M1).

The MariaDB counterpart of ``test_data_key_invariant.py``: under the case
row lock (``SELECT ... FOR UPDATE``), a write that would need a new key for
a seal holding protected data is refused (503; no key, record, nonce or mark
change), the conversion tool refuses such a seal's rows, and a genuinely
unprotected legacy case still gets its key. It also checks that an unreadable
record is skipped when a readable record carrying the marked policy decides
(the precise claim of the E3b report after Codex round 3).

Skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must be a
throwaway test instance: the module drops and recreates databases whose
names start with ``enc_release_test``. Synthetic data only. Environment as
in ``test_release_mariadb.py``.
"""

from __future__ import annotations

import io
import json
import os
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import (
    IDENTITY_VALUES,
    PDF_MARKER,
    identity_record,
    synthetic_pdf,
)
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    recover_standard,
    recovered_key,
    store_share,
    sync_payload,
)
from tests.fixtures.sync_web import high_water, nonce_rows, signed_payload

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = "enc_release_test_e3c"
MIGRATION_DB = DB + "_migr"
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


def _legacy_case(database: str, seal_id: str) -> None:
    _rows(database, "INSERT INTO cases (seal_id, case_number, investigator, suspect_name) "
                    "VALUES (%s, 'OLD', 'old', 'x')", (seal_id,))


def _drop_key(database: str, seal_id: str) -> None:
    _rows(database, "DELETE FROM seal_data_keys WHERE seal_id = %s", (seal_id,))


def _keys(database: str, seal_id: str) -> list[dict]:
    return _rows(database, "SELECT wrapped_key FROM seal_data_keys WHERE seal_id = %s",
                 (seal_id,))


def _records(database: str, seal_id: str) -> list[dict]:
    return _rows(database, "SELECT * FROM seal_records WHERE seal_id = %s ORDER BY event_id",
                 (seal_id,))


def _unsigned(seal: Any, record: dict, event_id: int = 1, event_type: str = "Sealing") -> dict:
    return sync_payload(seal, record=record, event_id=event_id, event_type=event_type,
                        include_wrapped=False)


class TestMariadbSyncRefusesAReplacementKey:
    @pytest.mark.parametrize("kind", ["protected_identity", "protected_records"])
    def test_a_new_event_for_a_protected_seal_without_its_key_is_refused(
        self, app, master_key, signer, kind
    ) -> None:
        seal_id = {"protected_identity": "S-20260928-M1D001",
                   "protected_records": "S-20260928-M1D002"}[kind]
        seal = _seal(seal_id, master_key, signer)
        if kind == "protected_identity":
            ensure_case(app, seal.seal_id)
        else:
            _legacy_case(DB, seal.seal_id)
        first = signed_payload(seal, signer, record=identity_record(seal))
        assert app.test_client().post(URL, json=first).status_code == 200
        mark, nonces, records = (high_water(app, seal.seal_id), nonce_rows(app),
                                 _records(DB, seal.seal_id))
        _drop_key(DB, seal.seal_id)
        second = signed_payload(seal, signer, event_id=2, event_type="Unsealing",
                                record=identity_record(seal, note="2"), include_wrapped=False)

        resp = app.test_client().post(URL, json=second)

        assert resp.status_code == 503
        assert "데이터 키" in resp.get_json()["message"]
        assert _keys(DB, seal.seal_id) == []
        assert nonce_rows(app) == nonces
        assert high_water(app, seal.seal_id) == mark and mark is not None
        assert _records(DB, seal.seal_id) == records

    def test_a_genuinely_legacy_case_still_gets_its_key(self, app, master_key) -> None:
        seal = _seal("S-20260928-M1D200", master_key, None)
        _legacy_case(DB, seal.seal_id)
        body = _unsigned(seal, identity_record(seal))

        assert app.test_client().post(URL, json=body).status_code == 200

        assert len(_keys(DB, seal.seal_id)) == 1
        with app.app_context():
            from web.models.release_models import find_record_json_at

            assert find_record_json_at(seal.seal_id, 1) == body["record_json"]


class TestMariadbUnreadableCandidates:
    def test_an_unreadable_record_is_skipped_when_a_readable_one_decides(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-M1D300", master_key, signer)
        other = _seal("S-20260928-M1D301", master_key, None)
        for event_id, event_type in ((1, "Sealing"), (2, "Unsealing")):
            body = signed_payload(seal, signer, event_id=event_id, event_type=event_type,
                                  record=identity_record(seal, note=str(event_id)),
                                  include_wrapped=event_id == 1)
            ensure_case(app, seal.seal_id)
            assert app.test_client().post(URL, json=body).status_code == 200
        ensure_case(app, other.seal_id)
        assert app.test_client().post(URL, json=_unsigned(other, other.record)).status_code == 200
        store_share(app, seal.seal_id, 1, seal.shares[0])
        [moved] = _rows(DB, "SELECT record_json FROM seal_records WHERE seal_id = %s",
                        (other.seal_id,))
        _rows(DB, "UPDATE seal_records SET record_json = %s WHERE seal_id = %s AND event_id = 2",
              (moved["record_json"], seal.seal_id))
        client = app.test_client()

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        [row] = audit_rows(app, seal.seal_id)
        assert (row["outcome"], row["policy_status"]) == ("released", "verified")
        assert "1 newer record(s) without an authenticated policy ignored" in row["detail"]


class TestMariadbConversionRefusesAReplacementKey:
    def test_a_mixed_seal_without_its_key_is_refused(self, monkeypatch, master_key) -> None:
        _recreate(MIGRATION_DB)
        app = _make_app(monkeypatch, MIGRATION_DB, RELEASE_KMS_MASTER_KEY_PATH=master_key)
        seal = _seal("S-20260928-M1D400", master_key, None)
        _legacy_case(MIGRATION_DB, seal.seal_id)
        assert app.test_client().post(
            URL, json=_unsigned(seal, identity_record(seal))).status_code == 200
        old_text = json.dumps(identity_record(seal, note="old"), ensure_ascii=False)
        _rows(MIGRATION_DB, """INSERT INTO seal_records (seal_id, event_id, event_type,
                               record_json, record_pdf) VALUES (%s, 2, 'Unsealing', %s, %s)""",
              (seal.seal_id, old_text, synthetic_pdf("old")))
        _drop_key(MIGRATION_DB, seal.seal_id)
        records = _records(MIGRATION_DB, seal.seal_id)
        [case_before] = _rows(MIGRATION_DB, "SELECT * FROM cases WHERE seal_id = %s",
                              (seal.seal_id,))

        from web.cli_support import build_cli_app
        from web.privacy.migrate import main

        out, err = io.StringIO(), io.StringIO()
        code = main(["--apply"], app=build_cli_app("testing"), stdout=out, stderr=err)
        text = out.getvalue() + err.getvalue()

        assert code == 1
        assert "데이터 키 없어 거부 1건" in text
        assert f"데이터 키 없음: {seal.seal_id!r}" in text
        for value in IDENTITY_VALUES:
            assert value not in text
        assert PDF_MARKER.decode("ascii") not in text
        assert _keys(MIGRATION_DB, seal.seal_id) == []
        assert _records(MIGRATION_DB, seal.seal_id) == records
        assert _rows(MIGRATION_DB, "SELECT * FROM cases WHERE seal_id = %s",
                     (seal.seal_id,)) == [case_before]
