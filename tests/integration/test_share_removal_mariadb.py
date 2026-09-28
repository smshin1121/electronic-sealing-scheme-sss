"""The administrator's audited share removal on MariaDB (stage F, gate fix).

The SQLite tests are in ``test_share_removal.py``; this module runs the
same remedy on a real MariaDB server: the ``share_removal_audit`` DDL and
its index, the removal under the case-row lock (``SELECT ... FOR UPDATE``)
with tuple rows and a ``DATETIME`` upload time, the genuine share stored and
released afterwards, a failed audit write that removes nothing, and a stale
form that removes nothing once the genuine share is back (Codex review R3,
finding 1).

It is skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must
be a throwaway test instance: the module drops and recreates a database
whose name starts with ``enc_release_test``. Synthetic data only.
Environment as in ``test_release_mariadb.py``: RELEASE_TEST_MARIADB_HOST,
_PORT, _USER, _PASSWORD, _DB.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    login_admin,
    post_form,
    recover_standard,
    recovered_key,
    sync_payload,
    sync_seal,
)
from tests.fixtures.share_uploads import (
    share_row_id,
    share_rows,
    take_flashes,
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
DB = os.environ.get("RELEASE_TEST_MARIADB_DB", "enc_release_test") + "_f7"
REMOVE_URL = "/admin/shares/remove"


def _server(database: str | None = None) -> Any:
    import mariadb

    return mariadb.connect(host=HOST, port=PORT, user=USER, password=PASSWORD,
                           database=database)


def _query(sql: str, params: tuple = ()) -> list[tuple]:
    conn = _server(DB)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = list(cur.fetchall()) if cur.description else []
        conn.commit()
        return rows
    finally:
        conn.close()


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    assert DB.startswith("enc_release_test"), "refusing to drop a non-test database"
    conn = _server()
    try:
        cur = conn.cursor()
        cur.execute(f"DROP DATABASE IF EXISTS `{DB}`")
        cur.execute(f"CREATE DATABASE `{DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(monkeypatch, release_pki, master_key):
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT),
                        ("DB_USER", USER), ("DB_PASSWORD", PASSWORD), ("DB_NAME", DB)):
        monkeypatch.setattr(TestingConfig, name, value)
    monkeypatch.setenv("USE_SQLITE", "false")
    from web.app import create_app

    app = create_app("testing")
    app.config.update(POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path),
                      RELEASE_KMS_MASTER_KEY_PATH=master_key)
    with app.app_context():
        from flask import g

        from web.models.db_models import get_db

        get_db()
        assert g.db_type == "mariadb", "the app fell back to SQLite; the MariaDB path was not exercised"
    return app


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _blocked_generation(app: Any, seal_id: str, master_key: str, signer: Any) -> tuple[Any, Any, Any]:
    """Generation 2 synced after generation 1, and the old share 1 stored by
    mistake in generation 2's slot (as in the SQLite module)."""
    first, second = (make_seal_material(seal_id=seal_id, master_key_path=master_key,
                                        signer=signer, generation=g) for g in (1, 2))
    client = app.test_client()
    sync_seal(client, app, first)
    subject = app.test_client()
    assert upload_owner_share(subject, seal_id, first.shares[0]).status_code == 302
    assert client.post("/sync/upload-record", json=sync_payload(
        second, event_id=2, event_type="Resealing")).status_code == 200
    assert upload_owner_share(subject, seal_id, first.shares[0]).status_code == 302
    take_flashes(subject)
    return first, second, subject


def _admin(app: Any, username: str = "admin-test") -> Any:
    client = app.test_client()
    login_admin(client, username)
    return client


def _remove(client: Any, seal_id: str, row_id: int | None = None) -> Any:
    """POST the removal form of share 1 of generation 2; ``row_id`` defaults
    to the row stored there now."""
    if row_id is None:
        row_id = share_row_id(client.application, seal_id, 1, 2)
    return post_form(client, REMOVE_URL, {"seal_id": seal_id, "share_index": "1",
                                          "generation": "2", "share_row_id": str(row_id),
                                          "reason": "wrong share"})


def test_the_audit_table_and_its_index(app) -> None:
    columns = _query("""SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'share_removal_audit'
                        ORDER BY ORDINAL_POSITION""", (DB,))
    index = _query("""SELECT COLUMN_NAME FROM information_schema.STATISTICS
                      WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'share_removal_audit'
                        AND INDEX_NAME = 'idx_share_removal_audit_seal'
                      ORDER BY SEQ_IN_INDEX""", (DB,))

    assert [name for name, _ in columns] == [
        "id", "seal_id", "share_index", "generation", "uploaded_by", "uploaded_at",
        "share_sha256", "operator", "reason", "removed_at"]
    assert [name for (name,) in index] == ["seal_id", "id"]


def test_the_wrong_share_is_removed_and_the_genuine_one_releases(
    app, master_key, signer
) -> None:
    seal_id = "S-20260928-F7MM01"
    first, second, subject = _blocked_generation(app, seal_id, master_key, signer)

    refused = upload_owner_share(subject, seal_id, second.shares[0])
    removed = _remove(_admin(app), seal_id)
    stored = upload_owner_share(subject, seal_id, second.shares[0])
    investigator = app.test_client()
    released = recover_standard(investigator, second)

    assert (refused.status_code, removed.status_code, stored.status_code,
            released.status_code) == (409, 302, 302, 302)
    assert recovered_key(investigator, seal_id) == second.key_hex
    assert share_rows(app, seal_id) == [(1, 1, first.shares[0]), (1, 2, second.shares[0])]
    [(slot, generation, operator, uploaded_at)] = _query(
        """SELECT share_index, generation, operator, uploaded_at FROM share_removal_audit
           WHERE seal_id = %s""", (seal_id,))
    assert (slot, generation, operator) == (1, 2, "admin-test") and uploaded_at


def test_a_failed_audit_write_removes_nothing(app, master_key, signer) -> None:
    seal_id = "S-20260928-F7MM02"
    _blocked_generation(app, seal_id, master_key, signer)
    before = share_rows(app, seal_id)
    admin = _admin(app)
    row_id = share_row_id(app, seal_id, 1, 2)
    _query("RENAME TABLE share_removal_audit TO share_removal_audit_away")
    try:
        resp = _remove(admin, seal_id, row_id)
    finally:
        _query("RENAME TABLE share_removal_audit_away TO share_removal_audit")

    assert resp.status_code == 503
    assert share_rows(app, seal_id) == before


def test_a_stale_form_leaves_the_genuine_share(app, master_key, signer) -> None:
    seal_id = "S-20260928-F7MM03"
    _, second, subject = _blocked_generation(app, seal_id, master_key, signer)
    seen = share_row_id(app, seal_id, 1, 2)
    first_admin, second_admin = _admin(app), _admin(app, "admin-second")

    removed = _remove(first_admin, seal_id, seen)
    stored = upload_owner_share(subject, seal_id, second.shares[0])
    stale = _remove(second_admin, seal_id, seen)
    investigator = app.test_client()
    released = recover_standard(investigator, second)

    assert (removed.status_code, stored.status_code, stale.status_code,
            released.status_code) == (302, 302, 409, 302)
    assert share_row_id(app, seal_id, 1, 2) > seen
    assert (1, 2, second.shares[0]) in share_rows(app, seal_id)
    assert recovered_key(investigator, seal_id) == second.key_hex
    assert _query("SELECT COUNT(*) FROM share_removal_audit WHERE seal_id = %s",
                  (seal_id,)) == [(1,)]


def test_the_audit_names_the_seal_as_stored(app, master_key, signer) -> None:
    """Fable re-check, finding 3: the seal column compares case-insensitively
    on MariaDB, so a form naming the seal in lower case removes the share;
    the audit row keeps the seal id as stored."""
    seal_id = "S-20260928-F7MM04"
    _blocked_generation(app, seal_id, master_key, signer)
    typed = seal_id.lower()

    resp = post_form(_admin(app), REMOVE_URL, {
        "seal_id": typed, "share_index": "1", "generation": "2",
        "share_row_id": str(share_row_id(app, seal_id, 1, 2)), "reason": "typed in lower case"})

    assert resp.status_code == 302
    assert _query("SELECT seal_id FROM share_removal_audit WHERE reason = %s",
                  ("typed in lower case",)) == [(seal_id,)]

