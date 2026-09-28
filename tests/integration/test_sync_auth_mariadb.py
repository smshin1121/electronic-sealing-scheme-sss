"""Sync authentication and policy generations on the MariaDB variant (stage E, E2a).

Runs the MariaDB-only code on a real server: the MariaDB DDL of
``sync_nonces`` and ``policy_high_water`` and their migration, the
``INSERT IGNORE`` nonce claim and mark writes read back as tuple rows,
the rollback refusals, nonce pruning, the transaction that commits the
nonce, the record and the mark together, and the gate's generation-based
record selection.

Skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must be a
throwaway test instance: the module drops and recreates its own database
(``enc_release_test_e2a``). Synthetic data only. Environment as in
``test_release_mariadb.py``.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    recover_standard,
    store_record_out_of_band,
    store_share,
    sync_payload,
)
from tests.fixtures.sync_copies import (
    ROLLBACK_REFUSAL,
    SAME_GENERATION_REFUSAL,
    replayed,
)
from tests.fixtures.sync_web import (
    high_water,
    nonce_rows,
    require_signatures,
    signed_payload,
)

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = "enc_release_test_e2a"
URL = "/sync/upload-record"


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    """Drop and recreate this module's test database once."""
    import mariadb

    assert DB.startswith("enc_release_test"), "refusing to drop a non-test database"
    conn = mariadb.connect(host=HOST, port=PORT, user=USER, password=PASSWORD)
    cur = conn.cursor()
    cur.execute(f"DROP DATABASE IF EXISTS `{DB}`")
    cur.execute(f"CREATE DATABASE `{DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    conn.commit()
    conn.close()


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(monkeypatch, release_pki, master_key):
    """A testing app on the MariaDB server; fails if it fell back to SQLite."""
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT), ("DB_USER", USER),
                        ("DB_PASSWORD", PASSWORD), ("DB_NAME", DB)):
        monkeypatch.setattr(TestingConfig, name, value)
    monkeypatch.setenv("USE_SQLITE", "false")
    from web.app import create_app

    application = create_app("testing")
    application.config.update(POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path),
                              RELEASE_KMS_MASTER_KEY_PATH=master_key)
    with application.app_context():
        from flask import g

        from web.models.db_models import get_db

        get_db()
        assert g.db_type == "mariadb", "the app fell back to SQLite; the MariaDB path was not exercised"
    return application


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _seal(seal_id: str, master_key: str, signer: Any, generation: int):
    return make_seal_material(seal_id=seal_id, master_key_path=master_key, signer=signer,
                              generation=generation)


def _post(app, body: dict) -> Any:
    ensure_case(app, body["seal_id"])
    return app.test_client().post(URL, json=body)


def _columns(app, table: str) -> dict[str, str]:
    with app.app_context():
        from web.models.db_models import get_db

        cur = get_db().cursor()
        cur.execute("SELECT column_name, IFNULL(collation_name, '') FROM information_schema.columns "
                    "WHERE table_schema = %s AND table_name = %s", (DB, table))
        return {row[0]: row[1] for row in cur.fetchall()}


class TestMariadbSchema:
    def test_the_tables_their_columns_and_the_expiry_index(self, app) -> None:
        nonces = _columns(app, "sync_nonces")
        marks = _columns(app, "policy_high_water")
        with app.app_context():
            from web.models.db_models import get_db

            cur = get_db().cursor()
            cur.execute("SELECT DISTINCT index_name FROM information_schema.statistics "
                        "WHERE table_schema = %s AND table_name = 'sync_nonces'", (DB,))
            indexes = {row[0] for row in cur.fetchall()}

        assert set(nonces) == {"nonce", "seal_id", "event_id", "sent_at", "expires_at", "received_at"}
        assert nonces["nonce"] == "utf8mb4_bin"
        assert set(marks) == {"seal_id", "generation", "policy_digest", "event_id", "updated_at"}
        assert "idx_sync_nonces_expiry" in indexes

    def test_the_migration_adds_the_tables_to_an_existing_database(self, app) -> None:
        with app.app_context():
            from flask import g

            from web.models.db_models import create_schema, get_db

            db = get_db()
            cur = db.cursor()
            cur.execute("DROP TABLE IF EXISTS sync_nonces")
            cur.execute("DROP TABLE IF EXISTS policy_high_water")
            db.commit()
            assert _columns(app, "sync_nonces") == {}
            create_schema(db, g.db_type)
            create_schema(db, g.db_type)
        assert "nonce" in _columns(app, "sync_nonces")
        assert "generation" in _columns(app, "policy_high_water")


class TestMariadbSyncAuthentication:
    def test_signed_admitted_nonce_reuse_and_unsigned_refused(self, app, master_key, signer) -> None:
        require_signatures(app)
        seal = _seal("S-20260928-M2A001", master_key, signer, 1)
        body = signed_payload(seal, signer)

        first = _post(app, body)
        replay = _post(app, body)
        unsigned = _post(app, sync_payload(seal, event_id=2, event_type="Unsealing",
                                           include_wrapped=False))

        assert first.status_code == 200, first.get_json()
        assert replay.status_code == 409 and "nonce" in replay.get_json()["message"]
        assert unsigned.status_code == 401
        assert body["sync_auth"]["envelope"]["nonce"] in nonce_rows(app)

    def test_nonce_and_mark_roll_back_with_a_failed_store(self, app, master_key, signer, monkeypatch) -> None:
        from web.routes import sync as sync_route

        seal = _seal("S-20260928-M2A002", master_key, signer, 1)
        body = signed_payload(seal, signer)

        def broken(**_kwargs: Any) -> None:
            raise RuntimeError("synthetic store failure")

        monkeypatch.setattr(sync_route, "raise_high_water", broken)
        failed = _post(app, body)
        monkeypatch.undo()

        assert failed.status_code == 500
        assert body["sync_auth"]["envelope"]["nonce"] not in nonce_rows(app)
        assert high_water(app, seal.seal_id) is None
        assert _post(app, body).status_code == 200
        assert high_water(app, seal.seal_id) == (1, seal.policy_digest.hex(), 1)

    def test_expired_nonces_are_pruned(self, app, master_key, signer) -> None:
        with app.app_context():
            from web.models.db_models import execute_query

            execute_query("INSERT INTO sync_nonces (nonce, seal_id, event_id, sent_at, expires_at, received_at) "
                          "VALUES (?, ?, ?, ?, ?, ?)",
                          ("e" * 64, "S-20260928-OLD001", 1, "2026-01-01T00:00:00Z", 1, "2026-01-01T00:00:00Z"))
        seal = _seal("S-20260928-M2A003", master_key, signer, 1)

        assert _post(app, signed_payload(seal, signer)).status_code == 200
        assert "e" * 64 not in nonce_rows(app)


class TestMariadbGenerations:
    def test_rollback_and_same_generation_are_refused(self, app, master_key, signer) -> None:
        sealed = _seal("S-20260928-M2A004", master_key, signer, 1)
        resealed = _seal("S-20260928-M2A004", master_key, signer, 2)
        rival = _seal("S-20260928-M2A004", master_key, signer, 2)

        assert _post(app, sync_payload(sealed)).status_code == 200
        assert _post(app, sync_payload(resealed, event_id=3, event_type="Resealing")).status_code == 200
        # An exact copy is refused before the generation rules (Fable gate,
        # finding 1); a replay with another field changed reaches them.
        replay = _post(app, sync_payload(sealed, event_id=4, record=replayed(sealed, 4)))
        same = _post(app, sync_payload(rival, event_id=5, event_type="Resealing"))

        assert (replay.status_code, same.status_code) == (409, 409)
        assert ROLLBACK_REFUSAL in replay.get_json()["message"]
        assert SAME_GENERATION_REFUSAL in same.get_json()["message"]
        assert high_water(app, sealed.seal_id) == (2, resealed.policy_digest.hex(), 3)

    def test_the_gate_decides_on_the_highest_generation(self, app, master_key, signer) -> None:
        sealed = _seal("S-20260928-M2A005", master_key, signer, 1)
        resealed = _seal("S-20260928-M2A005", master_key, signer, 2)
        assert _post(app, sync_payload(sealed)).status_code == 200
        assert _post(app, sync_payload(resealed, event_id=3, event_type="Resealing")).status_code == 200
        store_record_out_of_band(app, sealed, event_id=9, event_type="Unsealing")
        store_share(app, sealed.seal_id, 1, resealed.shares[0])

        resp = recover_standard(app.test_client(), resealed)

        assert resp.status_code == 302
        row = [r for r in audit_rows(app, sealed.seal_id) if r["path"] == "standard"][-1]
        assert (row["outcome"], row["policy_digest"]) == ("released", resealed.policy_digest.hex())
        assert "below the high-water mark" in row["detail"]

    def test_the_mark_is_bootstrapped_from_stored_records(self, app, master_key, signer) -> None:
        # Records stored without a mark (before E2a, or with no CA pinned):
        # the first verified admission sets the mark to the stored maximum.
        sealed = _seal("S-20260928-M2A006", master_key, signer, 1)
        resealed = _seal("S-20260928-M2A006", master_key, signer, 2)
        store_record_out_of_band(app, sealed, event_id=1)
        store_record_out_of_band(app, resealed, event_id=3, event_type="Resealing")

        replay = _post(app, sync_payload(sealed, event_id=9, event_type="Unsealing",
                                         record=replayed(sealed, 9), include_wrapped=False))

        assert replay.status_code == 409
        assert ROLLBACK_REFUSAL in replay.get_json()["message"]
        assert high_water(app, sealed.seal_id) == (2, resealed.policy_digest.hex(), 3)

    def test_the_first_release_backfills_the_mark(self, app, master_key, signer) -> None:
        sealed = _seal("S-20260928-M2A007", master_key, signer, 1)
        resealed = _seal("S-20260928-M2A007", master_key, signer, 2)
        store_record_out_of_band(app, resealed, event_id=2, event_type="Resealing")
        store_record_out_of_band(app, sealed, event_id=5, event_type="Unsealing")
        store_share(app, sealed.seal_id, 1, resealed.shares[0])

        resp = recover_standard(app.test_client(), resealed)

        assert resp.status_code == 302
        assert high_water(app, sealed.seal_id) == (2, resealed.policy_digest.hex(), 2)
