"""Release gate on the MariaDB variant (stage D follow-up).

The release-gate tests run on SQLite. This module runs the MariaDB-only code on a real MariaDB server:
the MariaDB DDL of ``wrapped_s3_shares`` and ``release_audit``, the ``INSERT IGNORE`` branch of the
wrapped-s3 store, the tuple-row branches of ``release_models``, and the three release paths.

It is skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must be a throwaway test instance:
the module drops and recreates ``RELEASE_TEST_MARIADB_DB``. Synthetic data only.
Environment: RELEASE_TEST_MARIADB_HOST, _PORT (3306), _USER (root), _PASSWORD, _DB (enc_release_test).
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    audit_rows,
    login_admin,
    post_form,
    recover_standard,
    recovered_key,
    store_share,
    sync_payload,
    sync_seal,
)
from tests.fixtures.sync_copies import replayed

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = os.environ.get("RELEASE_TEST_MARIADB_DB", "enc_release_test")
TIMELOCK_URL = "/investigator/recover-key-timelock"
ADMIN_URL = "/admin/emergency-recover"


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    """Drop and recreate the test database once for this module."""
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


def _make_app(monkeypatch: pytest.MonkeyPatch, **release: str) -> Any:
    """A testing app on the MariaDB server; fails if the app fell back to SQLite."""
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT), ("DB_USER", USER),
                        ("DB_PASSWORD", PASSWORD), ("DB_NAME", DB)):
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


def _last(app: Any, seal_id: str, path: str) -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row"
    return rows[-1]


class TestMariadbSchemaAndSync:
    def test_release_tables_and_index_exist(self, app) -> None:
        with app.app_context():
            from web.models.db_models import get_db

            cur = get_db().cursor()
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (DB,))
            tables = {row[0] for row in cur.fetchall()}
            cur.execute("SELECT DISTINCT table_name FROM information_schema.statistics "
                        "WHERE table_schema = %s AND index_name <> 'PRIMARY'", (DB,))
            indexed = {row[0] for row in cur.fetchall()}
        assert {"wrapped_s3_shares", "release_audit", "policy_enrollment"} <= tables
        assert "release_audit" in indexed

    def test_wrapped_s3_store_is_idempotent(self, app, client, master_key, signer) -> None:
        seal = make_seal_material(seal_id="S-20260927-M00001", master_key_path=master_key, signer=signer)
        sync_seal(client, app, seal)
        again = client.post("/sync/upload-record", json=sync_payload(seal))
        assert again.status_code == 200, again.get_json()
        with app.app_context():
            from web.models.db_models import get_db
            from web.models.release_models import find_latest_wrapped_s3

            assert find_latest_wrapped_s3(seal.seal_id) is not None
            cur = get_db().cursor()
            cur.execute("SELECT COUNT(*) FROM wrapped_s3_shares WHERE seal_id = %s", (seal.seal_id,))
            assert cur.fetchone()[0] == 1


class TestMariadbReleasePaths:
    def test_timelock_release_and_audit(self, app, client, master_key, signer) -> None:
        seal = make_seal_material(seal_id="S-20260927-M00002", master_key_path=master_key, signer=signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = post_form(client, TIMELOCK_URL, {"seal_id": seal.seal_id,
                                                "share_data": seal.shares[1]})

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        row = _last(app, seal.seal_id, "timelock")
        assert (row["outcome"], row["reason"], row["policy_status"]) == ("released", "released", "verified")
        assert row["tsa_token"] and len(row["tsa_token_sha256"]) == 64 and row["tsa_gen_time"]

    def test_timelock_denied_when_tsa_unreachable(self, monkeypatch, release_pki, master_key, signer) -> None:
        app = _make_app(
            monkeypatch,
            POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path),
            RELEASE_KMS_MASTER_KEY_PATH=master_key,
            RELEASE_TSA_URL="http://127.0.0.1:9/tsa",
            RELEASE_TSA_CERT_PATH=str(release_pki.tsa_cert_path),
            RELEASE_TSA_CA_CERT_PATH=str(release_pki.ca_cert_path),
            RELEASE_TSA_POLICY_OID=DEFAULT_TSA_POLICY_OID,
        )
        client = app.test_client()
        seal = make_seal_material(seal_id="S-20260927-M00003", master_key_path=master_key, signer=signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = post_form(client, TIMELOCK_URL, {"seal_id": seal.seal_id,
                                                "share_data": seal.shares[1]})

        assert resp.status_code == 503
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "timelock")
        assert (row["outcome"], row["reason"]) == ("denied", "tsa_failed")

    def test_standard_release_with_verified_policy(self, app, client, master_key, signer) -> None:
        seal = make_seal_material(seal_id="S-20260927-M00004", master_key_path=master_key, signer=signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        row = _last(app, seal.seal_id, "standard")
        assert (row["outcome"], row["policy_status"]) == ("released", "verified")

    def test_admin_release_with_verified_policy(self, app, client, master_key, signer) -> None:
        seal = make_seal_material(seal_id="S-20260927-M00005", master_key_path=master_key, signer=signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])
        username = login_admin(client)

        resp = post_form(client, ADMIN_URL, {"seal_id": seal.seal_id, "reason": "court order (synthetic)"})

        assert resp.status_code in (200, 302)
        row = _last(app, seal.seal_id, "admin")
        assert (row["outcome"], row["policy_status"]) == ("released", "verified")
        assert row["operator_reason"] == "court order (synthetic)"
        assert row["operator"] == username


class TestMariadbReviewFixes:
    """The fix-round rules on the MariaDB variant (tuple rows, INSERT IGNORE)."""

    def test_enrolled_seal_refuses_and_ignores_stripped_records(
        self, app, client, master_key, signer
    ) -> None:
        from datetime import timedelta

        from tests.fixtures.release_web import store_record_out_of_band

        seal = make_seal_material(seal_id="S-20260927-M00006", master_key_path=master_key,
                                  signer=signer, unlock_delta=timedelta(days=1))
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])
        stripped = {k: v for k, v in seal.record.items()
                    if k not in ("policy", "policy_signature", "policy_cert", "key_commitment")}
        stripped["unlock_time_iso"] = "2020-01-01T00:00:00Z"

        refused = client.post("/sync/upload-record", json=sync_payload(
            seal, event_id=2, event_type="Unsealing", record=stripped, include_wrapped=False))
        store_record_out_of_band(app, seal, event_id=9, event_type="Unsealing", record=stripped)
        resp = recover_standard(client, seal)

        assert refused.status_code == 409
        assert resp.status_code == 403
        row = _last(app, seal.seal_id, "standard")
        assert (row["reason"], row["policy_status"]) == ("before_unlock", "verified")

    def test_standard_path_refuses_s2_plus_s4(self, app, client, master_key, signer) -> None:
        seal = make_seal_material(seal_id="S-20260927-M00007", master_key_path=master_key,
                                  signer=signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = recover_standard(client, seal)

        assert resp.status_code == 400
        assert recovered_key(client, seal.seal_id) is None
        assert _last(app, seal.seal_id, "standard")["reason"] == "owner_share_missing"

    def test_timelock_requires_the_presented_share(self, app, client, master_key, signer) -> None:
        seal = make_seal_material(seal_id="S-20260927-M00008", master_key_path=master_key,
                                  signer=signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = post_form(client, TIMELOCK_URL, {"seal_id": seal.seal_id})

        assert resp.status_code == 400
        assert recovered_key(client, seal.seal_id) is None
        assert _last(app, seal.seal_id, "timelock")["reason"] == "investigator_share_missing"

    def test_authenticated_record_displaces_a_squatted_event(
        self, app, client, master_key, signer
    ) -> None:
        from tests.fixtures.release_web import ensure_case

        seal = make_seal_material(seal_id="S-20260927-M00009", master_key_path=master_key,
                                  signer=signer)
        ensure_case(app, seal.seal_id)
        # The re-review's literal case: record_json "{}" squats event 1 first.
        first = client.post("/sync/upload-record", json=sync_payload(
            seal, record={}, include_wrapped=False))
        second = client.post("/sync/upload-record", json=sync_payload(seal))
        store_share(app, seal.seal_id, 1, seal.shares[0])
        resp = recover_standard(client, seal)

        assert (first.status_code, second.status_code) == (200, 200)
        with app.app_context():
            from web.models.release_models import (
                find_latest_wrapped_s3,
                find_record_json_at,
                is_policy_enrolled,
            )

            assert json.loads(find_record_json_at(seal.seal_id, 1)) == seal.record
            assert find_latest_wrapped_s3(seal.seal_id) == seal.wrapped_s3
            assert is_policy_enrolled(seal.seal_id)
        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex

    def test_displacement_is_conditional_and_identical_retries_complete(
        self, app, client, master_key, signer
    ) -> None:
        from tests.fixtures.release_web import ensure_case, store_record_out_of_band

        seal = make_seal_material(seal_id="S-20260927-M00010", master_key_path=master_key,
                                  signer=signer)
        stripped = {k: v for k, v in seal.record.items()
                    if k not in ("policy", "policy_signature", "policy_cert")}
        store_record_out_of_band(app, seal, record=stripped)
        with app.app_context():
            from web.models.release_models import (
                find_latest_wrapped_s3,
                find_record_json_at,
                replace_synced_record,
                seal_write_transaction,
            )

            before = find_record_json_at(seal.seal_id, 1)
            change = dict(seal_id=seal.seal_id, event_id=1, event_type="Sealing",
                          record_json=json.dumps(seal.record), record_pdf=None,
                          wrapped_s3=seal.wrapped_s3,
                          enrolled_digest=seal.policy_digest.hex())
            # Byte-exact: a copy differing only in case must not match the
            # case-insensitive collation of the column.
            with seal_write_transaction(seal.seal_id):
                assert replace_synced_record(**change,
                                             expected_record_json=before.upper()) is False
            assert find_record_json_at(seal.seal_id, 1) == before
            with seal_write_transaction(seal.seal_id):
                assert replace_synced_record(**change, expected_record_json=before) is True

        other = make_seal_material(seal_id="S-20260927-M00011", master_key_path=master_key,
                                   signer=signer)
        ensure_case(app, other.seal_id)
        first = client.post("/sync/upload-record", json=sync_payload(other, include_wrapped=False))
        retry = client.post("/sync/upload-record", json=sync_payload(other))
        conflict = client.post("/sync/upload-record", json=sync_payload(
            other, wrapped_s3_b64=seal.wrapped_s3_b64))

        assert (first.status_code, retry.status_code, conflict.status_code) == (200, 200, 409)
        with app.app_context():
            assert find_latest_wrapped_s3(other.seal_id) == other.wrapped_s3

    def test_admission_holds_the_case_row_lock(
        self, app, client, master_key, monkeypatch
    ) -> None:
        import mariadb

        from tests.fixtures.release_web import ensure_case
        from web.routes import sync as sync_route

        seal = make_seal_material(seal_id="S-20260927-M00012", master_key_path=master_key,
                                  signer=None)
        ensure_case(app, seal.seal_id)
        outcomes: list[str] = []
        real = sync_route.is_policy_enrolled

        def probing(seal_id: str) -> bool:
            conn = mariadb.connect(host=HOST, port=PORT, user=USER, password=PASSWORD,
                                   database=DB)
            try:
                cur = conn.cursor()
                cur.execute("SET SESSION innodb_lock_wait_timeout = 1")
                cur.execute("SELECT seal_id FROM cases WHERE seal_id = %s FOR UPDATE",
                            (seal_id,))
                cur.fetchall()
                outcomes.append("acquired")
            except mariadb.Error as exc:
                outcomes.append("locked" if "Lock wait timeout" in str(exc) else str(exc))
            finally:
                conn.rollback()
                conn.close()
            return real(seal_id)

        monkeypatch.setattr(sync_route, "is_policy_enrolled", probing)

        resp = client.post("/sync/upload-record", json=sync_payload(seal))

        assert resp.status_code == 200
        assert outcomes == ["locked"]

    def test_timelock_skips_an_envelope_that_does_not_authenticate(
        self, app, client, master_key, signer
    ) -> None:
        # The signed record replayed under a higher event (with a field
        # outside the policy changed: an exact copy is refused since the
        # Fable gate fix for finding 1) and a malformed envelope: every
        # envelope is read newest first (tuple rows) and the first that
        # authenticates under the chosen policy is used.
        seal = make_seal_material(seal_id="S-20260927-M00013", master_key_path=master_key,
                                  signer=signer)
        sync_seal(client, app, seal)
        garbage = base64.b64encode(os.urandom(64)).decode("ascii")
        replay = client.post("/sync/upload-record",
                             json=sync_payload(seal, event_id=99, record=replayed(seal, 99),
                                               wrapped_s3_b64=garbage))

        resp = post_form(client, TIMELOCK_URL, {"seal_id": seal.seal_id,
                                                "share_data": seal.shares[1]})

        assert replay.status_code == 200
        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        with app.app_context():
            from web.models.release_models import find_wrapped_s3_newest_first

            stored = list(find_wrapped_s3_newest_first(seal.seal_id))
        assert len(stored) == 2 and stored[1] == seal.wrapped_s3
