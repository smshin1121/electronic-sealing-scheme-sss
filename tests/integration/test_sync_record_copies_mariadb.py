"""Copy refusal at sync on the MariaDB variant (Fable gate, finding 1).

Runs the scenarios of ``test_sync_record_copies.py`` on a real server: the
copy check reads the seal's records under the case-row lock, and the
refusal rolls back the whole transaction there too, so the ``sync_nonces``
row of a signed copy is never committed.

Skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must be a
throwaway test instance: the module drops and recreates its own database
(``enc_release_test_e3d``). Synthetic data only. Environment as in
``test_release_mariadb.py``.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.sync_copies import (
    FOREIGN_WRAPPED_S3,
    event_ids,
    event_record,
    post,
    refused_as_copy,
    signed,
    stored_record,
    stripped,
    unsigned,
)
from tests.fixtures.sync_web import high_water, nonce_rows

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = "enc_release_test_e3d"
SEALED = ("Sealing",)
UNSEALED = ("Sealing", "Unsealing")


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


def _seal(seal_id: str, master_key: str, signer: Any):
    return make_seal_material(seal_id=seal_id, master_key_path=master_key,
                              signer=signer, generation=1)


def _sealed(app, seal) -> dict:
    record = event_record(seal, SEALED)
    resp = post(app, unsigned(seal, record, 1, "Sealing", seal.wrapped_s3_b64))
    assert resp.status_code == 200, resp.get_json()
    return record


class TestMariadbCopyRefusal:
    @pytest.mark.parametrize("seal_id, event_type, wrapped", [
        ("S-20260928-CPM001", "Unsealing", None),
        ("S-20260928-CPM011", "Sealing", FOREIGN_WRAPPED_S3)])
    def test_a_copy_is_refused_and_the_genuine_event_is_then_admitted(
        self, app, master_key, signer, seal_id, event_type, wrapped
    ) -> None:
        seal = _seal(seal_id, master_key, signer)
        sealing = _sealed(app, seal)
        mark = high_water(app, seal.seal_id)

        squat = post(app, unsigned(seal, sealing, 2, event_type, wrapped))

        assert refused_as_copy(squat), squat.get_json()
        assert event_ids(app, "seal_records", seal.seal_id) == [1]
        assert event_ids(app, "wrapped_s3_shares", seal.seal_id) == [1]
        assert high_water(app, seal.seal_id) == mark
        genuine = post(app, unsigned(seal, event_record(seal, UNSEALED), 2,
                                     "Unsealing"))
        assert genuine.status_code == 200, genuine.get_json()
        assert event_ids(app, "seal_records", seal.seal_id) == [1, 2]

    def test_a_signed_copy_is_refused_and_its_nonce_row_rolls_back(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-CPM002", master_key, signer)
        sealing = _sealed(app, seal)
        copy_body = signed(seal, signer, sealing, 2, "Unsealing")
        before = nonce_rows(app)

        first = post(app, copy_body)
        replay = post(app, copy_body)

        assert refused_as_copy(first), first.get_json()
        assert refused_as_copy(replay), replay.get_json()
        assert nonce_rows(app) == before
        genuine = post(app, signed(seal, signer, event_record(seal, UNSEALED),
                                   2, "Unsealing"))
        assert genuine.status_code == 200, genuine.get_json()
        assert len(nonce_rows(app)) == len(before) + 1

    def test_a_copy_does_not_displace_an_unauthenticated_occupant(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-CPM003", master_key, signer)
        occupant = stripped(event_record(seal, UNSEALED))
        assert post(app, unsigned(seal, occupant, 2, "Unsealing")).status_code == 200
        sealing = _sealed(app, seal)

        squat = post(app, unsigned(seal, sealing, 2, "Unsealing"))

        assert refused_as_copy(squat), squat.get_json()
        assert stored_record(app, seal.seal_id, 2) == occupant
        genuine = post(app, unsigned(seal, event_record(seal, UNSEALED), 2,
                                     "Unsealing"))
        assert genuine.status_code == 200, genuine.get_json()
        assert stored_record(app, seal.seal_id, 2) == event_record(seal, UNSEALED)
