"""Sync route accepts and stores the wrapped s3 (stage D, D2).

``/sync/upload-record`` takes an optional ``wrapped_s3`` (base64 envelope
ciphertext of s3). It is accepted only on Sealing/Resealing events, only
when the record names the same seal, and it is stored in the same
transaction as the record, keyed by (seal_id, event_id). Payloads
without the field behave exactly as before.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import pytest

from desktop.sync_payload import build_sync_payload
from tests.fixtures.release_web import ensure_case, make_release_app

SEAL_ID = "S-20260926-5EED01"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    return make_release_app(tmp_path, monkeypatch)


@pytest.fixture()
def client(app):
    return app.test_client()


def _wrapped(size: int = 94) -> str:
    return base64.b64encode(os.urandom(size)).decode("ascii")


def _payload(**overrides: Any) -> dict:
    body = {
        "seal_id": SEAL_ID,
        "event_id": 1,
        "event_type": "Sealing",
        "record_json": json.dumps({"seal_id": SEAL_ID, "seal_mode": "standard"}),
        "wrapped_s3": _wrapped(),
    }
    body.update(overrides)
    return body


def _latest_wrapped(app: Any, seal_id: str = SEAL_ID) -> bytes | None:
    with app.app_context():
        from web.models.release_models import find_latest_wrapped_s3

        return find_latest_wrapped_s3(seal_id)


class TestSchemaMigration:
    def test_release_tables_exist(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import get_db

            names = {
                row[0] for row in get_db().execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert {"wrapped_s3_shares", "release_audit"} <= names

    def test_both_schema_variants_declare_the_tables(self) -> None:
        from web.models import db_models

        for ddl in (db_models._SQLITE_SCHEMA, db_models._MARIADB_SCHEMA):
            assert "CREATE TABLE IF NOT EXISTS wrapped_s3_shares" in ddl
            assert "CREATE TABLE IF NOT EXISTS release_audit" in ddl


class TestWrappedS3Sync:
    def test_wrapped_s3_is_stored_with_the_record(
        self, app: Any, client: Any
    ) -> None:
        ensure_case(app, SEAL_ID)
        payload = _payload()
        resp = client.post("/sync/upload-record", json=payload)

        assert resp.status_code == 200
        assert _latest_wrapped(app) == base64.b64decode(payload["wrapped_s3"])
        with app.app_context():
            from web.models.db_models import find_seal_records_by_seal_id

            assert len(find_seal_records_by_seal_id(SEAL_ID)) == 1

    def test_duplicate_sync_is_idempotent_and_refuses_another_envelope(
        self, app: Any, client: Any
    ) -> None:
        ensure_case(app, SEAL_ID)
        payload = _payload()
        assert client.post("/sync/upload-record", json=payload).status_code == 200
        assert client.post("/sync/upload-record", json=payload).status_code == 200
        replay = {**payload, "wrapped_s3": _wrapped()}
        assert client.post("/sync/upload-record", json=replay).status_code == 409
        assert _latest_wrapped(app) == base64.b64decode(payload["wrapped_s3"])

    def test_latest_event_wins(self, app: Any, client: Any) -> None:
        ensure_case(app, SEAL_ID)
        first, later = _payload(), _payload(event_id=3, event_type="Resealing")
        assert client.post("/sync/upload-record", json=first).status_code == 200
        assert client.post("/sync/upload-record", json=later).status_code == 200
        assert _latest_wrapped(app) == base64.b64decode(later["wrapped_s3"])

    def test_payload_without_wrapped_s3_is_unchanged(
        self, app: Any, client: Any
    ) -> None:
        ensure_case(app, SEAL_ID)
        payload = _payload(record_json=json.dumps({"action": "seal"}))
        del payload["wrapped_s3"]
        assert client.post("/sync/upload-record", json=payload).status_code == 200
        assert _latest_wrapped(app) is None

    def test_desktop_payload_round_trips(self, app: Any, client: Any) -> None:
        ensure_case(app, SEAL_ID)
        wrapped = _wrapped()
        payload = build_sync_payload(
            seal_id=SEAL_ID, event_id=1, event_type="Sealing",
            record_json=json.dumps({"seal_id": SEAL_ID}),
            wrapped_s3_b64=wrapped,
        )
        assert client.post("/sync/upload-record", json=payload).status_code == 200
        assert _latest_wrapped(app) == base64.b64decode(wrapped)


class TestWrappedS3Validation:
    @pytest.mark.parametrize(
        "overrides, status",
        [
            ({"wrapped_s3": "not base64!!"}, 400),
            ({"wrapped_s3": 12345}, 400),
            ({"wrapped_s3": base64.b64encode(b"x" * 20).decode()}, 400),
            ({"wrapped_s3": "A" * 8192}, 413),
            ({"event_type": "Unsealing"}, 400),
            ({"record_json": json.dumps({"seal_id": "S-20260926-OTHER1"})},
             400),
            ({"record_json": json.dumps({"action": "seal"})}, 400),
            ({"record_json": json.dumps(["not", "an", "object"])}, 400),
        ],
    )
    def test_invalid_wrapped_s3_payloads_are_refused(
        self, app: Any, client: Any, overrides: dict, status: int
    ) -> None:
        ensure_case(app, SEAL_ID)
        resp = client.post("/sync/upload-record", json=_payload(**overrides))
        assert resp.status_code == status
        assert resp.get_json()["status"] == "error"
        assert _latest_wrapped(app) is None
        with app.app_context():
            from web.models.db_models import find_seal_records_by_seal_id

            assert find_seal_records_by_seal_id(SEAL_ID) == []
