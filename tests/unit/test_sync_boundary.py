"""SQLite <-> Web DB synchronization boundary tests.

Covers:
  - Desktop sqlite_store.save_seal_record() data structure vs
    web sync endpoint expected JSON structure alignment
  - seal_id format consistency across both modules
  - Duplicate seal_id sync -> idempotent (no error, no duplication)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from desktop.db.sqlite_store import (
    get_seal_record,
    init_db as desktop_init_db,
    save_seal_record as desktop_save_record,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def desktop_db(tmp_path: Path) -> str:
    """Create and initialize a desktop SQLite database."""
    db_path = str(tmp_path / "desktop_test.db")
    desktop_init_db(db_path)
    return db_path


@pytest.fixture()
def web_app(tmp_path: Path):
    """Create a fresh Flask web app with a temporary SQLite DB."""
    db_path = str(tmp_path / "web_test.db")
    os.environ["USE_SQLITE"] = "true"
    os.environ["SQLITE_PATH"] = db_path

    from web.config import TestingConfig
    original_path = TestingConfig.SQLITE_PATH
    TestingConfig.SQLITE_PATH = db_path

    from web.app import create_app

    app = create_app("testing")

    yield app

    TestingConfig.SQLITE_PATH = original_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_SEAL_ID = "S-20251104-ABA82E"


def _ensure_web_case(app: Any, seal_id: str) -> None:
    """Create a parent case in the web DB so FK constraints pass."""
    with app.app_context():
        from web.models.db_models import find_case_by_seal_id, insert_case

        if not find_case_by_seal_id(seal_id):
            insert_case(
                seal_id=seal_id,
                case_number="C-SYNC",
                investigator="수사관",
                suspect_name="홍길동",
            )

_SAMPLE_RECORD_DICT = {
    "case_number": "2025-0001",
    "investigator": "수사관A",
    "action": "Sealing",
    "timestamp": "2025-11-04T10:30:00",
    "hash_before": "abc123",
    "hash_after": "def456",
}


def _sync_payload(
    seal_id: str,
    event_id: int,
    event_type: str,
    record_json: str,
    record_pdf: str | None = None,
) -> dict[str, Any]:
    """Build the JSON payload that the sync endpoint expects."""
    payload: dict[str, Any] = {
        "seal_id": seal_id,
        "event_id": event_id,
        "event_type": event_type,
        "record_json": record_json,
    }
    if record_pdf is not None:
        payload["record_pdf"] = record_pdf
    return payload


# ===================================================================
# Data structure alignment
# ===================================================================

class TestDataStructureAlignment:
    """Desktop save_seal_record() output matches sync endpoint expectations."""

    def test_desktop_record_json_is_valid_json(self, desktop_db: str) -> None:
        record_json_str = json.dumps(_SAMPLE_RECORD_DICT, ensure_ascii=False)
        desktop_save_record(
            db_path=desktop_db,
            seal_id=_SAMPLE_SEAL_ID,
            record_json=record_json_str,
            pdf_path="/tmp/test.pdf",
        )

        record = get_seal_record(desktop_db, _SAMPLE_SEAL_ID)
        assert record is not None
        # record_json is parsed to dict by get_seal_record
        assert isinstance(record["record_json"], dict)
        assert record["record_json"]["case_number"] == "2025-0001"

    def test_desktop_record_json_can_be_synced(
        self, desktop_db: str, web_app: Any
    ) -> None:
        """Record saved on desktop can be sent to sync endpoint as-is."""
        record_json_str = json.dumps(_SAMPLE_RECORD_DICT, ensure_ascii=False)
        desktop_save_record(
            db_path=desktop_db,
            seal_id=_SAMPLE_SEAL_ID,
            record_json=record_json_str,
            pdf_path="/tmp/test.pdf",
        )

        record = get_seal_record(desktop_db, _SAMPLE_SEAL_ID)
        assert record is not None

        # Create parent case in web DB for FK constraint
        _ensure_web_case(web_app, _SAMPLE_SEAL_ID)

        # Build sync payload from desktop data
        sync_json = json.dumps(record["record_json"], ensure_ascii=False)
        payload = _sync_payload(
            seal_id=_SAMPLE_SEAL_ID,
            event_id=1,
            event_type="Sealing",
            record_json=sync_json,
        )

        client = web_app.test_client()
        resp = client.post(
            "/sync/upload-record",
            json=payload,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_sync_payload_required_fields(self, web_app: Any) -> None:
        """Sync endpoint rejects incomplete payloads."""
        client = web_app.test_client()

        # Missing seal_id
        resp = client.post(
            "/sync/upload-record",
            json={"event_id": 1, "event_type": "Sealing", "record_json": "{}"},
        )
        assert resp.status_code == 400

        # Missing event_id
        resp = client.post(
            "/sync/upload-record",
            json={"seal_id": "S-001", "event_type": "Sealing", "record_json": "{}"},
        )
        assert resp.status_code == 400

        # Invalid event_type
        resp = client.post(
            "/sync/upload-record",
            json={
                "seal_id": "S-001",
                "event_id": 1,
                "event_type": "InvalidType",
                "record_json": "{}",
            },
        )
        assert resp.status_code == 400


# ===================================================================
# seal_id format consistency
# ===================================================================

class TestSealIdConsistency:
    """seal_id format is consistent across desktop and web."""

    @pytest.mark.parametrize(
        "seal_id",
        [
            "S-20251104-ABA82E",
            "S-20250101-000001",
            "S-20261231-FFFFFF",
        ],
    )
    def test_seal_id_accepted_by_both(
        self, desktop_db: str, web_app: Any, seal_id: str
    ) -> None:
        record_json = json.dumps({"test": True})

        # Desktop accepts
        desktop_save_record(desktop_db, seal_id, record_json, "/tmp/t.pdf")
        record = get_seal_record(desktop_db, seal_id)
        assert record is not None
        assert record["seal_id"] == seal_id

        # Create parent case in web DB for FK constraint
        _ensure_web_case(web_app, seal_id)

        # Web sync accepts
        client = web_app.test_client()
        resp = client.post(
            "/sync/upload-record",
            json=_sync_payload(seal_id, 1, "Sealing", record_json),
        )
        assert resp.status_code == 200

    def test_empty_seal_id_rejected_desktop(self, desktop_db: str) -> None:
        with pytest.raises(ValueError, match="seal_id"):
            desktop_save_record(desktop_db, "", '{"a":1}', "/tmp/t.pdf")

    def test_empty_seal_id_rejected_web(self, web_app: Any) -> None:
        client = web_app.test_client()
        resp = client.post(
            "/sync/upload-record",
            json=_sync_payload("", 1, "Sealing", '{"a":1}'),
        )
        assert resp.status_code == 400


# ===================================================================
# Idempotent sync
# ===================================================================

class TestIdempotentSync:
    """Duplicate (seal_id, event_id) sync requests are idempotent."""

    def test_duplicate_sync_no_error(self, web_app: Any) -> None:
        _ensure_web_case(web_app, "S-IDEM-001")
        client = web_app.test_client()
        payload = _sync_payload(
            seal_id="S-IDEM-001",
            event_id=1,
            event_type="Sealing",
            record_json='{"dup": "test"}',
        )

        resp1 = client.post("/sync/upload-record", json=payload)
        assert resp1.status_code == 200

        resp2 = client.post("/sync/upload-record", json=payload)
        assert resp2.status_code == 200

    def test_duplicate_sync_single_record(self, web_app: Any) -> None:
        """After two syncs of same (seal_id, event_id), only 1 row exists."""
        _ensure_web_case(web_app, "S-IDEM-002")
        client = web_app.test_client()
        payload = _sync_payload(
            seal_id="S-IDEM-002",
            event_id=1,
            event_type="Unsealing",
            record_json='{"dup": "check"}',
        )

        client.post("/sync/upload-record", json=payload)
        client.post("/sync/upload-record", json=payload)

        with web_app.app_context():
            from web.models.db_models import find_seal_records_by_seal_id

            records = find_seal_records_by_seal_id("S-IDEM-002")
            assert len(records) == 1

    def test_different_events_same_seal_id(self, web_app: Any) -> None:
        """Multiple distinct events for same seal_id all stored."""
        _ensure_web_case(web_app, "S-IDEM-003")
        client = web_app.test_client()

        for eid, etype in [(1, "Sealing"), (2, "Unsealing"), (3, "Resealing")]:
            payload = _sync_payload(
                "S-IDEM-003", eid, etype, json.dumps({"eid": eid})
            )
            resp = client.post("/sync/upload-record", json=payload)
            assert resp.status_code == 200

        with web_app.app_context():
            from web.models.db_models import find_seal_records_by_seal_id

            records = find_seal_records_by_seal_id("S-IDEM-003")
            assert len(records) == 3


# ===================================================================
# Invalid JSON handling
# ===================================================================

class TestInvalidJsonHandling:
    """Sync endpoint rejects invalid record_json."""

    def test_invalid_record_json(self, web_app: Any) -> None:
        client = web_app.test_client()
        resp = client.post(
            "/sync/upload-record",
            json={
                "seal_id": "S-BAD-JSON",
                "event_id": 1,
                "event_type": "Sealing",
                "record_json": "{broken json",
            },
        )
        assert resp.status_code == 400

    def test_desktop_rejects_invalid_json(self, desktop_db: str) -> None:
        with pytest.raises(ValueError, match="JSON"):
            desktop_save_record(desktop_db, "S-BAD", "{broken", "/tmp/t.pdf")

    def test_non_json_content_type_rejected(self, web_app: Any) -> None:
        # Non-JSON POST triggers CSRF protection (403) before reaching route
        client = web_app.test_client()
        resp = client.post(
            "/sync/upload-record",
            data="not json",
            content_type="text/plain",
        )
        assert resp.status_code in (400, 403)
