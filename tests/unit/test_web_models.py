"""Web DB model CRUD unit tests.

Covers:
  - init_db() table creation (cases, users, key_shares, seal_records)
  - Case insert -> find round-trip
  - Key share insert -> find
  - Seal record insert -> idempotent duplicate handling
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest


@pytest.fixture()
def app(tmp_path: Any):
    """Create a fresh Flask app with a temporary SQLite DB."""
    db_path = str(tmp_path / "test_web.db")
    os.environ["USE_SQLITE"] = "true"
    os.environ["SQLITE_PATH"] = db_path

    # Patch the config class attribute before create_app reads it
    from web.config import TestingConfig
    original_path = TestingConfig.SQLITE_PATH
    TestingConfig.SQLITE_PATH = db_path

    from web.app import create_app

    app = create_app("testing")

    yield app

    TestingConfig.SQLITE_PATH = original_path


# ===================================================================
# init_db: table creation
# ===================================================================

class TestInitDB:
    """Verify init_db creates expected tables."""

    def test_tables_exist(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import get_db

            db = get_db()
            cursor = db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = sorted(row[0] for row in cursor.fetchall())

        expected = ["auth_failures", "cases", "key_shares", "seal_records", "users"]
        for t in expected:
            assert t in tables, f"Table '{t}' not found. Existing: {tables}"

    def test_cases_columns(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import get_db

            db = get_db()
            cursor = db.execute("PRAGMA table_info(cases)")
            col_names = [row[1] for row in cursor.fetchall()]

        required_cols = [
            "id", "seal_id", "case_number", "investigator",
            "suspect_name", "suspect_email", "suspect_birth",
            "suspect_phone", "auth_level", "password_hash",
        ]
        for col in required_cols:
            assert col in col_names, f"Column '{col}' missing from cases table"


# ===================================================================
# Case CRUD
# ===================================================================

class TestCaseCRUD:
    """Insert and retrieve cases."""

    def test_insert_and_find(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import find_case_by_seal_id, insert_case

            row_id = insert_case(
                seal_id="S-CRUD-001",
                case_number="2025-TEST-01",
                investigator="수사관A",
                suspect_name="홍길동",
                suspect_email="hong@test.com",
                suspect_birth="19900101",
                suspect_phone="010-1234-5678",
                auth_level="basic+password",
                password_hash="abc123hash",  # public-test-fixture
            )
            assert row_id is not None

            row = find_case_by_seal_id("S-CRUD-001")
            assert row is not None
            assert row["seal_id"] == "S-CRUD-001"
            assert row["case_number"] == "2025-TEST-01"
            assert row["suspect_name"] == "홍길동"
            assert row["auth_level"] == "basic+password"

    def test_find_nonexistent(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import find_case_by_seal_id

            result = find_case_by_seal_id("DOES-NOT-EXIST")
            assert result is None

    def test_duplicate_seal_id_rejected(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import insert_case

            insert_case(
                seal_id="S-DUP-001",
                case_number="C-001",
                investigator="수사관",
                suspect_name="김철수",
            )
            with pytest.raises(Exception):
                insert_case(
                    seal_id="S-DUP-001",
                    case_number="C-002",
                    investigator="수사관",
                    suspect_name="이영희",
                )


# ===================================================================
# Key Share CRUD
# ===================================================================

class TestKeyShareCRUD:
    """Insert and retrieve key shares."""

    def _create_case(self) -> None:
        from web.models.db_models import insert_case

        insert_case(
            seal_id="S-SHARE-001",
            case_number="C-SHARE",
            investigator="수사관",
            suspect_name="홍길동",
        )

    def test_insert_and_find(self, app: Any) -> None:
        with app.app_context():
            self._create_case()
            from web.models.db_models import (
                find_key_shares_by_seal_id,
                insert_key_share,
            )

            insert_key_share("S-SHARE-001", 1, "share-data-1", "suspect")
            insert_key_share("S-SHARE-001", 2, "share-data-2", "investigator")

            shares = find_key_shares_by_seal_id("S-SHARE-001")
            assert len(shares) == 2
            assert shares[0]["share_index"] == 1
            assert shares[1]["share_index"] == 2

    def test_duplicate_share_ignored(self, app: Any) -> None:
        with app.app_context():
            self._create_case()
            from web.models.db_models import (
                find_key_shares_by_seal_id,
                insert_key_share,
            )

            insert_key_share("S-SHARE-001", 1, "share-data-1", "suspect")
            insert_key_share("S-SHARE-001", 1, "share-data-1-dup", "suspect")

            shares = find_key_shares_by_seal_id("S-SHARE-001")
            assert len(shares) == 1
            # Original data preserved (INSERT OR IGNORE)
            assert shares[0]["share_data"] == "share-data-1"

    def test_empty_seal_id_returns_empty(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import find_key_shares_by_seal_id

            shares = find_key_shares_by_seal_id("NONEXISTENT")
            assert shares == []


# ===================================================================
# Seal Record CRUD (idempotent)
# ===================================================================

class TestSealRecordCRUD:
    """Insert seal records with idempotent duplicate handling."""

    def _create_case(self) -> None:
        from web.models.db_models import insert_case

        insert_case(
            seal_id="S-REC-001",
            case_number="C-REC",
            investigator="수사관",
            suspect_name="홍길동",
        )

    def test_insert_and_find(self, app: Any) -> None:
        with app.app_context():
            self._create_case()
            from web.models.db_models import (
                find_seal_records_by_seal_id,
                insert_seal_record,
            )

            record_json = json.dumps({"action": "seal", "timestamp": "2025-01-01T00:00:00"})
            insert_seal_record(
                seal_id="S-REC-001",
                event_id=1,
                event_type="Sealing",
                record_json=record_json,
            )

            records = find_seal_records_by_seal_id("S-REC-001")
            assert len(records) == 1
            assert records[0]["event_type"] == "Sealing"
            assert records[0]["event_id"] == 1

    def test_idempotent_duplicate(self, app: Any) -> None:
        """Inserting same (seal_id, event_id) twice -> no error, 1 row."""
        with app.app_context():
            self._create_case()
            from web.models.db_models import (
                find_seal_records_by_seal_id,
                insert_seal_record,
            )

            record_json = json.dumps({"action": "seal"})
            insert_seal_record("S-REC-001", 1, "Sealing", record_json)
            insert_seal_record("S-REC-001", 1, "Sealing", record_json)

            records = find_seal_records_by_seal_id("S-REC-001")
            assert len(records) == 1

    def test_multiple_events_ordered(self, app: Any) -> None:
        with app.app_context():
            self._create_case()
            from web.models.db_models import (
                find_seal_records_by_seal_id,
                insert_seal_record,
            )

            insert_seal_record("S-REC-001", 1, "Sealing", '{"a":1}')
            insert_seal_record("S-REC-001", 2, "Unsealing", '{"a":2}')
            insert_seal_record("S-REC-001", 3, "Resealing", '{"a":3}')

            records = find_seal_records_by_seal_id("S-REC-001")
            assert len(records) == 3
            assert [r["event_id"] for r in records] == [1, 2, 3]

    def test_with_pdf_blob(self, app: Any) -> None:
        with app.app_context():
            self._create_case()
            from web.models.db_models import (
                find_seal_records_by_seal_id,
                insert_seal_record,
            )

            pdf_bytes = b"%PDF-1.4 fake content"
            insert_seal_record(
                "S-REC-001", 1, "Sealing", '{"a":1}', pdf_bytes
            )

            records = find_seal_records_by_seal_id("S-REC-001")
            assert len(records) == 1
            assert records[0]["record_pdf"] == pdf_bytes


# ===================================================================
# Auth Failures
# ===================================================================

class TestAuthFailures:
    """Record and count authentication failures."""

    def test_record_and_count(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import (
                count_recent_auth_failures,
                record_auth_failure,
            )

            record_auth_failure("S-FAIL-001", "127.0.0.1")
            record_auth_failure("S-FAIL-001", "127.0.0.1")
            record_auth_failure("S-FAIL-001", "127.0.0.1")

            count = count_recent_auth_failures("S-FAIL-001", "127.0.0.1", 600)
            assert count == 3

    def test_different_ip_not_counted(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import (
                count_recent_auth_failures,
                record_auth_failure,
            )

            record_auth_failure("S-FAIL-002", "127.0.0.1")
            record_auth_failure("S-FAIL-002", "192.168.1.1")

            count = count_recent_auth_failures("S-FAIL-002", "127.0.0.1", 600)
            assert count == 1
