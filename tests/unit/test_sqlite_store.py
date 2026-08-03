"""Unit tests for SQLite storage CRUD operations.

Validates:
  - init_db() creates all expected tables
  - save_seal_record() + get_seal_record() round-trip
  - save_key_shares() + get_key_share() round-trip
  - Duplicate seal_id handling (INSERT OR REPLACE)
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from desktop.db.sqlite_store import (
    get_dashboard_stats,
    get_key_share,
    get_seal_record,
    init_db,
    save_certificate,
    save_key_shares,
    save_seal_bundle,
    save_seal_record,
    update_case_meta,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path) -> str:
    """Create and initialize a temporary database."""
    path = str(tmp_path / "test_seal.db")
    init_db(path)
    return path


def _sample_record_json() -> str:
    return json.dumps({
        "seal_id": "S-20260401-ABC123",
        "case_info": {"case_number": "2026-0001"},
        "process_info": {"type": "Sealing"},
        "file_info": {"original_files": [{"filename": "test.bin"}]},
        "signer_info": {"name": "Lee"},
        "history": {"summary": "S1U0R0", "events": []},
    })


# ---------------------------------------------------------------------------
# Tests: init_db
# ---------------------------------------------------------------------------


class TestInitDB:
    """init_db() must create all required tables."""

    def test_tables_exist(self, db_path: str) -> None:
        conn = sqlite3.connect(db_path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "seal_records" in tables
        assert "key_shares" in tables
        assert "certificates" in tables

    def test_idempotent(self, db_path: str) -> None:
        """Calling init_db twice should not raise."""
        init_db(db_path)
        init_db(db_path)

    def test_creates_parent_directory(self, tmp_path) -> None:
        nested = str(tmp_path / "deep" / "nested" / "db.sqlite")
        init_db(nested)
        conn = sqlite3.connect(nested)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()
        assert "seal_records" in tables


# ---------------------------------------------------------------------------
# Tests: seal_records CRUD
# ---------------------------------------------------------------------------


class TestSealRecordsCRUD:
    """save_seal_record + get_seal_record round-trip."""

    def test_save_and_retrieve(self, db_path: str) -> None:
        seal_id = "S-20260401-ABC123"
        record_json = _sample_record_json()
        pdf_path = "/tmp/record.pdf"

        save_seal_record(db_path, seal_id, record_json, pdf_path)
        result = get_seal_record(db_path, seal_id)

        assert result is not None
        assert result["seal_id"] == seal_id
        assert result["record_json"]["seal_id"] == seal_id
        assert result["pdf_path"] == pdf_path
        assert "created_at" in result

    def test_nonexistent_id_returns_none(self, db_path: str) -> None:
        result = get_seal_record(db_path, "S-99999999-FFFFFF")
        assert result is None

    def test_empty_seal_id_raises(self, db_path: str) -> None:
        with pytest.raises(ValueError, match="seal_id"):
            save_seal_record(db_path, "", "{}", "/tmp/x.pdf")

    def test_empty_json_raises(self, db_path: str) -> None:
        with pytest.raises(ValueError, match="JSON"):
            save_seal_record(db_path, "S-20260401-ABC123", "", "/tmp/x.pdf")

    def test_invalid_json_raises(self, db_path: str) -> None:
        with pytest.raises(ValueError, match="JSON"):
            save_seal_record(
                db_path, "S-20260401-ABC123", "not-json", "/tmp/x.pdf"
            )

    def test_get_with_empty_seal_id_raises(self, db_path: str) -> None:
        with pytest.raises(ValueError, match="seal_id"):
            get_seal_record(db_path, "")


# ---------------------------------------------------------------------------
# Tests: key_shares CRUD
# ---------------------------------------------------------------------------


class TestKeySharesCRUD:
    """save_key_shares + get_key_share round-trip."""

    def test_save_and_retrieve(self, db_path: str) -> None:
        seal_id = "S-20260401-ABC123"
        shares = {3: b"share_three_data", 4: b"share_four_data"}

        save_key_shares(db_path, seal_id, shares)

        share3 = get_key_share(db_path, seal_id, 3)
        share4 = get_key_share(db_path, seal_id, 4)

        assert share3 == b"share_three_data"
        assert share4 == b"share_four_data"

    def test_nonexistent_share_returns_none(self, db_path: str) -> None:
        result = get_key_share(db_path, "S-20260401-FFFFFF", 3)
        assert result is None

    def test_empty_seal_id_raises(self, db_path: str) -> None:
        with pytest.raises(ValueError, match="seal_id"):
            save_key_shares(db_path, "", {3: b"data"})

    def test_empty_shares_raises(self, db_path: str) -> None:
        with pytest.raises(ValueError):
            save_key_shares(db_path, "S-20260401-ABC123", {})

    def test_get_with_empty_seal_id_raises(self, db_path: str) -> None:
        with pytest.raises(ValueError, match="seal_id"):
            get_key_share(db_path, "", 3)


# ---------------------------------------------------------------------------
# Tests: duplicate seal_id (INSERT OR REPLACE)
# ---------------------------------------------------------------------------


class TestDuplicateSealId:
    """Duplicate seal_id should overwrite existing record."""

    def test_overwrite_seal_record(self, db_path: str) -> None:
        seal_id = "S-20260401-ABC123"
        json1 = json.dumps({"version": 1})
        json2 = json.dumps({"version": 2})

        save_seal_record(db_path, seal_id, json1, "/v1.pdf")
        save_seal_record(db_path, seal_id, json2, "/v2.pdf")

        result = get_seal_record(db_path, seal_id)
        assert result is not None
        assert result["record_json"]["version"] == 2
        assert result["pdf_path"] == "/v2.pdf"

    def test_overwrite_key_share(self, db_path: str) -> None:
        seal_id = "S-20260401-ABC123"

        save_key_shares(db_path, seal_id, {3: b"old_data"})
        save_key_shares(db_path, seal_id, {3: b"new_data"})

        result = get_key_share(db_path, seal_id, 3)
        assert result == b"new_data"

    def test_overwrite_certificate(self, db_path: str) -> None:
        seal_id = "S-20260401-ABC123"

        save_certificate(db_path, seal_id, "CERT-V1", b"KEY-V1")
        save_certificate(db_path, seal_id, "CERT-V2", b"KEY-V2")

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT cert_pem FROM certificates WHERE seal_id = ?",
            (seal_id,),
        ).fetchone()
        conn.close()

        assert row["cert_pem"] == "CERT-V2"


# ---------------------------------------------------------------------------
# Tests: save_seal_bundle (single-transaction persistence)
# ---------------------------------------------------------------------------


class TestSaveSealBundle:
    """save_seal_bundle persists record + shares + cert atomically."""

    def test_bundle_round_trip(self, db_path: str) -> None:
        seal_id = "S-20260401-ABC123"
        shares = {3: b"share3", 4: b"share4"}

        save_seal_bundle(
            db_path, seal_id, _sample_record_json(), "/tmp/r.pdf",
            shares=shares, cert_pem="CERT", key_pem_encrypted=b"KEY",
        )

        record = get_seal_record(db_path, seal_id)
        assert record is not None
        assert record["pdf_path"] == "/tmp/r.pdf"
        assert get_key_share(db_path, seal_id, 3) == b"share3"
        assert get_key_share(db_path, seal_id, 4) == b"share4"

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT cert_pem FROM certificates WHERE seal_id = ?",
            (seal_id,),
        ).fetchone()
        conn.close()
        assert row["cert_pem"] == "CERT"

    def test_bundle_without_certificate(self, db_path: str) -> None:
        seal_id = "S-20260401-NOCERT"
        save_seal_bundle(
            db_path, seal_id, _sample_record_json(), "/tmp/r.pdf",
            shares={3: b"s3"},
        )

        conn = sqlite3.connect(db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE seal_id = ?",
            (seal_id,),
        ).fetchone()[0]
        conn.close()
        assert count == 0
        assert get_key_share(db_path, seal_id, 3) == b"s3"

    def test_bundle_validation(self, db_path: str) -> None:
        with pytest.raises(ValueError, match="seal_id"):
            save_seal_bundle(db_path, "", "{}", "/x.pdf", shares={3: b"d"})
        with pytest.raises(ValueError, match="JSON"):
            save_seal_bundle(
                db_path, "S-1", "not-json", "/x.pdf", shares={3: b"d"},
            )
        with pytest.raises(ValueError):
            save_seal_bundle(db_path, "S-1", "{}", "/x.pdf", shares={})

    def test_bundle_is_atomic_on_failure(self, db_path: str) -> None:
        """A failing statement must roll back the whole bundle."""
        seal_id = "S-20260401-ATOMIC"
        # share_data has a NOT NULL constraint -> None triggers failure
        bad_shares = {3: b"ok", 4: None}

        with pytest.raises(Exception):
            save_seal_bundle(
                db_path, seal_id, _sample_record_json(), "/tmp/r.pdf",
                shares=bad_shares,  # type: ignore[arg-type]
            )

        # Nothing from the bundle may have been persisted
        assert get_seal_record(db_path, seal_id) is None
        assert get_key_share(db_path, seal_id, 3) is None


# ---------------------------------------------------------------------------
# Tests: dashboard stats (single aggregated query)
# ---------------------------------------------------------------------------


class TestDashboardStats:
    """get_dashboard_stats must aggregate statuses correctly."""

    def test_empty_db(self, db_path: str) -> None:
        stats = get_dashboard_stats(db_path)
        assert stats == {
            "total": 0, "sealed_only": 0, "unsealed": 0, "resealed": 0,
        }

    def test_counts_by_status(self, db_path: str) -> None:
        cases = [
            ("S-A", "S1U0R0"),  # sealed only
            ("S-B", "S1U0R0"),  # sealed only
            ("S-C", "S1U1R0"),  # unsealed
            ("S-D", "S1U1R1"),  # unsealed + resealed
        ]
        for seal_id, status in cases:
            save_seal_record(db_path, seal_id, "{}", "/x.pdf")
            update_case_meta(db_path, seal_id, status=status)

        stats = get_dashboard_stats(db_path)
        assert stats["total"] == 4
        assert stats["sealed_only"] == 2
        assert stats["unsealed"] == 2
        assert stats["resealed"] == 1

    def test_created_at_index_exists(self, db_path: str) -> None:
        conn = sqlite3.connect(db_path)
        indexes = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        conn.close()
        assert "idx_seal_records_created_at" in indexes
