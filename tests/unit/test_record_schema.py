"""Unit tests for seal record JSON schema validation.

Validates:
  - build_seal_record() includes all 6 required top-level fields
  - seal_id format matches S-YYYYMMDD-XXXXXX
  - All time fields conform to ISO 8601 UTC
  - validate_record() returns errors for invalid input
  - process_info.type accepts only valid values
"""

from __future__ import annotations

import re

import pytest

from desktop.record.history_manager import create_initial_history
from desktop.record.record_builder import (
    build_seal_record,
    create_seal_id,
    validate_record,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_SEAL_ID_RE = re.compile(r"^S-\d{8}-[0-9A-F]{6}$")
_ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _make_case_info() -> dict:
    return {
        "case_number": "2026-0001",
        "investigator": "Kim",
        "device_user": "Park",
        "suspect": "Lee",
        "storage_type": "SSD",
        "storage_info": {
            "manufacturer": "Samsung",
            "model": "870 EVO",
            "serial": "S1234",
        },
        "seizure_time": "2026-04-01T09:00:00Z",
        "seizure_location": "Seoul",
    }


def _make_process_info(ptype: str = "Sealing") -> dict:
    return {
        "type": ptype,
        "start_time": "2026-04-01T10:00:00Z",
        "end_time": "2026-04-01T11:00:00Z",
        "file_count": 1,
        "investigator": "Kim",
        "reason": None,
        "participation": "present",
    }


def _make_file_info() -> dict:
    return {
        "original_files": [
            {
                "filename": "evidence.dd",
                "size": 1048576,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "mtime": "2026-03-31T08:00:00Z",
                "ctime": "2026-03-31T07:00:00Z",
                "atime": "2026-04-01T09:00:00Z",
            },
        ],
        "result_files": [
            {
                "filename": "evidence.dd.enc",
                "size": 1048600,
                "encryption_algo": "AES-256-GCM",
                "enc_ended_time": "2026-04-01T11:00:00Z",
                "nonces": ["aabbccddee001122aabbccdd"],
                "tags": ["00112233445566778899aabbccddeeff"],
                "chunk_lengths": [1048576],
            },
        ],
        "hash_match": True,
    }


def _make_signer_info() -> dict:
    return {
        "name": "Lee",
        "email": "lee@example.com",
        "birth_date": "1990-01-01",
        "phone": "010-1234-5678",
        "cert_fingerprint": "AB" * 32,
        "signature_image_hash": "CD" * 32,
    }


def _make_history() -> dict:
    event = {
        "seal_type": "Sealing",
        "start_time": "2026-04-01T10:00:00Z",
        "end_time": "2026-04-01T11:00:00Z",
        "investigator": "Kim",
    }
    return create_initial_history(event)


def _make_valid_record() -> dict:
    seal_id = create_seal_id()
    return build_seal_record(
        unlock_time_iso="2026-12-31T00:00:00Z",
        key_commitment="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  # public-test-fixture; gitleaks:allow
        seal_id=seal_id,
        case_info=_make_case_info(),
        process_info=_make_process_info(),
        file_info=_make_file_info(),
        signer_info=_make_signer_info(),
        history=_make_history(),
    )


# ---------------------------------------------------------------------------
# Tests: 6 required top-level fields
# ---------------------------------------------------------------------------


class TestTopLevelFields:
    """build_seal_record() must produce all 6 required fields."""

    REQUIRED = {"seal_id", "case_info", "process_info",
                "file_info", "signer_info", "history"}

    def test_all_fields_present(self) -> None:
        record = _make_valid_record()
        assert self.REQUIRED <= set(record.keys())

    def test_validate_passes_for_valid_record(self) -> None:
        record = _make_valid_record()
        errors = validate_record(record)
        assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Tests: seal_id format
# ---------------------------------------------------------------------------


class TestSealIdFormat:
    """seal_id must match ^S-YYYYMMDD-[0-9A-F]{6}$."""

    def test_create_seal_id_format(self) -> None:
        for _ in range(20):
            sid = create_seal_id()
            assert _SEAL_ID_RE.match(sid), f"Bad seal_id: {sid}"

    def test_valid_seal_id_passes_validation(self) -> None:
        record = _make_valid_record()
        errors = validate_record(record)
        assert not any("seal_id" in e for e in errors)

    def test_invalid_seal_id_fails_validation(self) -> None:
        record = _make_valid_record()
        record["seal_id"] = "INVALID"
        errors = validate_record(record)
        assert any("seal_id" in e for e in errors)

    def test_lowercase_hex_rejected(self) -> None:
        record = _make_valid_record()
        record["seal_id"] = "S-20260401-abcdef"
        errors = validate_record(record)
        assert any("seal_id" in e for e in errors)


# ---------------------------------------------------------------------------
# Tests: ISO 8601 time fields
# ---------------------------------------------------------------------------


class TestISO8601TimeFields:
    """All time fields must match ISO 8601 UTC (ending with Z)."""

    def test_valid_times_pass(self) -> None:
        record = _make_valid_record()
        errors = validate_record(record)
        time_errors = [e for e in errors if "ISO 8601" in e]
        assert time_errors == [], f"Time errors: {time_errors}"

    def test_non_iso_time_rejected(self) -> None:
        record = _make_valid_record()
        record["process_info"]["start_time"] = "2026/04/01 10:00:00"
        errors = validate_record(record)
        assert any("ISO 8601" in e for e in errors)

    def test_timezone_offset_format_rejected(self) -> None:
        """Times with +00:00 instead of Z should be rejected by schema."""
        record = _make_valid_record()
        record["process_info"]["start_time"] = "2026-04-01T10:00:00+00:00"
        errors = validate_record(record)
        assert any("ISO 8601" in e for e in errors)


# ---------------------------------------------------------------------------
# Tests: validate_record() with invalid input
# ---------------------------------------------------------------------------


class TestValidateRecordErrors:
    """validate_record() must return error list for bad data."""

    def test_empty_dict(self) -> None:
        errors = validate_record({})
        assert len(errors) > 0

    def test_missing_single_field(self) -> None:
        record = _make_valid_record()
        del record["case_info"]
        errors = validate_record(record)
        assert any("case_info" in e for e in errors)

    def test_empty_original_files(self) -> None:
        record = _make_valid_record()
        record["file_info"]["original_files"] = []
        errors = validate_record(record)
        assert any("original_files" in e for e in errors)

    def test_mismatched_nonces_tags_lengths(self) -> None:
        record = _make_valid_record()
        record["file_info"]["result_files"][0]["nonces"] = ["aa", "bb"]
        record["file_info"]["result_files"][0]["tags"] = ["cc"]
        errors = validate_record(record)
        assert any("nonces" in e or "tags" in e or "chunk_lengths" in e for e in errors)

    def test_history_summary_mismatch(self) -> None:
        record = _make_valid_record()
        record["history"]["summary"] = "S5U0R0"
        errors = validate_record(record)
        assert any("summary" in e for e in errors)

    def test_missing_case_info_fields(self) -> None:
        record = _make_valid_record()
        record["case_info"] = {"case_number": "2026-0001"}
        errors = validate_record(record)
        assert len(errors) >= 2  # many missing fields

    def test_missing_signer_info_fields(self) -> None:
        record = _make_valid_record()
        record["signer_info"] = {"name": "Lee"}
        errors = validate_record(record)
        assert any("signer_info" in e for e in errors)


# ---------------------------------------------------------------------------
# Tests: process_info.type values
# ---------------------------------------------------------------------------


class TestProcessInfoType:
    """process_info.type must be one of {Sealing, Unsealing, Resealing}."""

    @pytest.mark.parametrize("ptype", ["Sealing", "Unsealing", "Resealing"])
    def test_valid_types_accepted(self, ptype: str) -> None:
        record = _make_valid_record()
        record["process_info"]["type"] = ptype
        errors = validate_record(record)
        type_errors = [e for e in errors if "process_info.type" in e]
        assert type_errors == []

    @pytest.mark.parametrize("ptype", ["sealing", "SEALING", "invalid", ""])
    def test_invalid_types_rejected(self, ptype: str) -> None:
        record = _make_valid_record()
        record["process_info"]["type"] = ptype
        errors = validate_record(record)
        assert any("process_info.type" in e for e in errors)
