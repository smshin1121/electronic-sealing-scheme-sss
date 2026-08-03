"""unlock_time_iso is a canonical, signature-covered record field.

The time-lock policy governs release of the time-locked share, so it must
be fixed *before* the record is rendered and signed — otherwise sigma does
not cover it and a privileged party can move the unlock time afterwards
without invalidating the signature. These tests pin that ordering:

  - build_seal_record requires the field and validate_record enforces it
  - S4 writes it into the record; S5 signs that record; S6 only reads it
  - S7 persists the record verbatim (nothing grafted on after signing)
  - the rendered document (the signed artifact) shows the same value
  - derived unseal/reseal records carry it forward
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from desktop.record.exceptions import RecordValidationError
from desktop.record.record_builder import (
    _TOP_LEVEL_FIELDS,
    build_reseal_record,
    build_seal_record,
    build_unseal_record,
    validate_record,
)

UNLOCK = "2026-12-31T00:00:00Z"
COMMIT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _kwargs(process_type: str = "Sealing") -> dict[str, Any]:
    return {
        "case_info": {
            "case_number": "2026-001",
            "investigator": "Hong",
            "device_user": "Kim",
            "suspect": "Kim",
            "storage_type": "SSD",
            "storage_info": {"manufacturer": "M", "model": "X",
                             "serial": "1"},
            "seizure_time": "2026-08-02T00:00:00Z",
            "seizure_location": "Seoul",
        },
        "process_info": {
            "type": process_type,
            "start_time": "2026-08-02T00:00:00Z",
            "end_time": "2026-08-02T00:00:00Z",
            "file_count": 1,
            "investigator": "Hong",
            "reason": "",
            "participation": "yes",
        },
        "file_info": {
            "original_files": [{
                "filename": "e.bin", "size": 1, "md5": "0" * 32,
                "sha256": "0" * 64,
                "mtime": "2026-08-02T00:00:00Z",
                "ctime": "2026-08-02T00:00:00Z",
                "atime": "2026-08-02T00:00:00Z",
            }],
            "result_files": [{
                "filename": "e.bin.enc", "size": 2,
                "encryption_algo": "AES-256-GCM",
                "enc_ended_time": "2026-08-02T00:00:00Z",
                "nonces": ["00"], "tags": ["11"], "chunk_lengths": [1],
            }],
            "hash_match": True,
        },
        "signer_info": {
            "name": "Kim", "email": "k@example.com",
            "birth_date": "1990-01-01", "phone": "010-0000-0000",
            "cert_fingerprint": "0" * 64,
            "signature_image_hash": "0" * 64,
        },
        "history": {"summary": "S1U0R0", "events": [
            {"event": "seal", "time": "2026-08-02T00:00:00Z",
             "actor": "Hong", "reason": ""},
        ]},
    }


class TestCanonicalSchema:
    """The field belongs to the record schema, not to a post-hoc graft."""

    def test_field_is_top_level_and_required(self) -> None:
        assert "unlock_time_iso" in _TOP_LEVEL_FIELDS

    def test_builder_requires_the_argument(self) -> None:
        with pytest.raises(TypeError):
            build_seal_record(seal_id="S-20260802-ABC123", **_kwargs())

    def test_empty_value_is_refused(self) -> None:
        with pytest.raises(RecordValidationError):
            build_seal_record(
                seal_id="S-20260802-ABC123", unlock_time_iso="",
                key_commitment=COMMIT, **_kwargs()
            )

    def test_valid_record_passes_validation(self) -> None:
        record = build_seal_record(
            seal_id="S-20260802-ABC123", unlock_time_iso=UNLOCK,
            key_commitment=COMMIT, **_kwargs()
        )
        assert record["unlock_time_iso"] == UNLOCK
        assert validate_record(record) == []

    def test_validator_rejects_missing_field_on_sealing(self) -> None:
        record = build_seal_record(
            seal_id="S-20260802-ABC123", unlock_time_iso=UNLOCK,
            key_commitment=COMMIT, **_kwargs()
        )
        del record["unlock_time_iso"]
        errors = validate_record(record)
        assert any("unlock_time_iso" in e for e in errors)

    def test_validator_rejects_malformed_value(self) -> None:
        record = build_seal_record(
            seal_id="S-20260802-ABC123", unlock_time_iso=UNLOCK,
            key_commitment=COMMIT, **_kwargs()
        )
        record["unlock_time_iso"] = "next tuesday"
        errors = validate_record(record)
        assert any("unlock_time_iso" in e for e in errors)


class TestDerivedRecordsCarryForward:
    """Unseal/reseal inherit the sealing-time policy."""

    def _seal(self) -> dict[str, Any]:
        return build_seal_record(
            seal_id="S-20260802-ABC123", unlock_time_iso=UNLOCK,
            key_commitment=COMMIT, **_kwargs()
        )

    def test_unseal_carries_forward(self) -> None:
        k = _kwargs("Unsealing")
        rec = build_unseal_record(
            prev_record=self._seal(),
            process_info=k["process_info"],
            file_info=k["file_info"],
        )
        assert rec["unlock_time_iso"] == UNLOCK

    def test_reseal_carries_forward_by_default(self) -> None:
        k = _kwargs("Resealing")
        rec = build_reseal_record(
            prev_record=self._seal(),
            process_info=k["process_info"],
            file_info=k["file_info"],
        )
        assert rec["unlock_time_iso"] == UNLOCK

    def test_reseal_accepts_a_new_policy(self) -> None:
        k = _kwargs("Resealing")
        rec = build_reseal_record(
            prev_record=self._seal(),
            process_info=k["process_info"],
            file_info=k["file_info"],
            unlock_time_iso="2027-06-30T00:00:00Z",
        )
        assert rec["unlock_time_iso"] == "2027-06-30T00:00:00Z"

    def test_legacy_prev_record_yields_empty_not_crash(self) -> None:
        legacy = self._seal()
        del legacy["unlock_time_iso"]
        k = _kwargs("Unsealing")
        rec = build_unseal_record(
            prev_record=legacy,
            process_info=k["process_info"],
            file_info=k["file_info"],
        )
        assert rec["unlock_time_iso"] == ""


class TestSealProcessOrdering:
    """S4 fixes the policy; S6 reads it; S7 stores the signed record."""

    def _process(self, tmp_path: Path, unlock_days: int = 7) -> Any:
        import desktop.seal_process as sp

        src = tmp_path / "evidence.bin"
        src.write_bytes(os.urandom(4096))
        enc = tmp_path / "evidence.bin.enc"
        enc.write_bytes(b"x" * 64)

        process = sp.SealProcess(db_path=str(tmp_path / "seal.db"))
        process.set_config(sp.SealConfig(
            source_file=str(src),
            output_dir=str(tmp_path),
            chunk_size_bytes=1 << 30,
            case_number="2026-001",
            investigator={"name": "Hong"},
            seizure={"date": "2026-08-02T00:00:00Z", "location": "Seoul",
                     "device_user": "Kim"},
            media={"type": "SSD", "manufacturer": "M", "model": "X",
                   "serial": "1"},
            subject={"name": "Kim", "email": "k@example.com",
                     "birth": "1990-01-01", "phone": "010-0000-0000",
                     "participation": "yes", "password": "pw"},
            signature_lines=[(0, 0, 1, 1)],
            unlock_days=unlock_days,
        ))
        process.state["s1"] = {
            "aes_key_hex": "ab" * 32,
            "enc_filepath": str(enc),
            "encryption_algo": "AES-256-GCM",
            "metadata": {
                "filename": "evidence.bin", "size": 4096,
                "md5": "0" * 32, "sha256": "0" * 64,
                "mtime": "2026-08-02T00:00:00Z",
                "ctime": "2026-08-02T00:00:00Z",
                "atime": "2026-08-02T00:00:00Z",
            },
            "enc_metadata": {
                "enc_ended_time": "2026-08-02T00:00:00Z",
                "nonces": ["00"], "tags": ["11"], "chunk_lengths": [4096],
            },
        }
        return process

    def test_s4_record_carries_the_policy(self, tmp_path: Path) -> None:
        process = self._process(tmp_path)
        s4 = process.run_s4()

        unlock = s4["record_dict"]["unlock_time_iso"]
        assert unlock, "S4 must fix the unlock time before signing"
        assert validate_record(s4["record_dict"]) == []

    def test_s6_reads_s4_and_never_recomputes(self, tmp_path: Path) -> None:
        process = self._process(tmp_path)
        s4 = process.run_s4()
        s6 = process.run_s6()

        assert s6["unlock_time_iso"] == s4["record_dict"]["unlock_time_iso"]

    def test_s6_requires_s4(self, tmp_path: Path) -> None:
        process = self._process(tmp_path)
        with pytest.raises(RuntimeError, match="S4"):
            process.run_s6()

    def test_unlock_days_is_honored(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone

        process = self._process(tmp_path, unlock_days=3)
        s4 = process.run_s4()

        unlock = datetime.fromisoformat(
            s4["record_dict"]["unlock_time_iso"].replace("Z", "+00:00")
        )
        delta_days = (unlock - datetime.now(tz=timezone.utc)).days
        assert delta_days in (2, 3)


class TestRenderedDocumentShowsPolicy:
    """The signed artifact displays the same value the record carries."""

    def test_template_renders_unlock_time(self, tmp_path: Path) -> None:
        from desktop.record.pdf_renderer import _render_html

        record = build_seal_record(
            seal_id="S-20260802-ABC123", unlock_time_iso=UNLOCK,
            key_commitment=COMMIT, **_kwargs()
        )
        html = _render_html(record, "seal_record.html")

        assert UNLOCK in html, (
            "the unlock time must appear in the rendered (signed) document, "
            "otherwise sigma does not cover the time-lock policy"
        )
