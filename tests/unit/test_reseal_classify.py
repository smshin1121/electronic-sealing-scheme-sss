"""Tests for the reseal fallback classifier optimizations.

Validates:
- Size pre-filter: size-matching files are hashed and classified known
- Size-mismatched files are classified unknown without hashing
- Legacy records without size info fall back to hashing every file
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from desktop.reseal_process import _fallback_classify


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_prev_record(files: list[dict]) -> dict:
    return {"file_info": {"original_files": files}}


class TestFallbackClassify:
    """_fallback_classify with size pre-filter and parallel hashing."""

    def test_known_file_detected_via_hash(self, tmp_path: Path) -> None:
        data = b"known-evidence-content" * 100
        (tmp_path / "evidence.bin").write_bytes(data)

        prev = _make_prev_record([
            {"sha256": _sha256_hex(data), "size": len(data)},
        ])
        known, unknown = _fallback_classify(prev, str(tmp_path))

        assert len(known) == 1
        assert known[0]["filename"] == "evidence.bin"
        assert known[0]["sha256"] == _sha256_hex(data)
        assert not unknown

    def test_size_mismatch_is_unknown_without_hash(
        self, tmp_path: Path
    ) -> None:
        """Files whose size matches no known file skip hashing."""
        known_data = b"a" * 500
        (tmp_path / "extra.log").write_bytes(b"b" * 999)  # size mismatch

        prev = _make_prev_record([
            {"sha256": _sha256_hex(known_data), "size": len(known_data)},
        ])
        known, unknown = _fallback_classify(prev, str(tmp_path))

        assert not known
        assert len(unknown) == 1
        assert unknown[0]["filename"] == "extra.log"
        # Skipped hash is recorded as empty (size pre-filter)
        assert unknown[0]["sha256"] == ""
        assert unknown[0]["suggested_category"] == "analysis_log"

    def test_same_size_different_content_is_unknown(
        self, tmp_path: Path
    ) -> None:
        """Size collision still requires the hash to decide."""
        known_data = b"x" * 400
        impostor = b"y" * 400
        (tmp_path / "impostor.bin").write_bytes(impostor)

        prev = _make_prev_record([
            {"sha256": _sha256_hex(known_data), "size": len(known_data)},
        ])
        known, unknown = _fallback_classify(prev, str(tmp_path))

        assert not known
        assert len(unknown) == 1
        # Size matched, so the hash was computed for comparison
        assert unknown[0]["sha256"] == _sha256_hex(impostor)

    def test_legacy_record_without_size_hashes_everything(
        self, tmp_path: Path
    ) -> None:
        """Records lacking size info must not misclassify known files."""
        data = b"legacy-record-content" * 50
        (tmp_path / "legacy.bin").write_bytes(data)

        prev = _make_prev_record([{"sha256": _sha256_hex(data)}])  # no size
        known, unknown = _fallback_classify(prev, str(tmp_path))

        assert len(known) == 1
        assert known[0]["sha256"] == _sha256_hex(data)
        assert not unknown

    def test_many_files_parallel_hashing(self, tmp_path: Path) -> None:
        """Parallel hashing must classify a larger file set correctly."""
        known_entries = []
        for i in range(8):
            data = f"known-{i}".encode() * 1000
            (tmp_path / f"known_{i}.bin").write_bytes(data)
            known_entries.append(
                {"sha256": _sha256_hex(data), "size": len(data)}
            )
        (tmp_path / "unknown.txt").write_bytes(b"z" * 12345)

        prev = _make_prev_record(known_entries)
        known, unknown = _fallback_classify(prev, str(tmp_path))

        assert len(known) == 8
        assert len(unknown) == 1
        assert unknown[0]["filename"] == "unknown.txt"

    def test_missing_target_dir_returns_empty(self, tmp_path: Path) -> None:
        prev = _make_prev_record([{"sha256": "aa" * 32, "size": 1}])
        known, unknown = _fallback_classify(
            prev, str(tmp_path / "does_not_exist")
        )
        assert known == []
        assert unknown == []
