"""Regression tests for desktop integrity, resume, and UI behavior.

Covers:
1. Resume state is bound to the source file (path/size/mtime_ns) and
   structurally validated — unbound or out-of-range progress files are
   rejected and encryption restarts fresh.
2. Decryption writes plaintext to a temp file and publishes it to the
   final path atomically only after ALL auth tags and the metadata
   hash comparison verified — tampering never leaves plaintext at the
   final path.
3. U6/R6 preview history parsing handles the canonical dict schema
   ({"summary", "events"}) as well as the legacy list schema.
5. DB lookups fall back to the canonical file_info.result_files when
   the legacy encryption.enc_filepath key is absent.
8. run_async discards results once the cancel event is set.
10. Toasts restack after one closes (no floating gap).
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
import time
import tkinter as tk
from pathlib import Path
from types import SimpleNamespace

import pytest

from desktop.crypto import (
    TamperDetectedError,
    decrypt_file,
    encrypt_file,
)
from desktop.crypto.aes_gcm_encrypt import (
    _key_fingerprint,
    _normalize_source_path,
)

_1GB = 1 * 1024**3


def _sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class _InterruptAfterN:
    """Progress callback that raises after *n* invocations."""

    def __init__(self, interrupt_after: int) -> None:
        self._count = 0
        self._limit = interrupt_after

    def __call__(self, completed: int, total: int) -> None:
        self._count += 1
        if self._count >= self._limit:
            raise RuntimeError("Simulated interruption")


def _interrupt(file_path: str, key: bytes, enc_path: str) -> None:
    from desktop.crypto import EncryptionError

    with pytest.raises(EncryptionError):
        encrypt_file(
            file_path, key, enc_path,
            chunk_size=_1GB,
            progress_cb=_InterruptAfterN(interrupt_after=1),
        )


@pytest.fixture()
def root():
    r = tk.Tk()
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


# ---------------------------------------------------------------------------
# Fix 1: resume state bound to the source file
# ---------------------------------------------------------------------------

class TestResumeSourceBinding:
    def test_progress_file_contains_source_binding(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "bind.enc")
        _interrupt(file_1mb, aes_key, enc_path)

        with open(enc_path + ".progress", "r", encoding="utf-8") as f:
            progress = json.load(f)

        st = os.stat(file_1mb)
        assert progress["source_path"] == _normalize_source_path(file_1mb)
        assert progress["source_size"] == st.st_size
        assert progress["source_mtime_ns"] == st.st_mtime_ns

    def test_modified_source_starts_fresh(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """A source whose mtime changed after the interrupt must NOT be
        resumed onto the old partial ciphertext."""
        enc_path = str(tmp_work_dir / "mtime.enc")
        dec_dir = str(tmp_work_dir / "dec_mtime")
        os.makedirs(dec_dir)

        _interrupt(file_1mb, aes_key, enc_path)
        assert os.path.isfile(enc_path + ".progress")

        # Corrupt the partial ciphertext — if a (wrong) resume kept it,
        # decryption would fail. A fresh start overwrites it entirely.
        with open(enc_path, "r+b") as f:
            f.seek(8)
            f.write(b"\xff" * 64)

        # Change the source mtime so the binding no longer matches.
        st = os.stat(file_1mb)
        os.utime(file_1mb, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))

        original_hash = _sha256_of_file(file_1mb)
        result = encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)
        assert dec_result.hash_verified is True
        assert _sha256_of_file(dec_result.output_filepath) == original_hash

    def test_legacy_progress_without_binding_starts_fresh(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """A pre-fix progress file (no source binding) cannot prove the
        source is unchanged — it must be discarded."""
        enc_path = str(tmp_work_dir / "legacy_bind.enc")
        dec_dir = str(tmp_work_dir / "dec_legacy_bind")
        os.makedirs(dec_dir)

        legacy = {
            "target_file": os.path.basename(file_1mb),
            "completed_chunks": 1,
            "chunk_size": _1GB,
            "key_fingerprint": _key_fingerprint(aes_key),
            "nonces": ["aa" * 12],
            "tags": ["bb" * 16],
            "chunk_lengths": [1024],
        }
        with open(enc_path + ".progress", "w", encoding="utf-8") as f:
            json.dump(legacy, f)
        with open(enc_path, "wb") as f:
            f.write(b"\x00" * (8 + 1024 + 16))

        result = encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)
        assert dec_result.hash_verified is True

    def test_out_of_range_completed_chunks_starts_fresh(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """completed_chunks > num_chunks (structural nonsense) must be
        rejected instead of seeking past EOF during 'resume'."""
        enc_path = str(tmp_work_dir / "range.enc")
        dec_dir = str(tmp_work_dir / "dec_range")
        os.makedirs(dec_dir)

        st = os.stat(file_1mb)
        # 1 MB source with 1 GB chunks -> num_chunks == 1; claim 3.
        bogus = {
            "target_file": os.path.basename(file_1mb),
            "source_path": _normalize_source_path(file_1mb),
            "source_size": st.st_size,
            "source_mtime_ns": st.st_mtime_ns,
            "completed_chunks": 3,
            "chunk_size": _1GB,
            "key_fingerprint": _key_fingerprint(aes_key),
            "nonces": ["aa" * 12] * 3,
            "tags": ["bb" * 16] * 3,
            "chunk_lengths": [100, 100, 100],
        }
        with open(enc_path + ".progress", "w", encoding="utf-8") as f:
            json.dump(bogus, f)
        # Output big enough to satisfy the size-consistency guard alone.
        with open(enc_path, "wb") as f:
            f.write(b"\x00" * 1000)

        result = encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        dec_result = decrypt_file(result.enc_filepath, aes_key, dec_dir)
        assert dec_result.hash_verified is True
        assert not os.path.exists(enc_path + ".progress")


# ---------------------------------------------------------------------------
# Fix 2: decryption is atomic — no plaintext at the final path on failure
# ---------------------------------------------------------------------------

class TestDecryptAtomicity:
    def _final_path(self, source: str, dec_dir: str) -> str:
        return os.path.join(dec_dir, os.path.basename(source))

    def test_success_publishes_file_and_leaves_no_part(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "ok.enc")
        dec_dir = tmp_work_dir / "dec_ok"
        dec_dir.mkdir()

        encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        result = decrypt_file(enc_path, aes_key, str(dec_dir))

        assert result.hash_verified is True
        assert os.path.isfile(result.output_filepath)
        assert list(dec_dir.glob("*.part")) == []

    def test_tampered_ciphertext_leaves_no_plaintext(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        enc_path = str(tmp_work_dir / "tamper.enc")
        dec_dir = tmp_work_dir / "dec_tamper"
        dec_dir.mkdir()

        encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)

        # Flip one ciphertext byte (just after the 8-byte offset header).
        with open(enc_path, "r+b") as f:
            f.seek(8 + 100)
            byte = f.read(1)
            f.seek(8 + 100)
            f.write(bytes([byte[0] ^ 0xFF]))

        with pytest.raises(TamperDetectedError):
            decrypt_file(enc_path, aes_key, str(dec_dir))

        final = self._final_path(file_1mb, str(dec_dir))
        assert not os.path.exists(final), (
            "tampered decryption must never leave plaintext at the "
            "final output path"
        )
        assert list(dec_dir.glob("*.part")) == [], (
            "temp plaintext must be cleaned up on tamper detection"
        )

    def test_tampered_metadata_hash_is_rejected(
        self, file_1mb: str, aes_key: bytes, tmp_work_dir: Path
    ) -> None:
        """Tags verify but the (unauthenticated) metadata hash was
        altered — the plaintext must not be published."""
        enc_path = str(tmp_work_dir / "metatamper.enc")
        dec_dir = tmp_work_dir / "dec_metatamper"
        dec_dir.mkdir()

        result = encrypt_file(file_1mb, aes_key, enc_path, chunk_size=_1GB)
        orig_hex = result.metadata.sha256.encode("ascii")
        fake_hex = (
            ("0" if result.metadata.sha256[0] != "0" else "1")
            + result.metadata.sha256[1:]
        ).encode("ascii")

        data = Path(enc_path).read_bytes()
        idx = data.rfind(orig_hex)  # metadata JSON is at the tail
        assert idx != -1
        Path(enc_path).write_bytes(
            data[:idx] + fake_hex + data[idx + len(orig_hex):]
        )

        with pytest.raises(TamperDetectedError):
            decrypt_file(enc_path, aes_key, str(dec_dir))

        final = self._final_path(file_1mb, str(dec_dir))
        assert not os.path.exists(final)
        assert list(dec_dir.glob("*.part")) == []


# ---------------------------------------------------------------------------
# Fix 3: history preview parsing (canonical dict + legacy list)
# ---------------------------------------------------------------------------

class TestHistoryPreviewParsing:
    def test_canonical_history_dict(self) -> None:
        from desktop.gui.record_preview import extract_history_view

        record = {
            "history": {
                "summary": "S1U1R0",
                "events": [
                    {
                        "id": 1,
                        "seal_type": "Sealing",
                        "start_time": "2026-01-01T00:00:00Z",
                        "end_time": "2026-01-01T00:00:00Z",
                        "investigator": "kim",
                    },
                    {
                        "id": 2,
                        "seal_type": "Unsealing",
                        "start_time": "2026-02-01T00:00:00Z",
                        "end_time": "2026-02-01T00:00:00Z",
                        "investigator": "lee",
                    },
                ],
            }
        }
        events, summary = extract_history_view(record)
        assert summary == "S1U1R0"
        assert len(events) == 2
        assert events[0] == {
            "type": "Sealing",
            "time": "2026-01-01T00:00:00Z",
            "actor": "kim",
        }
        assert events[1]["type"] == "Unsealing"
        assert events[1]["actor"] == "lee"

    def test_legacy_history_list(self) -> None:
        from desktop.gui.record_preview import extract_history_view

        record = {
            "summary": "S1U1R0",
            "history": [
                {"event": "seal", "timestamp": "t1", "actor": "kim"},
                {"event": "unseal", "timestamp": "t2", "actor": "lee"},
            ],
        }
        events, summary = extract_history_view(record)
        assert summary == "S1U1R0"
        assert events[0] == {"type": "seal", "time": "t1", "actor": "kim"}
        assert events[1] == {"type": "unseal", "time": "t2", "actor": "lee"}

    def test_missing_history_is_safe(self) -> None:
        from desktop.gui.record_preview import extract_history_view

        events, summary = extract_history_view({})
        assert events == []
        assert summary == "N/A"

    def test_case_number_canonical_and_legacy(self) -> None:
        from desktop.gui.record_preview import extract_case_number

        assert extract_case_number(
            {"case_info": {"case_number": "2026-형제-123"}}
        ) == "2026-형제-123"
        assert extract_case_number({"case_number": "legacy-1"}) == "legacy-1"
        assert extract_case_number({}) == ""


# ---------------------------------------------------------------------------
# Fix 5: DB lookup falls back to file_info.result_files
# ---------------------------------------------------------------------------

class TestEncPathFallback:
    def _setup_db(self, tmp_path: Path, record: dict, pdf_path: str) -> str:
        from desktop.db.sqlite_store import init_db, save_seal_record

        db_path = str(tmp_path / "fallback.db")
        init_db(db_path)
        save_seal_record(
            db_path, "S-20260101-ABCDEF",
            json.dumps(record, ensure_ascii=False), pdf_path,
        )
        return db_path

    def test_canonical_record_resolves_enc_from_result_files(
        self, tmp_path: Path
    ) -> None:
        from desktop.db.sqlite_store import (
            get_case_artifacts,
            get_case_for_unseal,
        )

        pdf_path = str(tmp_path / "out" / "S-20260101-ABCDEF.pdf")
        record = {
            "seal_id": "S-20260101-ABCDEF",
            "file_info": {
                "result_files": [{"filename": "evidence.bin.enc"}],
            },
        }
        db_path = self._setup_db(tmp_path, record, pdf_path)

        info = get_case_for_unseal(db_path, "S-20260101-ABCDEF")
        expected = str(Path(pdf_path).parent / "evidence.bin.enc")
        assert info is not None
        assert info["enc_filepath"] == expected

        artifacts = get_case_artifacts(db_path, "S-20260101-ABCDEF")
        enc_artifacts = [a for a in artifacts if a["file_type"] == "enc"]
        assert enc_artifacts and enc_artifacts[0]["file_path"] == expected

    def test_legacy_encryption_key_still_preferred(
        self, tmp_path: Path
    ) -> None:
        from desktop.db.sqlite_store import get_case_for_unseal

        pdf_path = str(tmp_path / "S-20260101-ABCDEF.pdf")
        record = {
            "seal_id": "S-20260101-ABCDEF",
            "encryption": {"enc_filepath": r"D:\legacy\evidence.enc"},
            "file_info": {
                "result_files": [{"filename": "evidence.bin.enc"}],
            },
        }
        db_path = self._setup_db(tmp_path, record, pdf_path)

        info = get_case_for_unseal(db_path, "S-20260101-ABCDEF")
        assert info is not None
        assert info["enc_filepath"] == r"D:\legacy\evidence.enc"

    def test_record_without_any_enc_info_yields_empty(
        self, tmp_path: Path
    ) -> None:
        from desktop.db.sqlite_store import get_case_for_unseal

        record = {"seal_id": "S-20260101-ABCDEF"}
        db_path = self._setup_db(
            tmp_path, record, str(tmp_path / "r.pdf")
        )
        info = get_case_for_unseal(db_path, "S-20260101-ABCDEF")
        assert info is not None
        assert info["enc_filepath"] == ""


# ---------------------------------------------------------------------------
# Fix 8: run_async cancel event discards results
# ---------------------------------------------------------------------------

class TestRunAsyncCancel:
    def test_cancelled_result_is_discarded(self, root: tk.Tk) -> None:
        from desktop.gui.progress_dialog import run_async

        results: list[int] = []
        cancel = threading.Event()
        release = threading.Event()

        def slow_task() -> int:
            release.wait(5.0)
            return 42

        run_async(
            root, slow_task, results.append,
            poll_ms=10, cancel_event=cancel,
        )
        cancel.set()      # cancel BEFORE the worker finishes
        release.set()     # let the worker finish now

        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)
        assert results == [], "cancelled run_async must discard the result"

    def test_uncancelled_result_still_delivered(self, root: tk.Tk) -> None:
        from desktop.gui.progress_dialog import run_async

        results: list[int] = []
        cancel = threading.Event()
        run_async(root, lambda: 7, results.append, poll_ms=10,
                  cancel_event=cancel)

        deadline = time.monotonic() + 5.0
        while not results and time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)
        assert results == [7]


# ---------------------------------------------------------------------------
# Fix 10: toasts restack after one closes
# ---------------------------------------------------------------------------

class TestToastRestack:
    def _fake_toast(self, height: int, moves: list) -> SimpleNamespace:
        toast = SimpleNamespace(height=height)
        toast.move_to = lambda y, _t=toast: moves.append((_t, y))
        return toast

    def test_close_restacks_remaining_toasts(self) -> None:
        from desktop.gui.toast import ToastManager, _TOAST_GAP

        manager = ToastManager()
        moves: list = []
        t1 = self._fake_toast(40, moves)
        t2 = self._fake_toast(60, moves)
        t3 = self._fake_toast(40, moves)
        manager._active_toasts.extend([t1, t2, t3])

        # Close the middle toast — t3 must drop into its place.
        manager._on_toast_close(t2)

        assert manager._active_toasts == [t1, t3]
        assert (t1, 0) in moves
        assert (t3, 40 + _TOAST_GAP) in moves

    def test_close_unknown_toast_is_harmless(self) -> None:
        from desktop.gui.toast import ToastManager

        manager = ToastManager()
        manager._on_toast_close(self._fake_toast(40, []))
        assert manager._active_toasts == []
