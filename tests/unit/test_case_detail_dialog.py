"""Unit tests for the redesigned case detail dialog.

Covers:
- Regression: initial window width fits content (columns not clipped)
- Font-measured artifact Treeview columns (headers never truncated)
- Esc closes the dialog
- Status badge derivation from history summary (SxUyRz)
- Copyable readonly hash entries in the files tab
- New i18n keys present for both ko/en
"""

from __future__ import annotations

import json

import tkinter as tk
from tkinter import font as tkfont

import pytest

from desktop.db.sqlite_store import init_db, save_seal_record
from desktop.gui.case_detail_dialog import (
    CaseDetailDialog,
    _derive_status_kind,
)
from desktop.gui.theme import get_font

MD5_HASH = "d41d8cd98f00b204e9800998ecf8427e"
SHA256_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SEAL_ID = "S-20260401-000001"


def _make_record() -> dict:
    return {
        "seal_id": SEAL_ID,
        "case_info": {
            "case_number": "2026-0001",
            "investigator": "Kim",
            "suspect": "Lee",
            "storage_type": "SSD",
            "seizure_time": "2026-04-01T09:00:00Z",
            "seizure_location": "Seoul",
        },
        "process_info": {
            "type": "Sealing",
            "start_time": "2026-04-01T10:00:00Z",
            "end_time": "2026-04-01T11:00:00Z",
            "investigator": "Kim",
        },
        "file_info": {
            "original_files": [
                {
                    "filename": "evidence.dd",
                    "size": 1048576,
                    "md5": MD5_HASH,
                    "sha256": SHA256_HASH,
                    "mtime": "2026-03-31T08:00:00Z",
                },
            ],
            "result_files": [
                {
                    "filename": "evidence.dd.enc",
                    "size": 1048600,
                    "encryption_algo": "AES-256-GCM",
                    "enc_ended_time": "2026-04-01T11:00:00Z",
                },
            ],
            "hash_match": True,
        },
        "signer_info": {
            "name": "Lee",
            "email": "lee@example.com",
            "birth_date": "1990-01-01",
            "phone": "010-1234-5678",
        },
        "history": {
            "events": [
                {
                    "seal_type": "Sealing",
                    "start_time": "2026-04-01T10:00:00Z",
                    "end_time": "2026-04-01T11:00:00Z",
                    "investigator": "Kim",
                },
                {
                    "seal_type": "Unsealing",
                    "start_time": "2026-04-02T10:00:00Z",
                    "end_time": "2026-04-02T11:00:00Z",
                    "investigator": "Kim",
                    "reason": "분석을 위한 봉인해제",
                },
            ],
            "summary": "S1U1R0",
        },
    }


@pytest.fixture()
def root():
    """Create and teardown a Tk root window."""
    r = tk.Tk()
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture()
def seal_db(tmp_path) -> str:
    """Create a SQLite DB seeded with one seal record."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    save_seal_record(
        db_path,
        SEAL_ID,
        json.dumps(_make_record(), ensure_ascii=False),
        str(tmp_path / "record.pdf"),
    )
    return db_path


# ---------- Regression: initial size fits content ----------

def test_initial_width_fits_content(root: tk.Tk, seal_db: str) -> None:
    """The dialog must open wide enough for its content — no clipped columns.

    The root must be mapped for the transient dialog to become viewable,
    so it is deiconified for this smoke test.
    """
    root.deiconify()
    root.geometry("+0+0")
    dlg = CaseDetailDialog(root, seal_db, SEAL_ID)
    try:
        dlg.update()
        root.update()
        assert dlg.winfo_viewable()
        assert dlg.winfo_width() >= dlg.winfo_reqwidth()
    finally:
        dlg.destroy()


def test_artifact_columns_fit_headers(root: tk.Tk, seal_db: str) -> None:
    """Every artifact column must be at least as wide as its header text."""
    dlg = CaseDetailDialog(root, seal_db, SEAL_ID)
    try:
        dlg.update()
        tree = dlg._artifacts_tree
        assert tree is not None
        head_font = tkfont.Font(font=get_font("subheader"))
        for cid in tree["columns"]:
            heading = tree.heading(cid, "text")
            width = int(tree.column(cid, "width"))
            minwidth = int(tree.column(cid, "minwidth"))
            assert width >= head_font.measure(heading)
            assert minwidth >= head_font.measure(heading)
    finally:
        dlg.destroy()


# ---------- Keyboard ----------

def test_escape_closes_dialog(root: tk.Tk, seal_db: str) -> None:
    root.deiconify()
    root.geometry("+0+0")
    dlg = CaseDetailDialog(root, seal_db, SEAL_ID)
    dlg.update()
    dlg.focus_force()
    dlg.update()
    dlg.event_generate("<Escape>")
    root.update()
    assert not dlg.winfo_exists()


# ---------- Status badge derivation ----------

@pytest.mark.parametrize(
    ("summary", "expected"),
    [
        ("S1U0R0", "sealed"),
        ("S1U1R0", "unsealed"),
        ("S1U1R1", "resealed"),
        ("S2U2R1", "resealed"),
        ("", "unknown"),
        ("garbage", "unknown"),
    ],
)
def test_derive_status_kind(summary: str, expected: str) -> None:
    record = {"history": {"summary": summary}} if summary else {}
    kind, got_summary = _derive_status_kind(record)
    assert kind == expected
    if summary and expected != "unknown":
        assert got_summary == summary


def test_derive_status_kind_missing_history() -> None:
    assert _derive_status_kind({}) == ("unknown", "")
    assert _derive_status_kind({"history": []}) == ("unknown", "")


# ---------- Copyable hashes ----------

def test_hash_entries_readonly_and_copyable(root: tk.Tk, seal_db: str) -> None:
    dlg = CaseDetailDialog(root, seal_db, SEAL_ID)
    try:
        dlg.update_idletasks()
        assert len(dlg._hash_entries) == 2  # md5 + sha256
        values = {e.get() for e in dlg._hash_entries}
        assert MD5_HASH in values
        assert SHA256_HASH in values
        for entry in dlg._hash_entries:
            assert str(entry.cget("state")) == "readonly"
    finally:
        dlg.destroy()


# ---------- i18n keys ----------

def test_new_i18n_keys_have_ko_and_en() -> None:
    from desktop.gui.i18n import _TRANSLATIONS

    new_keys = [
        "case_detail.status_unknown",
        "case_detail.created_at",
        "case_detail.section_original_files",
        "case_detail.section_result_files",
        "case_detail.section_unknown_files",
        "case_detail.section_derived_files",
        "case_detail.file_size",
        "case_detail.file_mtime",
        "case_detail.enc_algo",
        "case_detail.enc_ended",
        "case_detail.hash_match",
        "case_detail.hash_mismatch",
        "case_detail.no_files",
    ]
    for key in new_keys:
        assert key in _TRANSLATIONS, key
        assert _TRANSLATIONS[key].get("ko"), key
        assert _TRANSLATIONS[key].get("en"), key
