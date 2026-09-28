"""seal_id collisions never replace another seal's row (Codex round 1, F9).

``S-YYYYMMDD-XXXXXX`` (portal contract) has 24 random bits per day. A case
registration draws a new ID when the drawn one is taken, sealing S4 without
a registered case picks an ID with no row yet, and ``save_seal_bundle``
refuses a bundle whose seal_id belongs to a different seal (the stored
history must be a prefix of the new record's history; the placeholder row
of a registered case has none). Resealing the same seal still replaces its
row. The collisions are forced by patching ``create_seal_id``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterator

import pytest

import desktop.record.record_builder as record_builder
from desktop.db import create_case, get_key_share, get_seal_record, init_db
from desktop.db.sqlite_store import (
    SealIdConflictError,
    save_seal_bundle,
    save_seal_record,
)
from desktop.signature.seal_policy import (
    POLICY_CERT_PATH_ENV,
    POLICY_KEY_PASSWORD_ENV,
    POLICY_KEY_PATH_ENV,
)
from tests.unit.test_e1_review_fixes import _after_s1

TAKEN = "S-20260928-AAAAAA"
FRESH = "S-20260928-BBBBBB"


@pytest.fixture()
def db(tmp_path: Path) -> str:
    path = str(tmp_path / "seal.db")
    init_db(path)
    return path


@pytest.fixture()
def no_policy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (POLICY_KEY_PATH_ENV, POLICY_CERT_PATH_ENV, POLICY_KEY_PASSWORD_ENV):
        monkeypatch.delenv(name, raising=False)


def _draws(monkeypatch: pytest.MonkeyPatch, *ids: str) -> list[str]:
    """Make ``create_seal_id`` return ``ids`` in turn (the last one repeats)."""
    drawn: list[str] = []
    queue: Iterator[str] = iter(ids)

    def _next() -> str:
        value = next(queue, ids[-1])
        drawn.append(value)
        return value

    monkeypatch.setattr(record_builder, "create_seal_id", _next)
    return drawn


def _event(seal_type: str, start: str, investigator: str = "Hong") -> dict:
    return {"id": 0, "seal_type": seal_type, "start_time": start,
            "end_time": start, "investigator": investigator}


def _record(seal_id: str, *events: dict, case_number: str = "2026-A") -> str:
    numbered = [{**event, "id": index + 1} for index, event in enumerate(events)]
    return json.dumps({
        "seal_id": seal_id,
        "case_info": {"case_number": case_number},
        "history": {"summary": "S1U0R0", "events": numbered},
    }, ensure_ascii=False, indent=2)


SEALED_A = _event("Sealing", "2026-09-28T01:00:00Z", "Hong")
SEALED_B = _event("Sealing", "2026-09-28T02:00:00Z", "Park")
UNSEALED_A = _event("Unsealing", "2026-10-06T01:00:00Z", "Hong")
RESEALED_A = _event("Resealing", "2026-10-06T02:00:00Z", "Hong")


def _stored(db: str, seal_id: str) -> dict:
    row = get_seal_record(db, seal_id)
    assert row is not None
    return row["record_json"]


# ===================================================================
# Case registration
# ===================================================================

def test_case_registration_draws_a_new_id_on_collision(db: str, monkeypatch) -> None:
    _draws(monkeypatch, TAKEN)
    assert create_case(db, "2026-FIRST", "Hong", "Kim") == TAKEN

    drawn = _draws(monkeypatch, TAKEN, FRESH)
    second = create_case(db, "2026-SECOND", "Park", "Lee")

    assert second == FRESH and drawn == [TAKEN, FRESH]
    assert _stored(db, TAKEN)["case_info"]["case_number"] == "2026-FIRST"
    assert _stored(db, FRESH)["case_info"]["case_number"] == "2026-SECOND"


def test_case_registration_gives_up_without_touching_rows(db: str, monkeypatch) -> None:
    _draws(monkeypatch, TAKEN)
    create_case(db, "2026-FIRST", "Hong", "Kim")

    with pytest.raises(SealIdConflictError):
        create_case(db, "2026-SECOND", "Park", "Lee")

    assert _stored(db, TAKEN)["case_info"]["case_number"] == "2026-FIRST"
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM seal_records").fetchone()[0] == 1


# ===================================================================
# save_seal_bundle
# ===================================================================

def test_a_bundle_never_replaces_another_seals_row(db: str) -> None:
    save_seal_bundle(db, TAKEN, _record(TAKEN, SEALED_A), "a.pdf",
                     shares={3: b"a3", 4: b"a4"}, cert_pem="CERT-A",
                     key_pem_encrypted=b"KEY-A", case_meta={"case_number": "2026-A"})

    with pytest.raises(SealIdConflictError):
        save_seal_bundle(db, TAKEN, _record(TAKEN, SEALED_B, case_number="2026-B"),
                         "b.pdf", shares={3: b"b3", 4: b"b4"}, cert_pem="CERT-B",
                         key_pem_encrypted=b"KEY-B", case_meta={"case_number": "2026-B"})

    row = get_seal_record(db, TAKEN)
    assert row["pdf_path"] == "a.pdf"
    assert row["record_json"]["history"]["events"][0]["investigator"] == "Hong"
    assert get_key_share(db, TAKEN, 3) == b"a3"
    assert get_key_share(db, TAKEN, 4) == b"a4"
    with sqlite3.connect(db) as conn:
        cert, case_number = conn.execute(
            "SELECT c.cert_pem, r.case_number FROM certificates c "
            "JOIN seal_records r USING (seal_id) WHERE seal_id = ?", (TAKEN,)).fetchone()
    assert cert == "CERT-A" and case_number == "2026-A"


def test_a_bundle_fills_the_row_of_its_registered_case(db: str, monkeypatch) -> None:
    _draws(monkeypatch, TAKEN)
    case_id = create_case(db, "2026-A", "Hong", "Kim")

    # E2d: filling the placeholder needs the claim on that registration.
    save_seal_bundle(db, case_id, _record(case_id, SEALED_A), "a.pdf",
                     shares={3: b"a3"}, case_meta={"case_number": "2026-A",
                                                   "status": "S1U0R0"},
                     registered_case_id=case_id)

    assert _stored(db, case_id)["history"]["events"][0]["seal_type"] == "Sealing"


def test_resealing_the_same_seal_replaces_its_row(db: str) -> None:
    save_seal_bundle(db, TAKEN, _record(TAKEN, SEALED_A), "a.pdf", shares={3: b"a3"})
    save_seal_record(db, TAKEN, _record(TAKEN, SEALED_A, UNSEALED_A), "u.pdf")

    save_seal_bundle(db, TAKEN, _record(TAKEN, SEALED_A, UNSEALED_A, RESEALED_A),
                     "r.pdf", shares={3: b"r3"})

    row = get_seal_record(db, TAKEN)
    assert row["pdf_path"] == "r.pdf"
    assert [e["seal_type"] for e in row["record_json"]["history"]["events"]] == [
        "Sealing", "Unsealing", "Resealing"]
    assert get_key_share(db, TAKEN, 3) == b"r3"


def test_saving_the_same_seal_record_again_is_allowed(db: str) -> None:
    record = _record(TAKEN, SEALED_A)
    save_seal_bundle(db, TAKEN, record, "a.pdf", shares={3: b"a3"})

    save_seal_bundle(db, TAKEN, record, "a.pdf", shares={3: b"a3"})

    assert get_key_share(db, TAKEN, 3) == b"a3"


def test_a_reseal_from_an_older_branch_is_refused(db: str) -> None:
    """Dropping stored history (an older record file) is refused as well."""
    later = _event("Unsealing", "2026-10-20T01:00:00Z", "Hong")
    save_seal_record(db, TAKEN, _record(TAKEN, SEALED_A, UNSEALED_A, RESEALED_A, later),
                     "u2.pdf")

    with pytest.raises(SealIdConflictError):
        save_seal_bundle(db, TAKEN, _record(TAKEN, SEALED_A, UNSEALED_A, RESEALED_A),
                         "r.pdf", shares={3: b"r3"})

    assert get_seal_record(db, TAKEN)["pdf_path"] == "u2.pdf"


def test_an_unreadable_stored_row_is_not_replaced(db: str) -> None:
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO seal_records (seal_id, record_json, pdf_path) "
                     "VALUES (?, ?, ?)", (TAKEN, "{broken", "old.pdf"))

    with pytest.raises(SealIdConflictError):
        save_seal_bundle(db, TAKEN, _record(TAKEN, SEALED_A), "a.pdf", shares={3: b"a3"})

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT record_json FROM seal_records WHERE seal_id = ?",
                            (TAKEN,)).fetchone()[0] == "{broken"


# ===================================================================
# Sealing without a registered case (S4)
# ===================================================================

def test_s4_picks_an_id_that_has_no_row(tmp_path: Path, monkeypatch, no_policy_env) -> None:
    db = str(tmp_path / "seal.db")  # the path _after_s1 uses
    init_db(db)
    _draws(monkeypatch, TAKEN)
    create_case(db, "2026-OTHER", "Park", "Lee")
    drawn = _draws(monkeypatch, TAKEN, FRESH)

    s4 = _after_s1(tmp_path).run_s4()

    assert s4["seal_id"] == FRESH and drawn == [TAKEN, FRESH]


def test_s4_without_a_database_file_creates_none(tmp_path: Path, monkeypatch,
                                                 no_policy_env) -> None:
    _draws(monkeypatch, FRESH)

    s4 = _after_s1(tmp_path).run_s4()

    assert s4["seal_id"] == FRESH
    assert not (tmp_path / "seal.db").exists()
