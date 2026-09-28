"""save_seal_bundle: the same-seal check and the write are one transaction (E2d; Codex r2, F9 residual).

Before: ``save_seal_bundle`` read the row for its seal_id before its write
transaction began, so two saves could both find no row and the later one
replaced the earlier seal. And the placeholder of any registered case was
treated as belonging to whatever bundle carried its seal_id.

Now the check runs after ``BEGIN IMMEDIATE`` in the transaction that writes,
and a registered case's placeholder is filled only by a bundle that claims
that registration (``registered_case_id``, which S7 sets from the case the
wizard was started from). Synthetic data only.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator

import pytest

import desktop.db.sqlite_store as store
import desktop.record.record_builder as record_builder
from desktop.crypto.local_kms import init_master_key
from desktop.db import create_case, get_key_share, get_seal_record, init_db
from desktop.db.sqlite_store import SealIdConflictError, save_seal_bundle
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.sync_processes import sealing_before_s7

TAKEN = "S-20260928-CCCCCC"
OTHER = "S-20260928-DDDDDD"


@pytest.fixture()
def db(tmp_path: Path) -> str:
    path = str(tmp_path / "seal.db")
    init_db(path)
    return path


def _draws(monkeypatch: pytest.MonkeyPatch, *ids: str) -> None:
    """Make ``create_seal_id`` return ``ids`` in turn (the last one repeats)."""
    queue: Iterator[str] = iter(ids)
    monkeypatch.setattr(record_builder, "create_seal_id",
                        lambda: next(queue, ids[-1]))


def _record(seal_id: str, investigator: str, case_number: str = "2026-A") -> str:
    event = {"id": 1, "seal_type": "Sealing", "start_time": "2026-09-28T01:00:00Z",
             "end_time": "2026-09-28T01:00:00Z", "investigator": investigator}
    return json.dumps({"seal_id": seal_id,
                       "case_info": {"case_number": case_number},
                       "history": {"summary": "S1U0R0", "events": [event]}},
                      ensure_ascii=False)


def _placeholder(db: str, seal_id: str) -> tuple:
    with sqlite3.connect(db) as conn:
        return conn.execute(
            "SELECT record_json, pdf_path, case_number, status FROM seal_records "
            "WHERE seal_id = ?", (seal_id,)).fetchone()


# ===================================================================
# Concurrent saves under one seal_id
# ===================================================================

def test_concurrent_saves_of_two_seals_keep_the_first(db: str, monkeypatch) -> None:
    """Both saves pause right after their check; only one may then write."""
    barrier = threading.Barrier(2, timeout=1.5)
    real = store._require_same_seal

    def paused(*args: Any, **kwargs: Any) -> Any:
        result = real(*args, **kwargs)
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass  # the other save is waiting for the write lock
        return result

    monkeypatch.setattr(store, "_require_same_seal", paused)
    outcomes: dict[str, str] = {}

    def save(name: str) -> None:
        try:
            save_seal_bundle(db, TAKEN, _record(TAKEN, name), f"{name}.pdf",
                             shares={3: name.encode()})
            outcomes[name] = "saved"
        except SealIdConflictError:
            outcomes[name] = "refused"
        except sqlite3.OperationalError:  # the write lock never came
            outcomes[name] = "locked"

    threads = [threading.Thread(target=save, args=(name,)) for name in ("Hong", "Park")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert sorted(outcomes.values()) == ["refused", "saved"]
    [winner] = [name for name, outcome in outcomes.items() if outcome == "saved"]
    row = get_seal_record(db, TAKEN)
    assert row["pdf_path"] == f"{winner}.pdf"
    assert row["record_json"]["history"]["events"][0]["investigator"] == winner
    assert get_key_share(db, TAKEN, 3) == winner.encode()


def test_the_check_runs_inside_the_write_transaction(db: str, monkeypatch) -> None:
    seen: list[bool] = []
    real = store._require_same_seal

    def observing(conn: sqlite3.Connection, *args: Any, **kwargs: Any) -> Any:
        seen.append(conn.in_transaction)
        return real(conn, *args, **kwargs)

    monkeypatch.setattr(store, "_require_same_seal", observing)

    save_seal_bundle(db, TAKEN, _record(TAKEN, "Hong"), "a.pdf", shares={3: b"a"})

    assert seen == [True]


# ===================================================================
# Placeholder ownership
# ===================================================================

def test_an_unclaimed_placeholder_is_not_filled(db: str, monkeypatch) -> None:
    _draws(monkeypatch, TAKEN)
    create_case(db, "2026-REGISTERED", "Park", "Lee")
    before = _placeholder(db, TAKEN)

    with pytest.raises(SealIdConflictError):
        save_seal_bundle(db, TAKEN, _record(TAKEN, "Hong"), "a.pdf",
                         shares={3: b"a"}, case_meta={"case_number": "2026-A"})

    assert _placeholder(db, TAKEN) == before
    assert get_key_share(db, TAKEN, 3) is None


def test_a_claim_for_another_case_does_not_fill_it(db: str, monkeypatch) -> None:
    _draws(monkeypatch, TAKEN)
    create_case(db, "2026-REGISTERED", "Park", "Lee")

    with pytest.raises(SealIdConflictError):
        save_seal_bundle(db, TAKEN, _record(TAKEN, "Hong"), "a.pdf",
                         shares={3: b"a"}, registered_case_id=OTHER)

    assert json.loads(_placeholder(db, TAKEN)[0]).get("history") is None


def test_the_registered_case_fills_its_placeholder(db: str, monkeypatch) -> None:
    _draws(monkeypatch, TAKEN)
    case_id = create_case(db, "2026-REGISTERED", "Park", "Lee")

    save_seal_bundle(db, case_id, _record(case_id, "Park", "2026-REGISTERED"),
                     "a.pdf", shares={3: b"a"}, registered_case_id=case_id,
                     case_meta={"case_number": "2026-REGISTERED",
                                "status": "S1U0R0"})

    assert get_seal_record(db, case_id)["pdf_path"] == "a.pdf"


def test_a_completed_row_is_never_taken_as_a_placeholder(db: str) -> None:
    save_seal_bundle(db, TAKEN, _record(TAKEN, "Hong"), "a.pdf", shares={3: b"a"})

    with pytest.raises(SealIdConflictError):
        save_seal_bundle(db, TAKEN, _record(TAKEN, "Park"), "b.pdf",
                         shares={3: b"b"}, registered_case_id=TAKEN)

    assert get_seal_record(db, TAKEN)["pdf_path"] == "a.pdf"


# ===================================================================
# Through the sealing process
# ===================================================================

@pytest.fixture()
def master_key(tmp_path, monkeypatch) -> None:
    path = str(tmp_path / "master.key")
    init_master_key(path)
    monkeypatch.setenv("MASTER_KEY_PATH", path)


def test_s7_refuses_a_case_registered_after_s4_drew_its_id(
    tmp_path, db, master_key, release_pki, monkeypatch
) -> None:
    """S4 drew an unused ID; a case registered with that ID before S7 keeps it."""
    _draws(monkeypatch, TAKEN)
    process = sealing_before_s7(tmp_path, load_test_signer(release_pki), db,
                                registered=False)
    assert process.state["s4"]["seal_id"] == TAKEN
    create_case(db, "2026-REGISTERED", "Park", "Lee")
    before = _placeholder(db, TAKEN)

    with pytest.raises(SealIdConflictError):
        process.run_s7()

    assert _placeholder(db, TAKEN) == before


def test_s7_fills_the_case_the_wizard_was_started_from(
    tmp_path, db, master_key, release_pki, monkeypatch
) -> None:
    _draws(monkeypatch, TAKEN)
    case_id = create_case(db, "2026-REGISTERED", "Park", "Lee")

    result = sealing_before_s7(tmp_path, load_test_signer(release_pki), db,
                               seal_id=case_id).run_s7()

    assert result.seal_id == case_id
    stored = get_seal_record(db, case_id)["record_json"]
    assert stored["history"]["events"][0]["seal_type"] == "Sealing"
