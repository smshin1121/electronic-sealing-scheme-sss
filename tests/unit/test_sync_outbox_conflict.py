"""A queued event is never silently replaced (stage E, E2e; Codex r3 M2).

Before: when the outbox already held a row for (seal, event, backend),
``SyncIntent.write`` only logged a warning if the queued record differed,
and the local save committed anyway. Unsealing twice from the original
sealing record produced event 2 twice: the second unsealing replaced the
local record while the outbox kept the first event 2, so the record now
saved had no pending delivery, and ``retry`` could not recover it.

Now:
- a duplicate is idempotent only when every immutable queued field agrees
  (event type, record JSON, PDF bytes, wrapped s3); anything else raises
  ``SyncConflictError`` and the local save rolls back;
- an unsealing from a record older than the one this desktop stored is
  refused: at U3 (early) and at U7 under the write lock, where the stored
  history must be the start of the new record's history, as for S7 and R8.
  The next unsealing continues from the latest record instead.

Synthetic data only; the backend is a loopback stub server.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.db import delete_case, get_seal_record, init_db, save_seal_record
from desktop.db.sqlite_store import SealIdConflictError, StaleRecordError
from desktop.sync import (
    SyncClient,
    SyncConflictError,
    SyncIntent,
    SyncItem,
    sync_after_completion,
)
from desktop.sync import outbox
from desktop.sync.backends import PORTAL_URL_ENV, WEB_URL_ENV
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.sync_processes import (
    E2E_SEAL_ID,
    seal_through_process,
    stub_record_render,
    unseal_from_file,
    unsealing_before_u7,
    unsealing_from_file,
    unsealing_u4_to_u6,
    write_record_file,
)
from tests.fixtures.sync_web import StubHttpServer

ACK = (200, {"status": "ok", "message": "동기화 완료"})
RECORD_A = json.dumps({"seal_id": E2E_SEAL_ID, "n": "a"})
RECORD_B = json.dumps({"seal_id": E2E_SEAL_ID, "n": "b"})


class _Crash(BaseException):
    """Stands for the process dying right after the local save returned."""


@pytest.fixture()
def env(tmp_path, monkeypatch) -> str:
    """A master key for S6, no configured backend, a desktop DB path."""
    master = str(tmp_path / "master.key")
    init_master_key(master)
    monkeypatch.setenv("MASTER_KEY_PATH", master)
    for name in (WEB_URL_ENV, PORTAL_URL_ENV, "SYNC_SHARED_SECRET"):
        monkeypatch.delenv(name, raising=False)
    return str(tmp_path / "desktop.db")


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


@pytest.fixture()
def stub_render(monkeypatch) -> None:
    """U6 renders a small synthetic PDF instead of the real template."""
    stub_record_render(monkeypatch)


def _outbox(db: str) -> list[tuple]:
    with sqlite3.connect(db) as conn:
        try:
            return conn.execute(
                "SELECT event_id, event_type, backend, status, attempts "
                "FROM sync_outbox ORDER BY id").fetchall()
        except sqlite3.OperationalError:  # no table: nothing was ever queued
            return []


def _queued_record(db: str, event_id: int) -> dict:
    with sqlite3.connect(db) as conn:
        [(record_json,)] = conn.execute(
            "SELECT record_json FROM sync_outbox WHERE event_id = ?",
            (event_id,)).fetchall()
    return json.loads(record_json)


def _posted_events(stub: StubHttpServer) -> list[int]:
    return [json.loads(raw)["event_id"] for _path, _headers, raw in stub.requests]


def _events(record: dict) -> list[tuple]:
    return [(e["id"], e["seal_type"], e["start_time"])
            for e in record["history"]["events"]]


# ===================================================================
# The rule: identical is idempotent, anything else is a conflict
# ===================================================================

def _item(**changes: Any) -> SyncItem:
    base = SyncItem(seal_id=E2E_SEAL_ID, event_id=2, event_type="Unsealing",
                    record_json=RECORD_A, record_pdf=b"%PDF-1.4 a",
                    wrapped_s3_b64=None)
    return replace(base, **changes)


def _write(db: str, item: SyncItem) -> None:
    outbox.ensure_outbox(db)
    with outbox.transaction(db) as conn:
        SyncIntent(item=item, backends=("web",)).write(conn)


def _queue(db: str, item: SyncItem, status: str) -> None:
    _write(db, item)
    if status == outbox.STATUS_SENT:
        [entry] = outbox.all_entries(db)
        outbox.record_success(db, entry.id, now="2026-09-28T01:00:00+00:00")


def _rows(db: str) -> list[tuple]:
    with sqlite3.connect(db) as conn:
        return conn.execute(
            "SELECT event_type, record_json, record_pdf, wrapped_s3, status, "
            "attempts FROM sync_outbox").fetchall()


class TestTheRule:
    @pytest.mark.parametrize("status", ["pending", "sent"])
    def test_an_identical_snapshot_is_idempotent(self, tmp_path, status) -> None:
        db = str(tmp_path / "desk.db")
        _queue(db, _item(), status)
        before = _rows(db)

        _write(db, _item())

        assert _rows(db) == before

    @pytest.mark.parametrize("status", ["pending", "sent"])
    @pytest.mark.parametrize("change", [
        {"record_json": RECORD_B},
        {"record_pdf": b"%PDF-1.4 b"},
        {"record_pdf": None},
        {"wrapped_s3_b64": "c3ludGhldGlj"},
        {"event_type": "Resealing"},
    ], ids=["record", "pdf", "no-pdf", "wrapped-s3", "event-type"])
    def test_a_different_snapshot_is_refused(self, tmp_path, status, change) -> None:
        db = str(tmp_path / "desk.db")
        _queue(db, _item(), status)
        before = _rows(db)

        with pytest.raises(SyncConflictError) as info:
            _write(db, _item(**change))

        assert _rows(db) == before
        message = str(info.value)
        assert E2E_SEAL_ID in message and "web" in message
        assert '"n"' not in message  # names the event, never the record

    def test_a_refusal_rolls_back_the_local_save(self, tmp_path) -> None:
        db = str(tmp_path / "desk.db")
        init_db(db)
        save_seal_record(db, E2E_SEAL_ID, RECORD_A, "a.pdf")
        _queue(db, _item(), "sent")

        with pytest.raises(SyncConflictError):
            save_seal_record(db, E2E_SEAL_ID, RECORD_B, "b.pdf",
                             extra_writes=SyncIntent(
                                 item=_item(record_json=RECORD_B),
                                 backends=("web",)).write)

        stored = get_seal_record(db, E2E_SEAL_ID)
        assert (stored["record_json"], stored["pdf_path"]) == (json.loads(RECORD_A), "a.pdf")

    def test_an_insert_that_left_no_row_is_an_error(self, tmp_path) -> None:
        """INSERT OR IGNORE also ignores a NOT NULL violation: not a duplicate."""
        db = str(tmp_path / "desk.db")

        with pytest.raises(sqlite3.Error):
            _write(db, _item(record_json=None))

        assert _rows(db) == []


# ===================================================================
# Through U7 (the lineage check passes; the outbox holds another event 2)
# ===================================================================

class TestThroughU7:
    @pytest.mark.parametrize("status", ["pending", "sent"])
    def test_a_conflicting_queued_event_refuses_the_unsealing(
        self, tmp_path, env, signer, monkeypatch, status
    ) -> None:
        sealed = seal_through_process(tmp_path, signer, env)  # nothing queued
        other = _item(record_json=RECORD_B)
        _queue(env, other, status)
        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            process = unsealing_before_u7(tmp_path, env, sealed.record_json)

            with pytest.raises(SyncConflictError):
                process.run_u7_save()

        stored = get_seal_record(env, E2E_SEAL_ID)["record_json"]
        assert stored == json.loads(sealed.record_json)
        assert _outbox(env) == [(2, "Unsealing", "web", status,
                                 1 if status == "sent" else 0)]
        assert _queued_record(env, 2) == json.loads(RECORD_B)
        assert stub.requests == []
        assert "u7" not in process.state

    def test_running_the_same_u7_again_is_idempotent(
        self, tmp_path, env, signer, monkeypatch
    ) -> None:
        sealed = seal_through_process(tmp_path, signer, env)
        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            process = unsealing_before_u7(tmp_path, env, sealed.record_json)
            process.run_u7_save()

            process.run_u7_save()

        assert _outbox(env) == [(2, "Unsealing", "web", "sent", 1)]
        assert _posted_events(stub) == [2]

    def test_a_crash_after_the_save_then_the_same_u7_again(
        self, tmp_path, env, signer, monkeypatch
    ) -> None:
        import desktop.db as db_pkg

        sealed = seal_through_process(tmp_path, signer, env)
        real = db_pkg.save_seal_record

        def crashing(*args: Any, **kwargs: Any) -> Any:
            real(*args, **kwargs)
            raise _Crash("save_seal_record")

        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            process = unsealing_before_u7(tmp_path, env, sealed.record_json)
            monkeypatch.setattr(db_pkg, "save_seal_record", crashing)
            with pytest.raises(_Crash):
                process.run_u7_save()
            monkeypatch.setattr(db_pkg, "save_seal_record", real)
            after_crash = _outbox(env)

            process.run_u7_save()

        assert after_crash == [(2, "Unsealing", "web", "pending", 0)]
        assert _outbox(env) == [(2, "Unsealing", "web", "sent", 1)]
        assert _posted_events(stub) == [2]


# ===================================================================
# Unsealing twice: real U3 and U6, record files on disk
# ===================================================================

_record_file = write_record_file
_unsealing = unsealing_from_file
_u4_to_u6 = unsealing_u4_to_u6
_unseal = unseal_from_file


@pytest.fixture()
def sealed_file(tmp_path, env, signer, monkeypatch, stub_render) -> Any:
    """Sealed with the web backend configured; the sealing record on disk."""
    stub = StubHttpServer([ACK]).__enter__()
    monkeypatch.setenv(WEB_URL_ENV, stub.url)
    sealed = seal_through_process(tmp_path, signer, env)
    path = _record_file(tmp_path, sealed.record_json, f"{E2E_SEAL_ID}_record.json")
    yield sealed, path, stub
    stub.__exit__(None, None, None)


class TestUnsealingTwice:
    def test_the_sealing_record_is_refused_at_u3_after_an_unsealing(
        self, tmp_path, env, sealed_file
    ) -> None:
        _sealed, sealing_file, stub = sealed_file
        first = _unseal(tmp_path, env, sealing_file, "out1")
        second = _unsealing(tmp_path, env, sealing_file, "out2")

        with pytest.raises(ValueError, match="최신 기록보다 이전"):
            second.run_u3_validate()

        stored = get_seal_record(env, E2E_SEAL_ID)["record_json"]
        assert _events(stored) == _events(first["record_dict"])
        assert [e[:2] for e in _events(stored)] == [(1, "Sealing"), (2, "Unsealing")]
        assert _outbox(env) == [(1, "Sealing", "web", "sent", 1),
                                (2, "Unsealing", "web", "sent", 1)]
        assert _posted_events(stub) == [1, 2]

    def test_two_unsealings_past_u3_together_save_only_the_first(
        self, tmp_path, env, sealed_file
    ) -> None:
        """Both loaded the sealing record before either saved (the U3-U7 race)."""
        _sealed, sealing_file, stub = sealed_file
        first = _unsealing(tmp_path, env, sealing_file, "out1")
        second = _unsealing(tmp_path, env, sealing_file, "out2")
        first.run_u3_validate()
        second.run_u3_validate()
        first_u6 = _u4_to_u6(first, tmp_path)
        first.run_u7_save()
        _u4_to_u6(second, tmp_path)

        with pytest.raises(StaleRecordError) as info:
            second.run_u7_save()

        assert isinstance(info.value, SealIdConflictError)
        assert "최신" in str(info.value)
        stored = get_seal_record(env, E2E_SEAL_ID)["record_json"]
        assert _events(stored) == _events(first_u6["record_dict"])
        assert _queued_record(env, 2) == first_u6["record_dict"]
        assert _posted_events(stub) == [1, 2]

    def test_the_next_unsealing_continues_from_the_latest_record(
        self, tmp_path, env, sealed_file
    ) -> None:
        _sealed, sealing_file, stub = sealed_file
        first = _unseal(tmp_path, env, sealing_file, "out1")

        second = _unseal(tmp_path, env, Path(first["record_json_path"]), "out2")

        stored = get_seal_record(env, E2E_SEAL_ID)["record_json"]
        assert [e[:2] for e in _events(stored)] == [
            (1, "Sealing"), (2, "Unsealing"), (3, "Unsealing")]
        assert _events(stored) == _events(second["record_dict"])
        assert _outbox(env) == [(1, "Sealing", "web", "sent", 1),
                                (2, "Unsealing", "web", "sent", 1),
                                (3, "Unsealing", "web", "sent", 1)]
        assert _posted_events(stub) == [1, 2, 3]

    def test_the_outbox_refuses_when_the_stored_record_is_gone(
        self, tmp_path, env, sealed_file
    ) -> None:
        """The case deleted in the case manager: only the outbox remembers event 2."""
        _sealed, sealing_file, stub = sealed_file
        first = _unseal(tmp_path, env, sealing_file, "out1")
        assert delete_case(env, E2E_SEAL_ID)
        second = _unsealing(tmp_path, env, sealing_file, "out2")
        second.run_u3_validate()  # nothing stored: the file is checked alone
        _u4_to_u6(second, tmp_path)

        with pytest.raises(SyncConflictError) as info:
            second.run_u7_save()

        assert "보냄" in str(info.value)
        assert get_seal_record(env, E2E_SEAL_ID) is None
        assert _queued_record(env, 2) == first["record_dict"]
        assert _posted_events(stub) == [1, 2]


# ===================================================================
# The lineage rule's messages (S7, U7 and R8 share it)
# ===================================================================

def _record(events: list[dict]) -> str:
    return json.dumps({"seal_id": E2E_SEAL_ID,
                       "history": {"summary": "", "events": events}})


_SEALING = {"id": 1, "seal_type": "Sealing", "start_time": "2026-09-28T01:00:00Z"}
_UNSEAL_1 = {"id": 2, "seal_type": "Unsealing", "start_time": "2026-09-28T02:00:00Z"}
_UNSEAL_2 = {"id": 2, "seal_type": "Unsealing", "start_time": "2026-09-28T03:00:00Z"}


def test_a_diverged_history_of_the_same_seal_is_a_stale_record(tmp_path) -> None:
    db = str(tmp_path / "desk.db")
    init_db(db)
    save_seal_record(db, E2E_SEAL_ID, _record([_SEALING, _UNSEAL_1]), "u1.pdf")

    with pytest.raises(StaleRecordError, match="최신"):
        save_seal_record(db, E2E_SEAL_ID, _record([_SEALING, _UNSEAL_2]),
                         "u2.pdf", require_lineage=True)

    assert get_seal_record(db, E2E_SEAL_ID)["pdf_path"] == "u1.pdf"


def test_another_seal_under_the_id_is_not_called_stale(tmp_path) -> None:
    db = str(tmp_path / "desk.db")
    init_db(db)
    save_seal_record(db, E2E_SEAL_ID, _record([_SEALING]), "a.pdf")
    other = {**_SEALING, "start_time": "2026-09-28T05:00:00Z"}

    with pytest.raises(SealIdConflictError) as info:
        save_seal_record(db, E2E_SEAL_ID, _record([other, _UNSEAL_1]),
                         "b.pdf", require_lineage=True)

    assert not isinstance(info.value, StaleRecordError)


def test_without_the_lineage_option_the_old_behaviour_stays(tmp_path) -> None:
    """Other callers of save_seal_record are unchanged."""
    db = str(tmp_path / "desk.db")
    init_db(db)
    save_seal_record(db, E2E_SEAL_ID, _record([_SEALING, _UNSEAL_1]), "u1.pdf")

    save_seal_record(db, E2E_SEAL_ID, _record([_SEALING, _UNSEAL_2]), "u2.pdf")

    assert get_seal_record(db, E2E_SEAL_ID)["pdf_path"] == "u2.pdf"


# ===================================================================
# One queueing path (stage E, E2f; Fable finding 6)
# ===================================================================

def _sealing_record(start: str) -> str:
    return json.dumps({"seal_id": E2E_SEAL_ID, "history": {"events": [
        {"id": 1, "seal_type": "Sealing", "start_time": start}]}})


class TestOneQueueingPath:
    def test_the_first_snapshot_wins_path_is_gone(self) -> None:
        """``SyncClient.submit`` and the own-transaction queueing kept the
        first snapshot with only a warning; nothing called them."""
        assert not hasattr(SyncClient, "submit")
        assert not hasattr(SyncClient, "_enqueue")
        assert not hasattr(outbox, "enqueue")
        assert not hasattr(outbox, "find_entry")

    def test_sync_after_completion_applies_the_conflict_rule(
        self, tmp_path, monkeypatch, caplog, signer
    ) -> None:
        """The one path left outside the processes keeps the queued snapshot.

        It runs after its caller's save, so it cannot undo that save; it
        refuses to queue the other snapshot and logs it (it never raises).
        """
        db = str(tmp_path / "desk.db")
        first = _sealing_record("2026-09-28T01:00:00Z")
        _queue(db, _item(event_id=1, event_type="Sealing", record_json=first,
                         record_pdf=None), "sent")
        before = _rows(db)
        monkeypatch.delenv(PORTAL_URL_ENV, raising=False)
        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            with caplog.at_level(logging.WARNING, logger="desktop.sync.client"):
                sync_after_completion(
                    db, event_type="Sealing",
                    record_json=_sealing_record("2026-09-28T02:00:00Z"),
                    pdf_path=None, signer=signer)

        assert _rows(db) == before
        assert stub.requests == []
        assert "SyncConflictError" in caplog.text
