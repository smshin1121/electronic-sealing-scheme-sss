"""The delivery intent is durable with the local save (stage E, E2d; Codex r2 N4).

Before: S7, U7 and R8 committed the local record, and only then did the
sync hook queue it in the outbox, in separate transactions. A crash, or a
failed outbox insert, in between left a completed local event that nothing
would ever deliver.

Now the outbox rows of every backend configured at completion time are
written in the same transaction as the local save; the network push comes
after the commit. A crash right after the save leaves a pending row that
``retry`` delivers once; a failed outbox insert rolls the local save back,
so the step fails visibly and can be run again.

Synthetic data only; the backend is a loopback stub server.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.db import get_seal_record
from desktop.sync import SyncClient
from desktop.sync.backends import PORTAL_URL_ENV, WEB_URL_ENV
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.sync_processes import (
    E2E_SEAL_ID,
    reseal_through_process,
    resealing_before_r8,
    seal_through_process,
    sealing_before_s7,
    unseal_through_process,
    unsealing_before_u7,
)
from tests.fixtures.sync_web import StubHttpServer

ACK = (200, {"status": "ok", "message": "동기화 완료"})


class _Crash(BaseException):
    """Stands for the process dying right after the local save returned."""


@pytest.fixture()
def env(tmp_path, monkeypatch) -> str:
    """A master key for S6/R7, no configured backend, a desktop DB path."""
    master = str(tmp_path / "master.key")
    init_master_key(master)
    monkeypatch.setenv("MASTER_KEY_PATH", master)
    for name in (WEB_URL_ENV, PORTAL_URL_ENV, "SYNC_SHARED_SECRET"):
        monkeypatch.delenv(name, raising=False)
    return str(tmp_path / "desktop.db")


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _crash_after(monkeypatch, name: str) -> Any:
    """Make ``desktop.db.<name>`` crash the process once it has returned.

    Returns a function that restores the real one (``monkeypatch.undo``
    would also undo the conftest's isolation of the operator's home).
    """
    import desktop.db as db_pkg

    real = getattr(db_pkg, name)

    def crashing(*args: Any, **kwargs: Any) -> Any:
        real(*args, **kwargs)
        raise _Crash(name)

    monkeypatch.setattr(db_pkg, name, crashing)
    return lambda: monkeypatch.setattr(db_pkg, name, real)


def _outbox(db: str) -> list[tuple]:
    with sqlite3.connect(db) as conn:
        try:
            return conn.execute(
                "SELECT event_id, event_type, backend, status, attempts "
                "FROM sync_outbox ORDER BY id").fetchall()
        except sqlite3.OperationalError:  # no table: nothing was ever queued
            return []


def _posted_events(stub: StubHttpServer) -> list[int]:
    return [json.loads(raw)["event_id"] for _path, _headers, raw in stub.requests]


def _last_event_type(db: str) -> str:
    stored = get_seal_record(db, E2E_SEAL_ID)["record_json"]
    return stored["history"]["events"][-1]["seal_type"]


def _shares(db: str) -> list[tuple]:
    with sqlite3.connect(db) as conn:
        return conn.execute(
            "SELECT share_index, share_data FROM key_shares WHERE seal_id = ? "
            "ORDER BY share_index", (E2E_SEAL_ID,)).fetchall()


def _failing_enqueue(monkeypatch) -> Any:
    """Make every outbox insert fail; returns a function that restores it."""
    import desktop.sync.outbox as outbox

    real = outbox.enqueue_on

    def failing(*_args: Any, **_kwargs: Any) -> bool:
        raise sqlite3.OperationalError("disk I/O error (synthetic)")

    monkeypatch.setattr(outbox, "enqueue_on", failing)
    return lambda: monkeypatch.setattr(outbox, "enqueue_on", real)


class TestCrashRightAfterTheLocalSave:
    def test_sealing(self, tmp_path, env, signer, monkeypatch) -> None:
        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            restore = _crash_after(monkeypatch, "save_seal_bundle")
            with pytest.raises(_Crash):
                seal_through_process(tmp_path, signer, env)
            restore()
            queued = _outbox(env)
            posted_before_restart = list(stub.requests)

            first = SyncClient.from_env(env, signer=signer).push_pending()
            second = SyncClient.from_env(env, signer=signer).push_pending()

        assert get_seal_record(env, E2E_SEAL_ID) is not None
        assert queued == [(1, "Sealing", "web", "pending", 0)]
        assert posted_before_restart == []
        assert (first.sent, second.sent) == (1, 0)
        assert _posted_events(stub) == [1]
        assert _outbox(env) == [(1, "Sealing", "web", "sent", 1)]

    def test_unsealing(self, tmp_path, env, signer, monkeypatch) -> None:
        sealed = seal_through_process(tmp_path, signer, env)
        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            restore = _crash_after(monkeypatch, "save_seal_record")
            with pytest.raises(_Crash):
                unseal_through_process(tmp_path, env, sealed.record_json)
            restore()
            queued = _outbox(env)

            SyncClient.from_env(env, signer=signer).push_pending()

        stored = get_seal_record(env, E2E_SEAL_ID)["record_json"]
        assert stored["history"]["events"][-1]["seal_type"] == "Unsealing"
        assert queued == [(2, "Unsealing", "web", "pending", 0)]
        assert _posted_events(stub) == [2]

    def test_resealing(self, tmp_path, env, signer, monkeypatch) -> None:
        sealed = seal_through_process(tmp_path, signer, env)
        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            restore = _crash_after(monkeypatch, "save_seal_bundle")
            with pytest.raises(_Crash):
                reseal_through_process(tmp_path, signer, env,
                                       json.loads(sealed.record_json),
                                       monkeypatch)
            restore()
            queued = _outbox(env)

            SyncClient.from_env(env, signer=signer).push_pending()

        assert queued == [(2, "Resealing", "web", "pending", 0)]
        assert _posted_events(stub) == [2]


class TestFailedOutboxInsert:
    """A failed outbox write leaves nothing: the step fails and is run again.

    Unlike a crash after the save (above), which leaves a pending row for
    ``retry``, there is nothing to retry here: the local save was rolled
    back with the outbox row, and the operator runs the step again.
    """

    def test_the_local_save_rolls_back_and_the_step_can_run_again(
        self, tmp_path, env, signer, monkeypatch
    ) -> None:
        import desktop.sync.outbox as outbox

        real = outbox.enqueue_on

        def failing(*_args: Any, **_kwargs: Any) -> bool:
            raise sqlite3.OperationalError("disk I/O error (synthetic)")

        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            process = sealing_before_s7(tmp_path, signer, env)
            monkeypatch.setattr(outbox, "enqueue_on", failing)
            with pytest.raises(sqlite3.OperationalError):
                process.run_s7()
            after_failure = (get_seal_record(env, E2E_SEAL_ID), _outbox(env))
            monkeypatch.setattr(outbox, "enqueue_on", real)

            result = process.run_s7()

        assert after_failure == (None, [])
        assert result.seal_id == E2E_SEAL_ID
        assert get_seal_record(env, E2E_SEAL_ID) is not None
        assert _outbox(env) == [(1, "Sealing", "web", "sent", 1)]
        assert _posted_events(stub) == [1]

    def test_unsealing_rolls_back_and_can_run_again(
        self, tmp_path, env, signer, monkeypatch
    ) -> None:
        sealed = seal_through_process(tmp_path, signer, env)  # nothing queued
        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            process = unsealing_before_u7(tmp_path, env, sealed.record_json)
            restore = _failing_enqueue(monkeypatch)
            with pytest.raises(sqlite3.OperationalError):
                process.run_u7_save()
            after_failure = (_last_event_type(env), _outbox(env))
            restore()

            process.run_u7_save()

        assert after_failure == ("Sealing", [])
        assert _last_event_type(env) == "Unsealing"
        assert _outbox(env) == [(2, "Unsealing", "web", "sent", 1)]
        assert _posted_events(stub) == [2]

    def test_resealing_rolls_back_and_can_run_again(
        self, tmp_path, env, signer, monkeypatch
    ) -> None:
        sealed = seal_through_process(tmp_path, signer, env)  # nothing queued
        sealing_shares = _shares(env)
        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            process = resealing_before_r8(tmp_path, signer, env,
                                          json.loads(sealed.record_json),
                                          monkeypatch)
            restore = _failing_enqueue(monkeypatch)
            with pytest.raises(sqlite3.OperationalError):
                process.run_r8_save()
            after_failure = (_last_event_type(env), _shares(env), _outbox(env))
            restore()

            process.run_r8_save()

        assert after_failure == ("Sealing", sealing_shares, [])
        assert _last_event_type(env) == "Resealing"
        assert _shares(env) != sealing_shares
        assert _outbox(env) == [(2, "Resealing", "web", "sent", 1)]
        assert _posted_events(stub) == [2]

    def test_an_outbox_that_cannot_be_created_fails_the_step_before_the_save(
        self, tmp_path, env, signer, monkeypatch
    ) -> None:
        """A behaviour change (E2d): with a backend configured, S7 does not
        save a seal whose delivery intent cannot be written."""
        import desktop.sync.outbox as outbox

        real = outbox.ensure_outbox

        def locked(_db_path: str) -> None:
            raise sqlite3.OperationalError("database is locked (synthetic)")

        with StubHttpServer([ACK]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            process = sealing_before_s7(tmp_path, signer, env)
            monkeypatch.setattr(outbox, "ensure_outbox", locked)
            with pytest.raises(sqlite3.OperationalError):
                process.run_s7()
            after_failure = (get_seal_record(env, E2E_SEAL_ID), _outbox(env))
            monkeypatch.setattr(outbox, "ensure_outbox", real)

            process.run_s7()

        assert after_failure == (None, [])
        assert _outbox(env) == [(1, "Sealing", "web", "sent", 1)]
        assert _posted_events(stub) == [1]


class TestWhatIsQueued:
    def test_one_row_per_backend_configured_at_completion(
        self, tmp_path, env, signer, monkeypatch
    ) -> None:
        with StubHttpServer([ACK]) as web, StubHttpServer(
            [(200, {"status": "success", "message": "stored"})]
        ) as portal:
            monkeypatch.setenv(WEB_URL_ENV, web.url)
            monkeypatch.setenv(PORTAL_URL_ENV, portal.url)
            monkeypatch.setenv("SYNC_SHARED_SECRET", "1" * 32)  # public-test-fixture
            seal_through_process(tmp_path, signer, env)

        assert sorted(_outbox(env)) == [(1, "Sealing", "portal", "sent", 1),
                                        (1, "Sealing", "web", "sent", 1)]
        assert (len(web.requests), len(portal.requests)) == (1, 1)

    def test_nothing_is_queued_without_a_configured_backend(
        self, tmp_path, env, signer
    ) -> None:
        seal_through_process(tmp_path, signer, env)

        assert _outbox(env) == []
        assert get_seal_record(env, E2E_SEAL_ID) is not None

    def test_the_queued_snapshot_is_the_saved_record(
        self, tmp_path, env, signer, monkeypatch
    ) -> None:
        with StubHttpServer([(503, {"status": "error", "message": "busy"})]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            result = seal_through_process(tmp_path, signer, env)

        [entry] = SyncClient(env, backends=[]).entries()
        assert entry.status == "pending" and entry.attempts == 1
        assert entry.record_json == result.record_json
        assert entry.record_pdf == Path(result.pdf_path).read_bytes()
        assert entry.wrapped_s3_b64 == result.wrapped_s3_b64
