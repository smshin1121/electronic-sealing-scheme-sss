"""Desktop sync client with an outbox (stage E, E2a).

One client, two backends: the reference web (``/sync/upload-record``,
every attempt signed with a fresh nonce and ``sent_at``) and the portal
(HMAC contract). A completed Sealing, Unsealing or Resealing is queued in
the desktop SQLite ``sync_outbox`` for every configured backend and pushed;
a failed push stays pending (WARNING) until ``python -m desktop.sync retry``
sends it. An unconfigured backend is skipped with one INFO line and
nothing is queued. The local process always completes.

Synthetic data only; the servers run on loopback ports.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.sync import SyncClient, SyncItemError, build_sync_item, sync_after_completion
from desktop.sync.backends import PORTAL_URL_ENV, WEB_URL_ENV
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.release_web import ensure_case, make_release_app
from tests.fixtures.sync_web import (
    StubHttpServer,
    live_server,
    require_signatures,
    unused_port,
)

SEAL_ID = "S-20260928-E2AC01"
SUBJECT = {"name": "합성피압수자", "birth_date": "1991-02-03",
           "phone": "010-2222-3333", "email": "subject@example.com"}
SRC_DIR = Path(__file__).resolve().parents[2] / "src"


def _record(event_types: tuple[str, ...] = ("Sealing",),
            seal_id: str = SEAL_ID) -> str:
    events = [{"id": i, "seal_type": t, "start_time": "t", "end_time": "t",
               "investigator": "Hong"} for i, t in enumerate(event_types, 1)]
    return json.dumps({
        "seal_id": seal_id, "seal_mode": "standard",
        "case_info": {"case_number": "2026-형제-E2A"},
        "process_info": {"type": event_types[-1]},
        "file_info": {"original_files": [], "result_files": []},
        "signer_info": dict(SUBJECT),
        "history": {"summary": "S1U0R0", "events": events},
    }, ensure_ascii=False)


@pytest.fixture()
def no_backends(monkeypatch) -> None:
    for name in (WEB_URL_ENV, PORTAL_URL_ENV, "SYNC_SHARED_SECRET"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


@pytest.fixture()
def policy_key_env(monkeypatch, release_pki) -> None:
    """The institutional key as the command line finds it (environment)."""
    from desktop.signature.seal_policy import (
        POLICY_CERT_PATH_ENV,
        POLICY_KEY_PASSWORD_ENV,
        POLICY_KEY_PATH_ENV,
    )
    from tests.fixtures.release_pki import POLICY_KEY_PASSWORD

    monkeypatch.setenv(POLICY_KEY_PATH_ENV, str(release_pki.policy_key_path))
    monkeypatch.setenv(POLICY_CERT_PATH_ENV, str(release_pki.policy_cert_path))
    monkeypatch.setenv(POLICY_KEY_PASSWORD_ENV, POLICY_KEY_PASSWORD)


@pytest.fixture()
def web_app(tmp_path, monkeypatch, release_pki):
    master = str(tmp_path / "release_master.key")
    init_master_key(master)
    app = make_release_app(tmp_path, monkeypatch,
                           ca_cert_path=str(release_pki.ca_cert_path),
                           master_key_path=master)
    require_signatures(app)
    ensure_case(app, SEAL_ID)
    return app


@pytest.fixture()
def pdf(tmp_path) -> str:
    path = tmp_path / "record.pdf"
    path.write_bytes(b"%PDF-1.4 synthetic record")
    return str(path)


# ===================================================================
# The item: event id and type from the record's own history
# ===================================================================

class TestSyncItem:
    def test_event_id_and_type_come_from_the_last_history_event(self, pdf) -> None:
        item = build_sync_item(event_type="Unsealing",
                               record_json=_record(("Sealing", "Unsealing")),
                               pdf_path=pdf)
        assert (item.seal_id, item.event_id, item.event_type) == (
            SEAL_ID, 2, "Unsealing")
        assert item.record_pdf == b"%PDF-1.4 synthetic record"

    def test_another_event_type_is_refused(self) -> None:
        with pytest.raises(SyncItemError):
            build_sync_item(event_type="Resealing", record_json=_record(),
                            pdf_path=None)

    @pytest.mark.parametrize("history", [
        None, {}, {"events": []}, {"events": [{"seal_type": "Sealing"}]},
        {"events": [{"id": "1", "seal_type": "Sealing"}]},
        {"events": [{"id": 0, "seal_type": "Sealing"}]},
    ])
    def test_a_record_without_a_usable_history_is_refused(self, history) -> None:
        record = json.dumps({"seal_id": SEAL_ID, "history": history})
        with pytest.raises(SyncItemError):
            build_sync_item(event_type="Sealing", record_json=record,
                            pdf_path=None)

    def test_the_item_repr_shows_no_record_or_share_material(self, pdf) -> None:
        item = build_sync_item(event_type="Sealing", record_json=_record(),
                               pdf_path=pdf, wrapped_s3_b64="QUJD" * 20)
        text = repr(item)
        assert SUBJECT["phone"] not in text and "QUJD" not in text


# ===================================================================
# Configuration: unconfigured backends are skipped, nothing queued
# ===================================================================

def test_unconfigured_backends_are_skipped_with_one_info_line_each(
    tmp_path, pdf, no_backends, caplog
) -> None:
    db = str(tmp_path / "desk.db")
    with caplog.at_level(logging.INFO, logger="desktop.sync"):
        sync_after_completion(db, event_type="Sealing", record_json=_record(),
                              pdf_path=pdf)

    skipped = [r for r in caplog.records if "not configured" in r.getMessage()]
    assert [r.levelno for r in skipped] == [logging.INFO, logging.INFO]
    assert SyncClient(db, backends=[]).entries() == []


# ===================================================================
# Reference web backend
# ===================================================================

class TestWebBackend:
    def test_a_completed_event_is_signed_sent_and_marked(
        self, tmp_path, pdf, web_app, signer, monkeypatch, no_backends
    ) -> None:
        db = str(tmp_path / "desk.db")
        with live_server(web_app) as (url, counter):
            monkeypatch.setenv(WEB_URL_ENV, url)
            sync_after_completion(db, event_type="Sealing",
                                  record_json=_record(), pdf_path=pdf,
                                  signer=signer)

        [entry] = SyncClient(db, backends=[]).entries()
        assert (entry.backend, entry.status, entry.attempts,
                entry.last_error) == ("web", "sent", 1, "")
        assert counter.calls.count("/sync/upload-record") == 1

    def test_server_down_stays_pending_and_retry_sends_exactly_once(
        self, tmp_path, pdf, web_app, signer, monkeypatch, no_backends, caplog
    ) -> None:
        db = str(tmp_path / "desk.db")
        monkeypatch.setenv(WEB_URL_ENV, f"http://127.0.0.1:{unused_port()}")
        with caplog.at_level(logging.WARNING):
            sync_after_completion(db, event_type="Sealing",
                                  record_json=_record(), pdf_path=pdf,
                                  signer=signer)
        [pending] = SyncClient(db, backends=[]).entries()
        warned = [r for r in caplog.records if r.levelno == logging.WARNING]

        with live_server(web_app) as (url, counter):
            monkeypatch.setenv(WEB_URL_ENV, url)
            first = SyncClient.from_env(db, signer=signer).push_pending()
            second = SyncClient.from_env(db, signer=signer).push_pending()

        assert (pending.status, pending.attempts) == ("pending", 1)
        assert pending.last_error
        assert warned and SEAL_ID in warned[0].getMessage()
        assert counter.calls.count("/sync/upload-record") == 1
        assert (first.sent, first.pending) == (1, 0)
        assert (second.sent, second.pending) == (0, 0)
        [sent] = SyncClient(db, backends=[]).entries()
        assert (sent.status, sent.attempts, sent.last_error) == ("sent", 2, "")

    def test_every_attempt_is_signed_anew(
        self, tmp_path, pdf, signer, monkeypatch, no_backends
    ) -> None:
        db = str(tmp_path / "desk.db")
        with StubHttpServer([(503, {"status": "error", "message": "busy"}),
                             (200, {"status": "ok", "message": "done"})]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            sync_after_completion(db, event_type="Sealing",
                                  record_json=_record(), pdf_path=pdf,
                                  signer=signer)
            SyncClient.from_env(db, signer=signer).push_pending()

        envelopes = [json.loads(raw)["sync_auth"]["envelope"]
                     for _path, _headers, raw in stub.requests]
        assert len(envelopes) == 2
        assert envelopes[0]["nonce"] != envelopes[1]["nonce"]
        assert all(e["event_id"] == 1 and e["seal_id"] == SEAL_ID
                   for e in envelopes)
        bodies = [json.loads(raw) for _p, _h, raw in stub.requests]
        assert bodies[0]["record_json"] == bodies[1]["record_json"]
        assert base64.b64decode(bodies[0]["record_pdf"]) == (
            b"%PDF-1.4 synthetic record")

    def test_events_of_a_seal_go_out_in_order(
        self, tmp_path, signer, monkeypatch, no_backends
    ) -> None:
        # Event 1 is refused; event 2 must wait (a later generation first
        # would make the server refuse event 1 as a rollback).
        db = str(tmp_path / "desk.db")
        with StubHttpServer([(500, {"status": "error", "message": "x"})]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            for types in (("Sealing",), ("Sealing", "Unsealing")):
                sync_after_completion(db, event_type=types[-1],
                                      record_json=_record(types), pdf_path=None,
                                      signer=signer)

        sent_events = [json.loads(raw)["event_id"]
                       for _p, _h, raw in stub.requests]
        assert sent_events == [1, 1]
        entries = SyncClient(db, backends=[]).entries()
        assert [(e.event_id, e.status, e.attempts) for e in entries] == [
            (1, "pending", 2), (2, "pending", 0)]

    def test_without_a_policy_key_the_submission_is_unsigned(
        self, tmp_path, pdf, monkeypatch, no_backends, caplog
    ) -> None:
        for name in ("ENC_ENVELOPE_POLICY_KEY_PATH",
                     "ENC_ENVELOPE_POLICY_CERT_PATH"):
            monkeypatch.delenv(name, raising=False)
        db = str(tmp_path / "desk.db")
        with StubHttpServer([(200, {"status": "ok", "message": "done"})]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            with caplog.at_level(logging.WARNING):
                sync_after_completion(db, event_type="Sealing",
                                      record_json=_record(), pdf_path=pdf)

        [(_path, _headers, raw)] = stub.requests
        assert "sync_auth" not in json.loads(raw)
        assert any("unsigned" in r.getMessage() for r in caplog.records)


# ===================================================================
# Logging: never record contents, identity values or share material
# ===================================================================

def test_logs_carry_no_record_identity_or_share_material(
    tmp_path, pdf, signer, monkeypatch, no_backends, caplog
) -> None:
    db = str(tmp_path / "desk.db")
    wrapped = base64.b64encode(os.urandom(64)).decode("ascii")
    with StubHttpServer([(409, {"status": "error", "message": "conflict"}),
                         (200, {"status": "ok", "message": "done"})]) as stub:
        monkeypatch.setenv(WEB_URL_ENV, stub.url)
        with caplog.at_level(logging.DEBUG):
            sync_after_completion(db, event_type="Sealing",
                                  record_json=_record(), pdf_path=pdf,
                                  wrapped_s3_b64=wrapped, signer=signer)
            SyncClient.from_env(db, signer=signer).push_pending()

    text = "\n".join(r.getMessage() for r in caplog.records)
    for value in (*SUBJECT.values(), wrapped, "2026-형제-E2A",
                  "synthetic record"):
        assert value not in text
    assert "conflict" in text


# ===================================================================
# Command line: python -m desktop.sync status|retry
# ===================================================================

class TestCommandLine:
    def test_status_and_retry(
        self, tmp_path, pdf, web_app, signer, monkeypatch, no_backends,
        policy_key_env, capsys
    ) -> None:
        from desktop.sync.__main__ import main

        db = str(tmp_path / "desk.db")
        monkeypatch.setenv(WEB_URL_ENV, f"http://127.0.0.1:{unused_port()}")
        sync_after_completion(db, event_type="Sealing", record_json=_record(),
                              pdf_path=pdf, signer=signer)

        assert main(["--db", db, "status"]) == 0
        status_out = capsys.readouterr().out
        with live_server(web_app) as (url, counter):
            monkeypatch.setenv(WEB_URL_ENV, url)
            retried = main(["--db", db, "retry"])
            again = main(["--db", db, "retry"])
        retry_out = capsys.readouterr().out

        assert SEAL_ID in status_out and "pending" in status_out
        assert SUBJECT["phone"] not in status_out
        assert (retried, again) == (0, 0)
        assert counter.calls.count("/sync/upload-record") == 1
        assert "sent" in retry_out

    def test_retry_reports_what_stays_pending(
        self, tmp_path, pdf, signer, monkeypatch, no_backends, policy_key_env
    ) -> None:
        from desktop.sync.__main__ import main

        db = str(tmp_path / "desk.db")
        monkeypatch.setenv(WEB_URL_ENV, f"http://127.0.0.1:{unused_port()}")
        sync_after_completion(db, event_type="Sealing", record_json=_record(),
                              pdf_path=pdf, signer=signer)

        assert main(["--db", db, "retry"]) == 1

    def test_a_missing_database_is_reported(self, tmp_path) -> None:
        from desktop.sync.__main__ import main

        assert main(["--db", str(tmp_path / "absent.db"), "status"]) == 1
        assert not (tmp_path / "absent.db").exists()

    def test_runs_as_a_module(self, tmp_path, no_backends) -> None:
        db = tmp_path / "desk.db"
        SyncClient(str(db), backends=[]).entries()
        env = {k: v for k, v in os.environ.items()
               if k not in (WEB_URL_ENV, PORTAL_URL_ENV)}
        env["PYTHONPATH"] = str(SRC_DIR)
        env["PYTHONIOENCODING"] = "utf-8"
        done = subprocess.run(
            [sys.executable, "-m", "desktop.sync", "--db", str(db), "status"],
            capture_output=True, encoding="utf-8", env=env, timeout=60,
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout.splitlines()[0].split() == [
            "id", "seal_id", "event", "type", "backend", "status", "attempts",
            "last_attempt", "last_error"]


# ===================================================================
# The hook in the three processes: local work always completes
# ===================================================================

def _unseal_process(tmp_path: Path):
    from desktop.db import init_db
    from desktop.unseal_process import UnsealConfig, UnsealProcess

    db = str(tmp_path / "unseal.db")
    init_db(db)
    process = UnsealProcess(db_path=db)
    process.set_config(UnsealConfig(
        enc_filepath="e.enc", seal_record_path="r.json", aes_key_hex="0" * 64,
        output_dir=str(tmp_path), reason="analysis", investigator="Hong",
        subject_participated=True))
    record = json.loads(_record(("Sealing", "Unsealing")))
    pdf = tmp_path / "u.pdf"
    pdf.write_bytes(b"%PDF-1.4 synthetic unseal record")
    process.state.update({
        "u3": {"seal_record": record, "seal_id": SEAL_ID, "valid": True},
        "u4": {"items": [], "all_matched": True, "seal_id": SEAL_ID},
        "u5": {"output_filepath": "out.bin", "hash_verified": True,
               "sha256_match": True, "md5_match": True, "metadata": {}},
        "u6": {"record_dict": record, "record_json_path": "u.json",
               "pdf_path": str(pdf)},
    })
    return process


def _queued(db: str) -> list[tuple]:
    return [(e.event_id, e.event_type, e.backend, e.status, e.attempts)
            for e in SyncClient(db, backends=[]).entries()]


class TestProcessHooks:
    """The processes queue their saved record and push it (real outbox)."""

    def test_unsealing_queues_and_pushes_the_unsealing_record(
        self, tmp_path, monkeypatch, no_backends
    ) -> None:
        with StubHttpServer([(200, {"status": "ok", "message": "ok"})]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            process = _unseal_process(tmp_path)
            result = process.run_u7_save()

        [(_path, _headers, raw)] = stub.requests
        body = json.loads(raw)
        assert (body["event_id"], body["event_type"]) == (2, "Unsealing")
        assert body["record_json"] == result.record_json
        assert _queued(process._db_path) == [(2, "Unsealing", "web", "sent", 1)]

    def test_unsealing_completes_and_keeps_the_record_queued_when_the_push_fails(
        self, tmp_path, monkeypatch, caplog, no_backends
    ) -> None:
        from tests.fixtures.sync_web import unused_port

        monkeypatch.setenv(WEB_URL_ENV, f"http://127.0.0.1:{unused_port()}")

        with caplog.at_level(logging.WARNING):
            process = _unseal_process(tmp_path)
            result = process.run_u7_save()

        assert result.seal_id == SEAL_ID
        assert _queued(process._db_path) == [(2, "Unsealing", "web", "pending", 1)]
        assert any("record kept in the outbox" in r.getMessage()
                   for r in caplog.records)

    def test_sealing_and_resealing_queue_their_records(
        self, tmp_path, monkeypatch, release_pki, no_backends
    ) -> None:
        from tests.fixtures.sync_processes import (
            reseal_through_process,
            seal_through_process,
        )

        master = str(tmp_path / "master.key")
        init_master_key(master)
        monkeypatch.setenv("MASTER_KEY_PATH", master)
        signer = load_test_signer(release_pki)
        db = str(tmp_path / "desk.db")
        with StubHttpServer([(200, {"status": "ok", "message": "ok"})]) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            sealed = seal_through_process(tmp_path, signer, db)
            resealed = reseal_through_process(tmp_path, signer, db,
                                              json.loads(sealed.record_json),
                                              monkeypatch)

        bodies = [json.loads(raw) for _p, _h, raw in stub.requests]
        assert [(b["event_id"], b["event_type"]) for b in bodies] == [
            (1, "Sealing"), (2, "Resealing")]
        assert [b["record_json"] for b in bodies] == [
            sealed.record_json, resealed.record_json]
        assert [b["wrapped_s3"] for b in bodies] == [
            sealed.wrapped_s3_b64, resealed.wrapped_s3_b64]
        assert [base64.b64decode(b["record_pdf"]) for b in bodies] == [
            Path(sealed.pdf_path).read_bytes(),
            Path(resealed.pdf_path).read_bytes()]
        # Signed with the key the processes signed their policies with.
        assert all(b["sync_auth"]["cert"] == signer.cert_pem for b in bodies)
        assert _queued(db) == [(1, "Sealing", "web", "sent", 1),
                               (2, "Resealing", "web", "sent", 1)]

    def test_sealing_completes_and_keeps_the_record_queued_when_the_push_fails(
        self, tmp_path, monkeypatch, release_pki, caplog, no_backends
    ) -> None:
        from tests.fixtures.sync_processes import seal_through_process
        from tests.fixtures.sync_web import unused_port

        master = str(tmp_path / "master.key")
        init_master_key(master)
        monkeypatch.setenv("MASTER_KEY_PATH", master)
        monkeypatch.setenv(WEB_URL_ENV, f"http://127.0.0.1:{unused_port()}")
        db = str(tmp_path / "d.db")

        with caplog.at_level(logging.WARNING):
            result = seal_through_process(tmp_path, load_test_signer(release_pki),
                                          db)

        assert result.seal_id
        assert _queued(db) == [(1, "Sealing", "web", "pending", 1)]
        assert any("record kept in the outbox" in r.getMessage()
                   for r in caplog.records)


# ===================================================================
# Review round: plain HTTP refused; an empty PDF is sent as none
# ===================================================================

@pytest.mark.parametrize("url_env", [WEB_URL_ENV, PORTAL_URL_ENV])
def test_plain_http_beyond_loopback_is_refused(
    tmp_path, pdf, signer, monkeypatch, no_backends, url_env
) -> None:
    db = str(tmp_path / "desk.db")
    monkeypatch.setenv(url_env, "http://example.invalid:9")
    monkeypatch.setenv("SYNC_SHARED_SECRET", "0" * 32)  # public-test-fixture

    sync_after_completion(db, event_type="Sealing", record_json=_record(),
                          pdf_path=pdf, signer=signer)

    [entry] = SyncClient(db, backends=[]).entries()
    assert (entry.status, entry.attempts) == ("pending", 1)
    assert "HTTPS" in entry.last_error and "network" not in entry.last_error


def test_an_empty_pdf_is_sent_as_no_pdf(
    tmp_path, web_app, signer, monkeypatch, no_backends, caplog
) -> None:
    empty = tmp_path / "empty.pdf"
    empty.write_bytes(b"")
    db = str(tmp_path / "desk.db")

    item = build_sync_item(event_type="Sealing", record_json=_record(),
                           pdf_path=str(empty))
    with live_server(web_app) as (url, _counter):
        monkeypatch.setenv(WEB_URL_ENV, url)
        with caplog.at_level(logging.WARNING):
            sync_after_completion(db, event_type="Sealing",
                                  record_json=_record(),
                                  pdf_path=str(empty), signer=signer)

    assert item.record_pdf is None
    [entry] = SyncClient(db, backends=[]).entries()
    assert (entry.status, entry.last_error) == ("sent", "")
    assert any("empty" in r.getMessage() for r in caplog.records)
