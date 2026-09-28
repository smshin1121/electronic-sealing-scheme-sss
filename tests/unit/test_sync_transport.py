"""Transport and acknowledgement rules of the desktop sync senders (E2d; Codex r2 N5, N6).

N5: the plain-HTTP refusal lived in the client's backends only; the
standalone portal sender (``push_seal_record``, ``push_seal_record_safe``
and the backfill command line) sent to any URL. Every sender now goes
through one transport function that refuses plain HTTP beyond loopback
before a connection is made, and never follows a redirect.

N6: a redirect (for example a POST sent on to a login page) or any HTTP 200
page used to mark an event as sent. An entry is now marked sent only on the
endpoint's documented acknowledgement: for the reference web, HTTP 200 with
JSON ``{"status": "ok"}``; for the portal, HTTP 200 with the contract's
JSON ``{"status", "message"}`` whose status is not an error. Anything else
leaves the entry pending with the reason.

Synthetic data only; servers run on loopback ports.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest

from desktop.sync import SyncClient, sync_after_completion
from desktop.sync import portal_client, transport
from desktop.sync.backends import PORTAL_URL_ENV, WEB_URL_ENV
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.sync_web import StubHttpServer

SEAL_ID = "S-20260928-E2D0A1"
SECRET = "2" * 32  # public-test-fixture


def _record(event_types: tuple[str, ...] = ("Sealing",)) -> str:
    """A contract-complete record (the six fields, birth date and phone)."""
    events = [{"id": i, "seal_type": t, "start_time": "2026-09-28T01:00:00Z",
               "end_time": "2026-09-28T01:00:00Z", "investigator": "Hong"}
              for i, t in enumerate(event_types, 1)]
    return json.dumps({
        "seal_id": SEAL_ID,
        "case_info": {"case_number": "2026-E2D", "suspect": "합성",
                      "investigator": "Hong"},
        "process_info": {"type": event_types[-1],
                         "start_time": "2026-09-28T01:00:00Z",
                         "end_time": "2026-09-28T01:00:00Z"},
        "file_info": {"original_files": [], "result_files": []},
        "signer_info": {"name": "합성", "birth_date": "1990-01-01",
                        "phone": "010-0000-0000", "email": "s@example.com"},
        "history": {"summary": "S1U0R0", "events": events},
    }, ensure_ascii=False)


@pytest.fixture()
def no_backends(monkeypatch) -> None:
    for name in (WEB_URL_ENV, PORTAL_URL_ENV, "SYNC_SHARED_SECRET"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def no_connection(monkeypatch) -> list[str]:
    """Fail the test if any sender tries to open a connection."""
    opened: list[str] = []

    def refuse(request: Any, timeout: float) -> Any:
        opened.append(request.full_url)
        raise AssertionError(f"a connection was opened to {request.full_url}")

    monkeypatch.setattr(transport, "_open", refuse)
    return opened


def _entries(db: str) -> list[tuple]:
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT backend, status, attempts, last_error "
                            "FROM sync_outbox ORDER BY id").fetchall()


# ===================================================================
# The transport policy
# ===================================================================

class TestUrlPolicy:
    @pytest.mark.parametrize("url", [
        "https://portal.example.org/api", "http://127.0.0.1:8080",
        "http://localhost:5000", "http://[::1]:9000", "http://127.0.0.2",
    ])
    def test_allowed(self, url: str) -> None:
        transport.require_safe_url(url)

    @pytest.mark.parametrize("url", [
        "http://example.org", "http://10.0.0.5:5000", "http://192.168.1.2",
        "ftp://127.0.0.1/", "file:///etc/passwd", "", "example.org",
        "http://user:pw@portal.example.org",  # public-test-fixture
    ])
    def test_refused(self, url: str) -> None:
        with pytest.raises(transport.TransportError) as info:
            transport.require_safe_url(url)
        assert "pw" not in str(info.value)


class TestStandalonePortalSender:
    """N5: every portal entry point goes through the transport policy."""

    def test_push_seal_record_refuses_plain_http(self, no_connection) -> None:
        with pytest.raises(portal_client.PortalSyncError) as info:
            portal_client.push_seal_record(
                _record(), base_url="http://portal.example.org", secret=SECRET)

        assert "HTTPS" in str(info.value)
        assert no_connection == []

    def test_push_seal_record_safe_refuses_plain_http(self, no_connection) -> None:
        sent = portal_client.push_seal_record_safe(
            _record(), base_url="http://portal.example.org", secret=SECRET)

        assert sent is False
        assert no_connection == []

    def test_the_command_line_refuses_plain_http(
        self, tmp_path, monkeypatch, no_connection
    ) -> None:
        record = tmp_path / "record.json"
        record.write_text(_record(), encoding="utf-8")
        monkeypatch.setenv("SYNC_SHARED_SECRET", SECRET)

        code = portal_client.main([str(record), "--url",
                                   "http://portal.example.org"])

        assert code == 1
        assert no_connection == []

    def test_a_redirect_is_not_followed(self) -> None:
        with StubHttpServer([(302, "", {"Location": "/login"})]) as stub:
            with pytest.raises(portal_client.PortalSyncError) as info:
                portal_client.push_seal_record(_record(), base_url=stub.url,
                                               secret=SECRET)

        assert "redirect" in str(info.value)
        assert (len(stub.requests), stub.gets) == (1, [])

    def test_a_redirect_to_plain_http_elsewhere_is_not_followed(self) -> None:
        answer = (307, "", {"Location": "http://portal.example.org/api/seal-records"})
        with StubHttpServer([answer]) as stub:
            with pytest.raises(portal_client.PortalSyncError) as info:
                portal_client.push_seal_record(_record(), base_url=stub.url,
                                               secret=SECRET)

        assert "redirect" in str(info.value)
        assert len(stub.requests) == 1


# ===================================================================
# Acknowledgements (N6)
# ===================================================================

class TestWebAcknowledgement:
    def _sync(self, tmp_path, monkeypatch, answers, signer) -> tuple[str, Any]:
        db = str(tmp_path / "desk.db")
        with StubHttpServer(answers) as stub:
            monkeypatch.setenv(WEB_URL_ENV, stub.url)
            sync_after_completion(db, event_type="Sealing", record_json=_record(),
                                  pdf_path=None, signer=signer)
        return db, stub

    def test_a_post_redirected_to_a_login_page_stays_pending(
        self, tmp_path, monkeypatch, no_backends, release_pki
    ) -> None:
        db, stub = self._sync(tmp_path, monkeypatch,
                              [(302, "", {"Location": "/login"})],
                              load_test_signer(release_pki))

        [(backend, status, attempts, error)] = _entries(db)
        assert (backend, status, attempts) == ("web", "pending", 1)
        assert "redirect" in error
        assert stub.gets == []

    @pytest.mark.parametrize("answer", [
        (200, "<html><body>Sign in</body></html>"),
        (200, {"status": "error", "message": "x"}),
        (200, {"message": "no status"}),
        (200, b"\x00\x01 not json"),
        (201, {"status": "ok", "message": "created?"}),
        (204, b""),
    ], ids=["html", "negative", "no-status", "not-json", "201", "204"])
    def test_anything_but_the_documented_acknowledgement_stays_pending(
        self, tmp_path, monkeypatch, no_backends, release_pki, answer
    ) -> None:
        db, _stub = self._sync(tmp_path, monkeypatch, [answer],
                               load_test_signer(release_pki))

        [(_backend, status, _attempts, error)] = _entries(db)
        assert status == "pending"
        assert error

    def test_a_refusal_keeps_the_status_and_the_server_message(
        self, tmp_path, monkeypatch, no_backends, release_pki
    ) -> None:
        db, _stub = self._sync(
            tmp_path, monkeypatch,
            [(409, {"status": "error", "message": "롤백 거부 (synthetic)"})],
            load_test_signer(release_pki))

        [(_backend, status, _attempts, error)] = _entries(db)
        assert status == "pending"
        assert error == "HTTP 409: 롤백 거부 (synthetic)"

    def test_the_documented_acknowledgement_marks_it_sent(
        self, tmp_path, monkeypatch, no_backends, release_pki
    ) -> None:
        db, _stub = self._sync(tmp_path, monkeypatch,
                               [(200, {"status": "ok", "message": "동기화 완료"})],
                               load_test_signer(release_pki))

        assert _entries(db) == [("web", "sent", 1, "")]


class TestPortalAcknowledgement:
    @pytest.mark.parametrize("answer", [
        (200, "<html><body>Sign in</body></html>"),
        (200, {"status": "error", "message": "rejected"}),
        (200, {"status": "success"}),
        (200, {"message": "no status"}),
        (202, {"status": "success", "message": "queued?"}),
    ], ids=["html", "negative", "no-message", "no-status", "202"])
    def test_anything_but_the_contract_response_is_refused(self, answer) -> None:
        with StubHttpServer([answer]) as stub:
            with pytest.raises(portal_client.PortalSyncError):
                portal_client.push_seal_record(_record(), base_url=stub.url,
                                               secret=SECRET)

    def test_the_contract_response_is_accepted(self) -> None:
        with StubHttpServer([(200, {"status": "success",
                                    "message": "stored"})]) as stub:
            answer = portal_client.push_seal_record(_record(), base_url=stub.url,
                                                    secret=SECRET)

        assert answer == {"status": "success", "message": "stored"}

    def test_a_redirected_portal_entry_stays_pending(
        self, tmp_path, monkeypatch, no_backends
    ) -> None:
        db = str(tmp_path / "desk.db")
        with StubHttpServer([(303, "", {"Location": "/login"})]) as stub:
            monkeypatch.setenv(PORTAL_URL_ENV, stub.url)
            monkeypatch.setenv("SYNC_SHARED_SECRET", SECRET)
            sync_after_completion(db, event_type="Sealing", record_json=_record(),
                                  pdf_path=None)

        [(backend, status, _attempts, error)] = _entries(db)
        assert (backend, status) == ("portal", "pending")
        assert "redirect" in error
        assert stub.gets == []


def test_the_client_backends_use_the_same_policy(
    tmp_path, monkeypatch, no_backends, no_connection, release_pki
) -> None:
    db = str(tmp_path / "desk.db")
    monkeypatch.setenv(WEB_URL_ENV, "http://sync.example.org")

    sync_after_completion(db, event_type="Sealing", record_json=_record(),
                          pdf_path=None, signer=load_test_signer(release_pki))

    [(_backend, status, _attempts, error)] = _entries(db)
    assert status == "pending" and "HTTPS" in error
    assert no_connection == []
    assert SyncClient(db, backends=[]).entries()[0].attempts == 1
