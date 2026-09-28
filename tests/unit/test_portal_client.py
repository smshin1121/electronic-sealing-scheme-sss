"""Portal seal-record push client (HMAC scheme of the portal sync contract).

Ported from the client and tests of origin/main commit 1570671 (stage E,
E2a). The module and environment names are neutral so the public export
scan stays clean; the logic is the one of that commit. The last class
checks the headers and the body against a local HTTP server on port 0.
No network beyond loopback; secrets are generated at run time.

Two ported tests were adapted in E2d: the client now sends through
``desktop.sync.transport`` (its ``_open`` seam replaces
``urllib.request.urlopen``), and it sends only a record that meets the
contract's required fields.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.error

import pytest

from desktop.sync import portal_client as client
from desktop.sync import transport
from tests.fixtures.sync_web import StubHttpServer


def _secret() -> str:
    return secrets.token_hex(16)


def _contract_record() -> str:
    return json.dumps({
        "seal_id": "S-20260928-E2A0F1",
        "case_info": {"case_number": "2026-형제-E2A", "suspect": "합성",
                      "investigator": "Hong"},
        "process_info": {"type": "Resealing", "start_time": "t",
                         "end_time": "t"},
        "file_info": {"original_files": [], "result_files": []},
        "signer_info": {"name": "합성", "birth_date": "1990-01-01",
                        "phone": "010-0000-0000", "email": "s@example.com"},
        "history": {"summary": "S1U1R1", "events": [
            {"id": 1, "seal_type": "Sealing"},
            {"id": 2, "seal_type": "Unsealing"},
            {"id": 3, "seal_type": "Resealing"},
        ]},
        "unlock_time_iso": "2026-10-10T00:00:00Z",
    }, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Canonical signature
# ---------------------------------------------------------------------------


def test_canonical_signature_matches_contract():
    secret = _secret()
    ts = "1767600000"
    nonce = "n-abc123"
    raw = b'{"seal_id":"S-20260711-ABCDEF"}'

    expected = hmac.new(
        secret.encode(),
        ts.encode() + b"\n" + nonce.encode() + b"\n" + raw,
        hashlib.sha256,
    ).hexdigest()

    assert client._canonical_signature(secret, ts, nonce, raw) == expected


# ---------------------------------------------------------------------------
# Payload preparation
# ---------------------------------------------------------------------------


def test_prepare_payload_maps_unlock_time_iso_into_process_info():
    record = json.dumps({
        "seal_id": "S-20260711-ABCDEF",
        "process_info": {"seal_type": "Sealing"},
        "unlock_time_iso": "2026-08-01T00:00:00Z",
    })
    payload = json.loads(client._prepare_payload(record))
    assert payload["process_info"]["unlock_time"] == "2026-08-01T00:00:00Z"


def test_prepare_payload_keeps_existing_unlock_time():
    record = json.dumps({
        "process_info": {"unlock_time": "2026-09-01T00:00:00Z"},
        "unlock_time_iso": "2026-08-01T00:00:00Z",
    })
    payload = json.loads(client._prepare_payload(record))
    assert payload["process_info"]["unlock_time"] == "2026-09-01T00:00:00Z"


def test_prepare_payload_attaches_pdf_base64(tmp_path):
    pdf = tmp_path / "record.pdf"
    pdf.write_bytes(b"%PDF-1.4 dummy")
    payload = json.loads(client._prepare_payload("{}", str(pdf)))
    assert base64.b64decode(payload["record_pdf"]) == b"%PDF-1.4 dummy"


def test_prepare_payload_rejects_non_pdf(tmp_path):
    bogus = tmp_path / "record.pdf"
    bogus.write_bytes(b"not a pdf")
    with pytest.raises(client.PortalSyncError):
        client._prepare_payload("{}", str(bogus))


def test_prepare_payload_names_each_event_for_idempotence():
    # The contract keys idempotence on history.events[-1].event_id; the
    # desktop history numbers events with an integer "id".
    record = json.dumps({"history": {"events": [
        {"id": 1, "seal_type": "Sealing"},
        {"id": 2, "seal_type": "Unsealing", "event_id": "KEEP-2"},
    ]}})
    events = json.loads(client._prepare_payload(record))["history"]["events"]
    assert [e["event_id"] for e in events] == ["EVT-0001", "KEEP-2"]


def test_prepare_payload_does_not_change_its_input():
    original = {"process_info": {}, "unlock_time_iso": "2026-08-01T00:00:00Z",
                "history": {"events": [{"id": 1}]}}
    text = json.dumps(original)
    client._prepare_payload(text)
    assert json.loads(text) == original


# ---------------------------------------------------------------------------
# push_seal_record / push_seal_record_safe
# ---------------------------------------------------------------------------


def test_push_raises_when_env_missing(monkeypatch):
    monkeypatch.delenv(client.ENV_BASE_URL, raising=False)
    monkeypatch.delenv(client.ENV_SECRET, raising=False)
    with pytest.raises(client.PortalSyncError):
        client.push_seal_record("{}")


def test_push_safe_skips_when_env_missing(monkeypatch):
    monkeypatch.delenv(client.ENV_BASE_URL, raising=False)
    monkeypatch.delenv(client.ENV_SECRET, raising=False)
    assert client.push_seal_record_safe("{}") is False


def test_push_sends_signed_request(monkeypatch):
    captured = {}
    secret = _secret()

    class _FakeResponse:
        status = 200

        def read(self, limit=None):
            return b'{"status": "success", "message": "ok"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_open(request, timeout=None):
        captured["request"] = request
        return _FakeResponse()

    monkeypatch.setattr(transport, "_open", fake_open)

    body = client.push_seal_record(
        _contract_record(),
        base_url="https://example.org:1643/",
        secret=secret,
    )
    assert body["status"] == "success"

    request = captured["request"]
    assert request.full_url == "https://example.org:1643/api/seal-records"
    ts = request.get_header("X-sync-timestamp")
    nonce = request.get_header("X-sync-nonce")
    sig = request.get_header("X-sync-signature")
    assert ts and nonce and sig
    assert sig == client._canonical_signature(secret, ts, nonce, request.data)


def test_push_safe_swallows_http_error(monkeypatch):
    def fake_open(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(transport, "_open", fake_open)
    assert (
        client.push_seal_record_safe(
            _contract_record(), base_url="https://example.org", secret=_secret()
        )
        is False
    )


# ---------------------------------------------------------------------------
# Against a local HTTP server (port 0): headers and contract body
# ---------------------------------------------------------------------------


class TestAgainstALocalServer:
    def test_hmac_headers_and_contract_body(self) -> None:
        secret = _secret()
        pdf = b"%PDF-1.4 synthetic record"
        with StubHttpServer([(200, {"status": "success",
                                    "message": "stored"})]) as server:
            before = int(time.time())
            answer = client.push_seal_record(
                _contract_record(), record_pdf=pdf, base_url=server.url,
                secret=secret)
            after = int(time.time())

        assert answer == {"status": "success", "message": "stored"}
        [(path, headers, raw)] = server.requests
        assert path == "/api/seal-records"
        assert headers["content-type"] == "application/json"
        ts, nonce = headers["x-sync-timestamp"], headers["x-sync-nonce"]
        assert before <= int(ts) <= after
        assert re.fullmatch(r"[A-Za-z0-9._-]{8,128}", nonce)
        expected = hmac.new(secret.encode(),
                            ts.encode() + b"\n" + nonce.encode() + b"\n" + raw,
                            hashlib.sha256).hexdigest()
        assert headers["x-sync-signature"] == expected
        assert len(raw) <= 8 * 1024 * 1024

        body = json.loads(raw.decode("utf-8"))
        assert {"seal_id", "case_info", "process_info", "file_info",
                "signer_info", "history"} <= set(body)
        assert re.fullmatch(r"S-\d{8}-[0-9A-F]{6}", body["seal_id"])
        assert body["process_info"]["unlock_time"] == "2026-10-10T00:00:00Z"
        assert base64.b64decode(body["record_pdf"]) == pdf
        assert body["history"]["events"][-1]["event_id"] == "EVT-0003"
        assert body["signer_info"]["birth_date"] and body["signer_info"]["phone"]

    def test_every_push_uses_a_fresh_nonce_and_signature(self) -> None:
        secret = _secret()
        with StubHttpServer([(200, {"status": "success",
                                    "message": "ok"})]) as server:
            for _ in range(2):
                client.push_seal_record(_contract_record(), base_url=server.url,
                                        secret=secret)

        nonces = {h["x-sync-nonce"] for _p, h, _r in server.requests}
        assert len(nonces) == 2

    def test_a_refusal_is_reported_without_the_record(self) -> None:
        with StubHttpServer([(409, {"status": "error",
                                    "message": "replay"})]) as server:
            with pytest.raises(client.PortalSyncError) as info:
                client.push_seal_record(_contract_record(),
                                        base_url=server.url, secret=_secret())

        text = str(info.value)
        assert "409" in text and "replay" in text
        assert "010-0000-0000" not in text and "1990-01-01" not in text
