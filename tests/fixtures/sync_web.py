"""Helpers for the sync-authentication tests (stage E, E2a; synthetic data).

``signed_payload`` builds a ``/sync/upload-record`` body carrying a
``sync_auth`` object signed with the test seal-policy key, exactly as the
desktop client does. ``live_server`` serves a Flask app over HTTP on an
ephemeral loopback port, so the desktop client is exercised end to end.
"""

from __future__ import annotations

import base64
import json
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterator, Optional

from tests.fixtures.release_web import sync_payload


def signed_payload(
    material: Any,
    signer: Any,
    *,
    event_id: int = 1,
    event_type: str = "Sealing",
    record: Optional[dict] = None,
    include_wrapped: bool = True,
    wrapped_s3_b64: Optional[str] = None,
    record_pdf: Optional[bytes] = None,
    sent_at: Optional[datetime] = None,
    nonce: Optional[str] = None,
    policy_generation: Optional[int] = None,
) -> dict:
    """The sync body of a synthetic seal with a signed ``sync_auth``."""
    from desktop.signature.seal_policy import policy_generation as generation_of
    from desktop.signature.sync_envelope import (
        build_sync_envelope,
        sign_sync_envelope,
    )

    body = sync_payload(material, event_id=event_id, event_type=event_type,
                        record=record, wrapped_s3_b64=wrapped_s3_b64,
                        include_wrapped=include_wrapped)
    if record_pdf is not None:
        body["record_pdf"] = base64.b64encode(record_pdf).decode("ascii")
    record_obj = json.loads(body["record_json"])
    if policy_generation is None:
        policy = record_obj.get("policy")
        policy_generation = generation_of(policy) if policy else 0
    wrapped = body.get("wrapped_s3")
    envelope = build_sync_envelope(
        seal_id=body["seal_id"], event_id=event_id, event_type=event_type,
        record_json=body["record_json"], record_pdf=record_pdf,
        wrapped_s3=base64.b64decode(wrapped) if wrapped else None,
        policy_generation=policy_generation, sent_at=sent_at, nonce=nonce,
    )
    signed = sign_sync_envelope(envelope, signer)
    return {**body, "sync_auth": signed.payload_field()}


def require_signatures(app: Any, on: bool = True) -> None:
    """Turn the ``SYNC_REQUIRE_SIGNATURE`` switch on (or off) at run time."""
    app.config["SYNC_REQUIRE_SIGNATURE"] = on


def high_water(app: Any, seal_id: str) -> Optional[tuple[int, str, int]]:
    """(generation, policy digest, event id) of the seal's mark, if any."""
    with app.app_context():
        from web.models.sync_models import find_high_water

        mark = find_high_water(seal_id)
    if mark is None:
        return None
    return mark.generation, mark.policy_digest, mark.event_id


def nonce_rows(app: Any) -> list[str]:
    """Every stored sync nonce."""
    with app.app_context():
        from web.models.db_models import execute_query

        rows = execute_query("SELECT nonce FROM sync_nonces ORDER BY nonce",
                             fetch_all=True) or []
    return [row["nonce"] if hasattr(row, "keys") else row[0] for row in rows]


class _CountingApp:
    """WSGI wrapper counting requests per path (the server's view)."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def __call__(self, environ: dict, start_response: Any) -> Any:
        with self._lock:
            self.calls.append(environ.get("PATH_INFO", ""))
        return self.app(environ, start_response)


@contextmanager
def live_server(app: Any, port: int = 0) -> Iterator[tuple[str, _CountingApp]]:
    """Serve ``app`` on 127.0.0.1; yields (base URL, request counter)."""
    from werkzeug.serving import make_server

    counter = _CountingApp(app)
    server = make_server("127.0.0.1", port, counter, threaded=True)
    thread = threading.Thread(target=server.serve_forever,
                              name="sync-test-server", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", counter
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def unused_port() -> int:
    """A loopback port nothing listens on (connection refused)."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _send_answer(handler: Any, answer: tuple) -> None:
    """Write ``(status, body[, headers])``: a dict as JSON, a str as HTML."""
    status, body = answer[0], answer[1]
    headers = answer[2] if len(answer) > 2 else {}
    if isinstance(body, dict):
        data, kind = json.dumps(body).encode("utf-8"), "application/json"
    elif isinstance(body, str):
        data, kind = body.encode("utf-8"), "text/html; charset=utf-8"
    else:
        data, kind = bytes(body), "application/octet-stream"
    handler.send_response(status)
    handler.send_header("Content-Type", kind)
    handler.send_header("Content-Length", str(len(data)))
    for name, value in headers.items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(data)


class StubHttpServer:
    """A loopback HTTP server that records requests and answers from a list.

    ``answers`` is a list used in turn for POSTs (the last one repeats).
    An answer is ``(status, body)`` or ``(status, body, headers)``: a dict
    body is sent as JSON, a ``str`` as HTML, ``bytes`` as they are. POSTs
    are kept as ``(path, headers, raw body)`` in ``requests``; GETs (for
    example a login page a redirect points to) are answered with
    ``get_answer`` and their paths kept in ``gets``.
    """

    def __init__(
        self,
        answers: list[tuple],
        get_answer: tuple = (200, "<html><body>login</body></html>"),
    ) -> None:
        import http.server

        self.answers = list(answers)
        self.get_answer = get_answer
        self.requests: list[tuple[str, dict[str, str], bytes]] = []
        self.gets: list[str] = []
        stub = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 (http.server API)
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                stub.requests.append(
                    (self.path, {k.lower(): v for k, v in self.headers.items()},
                     raw))
                index = min(len(stub.requests), len(stub.answers)) - 1
                self._answer(stub.answers[index])

            def do_GET(self) -> None:  # noqa: N802 (http.server API)
                stub.gets.append(self.path)
                self._answer(stub.get_answer)

            def _answer(self, answer: tuple) -> None:
                _send_answer(self, answer)

            def log_message(self, *_args: Any) -> None:
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                                                       _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="sync-stub-server", daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "StubHttpServer":
        self._thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
