"""Loopback HTTP endpoints standing in for a TSA, and raw HTTP helpers.

Each endpoint logs what it received and answers with a chosen status,
headers and body, so the TSA client's transport rules (no redirects, a
bounded reply, no content coding) can be tested against real sockets.
``raw_post`` sends exactly the headers given, for the bundled TSA's
request rules, and the rejection helpers read and build RFC 3161
rejection replies independently of the code under test. Test only, port
0 throughout; nothing here is used by production code.
"""

from __future__ import annotations

import gzip
import http.client
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterable, Iterator, Optional
from urllib.parse import urlsplit

import requests
from asn1crypto import cms, core, tsp

TSR_TYPE = "application/timestamp-reply"
_CHUNK = 64 * 1024


class Rfc3161Resp(core.Sequence):
    """TimeStampResp as RFC 3161 2.4.2 defines it: the token is OPTIONAL
    (asn1crypto 1.5.1 declares it mandatory and cannot read a rejection)."""

    _fields = [
        ("status", tsp.PKIStatusInfo),
        ("time_stamp_token", cms.ContentInfo, {"optional": True}),
    ]


def rejection_fail_info(body: bytes) -> set:
    """The fail_info of a rejection reply without a token (asserts both)."""
    reply = Rfc3161Resp.load(body, strict=True)
    assert reply["status"]["status"].native == "rejection"
    assert isinstance(reply["time_stamp_token"], core.Void)
    return set(reply["status"]["fail_info"].native)


def rejection_tsr(reason: str) -> bytes:
    """A DER rejection TimeStampResp, built without the code under test."""
    status = tsp.PKIStatusInfo({"status": "rejection",
                                "fail_info": {reason}}).dump()
    return b"\x30" + bytes([len(status)]) + status


def raw_post(url: str, headers: dict[str, str], body: bytes = b"") -> tuple[int, bytes]:
    """POST with exactly these headers (no automatic Content-Length)."""
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    try:
        conn.putrequest("POST", parts.path, skip_accept_encoding=True)
        for name, value in headers.items():
            conn.putheader(name, value)
        conn.endheaders(body or None)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


@dataclass
class EndpointLog:
    """What an endpoint saw: request methods and bodies, bytes it sent."""

    requests: list[tuple[str, bytes]] = field(default_factory=list)
    sent: int = 0
    finished: bool = False
    handled: threading.Event = field(default_factory=threading.Event)
    stop: threading.Event = field(default_factory=threading.Event)


# (status, headers, body chunks) for a request body.
Responder = Callable[[bytes, EndpointLog], tuple[int, dict, Iterable[bytes]]]


@contextmanager
def running_endpoint(respond: Responder) -> Iterator[tuple[str, EndpointLog]]:
    """An HTTP/1.0 endpoint on 127.0.0.1:0; yields its /tsa URL and log."""
    log = EndpointLog()

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            _answer(self, log, "POST", body, respond)

        def do_GET(self) -> None:  # noqa: N802
            _answer(self, log, "GET", b"", respond)

        def log_message(self, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/tsa", log
    finally:
        log.stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _answer(handler: BaseHTTPRequestHandler, log: EndpointLog, method: str,
            body: bytes, respond: Responder) -> None:
    log.requests.append((method, body))
    try:
        status, headers, chunks = respond(body, log)
        handler.send_response(status)
        for name, value in headers.items():
            handler.send_header(name, value)
        handler.end_headers()
        for chunk in chunks:
            handler.wfile.write(chunk)
            log.sent += len(chunk)
        log.finished = True
    except OSError:  # the client went away (expected for refused replies)
        pass
    finally:
        log.handled.set()


def redirect_to(location: str, status: int) -> Responder:
    """Answer every request with ``status`` and ``Location: location``."""
    return lambda _body, _log: (
        status, {"Location": location, "Content-Length": "0"}, [])


def forward_to(tsa_url: str, *, gzip_reply: bool = False) -> Responder:
    """Forward the TSQ to a real TSA and return its reply (optionally
    gzip-compressed with ``Content-Encoding: gzip``)."""

    def _respond(body: bytes, _log: EndpointLog) -> tuple[int, dict, list[bytes]]:
        reply = requests.post(
            tsa_url, data=body, timeout=10,
            headers={"Content-Type": "application/timestamp-query"},
        ).content
        headers = {"Content-Type": TSR_TYPE}
        if gzip_reply:
            reply = gzip.compress(reply)
            headers["Content-Encoding"] = "gzip"
        headers["Content-Length"] = str(len(reply))
        return 200, headers, [reply]

    return _respond


def reply_of_size(size: int, *, declare: bool = True,
                  declared: Optional[int] = None) -> Responder:
    """A 200 TSR-typed reply of ``size`` zero bytes.

    ``declare``: send a Content-Length (``declared`` if given, else
    ``size``); without it the body ends when the connection closes.
    """

    def _respond(_body: bytes, log: EndpointLog) -> tuple[int, dict, Iterable[bytes]]:
        headers = {"Content-Type": TSR_TYPE}
        if declare:
            headers["Content-Length"] = str(size if declared is None else declared)
        return 200, headers, _zeros(size, log)

    return _respond


def headers_then_wait(declared: int) -> Responder:
    """Declare a ``declared``-byte reply, then send nothing and wait (up to
    5 s, or until the endpoint stops): a client must refuse on the header."""

    def _respond(_body: bytes, log: EndpointLog) -> tuple[int, dict, Iterable[bytes]]:
        return 200, {"Content-Type": TSR_TYPE,
                     "Content-Length": str(declared)}, _wait(log)

    return _respond


def _zeros(size: int, log: EndpointLog) -> Iterator[bytes]:
    remaining = size
    while remaining > 0 and not log.stop.is_set():
        step = min(_CHUNK, remaining)
        yield b"\x00" * step
        remaining -= step


def _wait(log: EndpointLog) -> Iterator[bytes]:
    """No body; hold the connection open after the headers (up to 5 s)."""
    log.stop.wait(timeout=5)
    yield from ()
