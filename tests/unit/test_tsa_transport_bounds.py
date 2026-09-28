"""Transport bounds of the TSA client and the bundled TSA (Fable gate, 7-8).

Finding 7: the release host's TSA request must not follow redirects, must
not read a reply beyond ``tsa_client.MAX_TSA_REPLY_BYTES``, and refuses a
content-coded reply; each is ``tsa_transport``, without a retry. Finding 8:
the bundled TSA reads a request body only when its Content-Length is a
number from 1 to ``tsa_server.MAX_TSQ_BYTES``; it answers 413 above that
and 400 otherwise, without reading the body. All endpoints are loopback
servers on port 0.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from asn1crypto import tsp

from desktop.signature import tsa_client
from desktop.signature.exceptions import TSAError
from desktop.signature.tsa_client import (
    MAX_TSA_REPLY_BYTES,
    _build_tsq,
    request_timestamp,
    request_timestamp_trusted,
)
from desktop.signature.tsa_profile import TsaTrustProfile
from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID, MAX_TSQ_BYTES
from tests.fixtures.release_pki import running_tsa
from tests.fixtures.tsa_http import (
    forward_to,
    headers_then_wait,
    raw_post,
    redirect_to,
    rejection_fail_info,
    reply_of_size,
    running_endpoint,
)

_HUGE = 64 * 1024 * 1024  # far beyond any kernel buffering on loopback


def _hash() -> bytes:
    return hashlib.sha256(b"E2b transport bounds").digest()


def _profile(release_pki: Any) -> TsaTrustProfile:
    return TsaTrustProfile(str(release_pki.ca_cert_path), DEFAULT_TSA_POLICY_OID)


def _refused(url: str, release_pki: Any) -> TSAError:
    with pytest.raises(TSAError) as info:
        request_timestamp_trusted(_hash(), url, _profile(release_pki))
    assert info.value.code == "tsa_transport", str(info.value)
    return info.value


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tsa_client.time, "sleep", lambda _s: None)


# ===================================================================
# Finding 7: the client transport
# ===================================================================

class TestRedirects:
    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_redirect_is_refused_and_not_followed(
        self, release_pki, release_tsa, status: int
    ) -> None:
        # The redirect points at a working proxy for the real TSA; a
        # client that followed a 307/308 would get a valid token there.
        with running_endpoint(forward_to(release_tsa)) as (target, target_log):
            with running_endpoint(redirect_to(target, status)) as (url, log):
                exc = _refused(url, release_pki)

        assert f"redirect (HTTP {status})" in str(exc)
        assert [method for method, _ in log.requests] == ["POST"]  # no retry
        assert target_log.requests == []                          # not followed

    def test_redirect_is_refused_on_the_legacy_request_too(
        self, release_tsa
    ) -> None:
        with running_endpoint(forward_to(release_tsa)) as (target, target_log):
            with running_endpoint(redirect_to(target, 307)) as (url, _log):
                with pytest.raises(TSAError, match="redirect"):
                    request_timestamp(_hash(), url)
        assert target_log.requests == []


class TestReplySize:
    def test_declared_oversize_is_refused_on_the_header(self, release_pki) -> None:
        # Content-Length beyond the bound, then no body: a client that
        # waited for the body would hang until its read timeout.
        with running_endpoint(headers_then_wait(_HUGE)) as (url, log):
            exc = _refused(url, release_pki)
        assert "exceeds" in str(exc)
        assert len(log.requests) == 1

    def test_undeclared_oversize_is_not_read_to_the_end(self, release_pki) -> None:
        # No Content-Length: the body ends when the connection closes.
        with running_endpoint(reply_of_size(_HUGE, declare=False)) as (url, log):
            exc = _refused(url, release_pki)
            assert log.handled.wait(timeout=10)
        assert "exceeds" in str(exc)
        assert not log.finished and log.sent < 8 * 1024 * 1024

    def test_a_reply_at_the_bound_is_read(self, release_pki) -> None:
        # Exactly MAX_TSA_REPLY_BYTES: read, then refused as a TSR that
        # does not parse, not for its size.
        with running_endpoint(reply_of_size(MAX_TSA_REPLY_BYTES)) as (url, log):
            exc = _refused(url, release_pki)
            assert log.handled.wait(timeout=10)
        assert "exceeds" not in str(exc) and "parse" in str(exc)
        assert log.finished

    def test_one_byte_over_the_bound_is_refused(self, release_pki) -> None:
        with running_endpoint(reply_of_size(MAX_TSA_REPLY_BYTES + 1,
                                            declare=False)) as (url, _log):
            exc = _refused(url, release_pki)
        assert "exceeds" in str(exc)

    def test_bound_matches_the_desktop_sync_transport(self) -> None:
        from desktop.sync.transport import MAX_ANSWER_BYTES

        assert MAX_TSA_REPLY_BYTES == MAX_ANSWER_BYTES == 64 * 1024


class TestContentCoding:
    def test_compressed_reply_is_refused(self, release_pki, release_tsa) -> None:
        with running_endpoint(forward_to(release_tsa, gzip_reply=True)) as (url, _):
            exc = _refused(url, release_pki)
        assert "gzip" in str(exc)

    def test_identity_is_requested(
        self, release_pki, release_tsa, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[tuple[str, str]] = []
        original = tsa_client.requests.post

        def spy(url: str, *args: Any, **kwargs: Any) -> Any:
            seen.append((url, kwargs.get("headers", {}).get("Accept-Encoding", "")))
            return original(url, *args, **kwargs)

        monkeypatch.setattr(tsa_client.requests, "post", spy)
        with running_endpoint(forward_to(release_tsa)) as (url, _log):
            request_timestamp_trusted(_hash(), url, _profile(release_pki))
        # Only the client's own request (the proxy's forward is not ours).
        assert [enc for called, enc in seen if called == url] == ["identity"]


class TestNormalReplies:
    def test_a_normal_reply_through_a_proxy_is_accepted(
        self, release_pki, release_tsa
    ) -> None:
        with running_endpoint(forward_to(release_tsa)) as (url, log):
            stamp = request_timestamp_trusted(_hash(), url, _profile(release_pki))
        assert stamp.accuracy is not None
        assert len(log.requests) == 1

    def test_the_local_tsa_still_answers_directly(self, release_tsa) -> None:
        token = request_timestamp(_hash(), release_tsa)
        assert token


# ===================================================================
# Finding 8: the bundled TSA's request bound
# ===================================================================

@pytest.fixture()
def own_tsa(release_pki):
    """A TSA of its own per test (malformed requests stay off the shared one)."""
    with running_tsa(release_pki.tsa_key_path, release_pki.tsa_cert_path) as url:
        yield url


class TestServerRequestBound:
    def test_oversized_length_is_413_without_reading(self, own_tsa) -> None:
        # Headers only: a server that tried to read the body would wait
        # and the client would time out.
        status, _ = raw_post(own_tsa, {"Content-Length": str(MAX_TSQ_BYTES + 1)})
        assert status == 413

    @pytest.mark.parametrize("value", ["abc", "1.5", "1e3", " ", "-5", "0", "+7"])
    def test_malformed_or_non_positive_length_is_400(
        self, own_tsa, value: str
    ) -> None:
        status, _ = raw_post(own_tsa, {"Content-Length": value})
        assert status == 400

    def test_missing_length_is_400(self, own_tsa) -> None:
        assert raw_post(own_tsa, {})[0] == 400

    def test_chunked_request_is_400(self, own_tsa) -> None:
        status, _ = raw_post(own_tsa, {"Transfer-Encoding": "chunked"},
                              b"5\r\nhello\r\n0\r\n\r\n")
        assert status == 400

    def test_request_at_the_bound_is_read_and_answered(self, own_tsa) -> None:
        # Not a TimeStampReq: read in full, answered with a rejection TSR.
        status, body = raw_post(own_tsa, {"Content-Length": str(MAX_TSQ_BYTES)},
                                 b"\x00" * MAX_TSQ_BYTES)
        assert status == 200
        assert rejection_fail_info(body) == {"bad_request"}

    def test_a_normal_request_is_answered(self, own_tsa) -> None:
        tsq = _build_tsq(_hash(), nonce=7)
        status, body = raw_post(own_tsa, {"Content-Length": str(len(tsq))}, tsq)
        assert status == 200
        assert tsp.TimeStampResp.load(body)["status"]["status"].native == "granted"

    def test_the_bound_leaves_room_for_any_real_request(self) -> None:
        assert len(_build_tsq(_hash(), nonce=2**64 - 1)) < MAX_TSQ_BYTES // 64
