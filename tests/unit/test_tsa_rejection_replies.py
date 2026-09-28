"""RFC 3161 rejection replies of the bundled TSA and the TSA client.

Found while testing the Fable gate's finding 8. A TimeStampResp that
rejects a request carries no token (RFC 3161 2.4.2, ``timeStampToken``
OPTIONAL), but asn1crypto 1.5.1 declares the token mandatory. Before this
fix, the bundled TSA could not encode a rejection (and passed PKIFailureInfo
a string, not a set), so a malformed request closed the connection without
an answer. The client could not decode one either: its ``ValueError``
escaped the parser and was retried as a network failure. Both sides now use
the RFC structure (``tsa_profile.TimeStampResponse``); the tests read and
build rejections with an independent definition.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from desktop.signature import tsa_client
from desktop.signature.exceptions import TSAError
from desktop.signature.tsa_client import _build_tsq, request_timestamp
from tests.fixtures.release_pki import running_tsa
from tests.fixtures.tsa_http import (
    TSR_TYPE,
    raw_post,
    rejection_fail_info,
    rejection_tsr,
    running_endpoint,
)


@pytest.fixture()
def own_tsa(release_pki):
    """A TSA of its own per test (malformed requests stay off the shared one)."""
    with running_tsa(release_pki.tsa_key_path, release_pki.tsa_cert_path) as url:
        yield url


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tsa_client.time, "sleep", lambda _s: None)


def test_malformed_request_is_answered_with_a_rejection(own_tsa) -> None:
    status, body = raw_post(own_tsa, {"Content-Length": "10"}, b"\x30" * 10)
    assert status == 200
    assert rejection_fail_info(body) == {"bad_request"}


def test_a_signing_failure_is_answered_with_system_failure(
    own_tsa, monkeypatch: pytest.MonkeyPatch
) -> None:
    from desktop.signature import tsa_server

    def broken(*_args: Any) -> bytes:
        raise RuntimeError("injected signing failure")

    monkeypatch.setattr(tsa_server, "_sign_tst_info", broken)
    tsq = _build_tsq(hashlib.sha256(b"sign").digest(), nonce=9)
    status, body = raw_post(own_tsa, {"Content-Length": str(len(tsq))}, tsq)
    assert status == 200
    assert rejection_fail_info(body) == {"system_failure"}


def test_client_reports_a_rejection_once_without_retry() -> None:
    def reject(_body: bytes, _log: Any) -> Any:
        reply = rejection_tsr("bad_alg")
        return 200, {"Content-Type": TSR_TYPE,
                     "Content-Length": str(len(reply))}, [reply]

    with running_endpoint(reject) as (url, log):
        with pytest.raises(TSAError, match="rejected") as info:
            request_timestamp(hashlib.sha256(b"rej").digest(), url)
    assert "bad_alg" in str(info.value)
    assert len(log.requests) == 1


def test_a_granted_reply_still_yields_its_token(release_tsa) -> None:
    token = request_timestamp(hashlib.sha256(b"granted").digest(), release_tsa)
    assert token[:1] == b"\x30"
