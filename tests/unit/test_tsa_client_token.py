"""Token-returning verified TSA request (stage D, D4).

``request_timestamp_verified_token`` performs the same fail-closed checks
as ``request_timestamp_verified`` (fresh nonce echoed in the signed
TSTInfo, message-imprint equality, CMS signature against the pinned TSA
certificate) plus a SHA-256 imprint-algorithm check, and also returns the
token bytes so the release audit can keep them. The existing function
keeps its signature and return type.
"""

from __future__ import annotations

import hashlib
import inspect
import os
from datetime import datetime

import pytest
from asn1crypto import cms, tsp

from desktop.signature import tsa_client
from desktop.signature.exceptions import TSAError
from desktop.signature.tsa_client import (
    request_timestamp_verified,
    request_timestamp_verified_token,
    verify_timestamp,
)
from desktop.signature.types import VerifiedTimestamp
from tests.fixtures.tsa_proxy import (
    STALE_NONCE,
    forwarding_proxy,
    replaying_transport,
)


def _digest() -> bytes:
    return hashlib.sha256(os.urandom(16)).digest()


def _tst_info(token: bytes) -> tsp.TSTInfo:
    content = cms.ContentInfo.load(token)
    return tsp.TSTInfo.load(
        content["content"]["encap_content_info"]["content"].parsed.dump()
    )


class TestTokenReturningRequest:
    def test_returns_verified_token_and_time(
        self, release_pki, release_tsa
    ) -> None:
        digest = _digest()
        result = request_timestamp_verified_token(
            digest, release_tsa, str(release_pki.tsa_cert_path)
        )

        assert isinstance(result, VerifiedTimestamp)
        assert result.gen_time.tzinfo is not None
        info = _tst_info(result.token)
        assert info["message_imprint"]["hashed_message"].native == digest
        assert info["nonce"].native == result.nonce
        assert result.token_sha256 == hashlib.sha256(result.token).hexdigest()
        assert verify_timestamp(
            result.token, str(release_pki.tsa_cert_path)
        ) == result.gen_time

    def test_existing_function_keeps_its_contract(
        self, release_pki, release_tsa
    ) -> None:
        params = list(inspect.signature(request_timestamp_verified).parameters)
        assert params == ["data_hash", "tsa_url", "tsa_cert_path"]
        gen_time = request_timestamp_verified(
            _digest(), release_tsa, str(release_pki.tsa_cert_path)
        )
        assert isinstance(gen_time, datetime)


class TestHostileResponses:
    def test_replayed_earlier_token_is_rejected(
        self, release_pki, release_tsa, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        earlier = request_timestamp_verified_token(
            _digest(), release_tsa, str(release_pki.tsa_cert_path)
        )
        monkeypatch.setattr(
            tsa_client, "_send_tsq", replaying_transport(earlier.token)
        )
        with pytest.raises(TSAError):
            request_timestamp_verified_token(
                _digest(), release_tsa, str(release_pki.tsa_cert_path)
            )

    def test_stale_nonce_with_matching_imprint_is_rejected(
        self, release_pki, release_tsa, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            tsa_client, "_send_tsq",
            forwarding_proxy(tsa_client._send_tsq, nonce=STALE_NONCE),
        )
        with pytest.raises(TSAError, match="nonce"):
            request_timestamp_verified_token(
                _digest(), release_tsa, str(release_pki.tsa_cert_path)
            )

    def test_token_over_a_different_imprint_is_rejected(
        self, release_pki, release_tsa, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            tsa_client, "_send_tsq",
            forwarding_proxy(tsa_client._send_tsq, hashed_message=_digest()),
        )
        with pytest.raises(TSAError, match="messageImprint"):
            request_timestamp_verified_token(
                _digest(), release_tsa, str(release_pki.tsa_cert_path)
            )

    def test_non_sha256_imprint_algorithm_is_rejected(
        self, release_pki, release_tsa, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            tsa_client, "_send_tsq",
            forwarding_proxy(tsa_client._send_tsq, algorithm="sha512"),
        )
        with pytest.raises(TSAError, match="algorithm"):
            request_timestamp_verified_token(
                _digest(), release_tsa, str(release_pki.tsa_cert_path)
            )

    def test_signature_under_another_certificate_is_rejected(
        self, release_pki, release_tsa
    ) -> None:
        with pytest.raises(TSAError):
            request_timestamp_verified_token(
                _digest(), release_tsa, str(release_pki.other_policy_cert_path)
            )


class TestUnavailableTsa:
    def test_unreachable_tsa_raises(
        self, release_pki, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tsa_client.time, "sleep", lambda _s: None)
        with pytest.raises(TSAError):
            request_timestamp_verified_token(
                _digest(), "http://127.0.0.1:1/tsa",
                str(release_pki.tsa_cert_path),
            )

    @pytest.mark.parametrize("url, cert", [("", "x.pem"), ("http://x/tsa", "")])
    def test_missing_configuration_raises(self, url: str, cert: str) -> None:
        with pytest.raises(TSAError):
            request_timestamp_verified_token(_digest(), url, cert)
