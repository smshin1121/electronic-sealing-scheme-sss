"""Tests for fail-closed TSA time-lock verification (CR-01).

The manuscript claims (3.2, 3.3.5, Eq. 4, Alg. S4): RFC 3161 nonce echo,
imprint equality, signature verification, and fail-closed behavior on every
failure. These tests pin the component-level contract of
``check_unlock_time`` and the strict TSA verification helpers.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest

from desktop.crypto.time_access_control import check_unlock_time

_PAST = (datetime.now(tz=timezone.utc) - timedelta(days=1)).isoformat()
_FUTURE = (datetime.now(tz=timezone.utc) + timedelta(days=1)).isoformat()


class TestFailClosed:
    def test_no_tsa_url_denies(self) -> None:
        result = check_unlock_time(_PAST, tsa_url=None)
        assert result.allowed is False
        assert "TSA" in (result.warning or "")

    def test_empty_tsa_url_denies(self) -> None:
        result = check_unlock_time(_PAST, tsa_url="")
        assert result.allowed is False

    def test_unreachable_tsa_denies(self) -> None:
        # Nothing listens on this port; every transport failure must deny.
        result = check_unlock_time(
            _PAST, tsa_url="http://127.0.0.1:1/tsa"
        )
        assert result.allowed is False
        assert result.method == "tsa_unavailable"

    def test_future_unlock_denies_locally_before_tsa(self) -> None:
        # Local preliminary check may deny early without touching the TSA.
        result = check_unlock_time(_FUTURE, tsa_url=None)
        assert result.allowed is False

    def test_invalid_unlock_time_raises(self) -> None:
        from desktop.crypto.exceptions import AccessControlError

        with pytest.raises(AccessControlError):
            check_unlock_time("not-a-time", tsa_url=None)


class TestVerifiedTsaPath:
    """Live round-trip against the bundled TSA server, if available."""

    @pytest.fixture()
    def tsa(self):  # noqa: ANN201 — fixture shape follows test_tsa_server
        try:
            from desktop.signature import ensure_tsa_server_running
        except ImportError:
            pytest.skip("signature stack unavailable")
        try:
            tsa_url, tsa_cert_path = ensure_tsa_server_running()
        except Exception as exc:  # pragma: no cover - environment guard
            pytest.skip(f"local TSA not startable: {exc}")
        return tsa_url, tsa_cert_path

    def test_past_unlock_allowed_via_verified_tsa(self, tsa) -> None:
        tsa_url, tsa_cert_path = tsa
        result = check_unlock_time(
            _PAST, tsa_url=tsa_url, tsa_cert_path=str(tsa_cert_path)
        )
        assert result.allowed is True
        assert result.method == "tsa"

    def test_future_unlock_denied_via_verified_tsa(self, tsa) -> None:
        tsa_url, tsa_cert_path = tsa
        result = check_unlock_time(
            _FUTURE, tsa_url=tsa_url, tsa_cert_path=str(tsa_cert_path)
        )
        assert result.allowed is False

    def test_nonce_echo_and_imprint_verified(self, tsa) -> None:
        from desktop.signature.tsa_client import (
            request_timestamp_verified,
        )

        tsa_url, tsa_cert_path = tsa
        digest = hashlib.sha256(os.urandom(16)).digest()
        gen_time = request_timestamp_verified(
            digest, tsa_url, str(tsa_cert_path)
        )
        assert gen_time.tzinfo is not None

    def test_wrong_cert_fails_verification(self, tsa, tmp_path) -> None:
        from desktop.signature.exceptions import TSAError
        from desktop.signature.tsa_client import (
            request_timestamp_verified,
        )

        tsa_url, _ = tsa
        # Self-signed cert unrelated to the TSA — signature check must fail.
        from desktop.signature import create_self_signed_cert, generate_keypair
        from cryptography.hazmat.primitives import serialization

        key, _ = generate_keypair(2048)
        cert = create_self_signed_cert(
            private_key=key,
            subject_name="Wrong",
            email="wrong@example.com",
            signature_image_hash="0" * 64,
        )
        wrong_pem = tmp_path / "wrong.pem"
        wrong_pem.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )

        digest = hashlib.sha256(os.urandom(16)).digest()
        with pytest.raises(TSAError):
            request_timestamp_verified(digest, tsa_url, str(wrong_pem))
