"""Unit tests for TSA server and client functionality.

Validates:
  - TSA server creation and client timestamp request/response
  - genTime is close to current time
  - Function signature and structural tests (fallback when server unavailable)
"""

from __future__ import annotations

import hashlib
import inspect
import time
from datetime import datetime, timezone

import pytest

try:
    from desktop.signature.exceptions import TSAError
    from desktop.signature.tsa_client import (
        _build_tsq,
        _parse_tsr,
        request_timestamp,
        verify_timestamp,
    )
    from desktop.signature.tsa_server import (
        _TSAContext,
        _SerialCounter,
        _build_tst_info,
        _process_tsq,
        create_tsa_server,
        ensure_tsa_credentials,
        ensure_tsa_server_running,
        run_tsa_server,
        start_tsa_server_background,
    )
    _SIGNATURE_AVAILABLE = True
except ImportError:
    _SIGNATURE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _SIGNATURE_AVAILABLE,
    reason="signature module dependencies (asn1crypto, cryptography, pyhanko) not fully installed",
)

_TEST_TSA_KEY_PASSWORD = "test-only-tsa-key-password"  # public-test-fixture
_TEST_TSA_CA_KEY_PASSWORD = "test-only-tsa-ca-password"  # public-test-fixture

# ---------------------------------------------------------------------------
# Tests: function signatures
# ---------------------------------------------------------------------------


class TestFunctionSignatures:
    """Verify that public API functions have the expected signatures."""

    def test_request_timestamp_params(self) -> None:
        sig = inspect.signature(request_timestamp)
        params = list(sig.parameters.keys())
        assert "data_hash" in params
        assert "tsa_url" in params

    def test_verify_timestamp_params(self) -> None:
        sig = inspect.signature(verify_timestamp)
        params = list(sig.parameters.keys())
        assert "tst_token" in params
        assert "tsa_cert_path" in params

    def test_create_tsa_server_params(self) -> None:
        sig = inspect.signature(create_tsa_server)
        params = list(sig.parameters.keys())
        assert "tsa_key_path" in params
        assert "tsa_cert_path" in params
        assert "host" in params
        assert "port" in params

    def test_start_tsa_server_background_params(self) -> None:
        sig = inspect.signature(start_tsa_server_background)
        params = list(sig.parameters.keys())
        assert "tsa_key_path" in params
        assert "tsa_cert_path" in params

    def test_ensure_tsa_server_running_params(self) -> None:
        sig = inspect.signature(ensure_tsa_server_running)
        params = list(sig.parameters.keys())
        assert "tsa_dir" in params
        assert "host" in params
        assert "port" in params


# ---------------------------------------------------------------------------
# Tests: TSQ building
# ---------------------------------------------------------------------------


class TestBuildTSQ:
    """TSQ building from a SHA-256 hash."""

    def test_valid_hash(self) -> None:
        data_hash = hashlib.sha256(b"test data").digest()
        tsq_bytes = _build_tsq(data_hash)
        assert isinstance(tsq_bytes, bytes)
        assert len(tsq_bytes) > 0

    def test_invalid_hash_length(self) -> None:
        with pytest.raises(TSAError, match="32-byte"):
            _build_tsq(b"short")

    def test_empty_hash(self) -> None:
        with pytest.raises(TSAError):
            _build_tsq(b"")


# ---------------------------------------------------------------------------
# Tests: Serial counter
# ---------------------------------------------------------------------------


class TestSerialCounter:
    """Thread-safe auto-incrementing serial number counter."""

    def test_increments(self) -> None:
        counter = _SerialCounter(start=1)
        assert counter.next() == 1
        assert counter.next() == 2
        assert counter.next() == 3

    def test_custom_start(self) -> None:
        counter = _SerialCounter(start=100)
        assert counter.next() == 100


# ---------------------------------------------------------------------------
# Tests: TST Info building
# ---------------------------------------------------------------------------


class TestBuildTSTInfo:
    """_build_tst_info produces valid ASN.1 structure."""

    def test_builds_tst_info(self) -> None:
        from asn1crypto import algos, tsp

        message_imprint = tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "hashed_message": hashlib.sha256(b"test").digest(),
        })
        gen_time = datetime.now(timezone.utc)
        tst_info = _build_tst_info(message_imprint, 1, gen_time)
        dumped = tst_info.dump()
        assert isinstance(dumped, bytes)
        assert len(dumped) > 0


# ---------------------------------------------------------------------------
# Tests: TSA server+client integration (requires CA setup)
# ---------------------------------------------------------------------------


class TestTSAServerIntegration:
    """Full TSA server + client round-trip test."""

    @pytest.fixture
    def tsa_credentials(self, tmp_path):
        """Set up CA and TSA certificates for testing."""
        try:
            from desktop.signature.ca_setup import (
                create_ca,
                issue_tsa_cert,
                save_tsa_credentials,
            )
        except ImportError:
            pytest.skip("signature module dependencies not available")

        ca_dir = tmp_path / "ca"
        ca_key, ca_cert = create_ca(
            str(ca_dir),
            ca_key_password=_TEST_TSA_CA_KEY_PASSWORD,
        )
        tsa_key, tsa_cert = issue_tsa_cert(ca_key, ca_cert)

        tsa_dir = tmp_path / "tsa"
        key_path, cert_path = save_tsa_credentials(
            tsa_key,
            tsa_cert,
            str(tsa_dir),
            key_password=_TEST_TSA_KEY_PASSWORD,
        )
        return str(key_path), str(cert_path)

    def test_server_start_and_timestamp_request(self, tsa_credentials):
        """Start TSA server, request timestamp, verify genTime."""
        key_path, cert_path = tsa_credentials

        port = 13161  # Use non-standard port to avoid conflicts
        server, thread = start_tsa_server_background(
            tsa_key_path=key_path,
            tsa_cert_path=cert_path,
            host="127.0.0.1",
            port=port,
        )

        try:
            time.sleep(0.3)  # brief wait for server to bind

            data_hash = hashlib.sha256(b"evidence data").digest()
            tsa_url = f"http://127.0.0.1:{port}/tsa"

            tst_token = request_timestamp(data_hash, tsa_url)
            assert isinstance(tst_token, bytes)
            assert len(tst_token) > 0

            # Verify genTime is close to now
            gen_time = verify_timestamp(tst_token, cert_path)
            now = datetime.now(timezone.utc)
            delta = abs((now - gen_time).total_seconds())
            assert delta < 10, f"genTime delta too large: {delta}s"

        finally:
            server.shutdown()

    def test_gentime_near_current(self, tsa_credentials):
        """genTime in the TST token should be within a few seconds of now."""
        key_path, cert_path = tsa_credentials

        port = 13162
        server, thread = start_tsa_server_background(
            tsa_key_path=key_path,
            tsa_cert_path=cert_path,
            host="127.0.0.1",
            port=port,
        )

        try:
            time.sleep(0.3)

            before = datetime.now(timezone.utc)
            data_hash = hashlib.sha256(b"timing test").digest()
            tst_token = request_timestamp(
                data_hash, f"http://127.0.0.1:{port}/tsa"
            )
            gen_time = verify_timestamp(tst_token, cert_path)
            after = datetime.now(timezone.utc)

            assert before <= gen_time <= after or (
                abs((gen_time - before).total_seconds()) < 2
            )

        finally:
            server.shutdown()

    def test_server_echoes_nonce(self, tsa_credentials):
        """RFC3161 responses should preserve the request nonce."""
        from asn1crypto import algos, cms, tsp
        import requests

        key_path, cert_path = tsa_credentials
        port = 13165
        server, thread = start_tsa_server_background(
            tsa_key_path=key_path,
            tsa_cert_path=cert_path,
            host="127.0.0.1",
            port=port,
        )

        try:
            time.sleep(0.3)

            nonce = 987654321
            tsq = tsp.TimeStampReq({
                "version": "v1",
                "message_imprint": tsp.MessageImprint({
                    "hash_algorithm": algos.DigestAlgorithm({
                        "algorithm": "sha256",
                    }),
                    "hashed_message": hashlib.sha256(b"nonce-test").digest(),
                }),
                "nonce": nonce,
                "cert_req": True,
            })
            response = requests.post(
                f"http://127.0.0.1:{port}/tsa",
                data=tsq.dump(),
                headers={"Content-Type": "application/timestamp-query"},
                timeout=10,
            )
            response.raise_for_status()

            tsr = tsp.TimeStampResp.load(response.content)
            token = cms.ContentInfo.load(tsr["time_stamp_token"].dump())
            signed_data = token["content"]
            tst_info = tsp.TSTInfo.load(
                signed_data["encap_content_info"]["content"].parsed.dump()
            )
            assert tst_info["nonce"].native == nonce
        finally:
            server.shutdown()

    def test_ensure_tsa_credentials_creates_files(self, tmp_path):
        key_path, cert_path = ensure_tsa_credentials(tmp_path / "tsa-auto")
        assert key_path.is_file()
        assert cert_path.is_file()

    def test_ensure_tsa_server_running_bootstraps(self, tmp_path):
        tsa_url, cert_path = ensure_tsa_server_running(
            tsa_dir=tmp_path / "tsa-auto",
            host="127.0.0.1",
            port=13163,
        )

        assert tsa_url == "http://127.0.0.1:13163/tsa"
        assert cert_path.is_file()

        data_hash = hashlib.sha256(b"bootstrap").digest()
        tst_token = request_timestamp(data_hash, tsa_url)
        gen_time = verify_timestamp(tst_token, str(cert_path))
        assert gen_time.tzinfo is not None

    def test_missing_passwords_fail_before_creating_credentials(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.delenv("ENC_ENVELOPE_TSA_KEY_PASSWORD", raising=False)
        monkeypatch.delenv(
            "ENC_ENVELOPE_TSA_CA_KEY_PASSWORD",
            raising=False,
        )
        tsa_dir = tmp_path / "missing-passwords"

        with pytest.raises(TSAError, match="ENC_ENVELOPE_TSA_CA_KEY_PASSWORD"):
            ensure_tsa_credentials(tsa_dir)

        assert not tsa_dir.exists()

    def test_empty_tsa_password_fails_closed(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("ENC_ENVELOPE_TSA_KEY_PASSWORD", "")

        with pytest.raises(TSAError, match="ENC_ENVELOPE_TSA_KEY_PASSWORD"):
            ensure_tsa_server_running(
                tsa_dir=tmp_path / "empty-password",
                host="127.0.0.1",
                port=13166,
            )

    def test_explicit_password_overrides_environment(
        self,
        tmp_path,
        monkeypatch,
    ):
        explicit_tsa_password = "explicit-test-tsa-password"  # public-test-fixture
        explicit_ca_password = "explicit-test-ca-password"  # public-test-fixture
        monkeypatch.setenv(
            "ENC_ENVELOPE_TSA_KEY_PASSWORD",
            "different-environment-password",
        )
        tsa_dir = tmp_path / "explicit-password"

        key_path, cert_path = ensure_tsa_credentials(
            tsa_dir,
            ca_key_password=explicit_ca_password,
            tsa_key_password=explicit_tsa_password,
        )
        server = create_tsa_server(
            key_path,
            cert_path,
            key_password=explicit_tsa_password,
            host="127.0.0.1",
            port=0,
        )
        server.server_close()

    def test_wrong_environment_password_does_not_modify_existing_key(
        self,
        tmp_path,
        monkeypatch,
    ):
        tsa_dir = tmp_path / "wrong-password"
        key_path, cert_path = ensure_tsa_credentials(tsa_dir)
        original_key = key_path.read_bytes()
        monkeypatch.setenv(
            "ENC_ENVELOPE_TSA_KEY_PASSWORD",
            "wrong-test-password",
        )

        with pytest.raises(TSAError) as exc_info:
            create_tsa_server(
                key_path,
                cert_path,
                host="127.0.0.1",
                port=0,
            )

        assert "wrong-test-password" not in str(exc_info.value)
        assert key_path.read_bytes() == original_key


# ---------------------------------------------------------------------------
# Tests: error handling
# ---------------------------------------------------------------------------


class TestTSAErrors:
    """TSA client error handling."""

    def test_empty_url_raises(self) -> None:
        with pytest.raises(TSAError, match="URL"):
            request_timestamp(hashlib.sha256(b"x").digest(), "")

    def test_invalid_tst_token_raises(self) -> None:
        with pytest.raises(TSAError):
            verify_timestamp(b"not-a-token", "dummy.pem")
