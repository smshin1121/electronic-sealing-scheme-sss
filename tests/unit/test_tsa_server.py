"""Unit tests for TSA server and client functionality.

Validates:
  - TSA server creation and client timestamp request/response
  - genTime is close to current time
  - Function signature and structural tests (fallback when server unavailable)
"""

from __future__ import annotations

import hashlib
import inspect
import re
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


def _stop_registered_server(port: int) -> None:
    """Shut down a server that ``ensure_tsa_server_running`` registered."""
    from desktop.signature import tsa_server

    with tsa_server._SERVER_LOCK:
        running = tsa_server._RUNNING_SERVERS.pop(("127.0.0.1", port), None)
    if running is not None:
        server, thread = running
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

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

        # Port 0: the OS picks a free ephemeral port, so parallel test
        # processes on this machine can never share (or hijack) a port.
        server, thread = start_tsa_server_background(
            tsa_key_path=key_path,
            tsa_cert_path=cert_path,
            host="127.0.0.1",
            port=0,
        )
        port = server.server_address[1]

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

        server, thread = start_tsa_server_background(
            tsa_key_path=key_path,
            tsa_cert_path=cert_path,
            host="127.0.0.1",
            port=0,
        )
        port = server.server_address[1]

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
        server, thread = start_tsa_server_background(
            tsa_key_path=key_path,
            tsa_cert_path=cert_path,
            host="127.0.0.1",
            port=0,
        )
        port = server.server_address[1]

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
            port=0,
        )

        try:
            # Port 0 binds an ephemeral port; the URL names the bound one.
            match = re.fullmatch(r"http://127\.0\.0\.1:(\d+)/tsa", tsa_url)
            assert match is not None, tsa_url
            assert int(match.group(1)) != 0
            assert cert_path.is_file()

            data_hash = hashlib.sha256(b"bootstrap").digest()
            tst_token = request_timestamp(data_hash, tsa_url)
            gen_time = verify_timestamp(tst_token, str(cert_path))
            assert gen_time.tzinfo is not None
        finally:
            _stop_registered_server(int(match.group(1)) if match else 0)

    def test_ensure_tsa_server_running_port_zero_starts_a_fresh_server(
        self, tmp_path
    ):
        # Port 0 is "any free port": a second call never reuses a server
        # started for another credential directory.
        first_url, first_cert = ensure_tsa_server_running(
            tsa_dir=tmp_path / "tsa-first", host="127.0.0.1", port=0,
        )
        second_url, second_cert = ensure_tsa_server_running(
            tsa_dir=tmp_path / "tsa-second", host="127.0.0.1", port=0,
        )
        try:
            assert first_url != second_url
            data_hash = hashlib.sha256(b"second").digest()
            token = request_timestamp(data_hash, second_url)
            assert verify_timestamp(token, str(second_cert)).tzinfo is not None
        finally:
            for url in (first_url, second_url):
                _stop_registered_server(int(url.rsplit(":", 1)[1].split("/")[0]))

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
                port=0,
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


# ---------------------------------------------------------------------------
# Tests: token profile of the local TSA (stage E, E2b)
# ---------------------------------------------------------------------------


def _parse_token(token: bytes):
    """(SignedData, TSTInfo DER, TSTInfo, signed attributes by type name)."""
    from asn1crypto import cms, tsp

    signed_data = cms.ContentInfo.load(token)["content"]
    tst_der = signed_data["encap_content_info"]["content"].parsed.dump()
    signer = signed_data["signer_infos"][0]
    attrs = {attr["type"].native: attr["values"] for attr in signer["signed_attrs"]}
    return signed_data, tst_der, tsp.TSTInfo.load(tst_der), attrs


def _cert_asn1(path):
    from asn1crypto import x509 as asn1_x509
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return asn1_x509.Certificate.load(
        cert.public_bytes(serialization.Encoding.DER)
    )


class TestTokenProfileOutput:
    """The local TSA signs ESS attributes, its policy OID and its accuracy."""

    def test_token_carries_ess_signed_attributes(
        self, release_pki, release_tsa
    ) -> None:
        from pyhanko.sign.general import as_signing_certificate_v2

        token = request_timestamp(hashlib.sha256(b"ess").digest(), release_tsa)
        _signed, tst_der, _info, attrs = _parse_token(token)
        tsa_cert = _cert_asn1(release_pki.tsa_cert_path)

        assert set(attrs) == {
            "content_type", "message_digest", "signing_certificate_v2",
        }
        assert [v.native for v in attrs["content_type"]] == ["tst_info"]
        assert [v.native for v in attrs["message_digest"]] == [
            hashlib.sha256(tst_der).digest()
        ]
        (ess,) = attrs["signing_certificate_v2"]
        first = ess["certs"][0]
        assert first["hash_algorithm"]["algorithm"].native == "sha256"
        assert first["cert_hash"].native == hashlib.sha256(
            tsa_cert.dump()
        ).digest()
        serial = first["issuer_serial"]
        assert serial["serial_number"].native == tsa_cert.serial_number
        assert serial["issuer"][0].chosen == tsa_cert.issuer
        # An independent encoder (pyHanko) builds the same attribute value.
        assert ess.dump() == as_signing_certificate_v2(tsa_cert).dump()
        # The signature now covers the signed attributes; the existing
        # verifier handles that form.
        assert verify_timestamp(token, str(release_pki.tsa_cert_path)).tzinfo

    def test_default_policy_oid_and_accuracy(self, release_tsa) -> None:
        from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID

        token = request_timestamp(hashlib.sha256(b"dflt").digest(), release_tsa)
        info = _parse_token(token)[2]

        assert DEFAULT_TSA_POLICY_OID == "1.2.3.4.5.6.7.8.9"
        assert info["policy"].dotted == DEFAULT_TSA_POLICY_OID
        assert dict(info["accuracy"].native) == {
            "seconds": 1, "millis": None, "micros": None,
        }

    @pytest.mark.parametrize(
        "accuracy, expected",
        [
            ({"milliseconds": 250},
             {"seconds": None, "millis": 250, "micros": None}),
            ({"seconds": 2, "microseconds": 5},
             {"seconds": 2, "millis": None, "micros": 5}),
            ({}, {"seconds": 0, "millis": None, "micros": None}),
        ],
    )
    def test_configured_policy_oid_and_accuracy(
        self, release_pki, accuracy: dict, expected: dict
    ) -> None:
        from datetime import timedelta

        from tests.fixtures.release_pki import running_tsa

        with running_tsa(
            release_pki.tsa_key_path, release_pki.tsa_cert_path,
            policy_oid="1.2.3.4.5.6.7.8.10", accuracy=timedelta(**accuracy),
        ) as url:
            token = request_timestamp(hashlib.sha256(b"cfg").digest(), url)
        info = _parse_token(token)[2]

        assert info["policy"].dotted == "1.2.3.4.5.6.7.8.10"
        assert dict(info["accuracy"].native) == expected

    @pytest.mark.parametrize(
        "options",
        [
            {"policy_oid": "1.2.x"},
            {"policy_oid": "3.1"},
            {"policy_oid": ""},
            {"accuracy": "1s"},
        ],
    )
    def test_invalid_server_options_are_refused(
        self, release_pki, options: dict
    ) -> None:
        from tests.fixtures.release_pki import TSA_KEY_PASSWORD

        with pytest.raises(TSAError):
            create_tsa_server(
                release_pki.tsa_key_path, release_pki.tsa_cert_path,
                key_password=TSA_KEY_PASSWORD, host="127.0.0.1", port=0,
                **options,
            )

    def test_negative_accuracy_is_refused(self, release_pki) -> None:
        from datetime import timedelta

        from tests.fixtures.release_pki import TSA_KEY_PASSWORD

        with pytest.raises(TSAError, match="accuracy"):
            create_tsa_server(
                release_pki.tsa_key_path, release_pki.tsa_cert_path,
                key_password=TSA_KEY_PASSWORD, host="127.0.0.1", port=0,
                accuracy=timedelta(seconds=-1),
            )

    def test_clock_seam_pins_gen_time(self, release_tsa, monkeypatch) -> None:
        from desktop.signature import tsa_server

        pinned = datetime(2026, 9, 28, 10, 0, 0, 1, tzinfo=timezone.utc)
        monkeypatch.setattr(tsa_server, "_utc_now", lambda: pinned)

        token = request_timestamp(hashlib.sha256(b"clk").digest(), release_tsa)

        assert _parse_token(token)[2]["gen_time"].native == pinned

    def test_pyhanko_validates_the_token_against_the_ca(
        self, release_pki, release_tsa
    ) -> None:
        import asyncio

        from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
        from pyhanko_certvalidator import ValidationContext

        digest = hashlib.sha256(b"pyhanko").digest()
        token = request_timestamp(digest, release_tsa)
        signed_data = _parse_token(token)[0]
        context = ValidationContext(
            trust_roots=[_cert_asn1(release_pki.ca_cert_path)]
        )

        status = asyncio.run(
            validate_tst_signed_data(signed_data, context, lambda _alg: digest)
        )

        assert status["intact"] is True
        assert status["valid"] is True
        assert status["trust_problem_indic"] is None

    def test_pades_timestamp_from_the_local_tsa_validates(
        self, release_pki, release_tsa, tmp_path
    ) -> None:
        import io

        from pyhanko.pdf_utils import generic
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.pdf_utils.writer import PdfFileWriter
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext

        from desktop.signature.pdf_signer import sign_pdf
        from tests.fixtures.release_pki import POLICY_KEY_PASSWORD

        writer = PdfFileWriter()
        writer.insert_page(generic.DictionaryObject({
            generic.NameObject("/Type"): generic.NameObject("/Page"),
            generic.NameObject("/MediaBox"): generic.ArrayObject(
                [generic.NumberObject(v) for v in (0, 0, 200, 200)]
            ),
        }))
        buffer = io.BytesIO()
        writer.write(buffer)
        pdf_in, pdf_out = tmp_path / "blank.pdf", tmp_path / "signed.pdf"
        pdf_in.write_bytes(buffer.getvalue())

        warning = sign_pdf(
            pdf_in, release_pki.policy_cert_path, release_pki.policy_key_path,
            POLICY_KEY_PASSWORD, pdf_out, tsa_url=release_tsa,
        )

        assert warning == ""
        ca = _cert_asn1(release_pki.ca_cert_path)
        with open(pdf_out, "rb") as handle:
            embedded = PdfFileReader(handle).embedded_signatures[0]
            status = validate_pdf_signature(
                embedded,
                signer_validation_context=ValidationContext(trust_roots=[ca]),
                ts_validation_context=ValidationContext(trust_roots=[ca]),
            )
        stamp = status.timestamp_validity
        assert stamp is not None
        assert (stamp.intact, stamp.valid, stamp.trusted) == (True, True, True)
