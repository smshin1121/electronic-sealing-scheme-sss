"""RFC 3161 compatible lightweight HTTP TSA server.

Provides a minimal Time Stamping Authority that accepts TSQ requests
via HTTP POST and returns TSR responses with signed TST tokens.
Uses system time (assumes NTP synchronization) and auto-incrementing
serial numbers.

Token profile (stage E, E2b): the SignerInfo carries signed attributes
(content-type id-ct-TSTInfo, message-digest of the TSTInfo, and an ESS
signing-certificate-v2 attribute naming the TSA certificate by its
SHA-256 hash, RFC 5816) and the RSA PKCS#1 v1.5 signature covers those
attributes. Every TSTInfo carries the TSA policy OID and an accuracy;
both are server parameters (defaults :data:`DEFAULT_TSA_POLICY_OID` and
:data:`DEFAULT_TSA_ACCURACY`).

Requests (Fable gate, finding 8): the body is read only when Content-Length
is a decimal byte count from 1 to :data:`MAX_TSQ_BYTES`; a larger one is
answered HTTP 413, a missing (chunked), malformed or zero one HTTP 400,
without reading the body. A body that is not a TimeStampReq is answered
with a rejection TSR (``bad_request``). There is no read timeout: a client
that declares a length and sends less holds one handler thread (a
reference component on loopback).
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from asn1crypto import algos, cms, core, tsp, x509 as asn1_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, load_pem_x509_certificate

from .exceptions import TSAError
from .tsa_profile import TimeStampResponse, is_dotted_oid

logger = logging.getLogger(__name__)

# Policy OID of the local TSA. A placeholder, not a registered OID: a
# deployment pins the policy OID its own TSA asserts (on the release host,
# RELEASE_TSA_POLICY_OID), whatever that TSA is.
DEFAULT_TSA_POLICY_OID = "1.2.3.4.5.6.7.8.9"
# Accuracy the local TSA asserts around genTime (RFC 3161 section 2.4.2).
DEFAULT_TSA_ACCURACY = timedelta(seconds=1)
# Largest request body read (Fable gate, finding 8). A TimeStampReq is
# about a hundred bytes (imprint, nonce, certReq; a policy or extensions
# add little); a larger or undeclared length is refused unread.
MAX_TSQ_BYTES = 16 * 1024
_DEFAULT_TSA_DIR = Path.home() / ".enc_envelope" / "tsa"
_TSA_KEY_PASSWORD_ENV = "ENC_ENVELOPE_TSA_KEY_PASSWORD"  # public-config-key
_TSA_CA_KEY_PASSWORD_ENV = "ENC_ENVELOPE_TSA_CA_KEY_PASSWORD"  # public-config-key
_SERVER_LOCK = threading.Lock()
_RUNNING_SERVERS: dict[tuple[str, int], tuple[HTTPServer, threading.Thread]] = {}


def _resolve_credential_password(
    explicit: str | None,
    *,
    env_name: str,
    label: str,
) -> str:
    """Resolve a credential password without a built-in fallback.

    Explicit arguments take precedence so callers can use an external secret
    provider without mutating process state. Otherwise the value is read at
    call time, which also keeps test and launcher configuration predictable.
    """
    value = explicit if explicit is not None else os.environ.get(env_name)
    if not value:
        raise TSAError(
            f"{label} password is required; pass it explicitly or set "
            f"{env_name}"
        )
    return value


def _utc_now() -> datetime:
    """The TSA clock: system UTC time (assumed NTP-synchronised).

    Test seam only: tests monkeypatch this module-level function to pin
    genTime. Production code never replaces it.
    """
    return datetime.now(timezone.utc)


def _validated_options(policy_oid: str, accuracy: timedelta) -> None:
    """Refuse a malformed policy OID or accuracy before serving (fail early)."""
    if not is_dotted_oid(policy_oid):
        raise TSAError(f"TSA policy OID is not a dotted OID: {policy_oid!r}")
    if not isinstance(accuracy, timedelta) or accuracy < timedelta(0):
        raise TSAError("TSA accuracy must be a non-negative timedelta")


def _accuracy_value(accuracy: timedelta) -> tsp.Accuracy:
    """RFC 3161 Accuracy: whole seconds, then millis and micros (1..999).

    Zero components are omitted, as the ASN.1 ranges require; a zero
    accuracy is sent as ``seconds 0`` so the field is never empty.
    """
    micros_total = accuracy // timedelta(microseconds=1)
    seconds, rest = divmod(micros_total, 1_000_000)
    millis, micros = divmod(rest, 1_000)
    fields: dict[str, int] = {}
    if seconds or not rest:
        fields["seconds"] = seconds
    if millis:
        fields["millis"] = millis
    if micros:
        fields["micros"] = micros
    return tsp.Accuracy(fields)


class _SerialCounter:
    """Thread-safe auto-incrementing serial number counter."""

    def __init__(self, start: int = 1) -> None:
        self._value = start
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            current = self._value
            self._value += 1
            return current


class _TSAContext:
    """Holds TSA server state: key, certificate, serial counter, profile."""

    def __init__(
        self,
        tsa_key: RSAPrivateKey,
        tsa_cert: Certificate,
        tsa_cert_der: bytes,
        *,
        policy_oid: str = DEFAULT_TSA_POLICY_OID,
        accuracy: timedelta = DEFAULT_TSA_ACCURACY,
    ) -> None:
        self.tsa_key = tsa_key
        self.tsa_cert = tsa_cert
        self.tsa_cert_der = tsa_cert_der
        self.policy_oid = policy_oid
        self.accuracy = accuracy
        self.serial_counter = _SerialCounter()


def _build_tst_info(
    message_imprint: tsp.MessageImprint,
    serial_number: int,
    gen_time: datetime,
    nonce: int | None = None,
    *,
    policy_oid: str = DEFAULT_TSA_POLICY_OID,
    accuracy: timedelta = DEFAULT_TSA_ACCURACY,
) -> tsp.TSTInfo:
    """Build a TSTInfo structure.

    Args:
        message_imprint: The hash from the TSQ.
        serial_number: Unique serial number for this token.
        gen_time: Timestamp generation time.
        nonce: The request nonce to echo, if the TSQ carried one.
        policy_oid: TSA policy under which the token is issued.
        accuracy: Accuracy asserted around genTime (always emitted).

    Returns:
        TSTInfo ASN.1 structure.
    """
    tst_info = {
        "version": "v1",
        "policy": policy_oid,
        "message_imprint": message_imprint,
        "serial_number": serial_number,
        "gen_time": gen_time,
        "accuracy": _accuracy_value(accuracy),
        "ordering": False,
    }
    if nonce is not None:
        tst_info["nonce"] = nonce
    return tsp.TSTInfo(tst_info)


def _cms_attribute(name: str, value: object) -> cms.CMSAttribute:
    """A single-valued CMS attribute."""
    return cms.CMSAttribute({
        "type": cms.CMSAttributeType(name),
        "values": [value],
    })


def _signing_certificate_v2(
    cert_asn1: asn1_x509.Certificate,
) -> tsp.SigningCertificateV2:
    """ESS signing-certificate-v2 (RFC 5035/5816) naming the TSA certificate.

    ESSCertIDv2 with SHA-256 (the DEFAULT hash algorithm, so DER omits it)
    over the certificate DER, plus issuerSerial.
    """
    return tsp.SigningCertificateV2({
        "certs": [tsp.ESSCertIDv2({
            "cert_hash": hashlib.sha256(cert_asn1.dump()).digest(),
            "issuer_serial": tsp.IssuerSerial({
                "issuer": [
                    asn1_x509.GeneralName({"directory_name": cert_asn1.issuer}),
                ],
                "serial_number": cert_asn1.serial_number,
            }),
        })],
    })


def _signed_attributes(
    tst_info_bytes: bytes, cert_asn1: asn1_x509.Certificate
) -> cms.CMSAttributes:
    """content-type, message-digest and signing-certificate-v2 (DER SET OF)."""
    return cms.CMSAttributes([
        _cms_attribute("content_type", cms.ContentType("tst_info")),
        _cms_attribute("message_digest", hashlib.sha256(tst_info_bytes).digest()),
        _cms_attribute("signing_certificate_v2", _signing_certificate_v2(cert_asn1)),
    ])


def _sign_tst_info(
    tst_info_bytes: bytes,
    tsa_key: RSAPrivateKey,
    tsa_cert_der: bytes,
) -> bytes:
    """Create a CMS SignedData wrapping the TSTInfo.

    The signature covers the DER encoding of the signed attributes
    (RFC 5652 section 5.4), whose message-digest binds the TSTInfo.

    Args:
        tst_info_bytes: DER-encoded TSTInfo.
        tsa_key: TSA private key for signing.
        tsa_cert_der: DER-encoded TSA certificate.

    Returns:
        DER-encoded ContentInfo (SignedData) bytes.
    """
    cert_asn1 = asn1_x509.Certificate.load(tsa_cert_der)
    signed_attrs = _signed_attributes(tst_info_bytes, cert_asn1)
    signature = tsa_key.sign(
        signed_attrs.dump(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": cert_asn1.issuer,
                "serial_number": cert_asn1.serial_number,
            }),
        }),
        "digest_algorithm": algos.DigestAlgorithm({
            "algorithm": "sha256",
        }),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({
            "algorithm": "sha256_rsa",
        }),
        "signature": signature,
    })

    # Build SignedData with EncapsulatedContentInfo (not ContentInfo)
    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [
            algos.DigestAlgorithm({"algorithm": "sha256"}),
        ],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": core.ParsableOctetString(tst_info_bytes),
        }),
        "certificates": [
            cms.CertificateChoices({"certificate": cert_asn1}),
        ],
        "signer_infos": [signer_info],
    })

    # Wrap in ContentInfo
    content_info = cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    })

    return content_info.dump()


def _process_tsq(tsq_bytes: bytes, ctx: _TSAContext) -> bytes:
    """Process a TSQ and return a TSR.

    Args:
        tsq_bytes: DER-encoded TimeStampReq bytes.
        ctx: TSA server context.

    Returns:
        DER-encoded TimeStampResp bytes.
    """
    try:
        tsq = tsp.TimeStampReq.load(tsq_bytes)
    except Exception as exc:
        logger.error("Failed to parse TSQ: %s", exc)
        return _build_error_tsr("bad_request")

    message_imprint = tsq["message_imprint"]
    nonce = tsq["nonce"].native if "nonce" in tsq and tsq["nonce"].native is not None else None
    serial = ctx.serial_counter.next()
    gen_time = _utc_now()

    tst_info = _build_tst_info(
        message_imprint, serial, gen_time, nonce=nonce,
        policy_oid=ctx.policy_oid, accuracy=ctx.accuracy,
    )
    tst_info_bytes = tst_info.dump()

    try:
        tst_token_bytes = _sign_tst_info(
            tst_info_bytes, ctx.tsa_key, ctx.tsa_cert_der
        )
    except Exception as exc:
        logger.error("Failed to sign TST: %s", exc)
        return _build_error_tsr("system_failure")

    # Build success TSR
    tst_token = cms.ContentInfo.load(tst_token_bytes)
    tsr = tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({
            "status": "granted",
        }),
        "time_stamp_token": tst_token,
    })

    logger.info(
        "TST issued: serial=%d, genTime=%s",
        serial, gen_time.isoformat(),
    )
    return tsr.dump()


def _build_error_tsr(fail_reason: str) -> bytes:
    """Build an error TimeStampResp.

    PKIFailureInfo is a BIT STRING of named bits, so asn1crypto takes the
    set of set bits, and the reply carries no token, which asn1crypto's own
    TimeStampResp cannot encode. Before the Fable gate round both failed,
    and a malformed request closed the connection without an answer.

    Args:
        fail_reason: One of the PKIFailureInfo values.

    Returns:
        DER-encoded error TSR bytes.
    """
    tsr = TimeStampResponse({  # token OPTIONAL, unlike tsp.TimeStampResp
        "status": tsp.PKIStatusInfo({
            "status": "rejection",
            "fail_info": {fail_reason},
        }),
    })
    return tsr.dump()


def _load_tsa_credentials(
    tsa_key_path: str | Path,
    tsa_cert_path: str | Path,
    key_password: str,
    *,
    policy_oid: str = DEFAULT_TSA_POLICY_OID,
    accuracy: timedelta = DEFAULT_TSA_ACCURACY,
) -> _TSAContext:
    """Load TSA key and certificate from PEM files.

    Args:
        tsa_key_path: Path to the TSA private key PEM file.
        tsa_cert_path: Path to the TSA certificate PEM file.
        key_password: Password for the encrypted key file.
        policy_oid: TSA policy OID written into every TSTInfo.
        accuracy: Accuracy written into every TSTInfo.

    Returns:
        _TSAContext with loaded credentials.

    Raises:
        TSAError: If loading fails.
    """
    key_path = Path(tsa_key_path)
    cert_path = Path(tsa_cert_path)

    if not key_path.exists():
        raise TSAError(f"TSA key file not found: {key_path}")
    if not cert_path.exists():
        raise TSAError(f"TSA cert file not found: {cert_path}")

    try:
        key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=key_password.encode("utf-8"),
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TSAError("TSA key is not an RSA private key")

        cert = load_pem_x509_certificate(cert_path.read_bytes())
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        return _TSAContext(
            tsa_key=key, tsa_cert=cert, tsa_cert_der=cert_der,
            policy_oid=policy_oid, accuracy=accuracy,
        )

    except TSAError:
        raise
    except Exception as exc:
        raise TSAError(f"Failed to load TSA credentials: {exc}") from exc


def _request_length(header: Optional[str]) -> tuple[int, Optional[tuple[int, str]]]:
    """The TSQ length to read, or the HTTP error that refuses the request.

    Only ASCII digits from 1 to :data:`MAX_TSQ_BYTES` are accepted. A
    missing length (chunked requests included), a malformed, signed or zero
    one is 400; a larger one is 413. The body is not read in either case.
    """
    text = (header or "").strip()
    if not (text.isascii() and text.isdigit()):
        return 0, (400, "Content-Length with a decimal byte count required")
    length = int(text)
    if length == 0:
        return 0, (400, "Empty request body")
    if length > MAX_TSQ_BYTES:
        return 0, (413, f"Request body larger than {MAX_TSQ_BYTES} bytes")
    return length, None


class _TSARequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the TSA endpoint."""

    # Set by the server instance
    tsa_context: _TSAContext

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/tsa":
            self.send_error(404, "Not Found")
            return

        content_length, refusal = _request_length(
            self.headers.get("Content-Length")
        )
        if refusal is not None:
            # The body is never read, so the connection cannot be reused.
            self.close_connection = True
            self.send_error(*refusal)
            return

        tsq_bytes = self.rfile.read(content_length)

        tsr_bytes = _process_tsq(tsq_bytes, self.tsa_context)

        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(tsr_bytes)))
        self.end_headers()
        self.wfile.write(tsr_bytes)

    def log_message(self, format: str, *args: object) -> None:
        """Route HTTP server logs to the module logger."""
        logger.debug(format, *args)


def create_tsa_server(
    tsa_key_path: str | Path,
    tsa_cert_path: str | Path,
    key_password: str | None = None,
    host: str = "127.0.0.1",
    port: int = 3161,
    *,
    policy_oid: str = DEFAULT_TSA_POLICY_OID,
    accuracy: timedelta = DEFAULT_TSA_ACCURACY,
) -> HTTPServer:
    """Create an RFC 3161 compatible HTTP TSA server.

    The server handles ``POST /tsa`` requests containing DER-encoded
    TimeStampReq and returns DER-encoded TimeStampResp.

    Args:
        tsa_key_path: Path to the TSA private key PEM file.
        tsa_cert_path: Path to the TSA certificate PEM file.
        key_password: Password for the encrypted key file.
        host: Bind address. Defaults to localhost.
        port: Bind port. Defaults to 3161; 0 binds an ephemeral port
            (read it from ``server.server_address[1]``).
        policy_oid: TSA policy OID asserted in every token (dotted form).
        accuracy: Accuracy asserted in every token (non-negative).

    Returns:
        HTTPServer instance (call ``serve_forever()`` to start).

    Raises:
        TSAError: If an option is malformed, credentials cannot be loaded
            or server creation fails.
    """
    _validated_options(policy_oid, accuracy)
    resolved_password = _resolve_credential_password(
        key_password,
        env_name=_TSA_KEY_PASSWORD_ENV,
        label="TSA key",
    )
    ctx = _load_tsa_credentials(
        tsa_key_path,
        tsa_cert_path,
        resolved_password,
        policy_oid=policy_oid,
        accuracy=accuracy,
    )

    # Create a handler class bound to this context
    handler_class = type(
        "BoundTSAHandler",
        (_TSARequestHandler,),
        {"tsa_context": ctx},
    )

    try:
        # ThreadingHTTPServer handles each request on its own daemon
        # thread so concurrent TSQ requests don't serialize.
        server = ThreadingHTTPServer((host, port), handler_class)
        logger.info("TSA server created at http://%s:%d/tsa", host,
                    server.server_address[1])
        return server
    except Exception as exc:
        raise TSAError(f"Failed to create TSA server: {exc}") from exc


def run_tsa_server(
    tsa_key_path: str | Path,
    tsa_cert_path: str | Path,
    key_password: str | None = None,
    host: str = "127.0.0.1",
    port: int = 3161,
    *,
    policy_oid: str = DEFAULT_TSA_POLICY_OID,
    accuracy: timedelta = DEFAULT_TSA_ACCURACY,
) -> None:
    """Create and run the TSA server (blocking).

    Args:
        tsa_key_path: Path to the TSA private key PEM file.
        tsa_cert_path: Path to the TSA certificate PEM file.
        key_password: Password for the encrypted key file.
        host: Bind address. Defaults to localhost.
        port: Bind port. Defaults to 3161.
        policy_oid: TSA policy OID asserted in every token.
        accuracy: Accuracy asserted in every token.
    """
    server = create_tsa_server(
        tsa_key_path, tsa_cert_path, key_password, host, port,
        policy_oid=policy_oid, accuracy=accuracy,
    )
    logger.info("TSA server starting on http://%s:%d/tsa", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("TSA server shutting down")
    finally:
        server.server_close()


def start_tsa_server_background(
    tsa_key_path: str | Path,
    tsa_cert_path: str | Path,
    key_password: str | None = None,
    host: str = "127.0.0.1",
    port: int = 3161,
    *,
    policy_oid: str = DEFAULT_TSA_POLICY_OID,
    accuracy: timedelta = DEFAULT_TSA_ACCURACY,
) -> tuple[HTTPServer, threading.Thread]:
    """Start the TSA server in a background daemon thread.

    Args:
        tsa_key_path: Path to the TSA private key PEM file.
        tsa_cert_path: Path to the TSA certificate PEM file.
        key_password: Password for the encrypted key file.
        host: Bind address. Defaults to localhost.
        port: Bind port. Defaults to 3161; 0 binds an ephemeral port.
        policy_oid: TSA policy OID asserted in every token.
        accuracy: Accuracy asserted in every token.

    Returns:
        Tuple of (server, thread). Call ``server.shutdown()`` to stop.
    """
    server = create_tsa_server(
        tsa_key_path, tsa_cert_path, key_password, host, port,
        policy_oid=policy_oid, accuracy=accuracy,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        name="tsa-server",
        daemon=True,
    )
    thread.start()
    logger.info("TSA server started in background on http://%s:%d/tsa", host,
                server.server_address[1])
    return server, thread


def ensure_tsa_credentials(
    tsa_dir: str | Path | None = None,
    *,
    ca_key_password: str | None = None,
    tsa_key_password: str | None = None,
) -> tuple[Path, Path]:
    """Create TSA credentials on first run and return their paths."""
    from .ca_setup import create_ca, issue_tsa_cert, save_tsa_credentials

    base_dir = Path(tsa_dir) if tsa_dir is not None else _DEFAULT_TSA_DIR
    key_path = base_dir / "tsa_key.pem"
    cert_path = base_dir / "tsa_cert.pem"

    if key_path.exists() and cert_path.exists():
        return key_path, cert_path

    resolved_ca_password = _resolve_credential_password(
        ca_key_password,
        env_name=_TSA_CA_KEY_PASSWORD_ENV,
        label="TSA CA key",
    )
    resolved_tsa_password = _resolve_credential_password(
        tsa_key_password,
        env_name=_TSA_KEY_PASSWORD_ENV,
        label="TSA key",
    )

    ca_dir = base_dir / "ca"
    ca_key, ca_cert = create_ca(
        ca_dir,
        ca_key_password=resolved_ca_password,
    )
    tsa_key, tsa_cert = issue_tsa_cert(ca_key, ca_cert)
    save_tsa_credentials(
        tsa_key,
        tsa_cert,
        base_dir,
        key_password=resolved_tsa_password,
    )
    return key_path, cert_path


def ensure_tsa_server_running(
    tsa_dir: str | Path | None = None,
    *,
    host: str = "127.0.0.1",
    port: int = 3161,
    ca_key_password: str | None = None,
    tsa_key_password: str | None = None,
) -> tuple[str, Path]:
    """Ensure a local TSA server is running and return its URL and cert path.

    A server already started by this process for ``(host, port)`` is
    reused. ``port=0`` means "any free port": a new server is started on
    an ephemeral port on every call (never a reuse, since the credentials
    of another call may differ), registered under the port actually
    bound, and the returned URL names that port.
    """
    resolved_tsa_password = _resolve_credential_password(
        tsa_key_password,
        env_name=_TSA_KEY_PASSWORD_ENV,
        label="TSA key",
    )
    key_path, cert_path = ensure_tsa_credentials(
        tsa_dir,
        ca_key_password=ca_key_password,
        tsa_key_password=resolved_tsa_password,
    )

    with _SERVER_LOCK:
        running = _RUNNING_SERVERS.get((host, port)) if port else None
        if running is not None:
            server, thread = running
            if thread.is_alive():
                return f"http://{host}:{port}/tsa", cert_path
            _RUNNING_SERVERS.pop((host, port), None)

        server, thread = start_tsa_server_background(
            tsa_key_path=key_path,
            tsa_cert_path=cert_path,
            key_password=resolved_tsa_password,
            host=host,
            port=port,
        )
        bound_port = int(server.server_address[1])
        _RUNNING_SERVERS[(host, bound_port)] = (server, thread)

    return f"http://{host}:{bound_port}/tsa", cert_path
