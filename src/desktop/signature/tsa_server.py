"""RFC 3161 compatible lightweight HTTP TSA server.

Provides a minimal Time Stamping Authority that accepts TSQ requests
via HTTP POST and returns TSR responses with signed TST tokens.
Uses system time (assumes NTP synchronization) and auto-incrementing
serial numbers.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from asn1crypto import algos, cms, core, tsp, x509 as asn1_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, load_pem_x509_certificate

from .exceptions import TSAError

logger = logging.getLogger(__name__)

# TSA policy OID (custom for this system)
_TSA_POLICY_OID = "1.2.3.4.5.6.7.8.9"
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
    """Holds TSA server state: key, certificate, serial counter."""

    def __init__(
        self,
        tsa_key: RSAPrivateKey,
        tsa_cert: Certificate,
        tsa_cert_der: bytes,
    ) -> None:
        self.tsa_key = tsa_key
        self.tsa_cert = tsa_cert
        self.tsa_cert_der = tsa_cert_der
        self.serial_counter = _SerialCounter()


def _build_tst_info(
    message_imprint: tsp.MessageImprint,
    serial_number: int,
    gen_time: datetime,
    nonce: int | None = None,
) -> tsp.TSTInfo:
    """Build a TSTInfo structure.

    Args:
        message_imprint: The hash from the TSQ.
        serial_number: Unique serial number for this token.
        gen_time: Timestamp generation time.

    Returns:
        TSTInfo ASN.1 structure.
    """
    tst_info = {
        "version": "v1",
        "policy": _TSA_POLICY_OID,
        "message_imprint": message_imprint,
        "serial_number": serial_number,
        "gen_time": gen_time,
        "accuracy": tsp.Accuracy({
            "seconds": 1,
        }),
        "ordering": False,
    }
    if nonce is not None:
        tst_info["nonce"] = nonce
    return tsp.TSTInfo(tst_info)


def _sign_tst_info(
    tst_info_bytes: bytes,
    tsa_key: RSAPrivateKey,
    tsa_cert_der: bytes,
) -> bytes:
    """Create a CMS SignedData wrapping the TSTInfo.

    Args:
        tst_info_bytes: DER-encoded TSTInfo.
        tsa_key: TSA private key for signing.
        tsa_cert_der: DER-encoded TSA certificate.

    Returns:
        DER-encoded ContentInfo (SignedData) bytes.
    """
    # Compute digest of the TSTInfo
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tst_info_bytes)
    tst_digest = digest.finalize()

    # Sign the TSTInfo
    signature = tsa_key.sign(
        tst_info_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    # Parse the TSA certificate for ASN.1 fields
    cert_asn1 = asn1_x509.Certificate.load(tsa_cert_der)
    issuer = cert_asn1["tbs_certificate"]["issuer"]
    serial = cert_asn1["tbs_certificate"]["serial_number"]

    # Build SignerInfo
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": issuer,
                "serial_number": serial,
            }),
        }),
        "digest_algorithm": algos.DigestAlgorithm({
            "algorithm": "sha256",
        }),
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
    gen_time = datetime.now(timezone.utc)

    tst_info = _build_tst_info(message_imprint, serial, gen_time, nonce=nonce)
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

    Args:
        fail_reason: One of the PKIFailureInfo values.

    Returns:
        DER-encoded error TSR bytes.
    """
    tsr = tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({
            "status": "rejection",
            "fail_info": fail_reason,
        }),
    })
    return tsr.dump()


def _load_tsa_credentials(
    tsa_key_path: str | Path,
    tsa_cert_path: str | Path,
    key_password: str,
) -> _TSAContext:
    """Load TSA key and certificate from PEM files.

    Args:
        tsa_key_path: Path to the TSA private key PEM file.
        tsa_cert_path: Path to the TSA certificate PEM file.
        key_password: Password for the encrypted key file.

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

        return _TSAContext(tsa_key=key, tsa_cert=cert, tsa_cert_der=cert_der)

    except TSAError:
        raise
    except Exception as exc:
        raise TSAError(f"Failed to load TSA credentials: {exc}") from exc


class _TSARequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the TSA endpoint."""

    # Set by the server instance
    tsa_context: _TSAContext

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/tsa":
            self.send_error(404, "Not Found")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self.send_error(400, "Empty request body")
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
) -> HTTPServer:
    """Create an RFC 3161 compatible HTTP TSA server.

    The server handles ``POST /tsa`` requests containing DER-encoded
    TimeStampReq and returns DER-encoded TimeStampResp.

    Args:
        tsa_key_path: Path to the TSA private key PEM file.
        tsa_cert_path: Path to the TSA certificate PEM file.
        key_password: Password for the encrypted key file.
        host: Bind address. Defaults to localhost.
        port: Bind port. Defaults to 3161.

    Returns:
        HTTPServer instance (call ``serve_forever()`` to start).

    Raises:
        TSAError: If credentials cannot be loaded or server creation fails.
    """
    resolved_password = _resolve_credential_password(
        key_password,
        env_name=_TSA_KEY_PASSWORD_ENV,
        label="TSA key",
    )
    ctx = _load_tsa_credentials(
        tsa_key_path,
        tsa_cert_path,
        resolved_password,
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
        logger.info("TSA server created at http://%s:%d/tsa", host, port)
        return server
    except Exception as exc:
        raise TSAError(f"Failed to create TSA server: {exc}") from exc


def run_tsa_server(
    tsa_key_path: str | Path,
    tsa_cert_path: str | Path,
    key_password: str | None = None,
    host: str = "127.0.0.1",
    port: int = 3161,
) -> None:
    """Create and run the TSA server (blocking).

    Args:
        tsa_key_path: Path to the TSA private key PEM file.
        tsa_cert_path: Path to the TSA certificate PEM file.
        key_password: Password for the encrypted key file.
        host: Bind address. Defaults to localhost.
        port: Bind port. Defaults to 3161.
    """
    server = create_tsa_server(
        tsa_key_path, tsa_cert_path, key_password, host, port
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
) -> tuple[HTTPServer, threading.Thread]:
    """Start the TSA server in a background daemon thread.

    Args:
        tsa_key_path: Path to the TSA private key PEM file.
        tsa_cert_path: Path to the TSA certificate PEM file.
        key_password: Password for the encrypted key file.
        host: Bind address. Defaults to localhost.
        port: Bind port. Defaults to 3161.

    Returns:
        Tuple of (server, thread). Call ``server.shutdown()`` to stop.
    """
    server = create_tsa_server(
        tsa_key_path, tsa_cert_path, key_password, host, port
    )
    thread = threading.Thread(
        target=server.serve_forever,
        name="tsa-server",
        daemon=True,
    )
    thread.start()
    logger.info("TSA server started in background on http://%s:%d/tsa", host, port)
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
    """Ensure a local TSA server is running and return its URL and cert path."""
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
    server_key = (host, port)

    with _SERVER_LOCK:
        running = _RUNNING_SERVERS.get(server_key)
        if running is not None:
            server, thread = running
            if thread.is_alive():
                return f"http://{host}:{port}/tsa", cert_path
            _RUNNING_SERVERS.pop(server_key, None)

        server, thread = start_tsa_server_background(
            tsa_key_path=key_path,
            tsa_cert_path=cert_path,
            key_password=resolved_tsa_password,
            host=host,
            port=port,
        )
        _RUNNING_SERVERS[server_key] = (server, thread)

    return f"http://{host}:{port}/tsa", cert_path
