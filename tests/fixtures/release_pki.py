"""Synthetic PKI, TSA server and seal material for s3 release tests.

Everything here is test-only and generated in temporary directories:
an internal CA with a seal-policy signing certificate and a TSA
certificate, a second (untrusted) CA with its own policy certificate,
and a local RFC 3161 TSA server bound to an ephemeral loopback port.
No production credential or case data is used.
"""

from __future__ import annotations

import base64
import hashlib
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_CA_PASSWORD = "test-only-release-ca-password"  # public-test-fixture
TSA_KEY_PASSWORD = "test-only-release-tsa-password"  # public-test-fixture
POLICY_KEY_PASSWORD = "test-only-policy-key-password"  # public-test-fixture


@dataclass(frozen=True)
class ReleasePki:
    """Paths and objects of the synthetic release PKI."""

    root: Path
    ca_cert_path: Path
    ca_cert: x509.Certificate
    policy_key_path: Path
    policy_cert_path: Path
    tsa_key_path: Path
    tsa_cert_path: Path
    other_ca_cert_path: Path
    other_policy_key_path: Path
    other_policy_cert_path: Path
    ca_key: Any = field(repr=False)


def _write_key(key: Any, path: Path, password: str) -> None:
    """Write a password-encrypted PKCS#8 PEM private key."""
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode("utf-8")
            ),
        )
    )


def _write_cert(cert: x509.Certificate, path: Path) -> None:
    """Write a PEM certificate."""
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def build_release_pki(root: Path) -> ReleasePki:
    """Create the trusted CA, its policy/TSA certs, and an untrusted CA."""
    from desktop.signature.ca_setup import (
        create_ca,
        issue_policy_cert,
        issue_tsa_cert,
    )

    ca_key, ca_cert = create_ca(root / "ca", ca_key_password=_CA_PASSWORD)
    policy_key, policy_cert = issue_policy_cert(ca_key, ca_cert)
    tsa_key, tsa_cert = issue_tsa_cert(ca_key, ca_cert)

    other_key, other_cert = create_ca(
        root / "other_ca", ca_key_password=_CA_PASSWORD
    )
    other_policy_key, other_policy_cert = issue_policy_cert(
        other_key, other_cert
    )

    paths = {
        "policy_key": root / "policy_key.pem",
        "policy_cert": root / "policy_cert.pem",
        "tsa_key": root / "tsa_key.pem",
        "tsa_cert": root / "tsa_cert.pem",
        "other_policy_key": root / "other_policy_key.pem",
        "other_policy_cert": root / "other_policy_cert.pem",
    }
    _write_key(policy_key, paths["policy_key"], POLICY_KEY_PASSWORD)
    _write_cert(policy_cert, paths["policy_cert"])
    _write_key(tsa_key, paths["tsa_key"], TSA_KEY_PASSWORD)
    _write_cert(tsa_cert, paths["tsa_cert"])
    _write_key(other_policy_key, paths["other_policy_key"], POLICY_KEY_PASSWORD)
    _write_cert(other_policy_cert, paths["other_policy_cert"])

    return ReleasePki(
        root=root,
        ca_cert_path=root / "ca" / "ca_cert.pem",
        ca_cert=ca_cert,
        policy_key_path=paths["policy_key"],
        policy_cert_path=paths["policy_cert"],
        tsa_key_path=paths["tsa_key"],
        tsa_cert_path=paths["tsa_cert"],
        other_ca_cert_path=root / "other_ca" / "ca_cert.pem",
        other_policy_key_path=paths["other_policy_key"],
        other_policy_cert_path=paths["other_policy_cert"],
        ca_key=ca_key,
    )


def start_release_tsa(pki: ReleasePki) -> tuple[Any, threading.Thread, str]:
    """Start the local RFC 3161 TSA on an ephemeral loopback port."""
    from desktop.signature.tsa_server import create_tsa_server

    server = create_tsa_server(
        pki.tsa_key_path,
        pki.tsa_cert_path,
        key_password=TSA_KEY_PASSWORD,
        host="127.0.0.1",
        port=0,
    )
    thread = threading.Thread(
        target=server.serve_forever, name="release-test-tsa", daemon=True
    )
    thread.start()
    port = server.server_address[1]
    return server, thread, f"http://127.0.0.1:{port}/tsa"


@contextmanager
def running_tsa(
    key_path: Path,
    cert_path: Path,
    password: str = TSA_KEY_PASSWORD,
    **options: Any,
) -> Iterator[str]:
    """Run a local TSA on an ephemeral loopback port for one test.

    Yields the TSA URL and stops the server afterwards. ``options`` go to
    ``create_tsa_server`` (for example ``policy_oid`` or ``accuracy``).
    """
    from desktop.signature.tsa_server import create_tsa_server

    server = create_tsa_server(
        key_path, cert_path, key_password=password, host="127.0.0.1",
        port=0, **options,
    )
    thread = threading.Thread(
        target=server.serve_forever, name="test-tsa", daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/tsa"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def running_unauthorized_endpoint() -> Iterator[int]:
    """A loopback HTTP endpoint that answers every POST with 401.

    Yields its port. Stands for a TSA that requires credentials, so tests
    can check that credentials in the TSA URL never reach logs or audit.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _Unauthorized(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Unauthorized)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def write_tsa_credentials(
    directory: Path, key: Any, cert: x509.Certificate
) -> tuple[Path, Path]:
    """Write a TSA key (TSA_KEY_PASSWORD) and certificate for a test server."""
    directory.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = directory / "tsa_key.pem", directory / "tsa_cert.pem"
    _write_key(key, key_path, TSA_KEY_PASSWORD)
    _write_cert(cert, cert_path)
    return key_path, cert_path


def load_tsa_key(pki: ReleasePki) -> Any:
    """The synthetic TSA's private key (for forged tokens in tests)."""
    return serialization.load_pem_private_key(
        pki.tsa_key_path.read_bytes(), password=TSA_KEY_PASSWORD.encode("utf-8")
    )


def tsa_trust_settings(pki: ReleasePki) -> dict[str, str]:
    """``make_release_app`` arguments for the pinned TSA trust profile.

    The synthetic CA issued the TSA certificate, and the local TSA asserts
    its default policy OID.
    """
    from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID

    return {
        "tsa_ca_cert_path": str(pki.ca_cert_path),
        "tsa_policy_oid": DEFAULT_TSA_POLICY_OID,
    }


def load_test_signer(pki: ReleasePki, *, other_ca: bool = False) -> Any:
    """Load the policy signer issued by the trusted (or untrusted) CA."""
    from desktop.signature.seal_policy import load_policy_signer

    if other_ca:
        return load_policy_signer(
            pki.other_policy_key_path,
            pki.other_policy_cert_path,
            POLICY_KEY_PASSWORD,
        )
    return load_policy_signer(
        pki.policy_key_path, pki.policy_cert_path, POLICY_KEY_PASSWORD
    )


def make_expired_signer(pki: ReleasePki, *, days_expired: int = 1) -> Any:
    """A policy signer whose certificate (trusted CA) has since expired.

    The signer's sealing-time lifetime check is disabled so historical
    material can be produced; the release host must still classify it.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    from desktop.signature.ca_setup import _build_policy_certificate
    from desktop.signature.seal_policy import PolicySigner

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=timezone.utc)
    cert = _build_policy_certificate(
        key, pki.ca_key, pki.ca_cert, "Expired Policy Signer (test)",
        now - timedelta(days=400), now - timedelta(days=days_expired),
    )
    return PolicySigner(
        cert=cert,
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private_key=key,
        release_window=None,
    )


def write_ca_bundle(pki: ReleasePki, path: Path) -> Path:
    """A pinned-CA bundle holding the other (older) CA and the trusted CA."""
    path.write_bytes(
        pki.other_ca_cert_path.read_bytes() + pki.ca_cert_path.read_bytes()
    )
    return path


def iso_z(moment: datetime) -> str:
    """Format a datetime in the record's ISO 8601 UTC ``Z`` form."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class SealMaterial:
    """One synthetic seal: key, shares, record and wrapped s3."""

    seal_id: str
    mode: str
    record: dict
    wrapped_s3: bytes
    shares: tuple[str, str, str, str] = field(repr=False)
    key_hex: str = field(repr=False)
    policy_digest: bytes | None = None

    @property
    def wrapped_s3_b64(self) -> str:
        """Base64 form of the wrapped s3, as sent by the sync payload."""
        return base64.b64encode(self.wrapped_s3).decode("ascii")


def make_seal_material(
    *,
    seal_id: str,
    master_key_path: str,
    signer: Any | None,
    mode: str = "standard",
    unlock_delta: timedelta = timedelta(days=-1),
    case_no: str = "2026-TL-001",
    unlock_time_iso: str | None = None,
    generation: int | None = None,
) -> SealMaterial:
    """Build a seal with a (signed or legacy) record and wrapped s3.

    ``unlock_time_iso`` sets the unlock time exactly (it may carry
    microseconds); otherwise it is now + ``unlock_delta`` in whole seconds.
    ``generation`` signs a version-2 policy of that generation (stage E,
    E2a); ``None`` keeps the stage D version-1 policy (generation 0).
    """
    from desktop.crypto import encrypt_envelope, split_key, split_key_strict
    from desktop.signature.seal_policy import attach_policy, s3_wrap_aad

    key_hex = os.urandom(32).hex()
    shares = split_key_strict(key_hex) if mode == "strict" else split_key(key_hex)
    record: dict = {
        "seal_id": seal_id,
        "seal_mode": mode,
        "unlock_time_iso": unlock_time_iso or iso_z(
            datetime.now(tz=timezone.utc) + unlock_delta
        ),
        "key_commitment": hashlib.sha256(bytes.fromhex(key_hex)).hexdigest(),
        "case_info": {"case_number": case_no},
    }
    digest: bytes | None = None
    if signer is not None:
        record, signed = attach_policy(record, signer, generation=generation)
        digest = signed.digest
        wrapped = encrypt_envelope(
            shares[2].encode("utf-8"),
            master_key_path,
            aad=s3_wrap_aad(seal_id, digest),
        )
    else:
        wrapped = encrypt_envelope(shares[2].encode("utf-8"), master_key_path)
    return SealMaterial(
        seal_id=seal_id,
        mode=mode,
        record=record,
        wrapped_s3=wrapped,
        shares=tuple(shares),
        key_hex=key_hex,
        policy_digest=digest,
    )
