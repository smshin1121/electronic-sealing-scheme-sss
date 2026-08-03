"""X.509 certificate generation with custom OID extension for signature image hash.

Generates RSA key pairs and self-signed certificates binding a subject
to their handwritten signature image via a SHA-256 hash stored in a
custom certificate extension.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.x509 import (
    Certificate,
    CertificateBuilder,
    Name,
    NameAttribute,
)
from cryptography.x509.oid import NameOID

from .exceptions import CertificateError

logger = logging.getLogger(__name__)

# Custom OID for signature image SHA-256 hash binding
SIGNATURE_IMAGE_HASH_OID = x509.ObjectIdentifier("2.16.840.1.101.3.4.2.1.999.1")


def generate_keypair(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair.

    Args:
        key_size: RSA key size in bits. Defaults to 2048.

    Returns:
        Tuple of (private_key, public_key).

    Raises:
        CertificateError: If key generation fails.
    """
    if key_size < 2048:
        raise CertificateError(f"Key size must be >= 2048, got {key_size}")

    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()
        logger.info("RSA-%d key pair generated successfully", key_size)
        return private_key, public_key
    except Exception as exc:
        raise CertificateError(f"Failed to generate RSA key pair: {exc}") from exc


def _compute_signature_image_hash(signature_image_path: str | Path) -> str:
    """Compute SHA-256 hash of a signature image file.

    Args:
        signature_image_path: Path to the signature image.

    Returns:
        Hex-encoded SHA-256 hash string.

    Raises:
        CertificateError: If the file cannot be read.
    """
    path = Path(signature_image_path)
    if not path.exists():
        raise CertificateError(f"Signature image not found: {path}")

    try:
        sha256_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        logger.info("Signature image hash computed: %s...%s", sha256_hash[:8], sha256_hash[-8:])
        return sha256_hash
    except OSError as exc:
        raise CertificateError(f"Failed to read signature image: {exc}") from exc


def create_self_signed_cert(
    private_key: RSAPrivateKey,
    subject_name: str,
    email: str,
    signature_image_hash: str,
    validity_days: int = 365,
) -> Certificate:
    """Create a self-signed X.509 certificate with signature image hash extension.

    The certificate includes a custom OID extension containing the SHA-256
    hash of the subject's handwritten signature image, binding the certificate
    to a specific signing act.

    Args:
        private_key: RSA private key to sign the certificate.
        subject_name: Subject common name (e.g., suspect name).
        email: Subject email address.
        signature_image_hash: Hex-encoded SHA-256 hash of the signature image.
        validity_days: Certificate validity in days. Defaults to 365 (1 year).

    Returns:
        Self-signed X.509 certificate.

    Raises:
        CertificateError: If certificate creation fails.
    """
    if not subject_name or not email:
        raise CertificateError("Subject name and email are required")

    if not signature_image_hash or len(signature_image_hash) != 64:
        raise CertificateError(
            "signature_image_hash must be a 64-character hex SHA-256 digest"
        )

    try:
        now = datetime.now(timezone.utc)
        subject = issuer = Name([
            NameAttribute(NameOID.COMMON_NAME, subject_name),
            NameAttribute(NameOID.EMAIL_ADDRESS, email),
            NameAttribute(NameOID.ORGANIZATION_NAME, "Electronic Sealing Scheme (SSS)"),
        ])

        # Encode signature image hash as UTF-8 bytes for the custom extension
        sig_hash_bytes = signature_image_hash.encode("utf-8")

        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,  # non-repudiation
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    oid=SIGNATURE_IMAGE_HASH_OID,
                    value=sig_hash_bytes,
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        logger.info(
            "Self-signed certificate created for subject='%s', email='%s'",
            subject_name,
            email,
        )
        return cert

    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"Failed to create self-signed certificate: {exc}") from exc


def save_private_key(
    key: RSAPrivateKey,
    path: str | Path,
    password: str,
) -> None:
    """Save an RSA private key to a PEM file with password encryption.

    Args:
        key: RSA private key to save.
        path: Destination file path.
        password: Password for encrypting the key file.

    Raises:
        CertificateError: If the key cannot be saved.
    """
    if not password:
        raise CertificateError("Password is required for private key encryption")

    filepath = Path(path)

    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        pem_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode("utf-8")
            ),
        )
        filepath.write_bytes(pem_bytes)
        logger.info("Private key saved to %s", filepath)
    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"Failed to save private key: {exc}") from exc


def save_certificate(cert: Certificate, path: str | Path) -> None:
    """Save an X.509 certificate to a PEM file.

    Args:
        cert: X.509 certificate to save.
        path: Destination file path.

    Raises:
        CertificateError: If the certificate cannot be saved.
    """
    filepath = Path(path)

    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        filepath.write_bytes(pem_bytes)
        logger.info("Certificate saved to %s", filepath)
    except Exception as exc:
        raise CertificateError(f"Failed to save certificate: {exc}") from exc


def load_private_key(
    path: str | Path,
    password: str,
) -> RSAPrivateKey:
    """Load an RSA private key from a password-encrypted PEM file.

    Args:
        path: Path to the PEM file.
        password: Decryption password.

    Returns:
        RSA private key.

    Raises:
        CertificateError: If loading fails.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise CertificateError(f"Private key file not found: {filepath}")

    try:
        key = serialization.load_pem_private_key(
            filepath.read_bytes(),
            password=password.encode("utf-8"),
        )
        if not isinstance(key, RSAPrivateKey):
            raise CertificateError("Loaded key is not an RSA private key")
        return key
    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"Failed to load private key: {exc}") from exc


def load_certificate(path: str | Path) -> Certificate:
    """Load an X.509 certificate from a PEM file.

    Args:
        path: Path to the PEM file.

    Returns:
        X.509 certificate.

    Raises:
        CertificateError: If loading fails.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise CertificateError(f"Certificate file not found: {filepath}")

    try:
        cert = x509.load_pem_x509_certificate(filepath.read_bytes())
        return cert
    except Exception as exc:
        raise CertificateError(f"Failed to load certificate: {exc}") from exc
