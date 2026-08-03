"""Self-signed CA and TSA certificate issuance.

Creates a root CA key pair and certificate, then issues TSA-specific
certificates with the id-kp-timeStamping extended key usage.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .exceptions import CertificateError

logger = logging.getLogger(__name__)

_CA_VALIDITY_DAYS = 3650  # 10 years
_TSA_VALIDITY_DAYS = 365  # 1 year
_CA_KEY_SIZE = 4096
_TSA_KEY_SIZE = 2048


def create_ca(
    ca_dir: str | Path,
    ca_key_password: str,
) -> tuple[RSAPrivateKey, Certificate]:
    """Create a self-signed CA root key pair and certificate.

    The CA key and certificate are saved to ``ca_dir/ca_key.pem`` and
    ``ca_dir/ca_cert.pem`` respectively.

    Args:
        ca_dir: Directory to store CA key and certificate.
        ca_key_password: Password to encrypt the CA private key.

    Returns:
        Tuple of (CA private key, CA certificate).

    Raises:
        CertificateError: If CA creation fails.
    """
    if not ca_key_password:
        raise CertificateError("CA private-key password is required")

    ca_path = Path(ca_dir)

    try:
        ca_path.mkdir(parents=True, exist_ok=True)

        # Generate CA key pair
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_CA_KEY_SIZE,
        )

        now = datetime.now(timezone.utc)
        ca_subject = ca_issuer = Name([
            NameAttribute(NameOID.COMMON_NAME, "Digital Evidence Sealing CA"),
            NameAttribute(NameOID.ORGANIZATION_NAME, "Electronic Sealing Scheme (SSS)"),
            NameAttribute(NameOID.COUNTRY_NAME, "KR"),
        ])

        ca_cert = (
            CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_issuer)
            .public_key(ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=_CA_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    ca_private_key.public_key()
                ),
                critical=False,
            )
            .sign(ca_private_key, hashes.SHA256())
        )

        # Save CA key (password-encrypted)
        ca_key_path = ca_path / "ca_key.pem"
        ca_key_path.write_bytes(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    ca_key_password.encode("utf-8")
                ),
            )
        )

        # Save CA certificate
        ca_cert_path = ca_path / "ca_cert.pem"
        ca_cert_path.write_bytes(
            ca_cert.public_bytes(serialization.Encoding.PEM)
        )

        logger.info("CA created: key=%s, cert=%s", ca_key_path, ca_cert_path)
        return ca_private_key, ca_cert

    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"Failed to create CA: {exc}") from exc


def issue_tsa_cert(
    ca_key: RSAPrivateKey,
    ca_cert: Certificate,
    tsa_subject: str = "Digital Evidence Sealing TSA",
) -> tuple[RSAPrivateKey, Certificate]:
    """Issue a TSA-specific certificate signed by the CA.

    The issued certificate includes the id-kp-timeStamping extended
    key usage, making it valid only for timestamping operations.

    Args:
        ca_key: CA private key for signing the TSA certificate.
        ca_cert: CA certificate (issuer name is extracted from this).
        tsa_subject: Common name for the TSA certificate subject.

    Returns:
        Tuple of (TSA private key, TSA certificate).

    Raises:
        CertificateError: If TSA certificate issuance fails.
    """
    try:
        # Generate TSA key pair
        tsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_TSA_KEY_SIZE,
        )

        now = datetime.now(timezone.utc)
        tsa_subject_name = Name([
            NameAttribute(NameOID.COMMON_NAME, tsa_subject),
            NameAttribute(NameOID.ORGANIZATION_NAME, "Electronic Sealing Scheme (SSS)"),
            NameAttribute(NameOID.COUNTRY_NAME, "KR"),
        ])

        tsa_cert = (
            CertificateBuilder()
            .subject_name(tsa_subject_name)
            .issuer_name(ca_cert.subject)
            .public_key(tsa_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=_TSA_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
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
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.TIME_STAMPING,
                ]),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        logger.info("TSA certificate issued for subject='%s'", tsa_subject)
        return tsa_private_key, tsa_cert

    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"Failed to issue TSA certificate: {exc}") from exc


def save_tsa_credentials(
    tsa_key: RSAPrivateKey,
    tsa_cert: Certificate,
    output_dir: str | Path,
    key_password: str,
) -> tuple[Path, Path]:
    """Save TSA private key and certificate to PEM files.

    Args:
        tsa_key: TSA private key.
        tsa_cert: TSA certificate.
        output_dir: Directory to save files.
        key_password: Password to encrypt the TSA key.

    Returns:
        Tuple of (key_path, cert_path).

    Raises:
        CertificateError: If saving fails.
    """
    if not key_password:
        raise CertificateError("TSA private-key password is required")

    out_path = Path(output_dir)

    try:
        out_path.mkdir(parents=True, exist_ok=True)

        key_path = out_path / "tsa_key.pem"
        key_path.write_bytes(
            tsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    key_password.encode("utf-8")
                ),
            )
        )

        cert_path = out_path / "tsa_cert.pem"
        cert_path.write_bytes(
            tsa_cert.public_bytes(serialization.Encoding.PEM)
        )

        logger.info("TSA credentials saved: key=%s, cert=%s", key_path, cert_path)
        return key_path, cert_path

    except Exception as exc:
        raise CertificateError(f"Failed to save TSA credentials: {exc}") from exc
