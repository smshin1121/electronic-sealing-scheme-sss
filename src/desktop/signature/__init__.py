"""Signature module for the digital evidence electronic sealing system.

Provides X.509 certificate generation, PAdES PDF signing,
RFC 3161 TSA client/server, and CA infrastructure.
"""

from .ca_setup import (
    create_ca,
    issue_policy_cert,
    issue_tsa_cert,
    save_tsa_credentials,
)
from .cert_generator import (
    create_self_signed_cert,
    generate_keypair,
    load_certificate,
    load_private_key,
    save_certificate,
    save_private_key,
)
from .exceptions import (
    CertificateError,
    PDFSigningError,
    SignatureError,
    TSAError,
)
from .pdf_signer import (
    sign_pdf,
    verify_pdf_signature,
)
from .tsa_client import (
    request_timestamp,
    request_timestamp_trusted,
    request_timestamp_verified_token,
    verify_timestamp,
)
from .tsa_profile import (
    TsaTrustProfile,
    is_dotted_oid,
    load_tsa_ca_certificates,
    verify_trusted_token,
)
from .tsa_server import (
    DEFAULT_TSA_ACCURACY,
    DEFAULT_TSA_POLICY_OID,
    create_tsa_server,
    ensure_tsa_credentials,
    ensure_tsa_server_running,
    run_tsa_server,
    start_tsa_server_background,
)
from .types import (
    SignatureVerificationResult,
    TimestampVerificationResult,
    VerifiedTimestamp,
)

__all__ = [
    # Certificate generation
    "generate_keypair",
    "create_self_signed_cert",
    "save_private_key",
    "save_certificate",
    "load_private_key",
    "load_certificate",
    # CA setup
    "create_ca",
    "issue_tsa_cert",
    "save_tsa_credentials",
    "issue_policy_cert",
    # PDF signing
    "sign_pdf",
    "verify_pdf_signature",
    # TSA client
    "request_timestamp",
    "request_timestamp_trusted",
    "request_timestamp_verified_token",
    "verify_timestamp",
    # TSA trust profile (time-locked release path)
    "TsaTrustProfile",
    "is_dotted_oid",
    "load_tsa_ca_certificates",
    "verify_trusted_token",
    # TSA server
    "DEFAULT_TSA_ACCURACY",
    "DEFAULT_TSA_POLICY_OID",
    "create_tsa_server",
    "ensure_tsa_credentials",
    "ensure_tsa_server_running",
    "run_tsa_server",
    "start_tsa_server_background",
    # Types
    "SignatureVerificationResult",
    "TimestampVerificationResult",
    "VerifiedTimestamp",
    # Exceptions
    "SignatureError",
    "CertificateError",
    "TSAError",
    "PDFSigningError",
]
