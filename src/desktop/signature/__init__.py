"""Signature module for the digital evidence electronic sealing system.

Provides X.509 certificate generation, PAdES PDF signing,
RFC 3161 TSA client/server, and CA infrastructure.
"""

from .ca_setup import (
    create_ca,
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
    verify_timestamp,
)
from .tsa_server import (
    create_tsa_server,
    ensure_tsa_credentials,
    ensure_tsa_server_running,
    run_tsa_server,
    start_tsa_server_background,
)
from .types import (
    SignatureVerificationResult,
    TimestampVerificationResult,
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
    # PDF signing
    "sign_pdf",
    "verify_pdf_signature",
    # TSA client
    "request_timestamp",
    "verify_timestamp",
    # TSA server
    "create_tsa_server",
    "ensure_tsa_credentials",
    "ensure_tsa_server_running",
    "run_tsa_server",
    "start_tsa_server_background",
    # Types
    "SignatureVerificationResult",
    "TimestampVerificationResult",
    # Exceptions
    "SignatureError",
    "CertificateError",
    "TSAError",
    "PDFSigningError",
]
