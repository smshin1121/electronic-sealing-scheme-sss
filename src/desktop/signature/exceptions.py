"""Custom exception types for the signature module."""


class SignatureError(Exception):
    """Base exception for all digital signature operations."""


class CertificateError(SignatureError):
    """Raised when certificate generation or loading fails."""


class TSAError(SignatureError):
    """Raised when TSA operations (request, verify, server) fail."""


class PDFSigningError(SignatureError):
    """Raised when PDF signing or verification fails."""
