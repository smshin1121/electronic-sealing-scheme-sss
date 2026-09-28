"""Custom exception types for the signature module."""


class SignatureError(Exception):
    """Base exception for all digital signature operations."""


class CertificateError(SignatureError):
    """Raised when certificate generation or loading fails."""


class TSAError(SignatureError):
    """Raised when TSA operations (request, verify, server) fail.

    ``code`` is a stable failure code (for example ``tsa_chain``) set by
    the checks of the pinned TSA trust profile
    (:mod:`desktop.signature.tsa_profile`); it is empty where no code
    applies. The message itself is free text.
    """

    def __init__(self, message: str = "", *, code: str = "") -> None:
        super().__init__(message)
        self.code = code


class PDFSigningError(SignatureError):
    """Raised when PDF signing or verification fails."""
