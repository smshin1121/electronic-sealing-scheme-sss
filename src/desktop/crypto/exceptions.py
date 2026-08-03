"""Custom exception types for the crypto module."""


class CryptoError(Exception):
    """Base exception for all crypto operations."""


class EncryptionError(CryptoError):
    """Raised when encryption fails."""


class DecryptionError(CryptoError):
    """Raised when decryption fails."""


class TamperDetectedError(CryptoError):
    """Raised when authentication tag verification fails, indicating tampering."""


class KeyRecoveryError(CryptoError):
    """Raised when SSS key recovery fails."""


class KeySplitError(CryptoError):
    """Raised when SSS key splitting fails."""


class KMSError(CryptoError):
    """Raised when local KMS operations fail."""


class AccessControlError(CryptoError):
    """Raised when time-based access control denies access."""


class MetadataError(CryptoError):
    """Raised when file metadata collection fails."""
