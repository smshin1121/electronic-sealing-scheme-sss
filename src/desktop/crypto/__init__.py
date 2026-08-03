"""Crypto module for the digital evidence electronic sealing system.

Re-exports the primary public API for encryption, decryption,
key management, and access control.
"""

from .aes_gcm_decrypt import decrypt_file
from .aes_gcm_encrypt import (
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    encrypt_file,
)
from .exceptions import (
    AccessControlError,
    CryptoError,
    DecryptionError,
    EncryptionError,
    KeyRecoveryError,
    KeySplitError,
    KMSError,
    MetadataError,
    TamperDetectedError,
)
from .file_metadata import collect_metadata
from .local_kms import (
    decrypt_envelope,
    encrypt_envelope,
    get_master_key_path,
    init_master_key,
)
from .sss_recover import recover_key
from .sss_split import split_key
from .sss_strict import (
    SEAL_MODE_STANDARD,
    SEAL_MODE_STRICT,
    VALID_SEAL_MODES,
    recover_key_for_mode,
    recover_key_strict,
    split_key_strict,
)
from .time_access_control import check_unlock_time
from .types import (
    AccessCheckResult,
    DecryptionResult,
    EncryptionResult,
    FileMetadata,
)

__all__ = [
    # Encryption / Decryption
    "encrypt_file",
    "decrypt_file",
    "MIN_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "DEFAULT_CHUNK_SIZE",
    # Metadata
    "collect_metadata",
    # SSS
    "split_key",
    "recover_key",
    # Strict mode (outer 2-of-2 XOR wrap)
    "SEAL_MODE_STANDARD",
    "SEAL_MODE_STRICT",
    "VALID_SEAL_MODES",
    "split_key_strict",
    "recover_key_strict",
    "recover_key_for_mode",
    # Local KMS
    "init_master_key",
    "encrypt_envelope",
    "decrypt_envelope",
    "get_master_key_path",
    # Time access control
    "check_unlock_time",
    # Types
    "FileMetadata",
    "EncryptionResult",
    "DecryptionResult",
    "AccessCheckResult",
    # Exceptions
    "CryptoError",
    "EncryptionError",
    "DecryptionError",
    "TamperDetectedError",
    "KeyRecoveryError",
    "KeySplitError",
    "KMSError",
    "AccessControlError",
    "MetadataError",
]
