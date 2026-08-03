"""Immutable data types for the crypto module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FileMetadata:
    """Immutable file metadata collected before encryption."""

    filename: str
    size: int
    md5: str
    sha256: str
    mtime: str  # ISO 8601
    ctime: str  # ISO 8601
    atime: str  # ISO 8601


@dataclass(frozen=True)
class EncryptionResult:
    """Immutable result of a file encryption operation."""

    enc_filepath: str
    original_filepath: str
    metadata: FileMetadata
    chunk_count: int
    encryption_algo: str = "AES-256-GCM"


@dataclass(frozen=True)
class DecryptionResult:
    """Immutable result of a file decryption operation."""

    output_filepath: str
    original_filename: str
    hash_verified: bool
    sha256_match: bool
    md5_match: bool
    metadata: dict


@dataclass(frozen=True)
class AccessCheckResult:
    """Immutable result of a time-based access control check."""

    allowed: bool
    method: str  # "tsa" or "local_fallback"
    current_time_iso: str
    unlock_time_iso: str
    warning: Optional[str] = None
