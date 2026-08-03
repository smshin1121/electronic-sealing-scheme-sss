"""Immutable data types for the signature module."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class SignatureVerificationResult:
    """Immutable result of a PDF signature verification."""

    valid: bool
    signer_name: str
    signing_time: Optional[str] = None
    has_timestamp: bool = False
    timestamp_time: Optional[str] = None
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TimestampVerificationResult:
    """Immutable result of a TST token verification."""

    valid: bool
    gen_time: Optional[datetime] = None
    serial_number: Optional[int] = None
    hash_algorithm: str = "sha256"
    error: Optional[str] = None
