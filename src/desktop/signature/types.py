"""Immutable data types for the signature module."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from .exceptions import TSAError


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


@dataclass(frozen=True)
class VerifiedTimestamp:
    """A TSA token that passed the fail-closed request verification.

    ``token`` is the DER-encoded TimeStampToken (CMS ContentInfo) whose
    TSTInfo echoed ``nonce`` and whose CMS signature verified against the
    pinned TSA certificate; it is kept so release decisions can be audited
    and re-verified later.

    Tokens accepted under the pinned TSA trust profile
    (:func:`desktop.signature.tsa_profile.verify_trusted_token`) also
    carry the asserted ``accuracy``, the ``policy_oid`` and the SHA-256 of
    the signer certificate; the leaf-pinned verification leaves them at
    their defaults.
    """

    gen_time: datetime
    token: bytes
    nonce: int
    serial_number: int
    accuracy: Optional[timedelta] = None
    policy_oid: str = ""
    signer_cert_sha256: str = ""

    @property
    def token_sha256(self) -> str:
        """Hex SHA-256 of the DER token (audit reference)."""
        import hashlib

        return hashlib.sha256(self.token).hexdigest()

    @property
    def earliest_gen_time(self) -> datetime:
        """genTime minus accuracy: the earliest time of issuance.

        RFC 3161 section 2.4.2: subtracting the accuracy from genTime gives
        a lower limit of the time at which the TSA created the token.

        Raises:
            TSAError: ``tsa_accuracy_missing`` when the token was accepted
                without an accuracy (leaf-pinned verification).
        """
        if self.accuracy is None:
            raise TSAError("verified token carries no accuracy",
                           code="tsa_accuracy_missing")
        return self.gen_time - self.accuracy
