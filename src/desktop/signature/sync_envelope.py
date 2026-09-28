"""Per-event sync envelope, shared by the desktop and the release host (stage E, E2a).

For every submission to ``/sync/upload-record`` the desktop signs the
canonical envelope

    {"v": 1, "context": "ESS-SYNC-EVENT-v1", "seal_id", "event_id",
     "event_type", "record_sha256", "pdf_sha256", "wrapped_s3_sha256",
     "policy_generation", "sent_at", "nonce"}

serialized like the seal policy (sorted keys, ``(",", ":")`` separators,
UTF-8, ``ensure_ascii=False``). The three hashes are lowercase hex SHA-256
over the exact bytes submitted: the UTF-8 of the ``record_json`` string,
the PDF bytes and the wrapped-s3 bytes (the empty string when absent).
``policy_generation`` is the generation of the record's policy (0 for a
record without a policy or with a version-1 policy). ``sent_at`` is UTC
(``YYYY-MM-DDThh:mm:ssZ``) and ``nonce`` 32 random bytes as hex.

Key: the institutional seal-policy key signs it (RSA-PSS/SHA-256, the
policy's parameters); no second key or EKU is issued. The two kinds of
signature are separated by construction: each verifier requires an exact,
disjoint key set before it verifies (the envelope has ``context``, the
policy has ``case_no``), so the canonical bytes of one can never be
accepted as the other.

The request carries ``sync_auth = {"envelope", "signature", "cert"}``.
:func:`verify_sync_envelope` checks the schema; that the certificate is
issued directly by a pinned CA, is an end entity with digitalSignature and
the seal-policy EKU, and that it and an issuing anchor are valid at the
verification time; and the signature. Binding the envelope to the request,
the time window and the nonce store are the release host's
(:mod:`web.sync_auth`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes

# The certificate and signature checks are the seal policy's own; the same
# key signs both, so they are reused rather than duplicated.
from .seal_policy import (
    PolicyError,
    PolicySigner,
    _check_certificate_profile,
    _check_signature,
    _decode_signature,
    _issuing_anchors,
    _load_signer_certificate,
    _pss,
)

SYNC_ENVELOPE_VERSION = 1
SYNC_EVENT_CONTEXT = "ESS-SYNC-EVENT-v1"
SYNC_EVENT_TYPES = frozenset({"Sealing", "Unsealing", "Resealing"})
NONCE_BYTES = 32
MAX_EVENT_ID = 2 ** 31 - 1
MAX_GENERATION = 2 ** 31 - 1

_ENVELOPE_KEYS = frozenset({
    "v", "context", "seal_id", "event_id", "event_type", "record_sha256",
    "pdf_sha256", "wrapped_s3_sha256", "policy_generation", "sent_at",
    "nonce",
})
_AUTH_KEYS = frozenset({"envelope", "signature", "cert"})
_HEX64 = re.compile(r"[0-9a-f]{64}")
_NONCE_RE = re.compile(r"[0-9a-f]{32,128}")
_SENT_AT_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
_MAX_SEAL_ID_LEN = 64


class SyncEnvelopeError(PolicyError):
    """A sync envelope could not be built or does not satisfy the schema."""


class SyncEnvelopeVerificationError(SyncEnvelopeError):
    """A presented sync envelope failed verification (fail-closed)."""


@dataclass(frozen=True)
class SignedSyncEnvelope:
    """An envelope with its signature and the signer certificate."""

    envelope: dict[str, Any]
    signature_b64: str
    cert_pem: str

    def payload_field(self) -> dict[str, Any]:
        """The request's ``sync_auth`` object (a new dict)."""
        return {"envelope": dict(self.envelope),
                "signature": self.signature_b64, "cert": self.cert_pem}


@dataclass(frozen=True)
class VerifiedSyncEnvelope:
    """An envelope that passed :func:`verify_sync_envelope`."""

    seal_id: str
    event_id: int
    event_type: str
    record_sha256: str
    pdf_sha256: str
    wrapped_s3_sha256: str
    policy_generation: int
    sent_at: datetime
    sent_at_iso: str
    nonce: str
    cert_fingerprint: str


# ---------------------------------------------------------------------------
# Building and signing (desktop)
# ---------------------------------------------------------------------------

def sha256_hex(data: Optional[bytes]) -> str:
    """Lowercase hex SHA-256 of ``data``; the empty string for ``None``."""
    return "" if data is None else hashlib.sha256(data).hexdigest()


def format_sent_at(moment: datetime) -> str:
    """``moment`` in the envelope's UTC form, ``YYYY-MM-DDThh:mm:ssZ``."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_sync_envelope(
    *,
    seal_id: str,
    event_id: int,
    event_type: str,
    record_json: str,
    record_pdf: Optional[bytes],
    wrapped_s3: Optional[bytes],
    policy_generation: int,
    sent_at: Optional[datetime] = None,
    nonce: Optional[str] = None,
) -> dict[str, Any]:
    """Build and validate an envelope over the exact submitted bytes.

    ``sent_at`` defaults to now and ``nonce`` to 32 fresh random bytes, so
    every attempt carries its own.

    Raises:
        SyncEnvelopeError: On a field that violates the schema.
    """
    if not isinstance(record_json, str):
        raise SyncEnvelopeError("record_json must be a string")
    envelope = {
        "v": SYNC_ENVELOPE_VERSION,
        "context": SYNC_EVENT_CONTEXT,
        "seal_id": seal_id,
        "event_id": event_id,
        "event_type": event_type,
        "record_sha256": sha256_hex(record_json.encode("utf-8")),
        "pdf_sha256": sha256_hex(record_pdf),
        "wrapped_s3_sha256": sha256_hex(wrapped_s3),
        "policy_generation": policy_generation,
        "sent_at": format_sent_at(sent_at or datetime.now(tz=timezone.utc)),
        "nonce": nonce or secrets.token_hex(NONCE_BYTES),
    }
    return _validated(envelope)


def canonicalize_sync_envelope(envelope: Mapping[str, Any]) -> bytes:
    """The canonical UTF-8 JSON bytes of a validated envelope.

    Raises:
        SyncEnvelopeError: If the object violates the schema.
    """
    return json.dumps(_validated(envelope), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_sync_envelope(
    envelope: Mapping[str, Any], signer: PolicySigner
) -> SignedSyncEnvelope:
    """Sign the canonical envelope with the institutional key (RSA-PSS)."""
    canonical = canonicalize_sync_envelope(envelope)
    signature = signer.private_key.sign(canonical, _pss(), hashes.SHA256())
    return SignedSyncEnvelope(
        envelope=json.loads(canonical),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        cert_pem=signer.cert_pem,
    )


# ---------------------------------------------------------------------------
# Verification (release host)
# ---------------------------------------------------------------------------

def verify_sync_envelope(
    auth: Any, *, ca_certs: Sequence[x509.Certificate], at: datetime
) -> VerifiedSyncEnvelope:
    """Verify a request's ``sync_auth`` object (fail-closed).

    Order: the object's shape and the envelope schema; the certificate is
    issued directly by one of ``ca_certs``, is an end entity with
    digitalSignature and the seal-policy EKU; the RSA-PSS signature over
    the canonical bytes; the certificate and an issuing anchor are valid at
    ``at``.

    Raises:
        SyncEnvelopeVerificationError: On any failed check.
    """
    if not isinstance(auth, Mapping) or set(auth.keys()) != _AUTH_KEYS:
        raise SyncEnvelopeVerificationError(
            f"sync_auth must be an object with exactly {sorted(_AUTH_KEYS)}")
    try:
        canonical = canonicalize_sync_envelope(auth["envelope"])
        cert = _load_signer_certificate(auth["cert"])
        issuers = _issuing_anchors(cert, list(ca_certs))
        _check_certificate_profile(cert)
        _check_signature(cert, _decode_signature(auth["signature"]), canonical)
    except PolicyError as exc:
        raise SyncEnvelopeVerificationError(f"sync envelope: {exc}") from exc
    except Exception as exc:  # fail-closed: any other certificate failure
        raise SyncEnvelopeVerificationError(
            f"sync envelope: certificate check failed "
            f"({type(exc).__name__})") from exc
    _check_current_validity(cert, issuers, at)
    return _verified(json.loads(canonical), cert)


def parse_sent_at(value: Any) -> datetime:
    """Parse an envelope ``sent_at`` (UTC, ``Z`` suffix).

    Raises:
        SyncEnvelopeError: If malformed.
    """
    if not isinstance(value, str) or not _SENT_AT_RE.fullmatch(value):
        raise SyncEnvelopeError("sent_at must be YYYY-MM-DDThh:mm:ssZ")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SyncEnvelopeError("sent_at is not a valid time") from exc


def _check_current_validity(
    cert: x509.Certificate, issuers: Sequence[x509.Certificate], at: datetime
) -> None:
    """The certificate and at least one issuing anchor are valid at ``at``."""
    if not cert.not_valid_before_utc <= at <= cert.not_valid_after_utc:
        raise SyncEnvelopeVerificationError(
            f"sync certificate is not valid at {at.isoformat()}")
    if not any(a.not_valid_before_utc <= at <= a.not_valid_after_utc
               for a in issuers):
        raise SyncEnvelopeVerificationError(
            f"no issuing pinned CA is valid at {at.isoformat()}")


def _verified(fields: Mapping[str, Any],
              cert: x509.Certificate) -> VerifiedSyncEnvelope:
    return VerifiedSyncEnvelope(
        seal_id=fields["seal_id"], event_id=fields["event_id"],
        event_type=fields["event_type"],
        record_sha256=fields["record_sha256"], pdf_sha256=fields["pdf_sha256"],
        wrapped_s3_sha256=fields["wrapped_s3_sha256"],
        policy_generation=fields["policy_generation"],
        sent_at=parse_sent_at(fields["sent_at"]), sent_at_iso=fields["sent_at"],
        nonce=fields["nonce"],
        cert_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
    )


def _validated(envelope: Any) -> dict[str, Any]:
    """Check the envelope schema; return a new plain dict."""
    if not isinstance(envelope, Mapping) or set(envelope.keys()) != _ENVELOPE_KEYS:
        raise SyncEnvelopeError(
            f"envelope fields must be exactly {sorted(_ENVELOPE_KEYS)}")
    if type(envelope["v"]) is not int or envelope["v"] != SYNC_ENVELOPE_VERSION:
        raise SyncEnvelopeError("unsupported envelope version")
    if envelope["context"] != SYNC_EVENT_CONTEXT:
        raise SyncEnvelopeError("envelope context is not ESS-SYNC-EVENT-v1")
    _require_seal_id(envelope["seal_id"])
    _require_int(envelope["event_id"], "event_id", 1, MAX_EVENT_ID)
    if envelope["event_type"] not in SYNC_EVENT_TYPES:
        raise SyncEnvelopeError("envelope event_type is not a known event")
    _require_hash(envelope["record_sha256"], "record_sha256", optional=False)
    _require_hash(envelope["pdf_sha256"], "pdf_sha256", optional=True)
    _require_hash(envelope["wrapped_s3_sha256"], "wrapped_s3_sha256",
                  optional=True)
    _require_int(envelope["policy_generation"], "policy_generation", 0,
                 MAX_GENERATION)
    parse_sent_at(envelope["sent_at"])
    if not isinstance(envelope["nonce"], str) or not _NONCE_RE.fullmatch(
        envelope["nonce"]
    ):
        raise SyncEnvelopeError("envelope nonce must be 32-128 lowercase hex")
    return {key: envelope[key] for key in sorted(_ENVELOPE_KEYS)}


def _require_seal_id(value: Any) -> None:
    if not isinstance(value, str) or not value or len(value) > _MAX_SEAL_ID_LEN:
        raise SyncEnvelopeError("envelope seal_id must be a non-empty string")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise SyncEnvelopeError("envelope seal_id contains control characters")


def _require_int(value: Any, name: str, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        raise SyncEnvelopeError(
            f"envelope {name} must be an integer from {low} to {high}")


def _require_hash(value: Any, name: str, *, optional: bool) -> None:
    if optional and value == "":
        return
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise SyncEnvelopeError(f"envelope {name} must be 64 lowercase hex")
