"""Authentication of sync submissions (stage E, E2a).

A submission to ``/sync/upload-record`` may carry ``sync_auth`` =
``{"envelope", "signature", "cert"}``: a canonical envelope signed by the
institutional seal-policy key (:mod:`desktop.signature.sync_envelope`).

Checks, in order (the route calls them in this order):

  1. :func:`unsigned_refusal` -- with ``SYNC_REQUIRE_SIGNATURE`` on, a
     submission without ``sync_auth`` is refused (401) before any work.
  2. :func:`verify_submission_signature` -- before the payload is decoded:
     a present ``sync_auth`` needs a pinned CA (``POLICY_CA_CERT_PATH``;
     503 without one, never treated as unsigned); the certificate chain,
     profile and EKU, and the signature (:func:`verify_sync_envelope`); and
     ``sent_at`` within ``SYNC_SIGNATURE_WINDOW_SECONDS`` of the server's
     UTC clock, in either direction.
  3. :func:`check_request_binding` -- after decoding: every envelope field
     equals the request, the hashes taken over the exact received bytes
     (the UTF-8 of the ``record_json`` string, which must be a string, and
     the decoded PDF and wrapped-s3 bytes).
  4. :func:`check_generation_claim` -- after the record's policy has been
     assessed, the envelope's ``policy_generation`` must equal the
     generation of that policy (0 for none or a version-1 policy).

Any failure of 2 to 4 is 401 with one message (503 for the configuration
cases); the cause goes to the server log only.

The nonce is claimed later, under the seal's write lock and in the same
transaction as the store (the route); it expires ``sent_at`` plus
:data:`NONCE_RETENTION_SECONDS`, the largest window the configuration
allows, so pruning can never re-admit an envelope inside any window.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from desktop.signature.seal_policy import PolicyError, load_ca_certificates
from desktop.signature.sync_envelope import (
    SyncEnvelopeVerificationError,
    VerifiedSyncEnvelope,
    sha256_hex,
    verify_sync_envelope,
)

logger = logging.getLogger(__name__)

SYNC_AUTH_FIELD = "sync_auth"
DEFAULT_WINDOW_SECONDS = 300
MIN_WINDOW_SECONDS = 30
MAX_WINDOW_SECONDS = 3600
NONCE_RETENTION_SECONDS = MAX_WINDOW_SECONDS

MSG_UNSIGNED = "서명되지 않은 동기화 요청은 받지 않습니다."
MSG_INVALID = "동기화 요청의 서명을 검증할 수 없습니다."
MSG_NO_CA = "서버에 동기화 서명을 검증할 기관 CA가 설정되어 있지 않습니다."
MSG_CONFIG = "동기화 서명 설정이 올바르지 않아 요청을 처리할 수 없습니다."


class SyncConfigError(RuntimeError):
    """The sync-authentication configuration is unusable."""


@dataclass(frozen=True)
class SubmittedEvent:
    """What the request claims, as received (bytes already decoded)."""

    seal_id: str
    event_id: int
    event_type: str
    record_json: Any
    record_pdf: Optional[bytes]
    wrapped_s3: Optional[bytes]


@dataclass(frozen=True)
class AuthFailure:
    """A refusal: HTTP status, the user-facing message, the logged cause."""

    status: int
    message: str
    cause: str


def utc_now() -> datetime:
    """The server's clock (UTC)."""
    return datetime.now(tz=timezone.utc)


def validate_sync_config(config: Mapping[str, Any]) -> None:
    """Refuse start-up on an unusable sync-authentication configuration.

    Raises:
        SyncConfigError: When the window is out of range, or the switch is
            on without a pinned CA (every submission would be refused).
    """
    signature_window(config)
    if signatures_required(config) and not _ca_path(config):
        raise SyncConfigError(
            "SYNC_REQUIRE_SIGNATURE is set but POLICY_CA_CERT_PATH is not: "
            "no sync signature could be verified")


def signatures_required(config: Mapping[str, Any]) -> bool:
    """Whether unsigned submissions are refused."""
    return bool(config.get("SYNC_REQUIRE_SIGNATURE"))


def signature_window(config: Mapping[str, Any]) -> int:
    """The accepted distance of ``sent_at`` from the server clock (seconds).

    Raises:
        SyncConfigError: When not an integer from 30 to 3600.
    """
    value = config.get("SYNC_SIGNATURE_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS)
    if type(value) is not int or not (
        MIN_WINDOW_SECONDS <= value <= MAX_WINDOW_SECONDS
    ):
        raise SyncConfigError(
            f"SYNC_SIGNATURE_WINDOW_SECONDS must be an integer from "
            f"{MIN_WINDOW_SECONDS} to {MAX_WINDOW_SECONDS}")
    return value


def unsigned_refusal(
    data: Mapping[str, Any], config: Mapping[str, Any]
) -> Optional[AuthFailure]:
    """401 for an unsigned submission while signatures are required."""
    if data.get(SYNC_AUTH_FIELD) is None and signatures_required(config):
        return AuthFailure(401, MSG_UNSIGNED, "unsigned submission")
    return None


def verify_submission_signature(
    data: Mapping[str, Any], config: Mapping[str, Any], *, now: datetime,
) -> tuple[Optional[VerifiedSyncEnvelope], Optional[AuthFailure]]:
    """Verify a present ``sync_auth`` and its time, before any decoding.

    Needs only the envelope, the pinned CA bundle and the clock, so a bad
    signature or a stale envelope is refused before the payload (up to the
    request size limit) is decoded or parsed.

    Returns:
        ``(None, None)`` for an unsigned submission (admitted only while
        signatures are not required), ``(envelope, None)`` when it
        verifies, or ``(None, failure)``.
    """
    auth = data.get(SYNC_AUTH_FIELD)
    if auth is None:
        return None, None
    anchors, failure = _anchors(config)
    if failure is not None:
        return None, failure
    try:
        window = signature_window(config)
    except SyncConfigError as exc:
        return None, AuthFailure(503, MSG_CONFIG, str(exc))
    try:
        envelope = verify_sync_envelope(auth, ca_certs=anchors, at=now)
    except SyncEnvelopeVerificationError as exc:
        return None, AuthFailure(401, MSG_INVALID, str(exc))
    if abs(now - envelope.sent_at) > timedelta(seconds=window):
        return None, AuthFailure(
            401, MSG_INVALID,
            f"sent_at {envelope.sent_at_iso} is outside the {window} s window")
    return envelope, None


def check_request_binding(
    envelope: Optional[VerifiedSyncEnvelope], event: SubmittedEvent
) -> Optional[AuthFailure]:
    """Every envelope field must equal the decoded request (401 if not)."""
    if envelope is None:
        return None
    mismatch = _binding_mismatch(envelope, event)
    return AuthFailure(401, MSG_INVALID, mismatch) if mismatch else None


def check_generation_claim(
    envelope: Optional[VerifiedSyncEnvelope], generation: int
) -> Optional[AuthFailure]:
    """The envelope must name the generation of the record's policy."""
    if envelope is None or envelope.policy_generation == generation:
        return None
    return AuthFailure(
        401, MSG_INVALID,
        f"envelope policy_generation {envelope.policy_generation} differs "
        f"from the record's policy generation {generation}")


def nonce_expiry(envelope: VerifiedSyncEnvelope) -> int:
    """Unix time until which the nonce must be kept."""
    return int(envelope.sent_at.timestamp()) + NONCE_RETENTION_SECONDS


def _ca_path(config: Mapping[str, Any]) -> str:
    return str(config.get("POLICY_CA_CERT_PATH") or "").strip()


def _anchors(config: Mapping[str, Any]) -> tuple[list, Optional[AuthFailure]]:
    """The pinned CA bundle; 503 when none is configured or readable."""
    path = _ca_path(config)
    if not path:
        return [], AuthFailure(503, MSG_NO_CA, "no pinned CA configured")
    try:
        return load_ca_certificates(path), None
    except PolicyError as exc:
        return [], AuthFailure(503, MSG_NO_CA, f"pinned CA unreadable: {exc}")


def _binding_mismatch(envelope: VerifiedSyncEnvelope,
                      event: SubmittedEvent) -> str:
    """The first envelope field that differs from the request, or ''."""
    if not isinstance(event.record_json, str):
        return "record_json is not a string, so its bytes cannot be matched"
    try:
        record_bytes = event.record_json.encode("utf-8")
    except UnicodeEncodeError:
        return "record_json is not encodable as UTF-8"
    received = (
        ("seal_id", event.seal_id),
        ("event_id", event.event_id),
        ("event_type", event.event_type),
        ("record_sha256", sha256_hex(record_bytes)),
        ("pdf_sha256", sha256_hex(event.record_pdf)),
        ("wrapped_s3_sha256", sha256_hex(event.wrapped_s3)),
    )
    for name, value in received:
        if getattr(envelope, name) != value:
            return f"envelope {name} does not match the request"
    return ""
