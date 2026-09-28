"""The two sync backends of the desktop client (stage E, E2a).

``web``: the reference web application, ``POST <url>/sync/upload-record``
with the body of :func:`desktop.sync_payload.build_sync_payload` and a
``sync_auth`` envelope signed by the institutional seal-policy key (a new
nonce and ``sent_at`` for every attempt). Without the key the submission
goes unsigned (WARNING); a server with ``SYNC_REQUIRE_SIGNATURE`` refuses
it and the item stays pending.

``portal``: the separately operated portal, ``POST <url>/api/seal-records``
with the HMAC scheme of its contract (:mod:`desktop.sync.portal_client`).

A backend is configured when its URL is set; a configured backend with a
missing secret or key configuration fails its pushes (pending, WARNING)
instead of being skipped, so nothing meant for it is lost.

Both send through :mod:`desktop.sync.transport`: HTTPS, or plain HTTP to
a loopback address only (checked before a connection is made), and no
redirect is followed. A push counts as delivered only on the endpoint's
documented acknowledgement (stage E, E2d): the reference web's HTTP 200
with JSON ``{"status": "ok"}``, the portal contract's answer
(:mod:`desktop.sync.portal_client`). Anything else -- a redirect, an HTML
page, another status, a negative or malformed answer -- fails the push and
the record stays pending with the reason.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Callable, Optional, Protocol

from ..signature.seal_policy import (
    PolicyError,
    PolicySigner,
    load_policy_signer_from_env,
    policy_generation,
)
from ..signature.sync_envelope import build_sync_envelope, sign_sync_envelope
from ..sync_payload import build_sync_payload
from . import portal_client, transport
from .outbox import OutboxEntry

logger = logging.getLogger(__name__)

WEB_URL_ENV = "ENC_ENVELOPE_SYNC_WEB_URL"  # public-config-key
PORTAL_URL_ENV = portal_client.ENV_BASE_URL
PORTAL_SECRET_ENV = portal_client.ENV_SECRET
BACKEND_WEB = "web"
BACKEND_PORTAL = "portal"
WEB_SYNC_PATH = "/sync/upload-record"
DEFAULT_TIMEOUT = 15.0


class SyncPushError(RuntimeError):
    """One push attempt failed; the message is safe to log and store."""


class SyncBackend(Protocol):
    """What the client needs from a backend."""

    name: str

    def configured(self) -> bool: ...

    def config_hint(self) -> str: ...

    def push(self, entry: OutboxEntry) -> None: ...


class WebBackend:
    """The reference web application's sync route."""

    name = BACKEND_WEB

    def __init__(self, base_url: str, *,
                 signer_provider: Callable[[], Optional[PolicySigner]],
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self._base_url = base_url.strip()
        self._signer_provider = signer_provider
        self._timeout = timeout

    @classmethod
    def from_env(cls, *, signer: Optional[PolicySigner] = None,
                 timeout: float = DEFAULT_TIMEOUT) -> "WebBackend":
        """URL from the environment; the key injected or from the environment."""
        cached: list[Optional[PolicySigner]] = []

        def provider() -> Optional[PolicySigner]:
            if signer is not None:
                return signer
            if not cached:
                cached.append(load_policy_signer_from_env())
            return cached[0]

        return cls(os.environ.get(WEB_URL_ENV, ""), signer_provider=provider,
                   timeout=timeout)

    def configured(self) -> bool:
        return bool(self._base_url)

    def config_hint(self) -> str:
        return WEB_URL_ENV

    def push(self, entry: OutboxEntry) -> None:
        """Sign (when a key is configured) and POST one queued record.

        Raises:
            SyncPushError: Unless the answer is the endpoint's
                acknowledgement (HTTP 200, JSON ``status`` ``"ok"``).
        """
        url = self._base_url.rstrip("/") + WEB_SYNC_PATH
        try:
            transport.require_safe_url(url)
            body = self._body(entry, self._signer())
            answer = transport.post(url, json.dumps(body).encode("utf-8"),
                                    {"Content-Type": "application/json"},
                                    self._timeout)
        except transport.TransportError as exc:
            raise SyncPushError(str(exc)) from exc
        _require_web_acknowledgement(answer)

    def _signer(self) -> Optional[PolicySigner]:
        try:
            return self._signer_provider()
        except PolicyError as exc:
            raise SyncPushError(
                f"institutional seal-policy key unusable: {exc}") from exc

    @staticmethod
    def _body(entry: OutboxEntry, signer: Optional[PolicySigner]) -> dict:
        # An empty PDF is no PDF (the server reads an empty field as absent).
        record_pdf = entry.record_pdf or None
        payload = build_sync_payload(
            seal_id=entry.seal_id, event_id=entry.event_id,
            event_type=entry.event_type, record_json=entry.record_json,
            record_pdf=record_pdf, wrapped_s3_b64=entry.wrapped_s3_b64,
        )
        if signer is None:
            logger.warning("Sync submission is unsigned (no institutional "
                           "seal-policy key configured): seal_id=%s "
                           "event_id=%s", entry.seal_id, entry.event_id)
            return payload
        envelope = build_sync_envelope(
            seal_id=entry.seal_id, event_id=entry.event_id,
            event_type=entry.event_type, record_json=entry.record_json,
            record_pdf=record_pdf,
            wrapped_s3=(base64.b64decode(entry.wrapped_s3_b64)
                        if entry.wrapped_s3_b64 else None),
            policy_generation=_record_generation(entry.record_json),
        )
        signed = sign_sync_envelope(envelope, signer)
        return {**payload, "sync_auth": signed.payload_field()}


class PortalBackend:
    """The portal's seal-record route (HMAC contract)."""

    name = BACKEND_PORTAL

    def __init__(self, base_url: str, secret: str, *,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self._base_url = base_url.strip()
        self._secret = secret.strip()
        self._timeout = timeout

    @classmethod
    def from_env(cls, *, timeout: float = DEFAULT_TIMEOUT) -> "PortalBackend":
        return cls(os.environ.get(PORTAL_URL_ENV, ""),
                   os.environ.get(PORTAL_SECRET_ENV, ""), timeout=timeout)

    def configured(self) -> bool:
        return bool(self._base_url)

    def config_hint(self) -> str:
        return f"{PORTAL_URL_ENV} and {PORTAL_SECRET_ENV}"

    def push(self, entry: OutboxEntry) -> None:
        """POST one queued record with the contract's HMAC headers."""
        if not self._secret:
            raise SyncPushError(f"{PORTAL_SECRET_ENV} is not set")
        try:
            portal_client.push_seal_record(
                entry.record_json, record_pdf=_pdf_for_portal(entry),
                base_url=self._base_url, secret=self._secret,
                timeout=self._timeout)
        except portal_client.PortalSyncError as exc:
            raise SyncPushError(str(exc)) from exc


def _pdf_for_portal(entry: OutboxEntry) -> Optional[bytes]:
    """The contract takes only a real PDF; anything else is left out."""
    if entry.record_pdf is not None and entry.record_pdf.startswith(b"%PDF-"):
        return entry.record_pdf
    return None


def _record_generation(record_json: str) -> int:
    """The generation the envelope names: the record's policy's, else 0."""
    try:
        record = json.loads(record_json)
    except ValueError as exc:
        raise SyncPushError("queued record_json is not JSON") from exc
    policy = record.get("policy") if isinstance(record, dict) else None
    if policy is None:
        return 0
    try:
        return policy_generation(policy)
    except PolicyError as exc:
        raise SyncPushError(f"queued record carries a malformed policy: "
                            f"{exc}") from exc


def _require_web_acknowledgement(answer: transport.Answer) -> None:
    """HTTP 200 with JSON ``{"status": "ok"}``, the sync route's success."""
    body = answer.json_object()
    if answer.status == 200 and body is not None and body.get("status") == "ok":
        return
    if answer.status != 200:
        raise SyncPushError(f"HTTP {answer.status}: {answer.message()}")
    raise SyncPushError(
        "HTTP 200 without the sync route's acknowledgement "
        f'(JSON status "ok"): {answer.message()}')
