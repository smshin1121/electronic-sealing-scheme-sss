"""Desktop -> web sync payload (``POST /sync/upload-record`` body).

The desktop sync client (:mod:`desktop.sync`, stage E, E2a) sends this
body, with a ``sync_auth`` envelope signed by the institutional key added
when one is configured (:mod:`desktop.signature.sync_envelope`). It
includes the optional ``wrapped_s3`` (base64 envelope ciphertext of s3
bound to the record's signed policy). The server enforces the same rules:
``wrapped_s3`` only on Sealing and Resealing events, and only with a record
that names the same seal.
"""

from __future__ import annotations

import base64
from typing import Any, Optional

_EVENT_TYPES = frozenset({"Sealing", "Unsealing", "Resealing"})
_WRAPPED_S3_EVENTS = frozenset({"Sealing", "Resealing"})


def build_sync_payload(
    *,
    seal_id: str,
    event_id: int,
    event_type: str,
    record_json: str,
    record_pdf: Optional[bytes] = None,
    wrapped_s3_b64: Optional[str] = None,
) -> dict[str, Any]:
    """Build the JSON body for ``/sync/upload-record``.

    Args:
        seal_id: Seal identifier.
        event_id: Positive event sequence number within the seal.
        event_type: ``Sealing``, ``Unsealing`` or ``Resealing``.
        record_json: The serialized record JSON.
        record_pdf: Optional signed record PDF bytes.
        wrapped_s3_b64: Optional base64 wrapped s3 (sealing/resealing
            with an authenticated policy only).

    Returns:
        A new payload dict.

    Raises:
        ValueError: On an invalid combination of fields.
    """
    if not isinstance(seal_id, str) or not seal_id:
        raise ValueError("seal_id is required")
    if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id < 1:
        raise ValueError("event_id must be a positive integer")
    if event_type not in _EVENT_TYPES:
        raise ValueError(f"event_type must be one of {sorted(_EVENT_TYPES)}")
    if not isinstance(record_json, str) or not record_json:
        raise ValueError("record_json is required")
    if wrapped_s3_b64 is not None and event_type not in _WRAPPED_S3_EVENTS:
        raise ValueError("wrapped_s3 is only sent with Sealing/Resealing")

    payload: dict[str, Any] = {
        "seal_id": seal_id,
        "event_id": event_id,
        "event_type": event_type,
        "record_json": record_json,
        "record_pdf": (
            base64.b64encode(record_pdf).decode("ascii")
            if record_pdf is not None
            else None
        ),
    }
    if wrapped_s3_b64 is not None:
        return {**payload, "wrapped_s3": wrapped_s3_b64}
    return payload
