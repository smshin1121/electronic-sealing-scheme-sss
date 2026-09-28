"""Seal-record push client for the separately operated portal (HMAC contract).

Ported from the push client of origin/main commit 1570671 (stage E, E2a);
the contract is the portal sync contract added to ``docs/`` from commit
2f1325a (section 2, ``POST /api/seal-records``). The module and the
environment names are neutral so that the public export stays free of the
portal's private identifier.

HMAC signature::

    canonical = str(timestamp) + "\\n" + nonce + "\\n" + raw_body   (bytes)
    X-Sync-Signature = hex( HMAC_SHA256(SYNC_SHARED_SECRET, canonical) )

Every call signs with the current Unix time and a fresh nonce, so a retry
is a new request. The body is the record JSON adapted to the contract's
documented fields (§2.3), each added only when absent:

  - ``process_info.seal_type`` from the desktop's ``process_info.type``
    (or the last history event); ``type`` itself is kept, an extra field;
  - ``process_info.unlock_time`` from the record's ``unlock_time_iso``;
  - each history event's ``event_id`` (``EVT-0001`` from the desktop's
    integer ``id``; the contract's idempotence key is
    ``history.events[-1].event_id``);
  - ``record_pdf``, the base64 PDF (a real ``%PDF-`` file only).

Before sending, the payload is checked against the contract's required
fields (:func:`contract_problems`); a payload outside it is not sent.
Sending goes through :mod:`desktop.sync.transport` (HTTPS, or plain HTTP
to loopback only; no redirect followed), and a push counts as delivered
only on the contract's answer: HTTP 200 with JSON ``{"status", "message"}``
whose status is not an error (§2.5; the contract names no success value).

Environment (both needed; :func:`push_seal_record_safe` skips otherwise)::

    ENC_ENVELOPE_SYNC_PORTAL_URL   base URL of the portal
    SYNC_SHARED_SECRET             the shared secret; never commit it

Manual or backfill push::

    python -m desktop.sync.portal_client record.json [--pdf record.pdf]

Standard library only. The record is never logged.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import time
from typing import Any, Mapping, Optional

from . import transport

logger = logging.getLogger(__name__)

API_PATH = "/api/seal-records"
DEFAULT_TIMEOUT = 15
MAX_BODY_BYTES = 8 * 1024 * 1024  # contract §2.3

ENV_BASE_URL = "ENC_ENVELOPE_SYNC_PORTAL_URL"
ENV_SECRET = "SYNC_SHARED_SECRET"  # public-config-key

_SIX_FIELDS = ("seal_id", "case_info", "process_info", "file_info",
               "signer_info", "history")
_SEAL_TYPES = ("Sealing", "Unsealing", "Resealing")
_SEAL_ID_RE = re.compile(r"S-\d{8}-[0-9A-F]{6}")
_ERROR_STATUSES = frozenset({"error", "fail", "failed", "failure"})


class PortalSyncError(RuntimeError):
    """Portal push failed (configuration, contract, network or refusal)."""


def _canonical_signature(secret: str, timestamp: str, nonce: str,
                         raw_body: bytes) -> str:
    canonical = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + raw_body
    return hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()


def _prepare_payload(
    record_json: str | bytes,
    record_pdf_path: Optional[str] = None,
    *,
    record_pdf: Optional[bytes] = None,
) -> bytes:
    """The request body: the record adapted to the contract's fields.

    Raises:
        PortalSyncError: When the record is not a JSON object or the PDF
            does not start with ``%PDF-``.
    """
    if isinstance(record_json, bytes):
        record_json = record_json.decode("utf-8")
    data = json.loads(record_json)
    if not isinstance(data, dict):
        raise PortalSyncError("봉인기록 JSON 최상위가 객체가 아닙니다.")
    payload = _with_process_fields(_with_event_ids(data))
    if record_pdf_path:
        with open(record_pdf_path, "rb") as f:
            record_pdf = f.read()
    if record_pdf is not None:
        if not record_pdf.startswith(b"%PDF-"):
            raise PortalSyncError("첨부할 봉인기록지가 PDF(%PDF-)가 아닙니다.")
        payload = {**payload,
                   "record_pdf": base64.b64encode(record_pdf).decode("ascii")}
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _with_process_fields(data: dict[str, Any]) -> dict[str, Any]:
    """``process_info.seal_type`` and ``.unlock_time`` when absent."""
    process_info = data.get("process_info", {})
    if not isinstance(process_info, dict):
        return data
    added = dict(process_info)
    if not added.get("seal_type"):
        seal_type = _record_seal_type(data, process_info)
        if seal_type:
            added["seal_type"] = seal_type
    unlock_iso = data.get("unlock_time_iso")
    if unlock_iso and not added.get("unlock_time"):
        added["unlock_time"] = unlock_iso
    return {**data, "process_info": added}


def _record_seal_type(data: Mapping[str, Any],
                      process_info: Mapping[str, Any]) -> Optional[str]:
    """The desktop's ``process_info.type``, else the last event's type."""
    if process_info.get("type") in _SEAL_TYPES:
        return process_info["type"]
    events = _events(data)
    last = events[-1] if events else None
    if isinstance(last, dict) and last.get("seal_type") in _SEAL_TYPES:
        return last["seal_type"]
    return None


def _with_event_ids(data: dict[str, Any]) -> dict[str, Any]:
    """Name each history event ``EVT-%04d`` from its ``id`` when unnamed."""
    history = data.get("history")
    events = history.get("events") if isinstance(history, dict) else None
    if not isinstance(events, list):
        return data
    named = []
    for event in events:
        event = copy.deepcopy(event)
        if isinstance(event, dict) and "event_id" not in event and (
            type(event.get("id")) is int
        ):
            event = {**event, "event_id": f"EVT-{event['id']:04d}"}
        named.append(event)
    return {**data, "history": {**history, "events": named}}


def _events(data: Mapping[str, Any]) -> list:
    history = data.get("history")
    events = history.get("events") if isinstance(history, dict) else None
    return events if isinstance(events, list) else []


def contract_problems(payload: Mapping[str, Any]) -> list[str]:
    """The contract's required fields a payload misses (names, no values).

    Checks (§2.3, §2.4): the six fields (objects, ``seal_id`` a string);
    ``seal_id`` as ``S-YYYYMMDD-XXXXXX`` (upper-case hex);
    ``signer_info.birth_date`` and ``.phone`` non-empty; ``process_info.
    seal_type`` one of the three events; the last history event names its
    ``event_id`` and has the same ``seal_type`` (the current event); a
    ``record_pdf``, when present, is base64 of a ``%PDF-`` file.
    """
    problems = [name for name in _SIX_FIELDS if name not in payload or (
        name != "seal_id" and not isinstance(payload[name], dict))]
    if not isinstance(payload.get("seal_id"), str) or not _SEAL_ID_RE.fullmatch(
        payload.get("seal_id") or ""
    ):
        problems.append("seal_id")
    signer = payload.get("signer_info")
    signer = signer if isinstance(signer, dict) else {}
    for name in ("birth_date", "phone"):
        value = signer.get(name)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"signer_info.{name}")
    problems.extend(_process_and_history_problems(payload))
    if "record_pdf" in payload and not _is_pdf_b64(payload["record_pdf"]):
        problems.append("record_pdf")
    return sorted(set(problems), key=problems.index)


def _process_and_history_problems(payload: Mapping[str, Any]) -> list[str]:
    process_info = payload.get("process_info")
    seal_type = (process_info.get("seal_type")
                 if isinstance(process_info, dict) else None)
    problems = [] if seal_type in _SEAL_TYPES else ["process_info.seal_type"]
    events = _events(payload)
    if not events:
        return [*problems, "history.events"]
    last = events[-1] if isinstance(events[-1], dict) else {}
    event_id = last.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        problems.append("history.events[-1].event_id")
    if last.get("seal_type") != seal_type:
        problems.append("history.events[-1].seal_type")
    return problems


def _is_pdf_b64(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return base64.b64decode(value, validate=True).startswith(b"%PDF-")
    except (binascii.Error, ValueError):
        return False


def push_seal_record(
    record_json: str | bytes,
    record_pdf_path: Optional[str] = None,
    *,
    record_pdf: Optional[bytes] = None,
    base_url: Optional[str] = None,
    secret: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Push a seal record to the portal.

    Returns:
        The portal's answer (``{"status": ..., "message": ...}``).

    Raises:
        PortalSyncError: On missing configuration, a payload outside the
            contract, an unsafe URL, a redirect, a network failure, or an
            answer that is not the contract's acknowledgement (the message
            names the status and the portal's message, never the record).
    """
    base_url = base_url or os.environ.get(ENV_BASE_URL, "").strip()
    secret = secret or os.environ.get(ENV_SECRET, "").strip()
    if not base_url or not secret:
        raise PortalSyncError(
            f"{ENV_BASE_URL}/{ENV_SECRET} 환경변수가 설정되지 않았습니다.")
    url = base_url.rstrip("/") + API_PATH
    try:
        transport.require_safe_url(url)
    except transport.TransportError as exc:
        raise PortalSyncError(str(exc)) from exc
    raw_body = _prepare_payload(record_json, record_pdf_path,
                                record_pdf=record_pdf)
    _require_contract(raw_body)
    timestamp = str(int(time.time()))
    nonce = "n-" + secrets.token_hex(16)
    headers = {
        "Content-Type": "application/json",
        "X-Sync-Timestamp": timestamp,
        "X-Sync-Nonce": nonce,
        "X-Sync-Signature": _canonical_signature(secret, timestamp, nonce,
                                                 raw_body),
    }
    try:
        answer = transport.post(url, raw_body, headers, timeout)
    except transport.TransportError as exc:
        raise PortalSyncError(str(exc)) from exc
    body = _acknowledged(answer)
    logger.info("Portal push accepted: %s", transport.clip(body["message"]))
    return body


def _require_contract(raw_body: bytes) -> None:
    """Refuse to send a payload outside the contract (fields named only)."""
    if len(raw_body) > MAX_BODY_BYTES:
        raise PortalSyncError("본문이 계약 상한(8MB)을 넘어 보내지 않았습니다.")
    problems = contract_problems(json.loads(raw_body.decode("utf-8")))
    if problems:
        raise PortalSyncError(
            "포털 계약의 필수 필드를 갖추지 못해 보내지 않았습니다: "
            + ", ".join(problems))


def _acknowledged(answer: transport.Answer) -> dict[str, Any]:
    """The contract's acknowledgement: HTTP 200, JSON status and message."""
    body = answer.json_object()
    well_formed = body is not None and isinstance(
        body.get("status"), str) and isinstance(body.get("message"), str)
    if answer.status == 200 and well_formed and (
        body["status"].strip().lower() not in _ERROR_STATUSES
    ):
        return body
    if answer.status != 200:
        raise PortalSyncError(f"HTTP {answer.status}: {answer.message()}")
    raise PortalSyncError(
        "HTTP 200 without the contract's acknowledgement (JSON status and "
        f"message; status not an error): {answer.message()}")


def push_seal_record_safe(
    record_json: str | bytes,
    record_pdf_path: Optional[str] = None,
    **kwargs: Any,
) -> bool:
    """Push without raising (kept from 1570671; the processes use the outbox).

    An unconfigured portal is skipped (INFO); a failure is a WARNING.
    """
    if not (
        (kwargs.get("base_url") or os.environ.get(ENV_BASE_URL, "").strip())
        and (kwargs.get("secret") or os.environ.get(ENV_SECRET, "").strip())
    ):
        logger.info("Portal sync not configured; push skipped")
        return False
    try:
        push_seal_record(record_json, record_pdf_path, **kwargs)
        return True
    except Exception as exc:
        logger.warning("Portal push failed (local record kept): %s", exc)
        return False


def main(argv: Optional[list[str]] = None) -> int:
    """Manual push of one record file (backfill)."""
    parser = argparse.ArgumentParser(
        description="봉인기록 JSON을 포털로 수동 전송합니다(백필용).")
    parser.add_argument("record", help="봉인기록 JSON 파일 경로")
    parser.add_argument("--pdf", help="첨부할 봉인기록지 PDF 경로", default=None)
    parser.add_argument("--url", help=f"베이스 URL (기본: ${ENV_BASE_URL})",
                        default=None)
    args = parser.parse_args(argv)
    with open(args.record, encoding="utf-8") as f:
        record_json = f.read()
    try:
        body = push_seal_record(record_json, args.pdf, base_url=args.url)
    except PortalSyncError as exc:
        logger.error("전송 실패: %s", exc)
        return 1
    sys.stdout.write(json.dumps(body, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    sys.exit(main())
