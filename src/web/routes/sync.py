"""Synchronization endpoint.

Receives seal records from the desktop SQLite DB and stores them
in the web MariaDB (or SQLite fallback). Idempotent: duplicate
(seal_id, event_id) pairs are silently ignored.

Endpoint
--------
POST /sync/upload-record  -- SQLite -> MariaDB record sync
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from flask import Blueprint, jsonify, request

from ..models.db_models import insert_seal_record

logger = logging.getLogger(__name__)

bp = Blueprint("sync", __name__, url_prefix="/sync")

# Maximum accepted base64-encoded PDF length (~30 MB decoded)
MAX_PDF_B64_LENGTH = 40 * 1024 * 1024


@bp.route("/upload-record", methods=["POST"])
def upload_record() -> tuple[Any, int]:
    """Receive and store a seal record (idempotent).

    Expected JSON body::

        {
            "seal_id":     "S-20251104-ABA82E",
            "event_id":    1,
            "event_type":  "Sealing",
            "record_json": "{ ... }",
            "record_pdf":  "<base64-encoded PDF or null>"
        }

    Returns:
        JSON response with status.
    """
    if not request.is_json:
        return jsonify({"status": "error", "message": "JSON 요청이 필요합니다."}), 400

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"status": "error", "message": "잘못된 JSON 형식입니다."}), 400

    seal_id = (data.get("seal_id") or "").strip()
    event_id = data.get("event_id")
    event_type = (data.get("event_type") or "").strip()
    record_json = data.get("record_json", "")
    record_pdf_b64 = data.get("record_pdf")

    # --- validation ---
    errors: list[str] = []
    if not seal_id:
        errors.append("seal_id는 필수입니다.")
    if event_id is None:
        errors.append("event_id는 필수입니다.")
    if event_type not in ("Sealing", "Unsealing", "Resealing"):
        errors.append("event_type은 Sealing, Unsealing, Resealing 중 하나여야 합니다.")
    if not record_json:
        errors.append("record_json은 필수입니다.")

    if errors:
        return jsonify({"status": "error", "message": " / ".join(errors)}), 400

    # Validate record_json is parseable
    try:
        json.loads(record_json) if isinstance(record_json, str) else record_json
    except (json.JSONDecodeError, TypeError):
        return jsonify({"status": "error", "message": "record_json이 올바른 JSON이 아닙니다."}), 400

    # Decode optional PDF (validate type/length before decoding)
    record_pdf: bytes | None = None
    if record_pdf_b64:
        if not isinstance(record_pdf_b64, str):
            return jsonify({"status": "error", "message": "record_pdf는 base64 문자열이어야 합니다."}), 400
        if len(record_pdf_b64) > MAX_PDF_B64_LENGTH:
            return jsonify({"status": "error", "message": "record_pdf가 허용 크기를 초과했습니다."}), 413
        try:
            record_pdf = base64.b64decode(record_pdf_b64, validate=True)
        except Exception:
            return jsonify({"status": "error", "message": "record_pdf의 base64 디코딩에 실패했습니다."}), 400

    # Ensure record_json is a string
    if not isinstance(record_json, str):
        record_json = json.dumps(record_json, ensure_ascii=False)

    try:
        insert_seal_record(
            seal_id=seal_id,
            event_id=int(event_id),
            event_type=event_type,
            record_json=record_json,
            record_pdf=record_pdf,
        )
    except Exception:
        logger.exception("동기화 실패: seal_id=%s event_id=%s", seal_id, event_id)
        return jsonify({"status": "error", "message": "기록 저장에 실패했습니다."}), 500

    return jsonify({"status": "ok", "message": "동기화 완료"}), 200
