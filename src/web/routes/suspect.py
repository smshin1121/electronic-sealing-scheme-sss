"""Suspect (피압수자) Blueprint.

Endpoints
---------
GET  /suspect/auth/<seal_id>     -- 본인 인증 페이지
POST /suspect/auth/<seal_id>     -- 인증 처리
POST /suspect/upload-share       -- 키 조각 1 업로드
GET  /suspect/records/<seal_id>  -- 봉인기록지 열람
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..auth.auth_chain import AuthChain
from ..auth.otp_service import OTPService
from ..models.db_models import (
    count_recent_auth_failures,
    find_case_by_seal_id,
    find_seal_record_json,
    find_seal_record_summaries_by_seal_id,
    insert_key_share,
    record_auth_failure,
)

logger = logging.getLogger(__name__)

bp = Blueprint(
    "suspect",
    __name__,
    url_prefix="/suspect",
    template_folder="../templates/suspect",
)


def _case_to_dict(row: Any) -> dict[str, Any]:
    """Convert a database row to a plain dict."""
    if isinstance(row, dict):
        return row
    if hasattr(row, "keys"):
        return {k: row[k] for k in row.keys()}
    # Tuple fallback: match cases table column order
    cols = [
        "id", "seal_id", "case_number", "investigator", "suspect_name",
        "suspect_email", "suspect_birth", "suspect_phone",
        "auth_level", "password_hash", "created_at", "updated_at",
    ]
    return dict(zip(cols, row))


# ---------------------------------------------------------------------------
# GET/POST /suspect/auth/<seal_id>
# ---------------------------------------------------------------------------
@bp.route("/auth/", defaults={"seal_id": ""}, methods=["GET"])
@bp.route("/auth/<seal_id>", methods=["GET", "POST"])
def auth(seal_id: str) -> Any:
    """Suspect identity verification page."""
    if not seal_id:
        return render_template(
            "auth.html",
            seal_id="",
            case=None,
            auth_level="basic",
            otp_session_id="",
            locked=False,
        )

    case_row = find_case_by_seal_id(seal_id)
    if not case_row:
        flash("해당 봉인 ID의 사건이 존재하지 않습니다.", "danger")
        return render_template("auth.html", seal_id=seal_id, case=None), 404

    case = _case_to_dict(case_row)
    auth_level = case.get("auth_level", "basic")

    # --- Lockout check ---
    max_failures = current_app.config.get("AUTH_MAX_FAILURES", 5)
    lockout_seconds = current_app.config.get("AUTH_LOCKOUT_SECONDS", 600)
    client_ip = request.remote_addr or "unknown"

    recent_failures = count_recent_auth_failures(
        seal_id, client_ip, lockout_seconds
    )
    if recent_failures >= max_failures:
        flash(
            f"인증 실패 횟수 초과로 {lockout_seconds // 60}분간 차단되었습니다.",
            "danger",
        )
        return render_template(
            "auth.html", seal_id=seal_id, case=case, locked=True
        ), 429

    if request.method == "GET":
        # If OTP is part of auth, generate a session_id for future verification
        otp_session_id = ""
        if "otp" in auth_level:
            otp_session_id = str(uuid.uuid4())
            session[f"otp_session_{seal_id}"] = otp_session_id

        return render_template(
            "auth.html",
            seal_id=seal_id,
            case=case,
            auth_level=auth_level,
            otp_session_id=otp_session_id,
            locked=False,
        )

    # --- POST: perform authentication ---
    credentials: dict[str, Any] = {
        "name": request.form.get("name", ""),
        "birth_date": request.form.get("birth_date", ""),
        "phone": request.form.get("phone", ""),
        "password": request.form.get("password", ""),
        "otp": request.form.get("otp", ""),
        "session_id": session.get(f"otp_session_{seal_id}", ""),
    }

    chain = AuthChain(auth_level)
    result = chain.run(case, credentials)

    if not result.success:
        record_auth_failure(seal_id, client_ip)
        flash(result.message, "danger")
        return render_template(
            "auth.html", seal_id=seal_id, case=case, auth_level=auth_level
        ), 401

    # Mark session as authenticated for this seal_id
    session[f"auth_{seal_id}"] = True
    flash("본인 인증이 완료되었습니다.", "success")
    return redirect(url_for("suspect.upload_share_page", seal_id=seal_id))


# ---------------------------------------------------------------------------
# POST /suspect/send-otp/<seal_id>
# ---------------------------------------------------------------------------
def _wants_json_response() -> bool:
    """Check whether the client expects a JSON response (fetch/AJAX)."""
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    return "application/json" in (request.headers.get("Accept") or "")


@bp.route("/send-otp/<seal_id>", methods=["POST"])
def send_otp(seal_id: str) -> Any:
    """Send OTP email to the suspect's registered address.

    Supports both classic form POST (redirect + flash) and
    fetch()-based async requests (JSON response).
    """
    wants_json = _wants_json_response()

    def _respond(success: bool, message: str, category: str) -> Any:
        if wants_json:
            status = 200 if success else 400
            return jsonify({"success": success, "message": message}), status
        flash(message, category)
        return redirect(url_for("suspect.auth", seal_id=seal_id))

    case_row = find_case_by_seal_id(seal_id)
    if not case_row:
        return _respond(False, "사건을 찾을 수 없습니다.", "danger")

    case = _case_to_dict(case_row)
    email = case.get("suspect_email", "")
    if not email:
        return _respond(False, "등록된 이메일이 없습니다.", "danger")

    otp_session_id = str(uuid.uuid4())
    session[f"otp_session_{seal_id}"] = otp_session_id

    svc = OTPService()
    code = svc.generate_otp()
    svc.store_otp(otp_session_id, code)
    sent = svc.send_otp(email, code)

    if sent:
        return _respond(True, "인증번호가 이메일로 발송되었습니다. (유효시간 5분)", "info")
    return _respond(False, "인증번호 발송에 실패했습니다. 다시 시도해 주세요.", "danger")


# ---------------------------------------------------------------------------
# GET/POST /suspect/upload-share
# ---------------------------------------------------------------------------
@bp.route("/upload-share", methods=["GET", "POST"])
@bp.route("/upload-share/<seal_id>", methods=["GET", "POST"])
def upload_share_page(seal_id: str | None = None) -> Any:
    """Upload suspect key share (키 조각 1)."""
    if request.method == "GET":
        return render_template("upload_share.html", seal_id=seal_id or "")

    seal_id_form = (request.form.get("seal_id") or seal_id or "").strip()
    share_data = (request.form.get("share_data") or "").strip()

    if not seal_id_form or not share_data:
        flash("봉인 ID와 키 조각을 모두 입력해 주세요.", "danger")
        return render_template("upload_share.html", seal_id=seal_id_form), 400

    # Check authentication
    if not session.get(f"auth_{seal_id_form}"):
        flash("본인 인증이 필요합니다.", "warning")
        return redirect(url_for("suspect.auth", seal_id=seal_id_form))

    case = find_case_by_seal_id(seal_id_form)
    if not case:
        flash("해당 봉인 ID의 사건이 존재하지 않습니다.", "danger")
        return render_template("upload_share.html", seal_id=seal_id_form), 404

    try:
        insert_key_share(
            seal_id=seal_id_form,
            share_index=1,
            share_data=share_data,
            uploaded_by="suspect",
        )
    except Exception:
        logger.exception("피압수자 키 조각 업로드 실패")
        flash("키 조각 업로드 중 오류가 발생했습니다.", "danger")
        return render_template("upload_share.html", seal_id=seal_id_form), 500

    flash("키 조각이 업로드되었습니다.", "success")
    return redirect(url_for("suspect.records", seal_id=seal_id_form))


# ---------------------------------------------------------------------------
# GET /suspect/records/<seal_id>
# ---------------------------------------------------------------------------
@bp.route("/records/<seal_id>")
def records(seal_id: str) -> Any:
    """View seal records for a given seal_id."""
    # Require authentication
    if not session.get(f"auth_{seal_id}"):
        flash("본인 인증이 필요합니다.", "warning")
        return redirect(url_for("suspect.auth", seal_id=seal_id))

    rows = find_seal_record_summaries_by_seal_id(seal_id)
    records_list: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            records_list.append(row)
        elif hasattr(row, "keys"):
            records_list.append({k: row[k] for k in row.keys()})
        else:
            records_list.append({
                "id": row[0],
                "seal_id": row[1],
                "event_id": row[2],
                "event_type": row[3],
                "synced_at": row[4],
            })

    return render_template(
        "records.html", seal_id=seal_id, records=records_list
    )


# ---------------------------------------------------------------------------
# GET /suspect/records/<seal_id>/detail/<event_id>
# ---------------------------------------------------------------------------
@bp.route("/records/<seal_id>/detail/<int:event_id>")
def record_detail(seal_id: str, event_id: int) -> Any:
    """Return the record_json payload of a single seal record (JSON API).

    Used by the records page modal to lazily load record details,
    so the list view does not carry heavy JSON/PDF payloads.
    """
    if not session.get(f"auth_{seal_id}"):
        return jsonify({"success": False, "message": "본인 인증이 필요합니다."}), 401

    record_json = find_seal_record_json(seal_id, event_id)
    if record_json is None:
        return jsonify({"success": False, "message": "기록을 찾을 수 없습니다."}), 404

    return jsonify({
        "success": True,
        "seal_id": seal_id,
        "event_id": event_id,
        "record_json": record_json,
    })
