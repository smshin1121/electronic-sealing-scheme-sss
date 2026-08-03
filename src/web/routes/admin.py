"""Admin (관리자) Blueprint.

Endpoints
---------
GET  /admin/shares              -- 키 조각 4 목록
POST /admin/emergency-recover   -- 비상 복구 (관리자 승인)
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..models.db_models import (
    find_admin_share_summaries,
    find_key_shares_by_seal_id,
    find_latest_seal_mode,
)

logger = logging.getLogger(__name__)

bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder="../templates/admin",
)


def _require_admin() -> bool:
    """Check if the current session has admin access.

    Returns:
        True if admin, False otherwise.
    """
    return bool(session.get("is_admin"))


# ---------------------------------------------------------------------------
# GET /admin/shares
# ---------------------------------------------------------------------------
@bp.route("/shares", methods=["GET"])
def shares() -> Any:
    """List admin key shares (키 조각 4) across all cases."""
    if not _require_admin():
        flash("관리자 인증이 필요합니다.", "danger")
        return redirect(url_for("admin.login"))

    rows = find_admin_share_summaries()

    shares_list: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            shares_list.append(row)
        elif hasattr(row, "keys"):
            shares_list.append({k: row[k] for k in row.keys()})
        else:
            shares_list.append({
                "id": row[0],
                "seal_id": row[1],
                "share_index": row[2],
                "uploaded_by": row[3],
                "uploaded_at": row[4],
            })

    return render_template("shares.html", shares=shares_list)


# ---------------------------------------------------------------------------
# GET/POST /admin/emergency-recover
# ---------------------------------------------------------------------------
@bp.route("/emergency-recover", methods=["GET", "POST"])
def emergency_recover() -> Any:
    """Emergency key recovery using admin share (키 조각 4) + any other share."""
    if not _require_admin():
        flash("관리자 인증이 필요합니다.", "danger")
        return redirect(url_for("admin.login"))

    if request.method == "GET":
        return render_template("emergency_recover.html")

    seal_id = (request.form.get("seal_id") or "").strip()
    reason = (request.form.get("reason") or "").strip()

    if not seal_id:
        flash("봉인 ID를 입력해 주세요.", "danger")
        return render_template("emergency_recover.html"), 400

    if not reason:
        flash("비상 복구 사유를 입력해 주세요.", "danger")
        return render_template("emergency_recover.html"), 400

    shares_rows = find_key_shares_by_seal_id(seal_id)
    if len(shares_rows) < 2:
        flash(
            f"키 조각이 부족합니다. 현재 {len(shares_rows)}개 / 최소 2개 필요",
            "danger",
        )
        return render_template("emergency_recover.html"), 400

    # Must include admin share (index 4)
    admin_share = None
    other_share = None
    for row in shares_rows:
        if isinstance(row, dict):
            idx = row["share_index"]
            data = row["share_data"]
        elif hasattr(row, "keys"):
            idx = row["share_index"]
            data = row["share_data"]
        else:
            idx = row[2]
            data = row[3]

        if idx == 4:
            admin_share = data
        elif other_share is None:
            other_share = data

    if not admin_share:
        flash("관리자 키 조각(4)이 존재하지 않습니다.", "danger")
        return render_template("emergency_recover.html"), 400

    if not other_share:
        flash("복원에 필요한 다른 키 조각이 존재하지 않습니다.", "danger")
        return render_template("emergency_recover.html"), 400

    # CR-04: the emergency path goes through the same mode dispatcher as
    # investigator recovery. Under strict mode this correctly REFUSES an
    # s2+s4 coalition — the owner share is required in every path.
    try:
        seal_mode = find_latest_seal_mode(seal_id)
    except ValueError:
        logger.exception("seal_mode unresolvable for %s", seal_id)
        flash(
            "봉인 기록의 복구 방식(seal_mode)을 검증할 수 없어 복원을 "
            "거부합니다.", "danger",
        )
        return render_template("emergency_recover.html"), 500

    if seal_mode is None:
        logger.warning(
            "No synced sealing record for %s; applying legacy standard "
            "mode", seal_id,
        )
        seal_mode = "standard"

    try:
        import sys
        import os

        crypto_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "desktop", "crypto")
        )
        if crypto_path not in sys.path:
            sys.path.insert(0, os.path.dirname(crypto_path))

        from desktop.crypto.sss_strict import recover_key_for_mode

        recovered_hex = recover_key_for_mode(
            seal_mode, [other_share, admin_share]
        )
    except Exception:
        logger.exception("비상 키 복원 실패")
        flash("키 복원에 실패했습니다.", "danger")
        return render_template("emergency_recover.html"), 500

    logger.info(
        "Emergency key recovery performed for seal_id=%s reason=%s",
        seal_id,
        reason,
    )

    return render_template(
        "emergency_result.html",
        seal_id=seal_id,
        recovered_key=recovered_hex,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# GET/POST /admin/login
# ---------------------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
def login() -> Any:
    """Simple admin login (password-based)."""
    if request.method == "GET":
        return render_template("login.html")

    password = request.form.get("password", "")
    # This prototype accepts an environment-provided password. It deliberately
    # has no built-in credential: an unset value disables admin login.
    admin_password = current_app.config.get("ADMIN_PASSWORD")
    if not isinstance(admin_password, str) or not admin_password:
        logger.error("Admin login unavailable: ADMIN_PASSWORD is not configured")
        flash("Admin login is not configured.", "danger")
        return render_template("login.html"), 503

    if secrets.compare_digest(password, admin_password):
        session["is_admin"] = True
        flash("관리자 로그인 성공", "success")
        return redirect(url_for("admin.shares"))

    flash("관리자 비밀번호가 일치하지 않습니다.", "danger")
    return render_template("login.html"), 401
