"""Investigator (수사관) Blueprint.

Endpoints
---------
POST /investigator/register-case  -- 사건 등록
POST /investigator/upload-share   -- 키 조각 2 업로드
POST /investigator/recover-key    -- SSS 키 복원
GET  /investigator/download-key/<seal_id> -- .key 파일 다운로드
GET  /investigator/recovered/<seal_id>    -- 복원 키 표시 페이지
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from ..auth.auth_chain import normalize_birth_date
from ..models.db_models import (
    find_case_by_seal_id,
    find_key_shares_by_seal_id,
    find_latest_key_commitment,
    find_latest_seal_mode,
    find_latest_unlock_time,
    insert_case,
    insert_key_share,
)

logger = logging.getLogger(__name__)

bp = Blueprint(
    "investigator",
    __name__,
    url_prefix="/investigator",
    template_folder="../templates/investigator",
)


# ---------------------------------------------------------------------------
# POST /investigator/register-case
# ---------------------------------------------------------------------------
@bp.route("/register-case", methods=["GET", "POST"])
def register_case() -> Any:
    """Register a new case (사건 등록)."""
    if request.method == "GET":
        return render_template("register_case.html")

    seal_id = (request.form.get("seal_id") or "").strip()
    case_number = (request.form.get("case_number") or "").strip()
    investigator_name = (request.form.get("investigator") or "").strip()
    suspect_name = (request.form.get("suspect_name") or "").strip()
    suspect_email = (request.form.get("suspect_email") or "").strip()
    # Canonicalize birth date (accepts '1990-01-01' and '19900101' forms)
    suspect_birth = normalize_birth_date(
        (request.form.get("suspect_birth") or "").strip()
    )
    suspect_phone = (request.form.get("suspect_phone") or "").strip()
    auth_level = (request.form.get("auth_level") or "basic").strip()
    password_raw = request.form.get("password") or ""

    # --- validation ---
    errors: list[str] = []
    if not seal_id:
        errors.append("봉인 ID를 입력해 주세요.")
    if not case_number:
        errors.append("사건번호를 입력해 주세요.")
    if not investigator_name:
        errors.append("수사관 이름을 입력해 주세요.")
    if not suspect_name:
        errors.append("피압수자 이름을 입력해 주세요.")

    if "password" in auth_level and not password_raw:
        errors.append("비밀번호 인증을 사용하려면 비밀번호를 입력해 주세요.")

    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template("register_case.html"), 400

    # Hash the password if provided
    password_hash = ""
    if password_raw:
        password_hash = hashlib.sha256(password_raw.encode("utf-8")).hexdigest()

    # Check for duplicate
    existing = find_case_by_seal_id(seal_id)
    if existing:
        flash("이미 등록된 봉인 ID입니다.", "warning")
        return render_template("register_case.html"), 409

    try:
        insert_case(
            seal_id=seal_id,
            case_number=case_number,
            investigator=investigator_name,
            suspect_name=suspect_name,
            suspect_email=suspect_email,
            suspect_birth=suspect_birth,
            suspect_phone=suspect_phone,
            auth_level=auth_level,
            password_hash=password_hash,
        )
    except Exception:
        logger.exception("사건 등록 실패")
        flash("사건 등록 중 오류가 발생했습니다.", "danger")
        return render_template("register_case.html"), 500

    flash("사건이 등록되었습니다.", "success")
    return redirect(url_for("investigator.register_case"))


# ---------------------------------------------------------------------------
# POST /investigator/upload-share
# ---------------------------------------------------------------------------
@bp.route("/upload-share", methods=["GET", "POST"])
def upload_share() -> Any:
    """Upload investigator key share (키 조각 2)."""
    if request.method == "GET":
        return render_template("upload_share.html")

    seal_id = (request.form.get("seal_id") or "").strip()
    share_data = (request.form.get("share_data") or "").strip()

    if not seal_id or not share_data:
        flash("봉인 ID와 키 조각을 모두 입력해 주세요.", "danger")
        return render_template("upload_share.html"), 400

    case = find_case_by_seal_id(seal_id)
    if not case:
        flash("해당 봉인 ID의 사건이 존재하지 않습니다.", "danger")
        return render_template("upload_share.html"), 404

    try:
        insert_key_share(
            seal_id=seal_id,
            share_index=2,
            share_data=share_data,
            uploaded_by="investigator",
        )
    except Exception:
        logger.exception("키 조각 업로드 실패")
        flash("키 조각 업로드 중 오류가 발생했습니다.", "danger")
        return render_template("upload_share.html"), 500

    flash("수사관 키 조각이 업로드되었습니다.", "success")
    return redirect(url_for("investigator.upload_share"))


# ---------------------------------------------------------------------------
# POST /investigator/recover-key
# ---------------------------------------------------------------------------
@bp.route("/recover-key", methods=["GET", "POST"])
def recover_key() -> Any:
    """Recover AES key from uploaded shares via SSS."""
    if request.method == "GET":
        return render_template("recover_key.html")

    seal_id = (request.form.get("seal_id") or "").strip()
    if not seal_id:
        flash("봉인 ID를 입력해 주세요.", "danger")
        return render_template("recover_key.html"), 400

    shares_rows = find_key_shares_by_seal_id(seal_id)
    if len(shares_rows) < 2:
        flash(
            f"키 조각이 부족합니다. 현재 {len(shares_rows)}개 / 최소 2개 필요",
            "danger",
        )
        return render_template("recover_key.html"), 400

    # Extract share_data — handle both dict-like and tuple rows
    share_strings: list[str] = []
    for row in shares_rows:
        if isinstance(row, dict):
            share_strings.append(row["share_data"])
        elif hasattr(row, "keys"):
            # sqlite3.Row
            share_strings.append(row["share_data"])
        else:
            # Tuple: share_data is index 3
            share_strings.append(row[3])

    # Server-side mode dispatch (no UI branch): the sealing record synced
    # from the offline environment states the recovery regime. A present
    # but unreadable/unrecognized record denies recovery (fail-closed);
    # only the documented legacy case (no synced record at all) defaults
    # to standard.
    try:
        seal_mode = find_latest_seal_mode(seal_id)
    except ValueError:
        logger.exception("seal_mode unresolvable for %s", seal_id)
        flash(
            "봉인 기록의 복구 방식(seal_mode)을 검증할 수 없어 복원을 "
            "거부합니다.", "danger",
        )
        return render_template("recover_key.html"), 500

    if seal_mode is None:
        logger.warning(
            "No synced sealing record for %s; applying legacy standard "
            "mode", seal_id,
        )
        seal_mode = "standard"

    # Unlock-time policy gate: a server-side comparison of the current
    # time against the unlock time anchored at sealing. This is a policy
    # check distinct from the cryptographic s3 release verification and
    # deliberately involves no TSA round trip, so a TSA outage does not
    # block standard recovery. A present but unparseable unlock time
    # denies recovery (fail-closed); records without the field (legacy)
    # are ungated.
    try:
        unlock_iso = find_latest_unlock_time(seal_id)
    except ValueError:
        logger.exception("unlock_time unresolvable for %s", seal_id)
        flash(
            "봉인 기록의 열람 제한 시각(unlock_time)을 검증할 수 없어 "
            "복원을 거부합니다.", "danger",
        )
        return render_template("recover_key.html"), 500

    if unlock_iso is not None:
        try:
            # Records use the trailing-Z ISO form; accept the offset form
            # too so legacy rows parse on any supported interpreter.
            unlock_dt = datetime.fromisoformat(
                unlock_iso.replace("Z", "+00:00")
            )
            if unlock_dt.tzinfo is None:
                unlock_dt = unlock_dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            logger.error(
                "Invalid unlock_time %r for %s", unlock_iso, seal_id,
            )
            flash(
                "봉인 기록의 열람 제한 시각이 올바르지 않아 복원을 "
                "거부합니다.", "danger",
            )
            return render_template("recover_key.html"), 500

        if datetime.now(tz=timezone.utc) < unlock_dt:
            flash(
                "열람 제한 기간이 경과하지 않아 키 복원이 제한됩니다. "
                f"(해제 시각: {unlock_dt.isoformat()})", "danger",
            )
            return render_template("recover_key.html"), 403

    try:
        import sys
        import os

        # Import the crypto module's recovery dispatch
        crypto_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "desktop", "crypto")
        )
        if crypto_path not in sys.path:
            sys.path.insert(0, os.path.dirname(crypto_path))

        from desktop.crypto.sss_strict import (
            SEAL_MODE_STRICT,
            recover_key_for_mode,
        )

        if seal_mode == SEAL_MODE_STRICT:
            recovered_hex = recover_key_for_mode(seal_mode, share_strings)
        else:
            recovered_hex = recover_key_for_mode(
                seal_mode, share_strings[:2]
            )
    except Exception:
        logger.exception("키 복원 실패")
        flash("키 복원에 실패했습니다. 키 조각이 올바른지 확인해 주세요.", "danger")
        return render_template("recover_key.html"), 500

    # Verify the reconstruction against the signed commitment. Threshold
    # recovery yields a plausible-looking key from wrong or corrupted
    # shares, so without this check the portal would hand out a key that
    # only fails much later, at unseal time.
    try:
        commitment = find_latest_key_commitment(seal_id)
    except ValueError:
        logger.exception("key_commitment unresolvable for %s", seal_id)
        flash(
            "봉인 기록의 복구키 확인값을 검증할 수 없어 복원을 거부합니다.",
            "danger",
        )
        return render_template("recover_key.html"), 500

    if commitment is None:
        logger.warning(
            "No key_commitment recorded for %s; reconstruction cannot be "
            "verified (legacy record)", seal_id,
        )
    elif hashlib.sha256(
        bytes.fromhex(recovered_hex)
    ).hexdigest() != commitment:
        logger.error("key_commitment mismatch for %s", seal_id)
        flash(
            "복원된 키가 봉인 기록의 확인값과 일치하지 않습니다. 키 조각을 "
            "다시 확인해 주세요.", "danger",
        )
        return render_template("recover_key.html"), 400

    # Store temporarily in session for download
    session[f"recovered_key_{seal_id}"] = recovered_hex

    return redirect(url_for("investigator.recovered", seal_id=seal_id))


# ---------------------------------------------------------------------------
# GET /investigator/recovered/<seal_id>
# ---------------------------------------------------------------------------
@bp.route("/recovered/<seal_id>")
def recovered(seal_id: str) -> Any:
    """Display recovered key with copy button and safety guidance."""
    recovered_hex = session.get(f"recovered_key_{seal_id}")
    if not recovered_hex:
        flash("복원된 키가 없습니다. 먼저 키 복원을 수행해 주세요.", "warning")
        return redirect(url_for("investigator.recover_key"))

    return render_template(
        "recovered_key.html",
        seal_id=seal_id,
        recovered_key=recovered_hex,
    )


# ---------------------------------------------------------------------------
# GET /investigator/download-key/<seal_id>
# ---------------------------------------------------------------------------
@bp.route("/download-key/<seal_id>")
def download_key(seal_id: str) -> Any:
    """Download recovered key as a .key file."""
    recovered_hex = session.get(f"recovered_key_{seal_id}")
    if not recovered_hex:
        flash("다운로드할 키가 없습니다.", "warning")
        return redirect(url_for("investigator.recover_key"))

    buf = io.BytesIO(recovered_hex.encode("utf-8"))
    buf.seek(0)

    return send_file(
        buf,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"{seal_id}.key",
    )
