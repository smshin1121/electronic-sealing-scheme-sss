"""Suspect (피압수자) Blueprint.

Endpoints
---------
GET  /suspect/auth/<seal_id>     -- 본인 인증 페이지
POST /suspect/auth/<seal_id>     -- 인증 처리
POST /suspect/send-otp/<seal_id> -- 인증번호 발송 (기본·비밀번호 인증 뒤)
POST /suspect/upload-share       -- 키 조각 1 업로드
GET  /suspect/records/<seal_id>  -- 봉인기록지 열람 (목록, 내용 없음)
GET  /suspect/records/<seal_id>/detail/<event_id> -- 기록 내용 (JSON, 열람 감사)
GET  /suspect/records/<seal_id>/pdf/<event_id>    -- 기록지 PDF (내려받기, 열람 감사)

Identity protection (stage E, E3a): the case's name, birth date and phone
are compared as keyed digests (:mod:`web.privacy.case_identity`), and the
authentication chain always starts with that basic check. The e-mail is
decrypted only to deliver an OTP, only after the basic (and, when the case
uses it, password) factors of that case passed in the same request, and
every decryption writes an ``identity_access_audit`` row. Missing keys
answer 503 and do not count as a failed attempt. A case whose identity was
never converted answers exactly as a wrong credential (401, the same
message, counted toward the lockout), so a response does not show which
cases are still unconverted; the cause is logged at WARNING (Fable gate,
finding 10). No template receives the case's identity.

Seal records (stage E, E3b): synced records are stored encrypted. The
record detail and the PDF download decrypt only after the subject's
session check for that seal, through :mod:`web.privacy.record_access`,
which writes an ``identity_access_audit`` row per decryption and withholds
the content (503) when that row cannot be written. The list page reads no
content. Responses carrying content are marked ``Cache-Control: no-store``.
"""

from __future__ import annotations

import io
import logging
import uuid
from typing import Any, Callable, Optional

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from ..auth.auth_chain import MSG_IDENTITY_MISMATCH, AuthChain, AuthResult
from ..auth.case_passwords import is_legacy_password_hash, upgraded_hash
from ..auth.kdf_slots import DerivationBusy
from ..auth.otp_service import OTPService
from ..auth.passwords import MAX_PASSWORD_LENGTH
from ..models.db_models import (
    count_recent_auth_failures,
    find_case_by_seal_id,
    find_seal_record_summaries_by_seal_id,
    insert_key_share,
    record_auth_failure,
)
from ..models.privacy_models import (
    CaseIdentityRow,
    find_case_identity,
    replace_case_password_hash,
)
from ..models.release_models import seal_write_transaction
from ..privacy.case_identity import (
    PURPOSE_CODE_DELIVERY,
    IdentityAuditError,
    LegacyIdentityError,
    recent_reveals,
    reveal_case_field,
)
from ..privacy.field_crypto import FieldCryptoError
from ..privacy.keys import PrivacyError, privacy_keys_configured
from ..privacy.record_access import reveal_record_json, reveal_record_pdf
from ..privacy.record_store import LegacyRecordError

logger = logging.getLogger(__name__)

bp = Blueprint(
    "suspect",
    __name__,
    url_prefix="/suspect",
    template_folder="../templates/suspect",
)

_MSG_KEYS_MISSING = (
    "개인정보 보호 키가 설정되지 않았거나 쓸 수 없어 본인 인증을 진행할 수 "
    "없습니다. 관리자에게 문의해 주세요."
)
_MSG_ACCESS_NOT_AUDITED = (
    "개인정보 열람 기록을 남길 수 없어 인증번호를 발송하지 않았습니다. "
    "잠시 후 다시 시도해 주세요."
)
_MSG_DELIVERY_ERROR = "인증번호 발송 중 오류가 발생했습니다. 관리자에게 문의해 주세요."
_MSG_TOO_MANY_DELIVERIES = "인증번호를 여러 번 발송했습니다. 잠시 후 다시 시도해 주세요."
_MSG_TRY_AGAIN = "요청을 지금 처리하지 못했습니다. 잠시 후 다시 시도해 주세요."
_MSG_BUSY = ("서버에서 처리 중인 인증 요청이 많아 지금은 처리하지 못했습니다. "
             "잠시 후 다시 시도해 주세요.")
_MIGRATION_COMMAND = "python -m src.web.privacy.migrate --apply"
_MSG_AUTH_REQUIRED = "본인 인증이 필요합니다."
# Refusals of the record content routes: (HTTP status, message).
_RECORD_NOT_AUDITED = (503, "개인정보 열람 기록을 남길 수 없어 기록을 보여 드리지 "
                            "않았습니다. 잠시 후 다시 시도해 주세요.")
_RECORD_NOT_CONVERTED = (503, "이 봉인 기록은 아직 보호 형식으로 이관되지 않아 "
                              "열람할 수 없습니다. 관리자에게 문의해 주세요.")
_RECORD_KEYS_MISSING = (503, "개인정보 보호 키가 설정되지 않았거나 쓸 수 없어 "
                             "기록을 열람할 수 없습니다. 관리자에게 문의해 주세요.")
_RECORD_UNREADABLE = (500, "기록을 읽을 수 없습니다. 관리자에게 문의해 주세요.")
_RECORD_FAILED = (500, "기록을 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.")
_RECORD_NOT_FOUND = (404, "기록을 찾을 수 없습니다.")
_PDF_NOT_FOUND = (404, "이 기록에는 기록지 PDF가 없습니다.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _lockout_seconds() -> int:
    return current_app.config.get("AUTH_LOCKOUT_SECONDS", 600)


def _locked(seal_id: str, client_ip: str) -> bool:
    """Whether this client reached the failure limit for this seal."""
    limit = current_app.config.get("AUTH_MAX_FAILURES", 5)
    recent = count_recent_auth_failures(seal_id, client_ip, _lockout_seconds())
    return recent >= limit


def _keys_refusal() -> Optional[tuple[int, str]]:
    """503 when the keys are missing (a server state, not a failed attempt).

    An unconverted case is not refused here: the chain runs, and
    :func:`_run_chain` answers it as a wrong credential.
    """
    if not privacy_keys_configured():
        return 503, _MSG_KEYS_MISSING
    return None


def _factors(auth_level: str) -> list[str]:
    """The factor names of a stored level (``basic+password`` style)."""
    return [step.strip() for step in (auth_level or "").split("+") if step.strip()]


def _with_basic(auth_level: str, *, without_otp: bool = False) -> str:
    """The chain descriptor, always starting with the basic check."""
    others = [s for s in _factors(auth_level)
              if s != "basic" and not (without_otp and s == "otp")]
    return "+".join(["basic"] + others)


def _credentials(seal_id: str) -> dict[str, Any]:
    return {
        "name": request.form.get("name", ""),
        "birth_date": request.form.get("birth_date", ""),
        "phone": request.form.get("phone", ""),
        "password": request.form.get("password", ""),
        "otp": request.form.get("otp", ""),
        "session_id": session.get(f"otp_session_{seal_id}", ""),
    }


def _run_chain(
    descriptor: str, case: CaseIdentityRow, seal_id: str
) -> tuple[Optional[AuthResult], tuple[int, str]]:
    """``(result, _)``, or ``(None, (status, message))`` when the check could
    not run: identity keys unavailable, or the case-password pool full.
    Neither is a failed attempt. A case whose identity was never converted
    fails the basic step with its wrong-credential answer (the basic step
    has checked that every field was given before it looks at the case)."""
    try:
        return AuthChain(descriptor).run(case.as_auth_case(), _credentials(seal_id)), (0, "")
    except DerivationBusy:
        logger.warning("Subject authentication refused: case-password checks at "
                       "capacity (seal_id=%r)", seal_id[:200])
        return None, (503, _MSG_BUSY)
    except LegacyIdentityError:
        logger.warning("Subject authentication failed: the case identity is still "
                       "in plaintext (seal_id=%r); answered as a wrong credential; "
                       "convert it with %s", seal_id[:200], _MIGRATION_COMMAND)
        return AuthResult(success=False, step="basic",
                          message=MSG_IDENTITY_MISMATCH), (0, "")
    except PrivacyError:
        logger.error("Subject authentication unavailable (seal_id=%r)", seal_id[:200])
        return None, (503, _MSG_KEYS_MISSING)


def _upgrade_legacy_password(case: CaseIdentityRow, password: str) -> None:
    """Replace a v1.0.1 SHA-256 case password hash after a successful login
    (best effort: the login stands whatever happens here)."""
    if "password" not in _factors(case.auth_level):
        return
    if not is_legacy_password_hash(case.password_hash):
        return
    if len(password) > MAX_PASSWORD_LENGTH:
        logger.warning("Legacy case password not upgraded: longer than the scrypt "
                       "bound (seal_id=%r)", case.seal_id[:200])
        return
    try:
        replaced = replace_case_password_hash(
            case.seal_id, upgraded_hash(password), case.password_hash
        )
    except DerivationBusy:
        logger.warning("Legacy case password not upgraded this time: case-password "
                       "checks at capacity (seal_id=%r)", case.seal_id[:200])
        return
    except Exception:
        logger.exception("Legacy case password kept (the login succeeded): "
                         "seal_id=%r", case.seal_id[:200])
        return
    if replaced:
        logger.info("Legacy case password replaced by a scrypt hash: seal_id=%r",
                    case.seal_id[:200])


# ---------------------------------------------------------------------------
# GET/POST /suspect/auth/<seal_id>
# ---------------------------------------------------------------------------
@bp.route("/auth/", defaults={"seal_id": ""}, methods=["GET"])
@bp.route("/auth/<seal_id>", methods=["GET", "POST"])
def auth(seal_id: str) -> Any:
    """Suspect identity verification page."""
    if not seal_id:
        return render_template("auth.html", seal_id="", case=None,
                               auth_level="basic", otp_session_id="", locked=False)

    case = find_case_identity(seal_id)
    if case is None:
        flash("해당 봉인 ID의 사건이 존재하지 않습니다.", "danger")
        return render_template("auth.html", seal_id=seal_id, case=None), 404
    view = {"seal_id": case.seal_id}  # the page never receives the identity

    if _locked(seal_id, _client_ip()):
        flash(f"인증 실패 횟수 초과로 {_lockout_seconds() // 60}분간 차단되었습니다.",
              "danger")
        return render_template("auth.html", seal_id=seal_id, case=view, locked=True), 429

    if request.method == "GET":
        return _auth_page(seal_id, case, view)
    return _authenticate(seal_id, case, view)


def _auth_page(seal_id: str, case: CaseIdentityRow, view: dict[str, str]) -> Any:
    # If OTP is part of auth, generate a session_id for future verification
    otp_session_id = ""
    if "otp" in _factors(case.auth_level):
        otp_session_id = str(uuid.uuid4())
        session[f"otp_session_{seal_id}"] = otp_session_id
    return render_template("auth.html", seal_id=seal_id, case=view,
                           auth_level=case.auth_level,
                           otp_session_id=otp_session_id, locked=False)


def _authenticate(seal_id: str, case: CaseIdentityRow, view: dict[str, str]) -> Any:
    refusal = _keys_refusal()
    result, unavailable = ((None, refusal) if refusal
                           else _run_chain(_with_basic(case.auth_level), case, seal_id))
    if result is None:
        status, message = unavailable
        flash(message, "danger")
        return render_template("auth.html", seal_id=seal_id, case=view,
                               auth_level=case.auth_level), status

    if not result.success:
        record_auth_failure(seal_id, _client_ip())
        flash(result.message, "danger")
        return render_template("auth.html", seal_id=seal_id, case=view,
                               auth_level=case.auth_level), 401

    _upgrade_legacy_password(case, request.form.get("password", ""))
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


def _otp_response(seal_id: str, status: int, message: str) -> Any:
    """JSON for fetch() callers; flash and redirect for a classic form POST."""
    if _wants_json_response():
        return jsonify({"success": status == 200, "message": message}), status
    flash(message, "info" if status == 200 else "danger")
    return redirect(url_for("suspect.auth", seal_id=seal_id))


@bp.route("/send-otp/<seal_id>", methods=["POST"])
def send_otp(seal_id: str) -> Any:
    """Send an OTP to the case's registered e-mail address.

    The request carries the basic credentials (and the password when the
    case uses it); the same lockout as the login applies, a failure counts
    toward it, and the e-mail is decrypted (audited) only after those
    factors passed. Supports classic form POST (redirect + flash) and
    fetch()-based requests (JSON with a status code).
    """
    case = find_case_identity(seal_id)
    if case is None:
        return _otp_response(seal_id, 404, "사건을 찾을 수 없습니다.")
    if "otp" not in _factors(case.auth_level):
        return _otp_response(seal_id, 400, "이 사건은 이메일 인증을 사용하지 않습니다.")
    client_ip = _client_ip()
    if _locked(seal_id, client_ip):
        return _otp_response(seal_id, 429, f"인증 실패 횟수 초과로 "
                             f"{_lockout_seconds() // 60}분간 차단되었습니다.")
    refusal = _keys_refusal()
    result, unavailable = ((None, refusal) if refusal else _run_chain(
        _with_basic(case.auth_level, without_otp=True), case, seal_id))
    if result is None:
        return _otp_response(seal_id, *unavailable)
    if not result.success:
        record_auth_failure(seal_id, client_ip)
        return _otp_response(seal_id, 401, result.message)
    return _deliver_otp(seal_id, client_ip)


class _DeliveryCapReached(Exception):
    """The seal's OTP delivery cap is reached (nothing was decrypted)."""


def _deliver_otp(seal_id: str, client_ip: str) -> Any:
    """Decrypt the e-mail (audited) and send a fresh code to it.

    At most ``OTP_MAX_DELIVERIES_PER_SEAL`` deliveries per seal within
    ``OTP_DELIVERY_WINDOW_SECONDS`` (counted from the access audit, from
    any client address): more are refused with 429 before decrypting, so
    someone who knows the factors cannot flood the subject's mailbox. The
    check and the delivery's audit row are one step serialized per seal
    (:func:`_reveal_email_within_cap`), also under simultaneous requests.
    """
    try:
        email = _reveal_email_within_cap(seal_id, client_ip)
    except _DeliveryCapReached:
        logger.warning("OTP delivery refused: too many recent deliveries "
                       "(seal_id=%r)", seal_id[:200])
        return _otp_response(seal_id, 429, _MSG_TOO_MANY_DELIVERIES)
    except IdentityAuditError:
        return _otp_response(seal_id, 503, _MSG_ACCESS_NOT_AUDITED)
    except PrivacyError:
        return _otp_response(seal_id, 503, _MSG_KEYS_MISSING)
    except FieldCryptoError:
        logger.error("OTP not sent: the stored e-mail does not decrypt (seal_id=%r)",
                     seal_id[:200])
        return _otp_response(seal_id, 500, _MSG_DELIVERY_ERROR)
    except Exception:  # a database error or lock timeout: nothing was used
        logger.exception("OTP delivery refused: database unavailable (seal_id=%r)",
                         seal_id[:200])
        return _otp_response(seal_id, 503, _MSG_TRY_AGAIN)
    if not email:
        return _otp_response(seal_id, 400, "등록된 이메일이 없습니다.")

    otp_session_id = str(uuid.uuid4())
    session[f"otp_session_{seal_id}"] = otp_session_id
    svc = OTPService()
    code = svc.generate_otp()
    svc.store_otp(otp_session_id, code)
    if svc.send_otp(email, code):
        return _otp_response(seal_id, 200,
                             "인증번호가 이메일로 발송되었습니다. (유효시간 5분)")
    return _otp_response(seal_id, 400, "인증번호 발송에 실패했습니다. 다시 시도해 주세요.")


def _reveal_email_within_cap(seal_id: str, client_ip: str) -> str:
    """Check the delivery cap and decrypt the e-mail as one serialized step.

    Runs under the seal's write lock (:func:`seal_write_transaction`:
    SQLite's database write lock, or the case row ``FOR UPDATE`` on
    MariaDB), so requests from any worker process take their turn. The
    audit row written by :func:`reveal_case_field` is committed before the
    address is returned, and that commit is what releases the lock: the
    next request's count includes this delivery. The audit row is thus the
    reservation of the capacity: a failure before it commits (decryption,
    audit write) rolls back and consumes nothing; once committed the
    delivery counts for the window, even if the e-mail then fails to go out.

    Raises:
        _DeliveryCapReached: The cap is reached; nothing was decrypted.
    """
    cfg = current_app.config
    with seal_write_transaction(seal_id):
        if recent_reveals(seal_id, PURPOSE_CODE_DELIVERY,
                          cfg.get("OTP_DELIVERY_WINDOW_SECONDS", 600)) >= cfg.get(
                              "OTP_MAX_DELIVERIES_PER_SEAL", 5):
            raise _DeliveryCapReached()
        # Must stay the last statement of this block: its audit insert
        # commits, which ends the transaction and releases the lock.
        return reveal_case_field(seal_id, "suspect_email", purpose=PURPOSE_CODE_DELIVERY,
                                 actor_role="subject", client_address=client_ip)


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
    """View seal records for a given seal_id (list only; nothing decrypted)."""
    # Require authentication
    if not session.get(f"auth_{seal_id}"):
        flash(_MSG_AUTH_REQUIRED, "warning")
        return redirect(url_for("suspect.auth", seal_id=seal_id))
    return _records_page(seal_id)


def _records_page(seal_id: str) -> str:
    """The list page: event, type, sync time and whether a PDF is stored."""
    records_list: list[dict[str, Any]] = []
    for row in find_seal_record_summaries_by_seal_id(seal_id):
        if hasattr(row, "keys"):
            records_list.append({k: row[k] for k in row.keys()})
        else:
            records_list.append(dict(zip(
                ("id", "seal_id", "event_id", "event_type", "synced_at", "has_pdf"),
                tuple(row))))
    return render_template("records.html", seal_id=seal_id, records=records_list)


def _reveal(
    reveal: Callable[..., Any], seal_id: str, event_id: int, missing: tuple[int, str]
) -> tuple[Any, Optional[tuple[int, str]]]:
    """Decrypt through the audited reveal; ``(content, None)`` or ``(None, refusal)``."""
    try:
        content = reveal(seal_id, event_id, actor_role="subject",
                         client_address=_client_ip())
    except IdentityAuditError:
        return None, _RECORD_NOT_AUDITED
    except LegacyRecordError:
        return None, _RECORD_NOT_CONVERTED
    except PrivacyError:
        return None, _RECORD_KEYS_MISSING
    except FieldCryptoError:
        return None, _RECORD_UNREADABLE
    except Exception:  # a database error: nothing was shown
        logger.exception("Seal record view failed (seal_id=%r event_id=%s)",
                         seal_id[:200], event_id)
        return None, _RECORD_FAILED
    return (content, None) if content is not None else (None, missing)


# ---------------------------------------------------------------------------
# GET /suspect/records/<seal_id>/detail/<event_id>
# ---------------------------------------------------------------------------
@bp.route("/records/<seal_id>/detail/<int:event_id>")
def record_detail(seal_id: str, event_id: int) -> Any:
    """Return the record_json payload of a single seal record (JSON API).

    Used by the records page modal to lazily load record details, so the
    list view carries no content. Decrypted only after the session check,
    and audited (:mod:`web.privacy.record_access`).
    """
    if not session.get(f"auth_{seal_id}"):
        return jsonify({"success": False, "message": _MSG_AUTH_REQUIRED}), 401

    record_json, refusal = _reveal(reveal_record_json, seal_id, event_id,
                                   _RECORD_NOT_FOUND)
    if refusal is not None:
        status, message = refusal
        return jsonify({"success": False, "message": message}), status

    response = jsonify({
        "success": True,
        "seal_id": seal_id,
        "event_id": event_id,
        "record_json": record_json,
    })
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# GET /suspect/records/<seal_id>/pdf/<event_id>
# ---------------------------------------------------------------------------
@bp.route("/records/<seal_id>/pdf/<int:event_id>")
def record_pdf(seal_id: str, event_id: int) -> Any:
    """Download the record PDF of one event (decrypted after the session
    check, audited). The file name is fixed, not taken from the URL."""
    if not session.get(f"auth_{seal_id}"):
        flash(_MSG_AUTH_REQUIRED, "warning")
        return redirect(url_for("suspect.auth", seal_id=seal_id))

    pdf, refusal = _reveal(reveal_record_pdf, seal_id, event_id, _PDF_NOT_FOUND)
    if refusal is not None:
        status, message = refusal
        flash(message, "danger")
        return _records_page(seal_id), status

    response = send_file(io.BytesIO(pdf), mimetype="application/pdf",
                         as_attachment=True, conditional=False, etag=False,
                         download_name=f"seal-record-event-{event_id}.pdf")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
