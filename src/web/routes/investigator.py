"""Investigator (수사관) Blueprint.

Endpoints
---------
POST /investigator/register-case  -- 사건 등록 (관리자 로그인 필요)
POST /investigator/upload-share   -- 키 조각 2 업로드 (관리자 비상 복구용)
POST /investigator/recover-key    -- SSS 키 복원 (표준 경로 s1+입력한 s2)
POST /investigator/recover-key-timelock -- 시간 잠금 해제 (입력한 s2+s3, TSA 검증)
GET  /investigator/download-key/<seal_id> -- .key 파일 다운로드
GET  /investigator/recovered/<seal_id>    -- 복원 키 표시 페이지

Both recovery routes decide through the single release gate
(:mod:`web.release_gate`), which also writes the release audit trail.
Both take the investigator share s2 from the form: this reference app has
no investigator accounts, so holding the share is the credential, and a
share uploaded to slot 2 is used only by the admin emergency path.

Case registration (stage F, F2): the form needs a signed-in administrator
account (E4); it was open to anyone until v1.1 (Fable gate, finding 4). A
case is also created by its seal's signed record on the first sync
(:mod:`web.sync_registration`); both follow the rules of
:mod:`web.case_rules`, and ``cases.registered_by`` records which of them
registered it.
"""

from __future__ import annotations

import io
import logging
from typing import Any, Optional

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

from ..auth.case_passwords import check_case_password_policy, hash_case_password
from ..auth.kdf_slots import DerivationBusy
from ..auth.passwords import PasswordPolicyError
from ..case_rules import AUTH_LEVELS, FIELD_LIMITS, RESERVED_SEAL_PREFIX
from ..models.db_models import (
    count_recent_auth_failures,
    delete_auth_failure,
    find_case_by_seal_id,
    record_auth_failure,
)
from ..models.privacy_models import CaseInsertError
from ..privacy.case_identity import CaseRegistration, register_protected_case
from ..privacy.keys import PrivacyUnavailable, privacy_keys_configured
from ..share_upload import checked_share, store_uploaded_share
# The admin blueprint's session check (E4), which re-reads the account on
# every request; the registration form reuses it (stage F, F2).
from .admin import _require_admin, _to_login
from .release_messages import denial_response

logger = logging.getLogger(__name__)

bp = Blueprint(
    "investigator",
    __name__,
    url_prefix="/investigator",
    template_folder="../templates/investigator",
)

_MSG_PRIVACY_KEYS_MISSING = (
    "개인정보 보호 키가 설정되지 않았거나 쓸 수 없어 사건을 등록할 수 "
    "없습니다. 관리자에게 문의해 주세요."
)
_MSG_REGISTRATION_BUDGET = (
    "이 주소에서 비밀번호를 쓰는 사건 등록이 많아 {minutes}분 동안 더 받지 "
    "않습니다. 잠시 후 다시 시도해 주세요."
)
_MSG_BUSY = (
    "서버에서 처리 중인 요청이 많아 지금은 사건을 등록하지 못했습니다. "
    "잠시 후 다시 시도해 주세요."
)
# Budget rows of registrations that hash a case password, in auth_failures
# (per client address), like E4's admin login budget. Seal IDs may not
# start with '@', so no case can share these counters.
_REGISTRATION_KEY = "@case-registration"
_RESERVED_PREFIX = RESERVED_SEAL_PREFIX
# The levels the registration form offers; each includes the basic check.
_AUTH_LEVELS = AUTH_LEVELS
_PAGE = "register_case.html"
_FORM_FIELDS = (
    "seal_id", "case_number", "investigator", "suspect_name", "suspect_email",
    "suspect_birth", "suspect_phone", "auth_level",
)
_REQUIRED_FIELDS = (
    ("seal_id", "봉인 ID를 입력해 주세요."),
    ("case_number", "사건번호를 입력해 주세요."),
    ("investigator", "수사관 이름을 입력해 주세요."),
    ("suspect_name", "피압수자 이름을 입력해 주세요."),
)
# The v1.0.1 MariaDB column sizes (web.case_rules), checked before any
# write: the identity columns now hold '', and the seal ID is also the
# associated data of the ciphertexts, so MariaDB must never store it
# truncated. A signed record that creates its case follows the same limits.
_FIELD_LABELS = (
    ("seal_id", "봉인 ID"),
    ("case_number", "사건번호"),
    ("investigator", "수사관 이름"),
    ("suspect_name", "피압수자 이름"),
    ("suspect_email", "이메일"),
    ("suspect_birth", "생년월일"),
    ("suspect_phone", "연락처"),
)
_FIELD_LIMITS = tuple((name, FIELD_LIMITS[name], label) for name, label in _FIELD_LABELS)


# ---------------------------------------------------------------------------
# POST /investigator/register-case
# ---------------------------------------------------------------------------
@bp.route("/register-case", methods=["GET", "POST"])
def register_case() -> Any:
    """Register a new case (사건 등록); a signed-in administrator only.

    Stage F (F2): GET and POST need the session of an enabled
    administrator account (E4). The admin blueprint's check re-reads the
    account on every request, so the session of a disabled or deleted
    account ends here too; the v1.0.1 ``is_admin`` flag counts for nothing.
    Without one, both are redirected to the admin login (302, as every
    admin page answers); nothing is read from the form or stored, and no
    budget place is reserved. Only a POST (which the CSRF check covers)
    registers; any other method, such as the HEAD Flask adds, gets the
    page. The case records the account's username in ``registered_by``.
    Otherwise the form behaves as in v1.1 (below). A seal whose signed
    record reached the sync route first has registered its own case
    (:mod:`web.sync_registration`) and is refused with 409 like any
    existing seal ID, also when that sync creates the case between the
    form's check and its insert.

    Stage E (E3a): the name, birth date and phone are stored as keyed
    digests and the name and e-mail as ciphertexts under a new per-seal
    data key (:mod:`web.privacy.case_identity`); no plaintext identity is
    written. Without the identity-protection keys the route answers 503.
    The authentication level must be one of the four the form offers (all
    include the basic identity check). A password is required, and kept as
    a scrypt hash, only for a level that uses it; it needs 12 to 1024
    characters. Fields keep the length limits of the v1.0.1 MariaDB
    columns (seal ID 64, case number and investigator 128, name 128,
    e-mail 256, birth date 16, phone 32).

    Hashing a password costs one scrypt derivation (about 32 MiB): such a
    registration first reserves a place in its client address's budget
    (429 beyond it), then needs a free slot of the case-password pool
    (503, with its reservation withdrawn, otherwise); neither refusal
    derives anything.
    """
    admin = _require_admin()
    if admin is None:
        return _to_login()
    registrar = admin.username
    # Only a POST registers: Flask answers HEAD on this route as well, and
    # the CSRF check skips HEAD, so a HEAD with a form body gets the page.
    if request.method != "POST":
        return _form_page(registrar)
    if not privacy_keys_configured():
        flash(_MSG_PRIVACY_KEYS_MISSING, "danger")
        return _form_page(registrar, 503)

    form = _registration_form()
    errors = _registration_errors(form)
    if errors:
        for error in errors:
            flash(error, "danger")
        return _form_page(registrar, 400)
    if find_case_by_seal_id(form["seal_id"]):
        flash("이미 등록된 봉인 ID입니다.", "warning")
        return _form_page(registrar, 409)
    reservation = None
    if _uses_factor(form["auth_level"], "password"):
        reservation = _reserve_registration()
        if reservation is None:
            window = current_app.config.get("CASE_REGISTRATION_WINDOW_SECONDS", 600)
            flash(_MSG_REGISTRATION_BUDGET.format(minutes=window // 60), "danger")
            return _form_page(registrar, 429)
    return _store_registration(form, reservation, registrar)


def _form_page(registrar: str, status: int = 200,
               headers: Optional[dict[str, str]] = None) -> Any:
    """The registration page, naming the signed-in administrator."""
    return render_template(_PAGE, admin_username=registrar), status, headers or {}


def _store_registration(form: dict[str, str], reservation: Optional[int],
                        registrar: str) -> Any:
    """Hash the password (if any), store the protected case, answer."""
    try:
        register_protected_case(_case_registration(form, registrar))
    except DerivationBusy:
        if reservation is not None:
            delete_auth_failure(reservation)  # refused before any password work
        logger.warning("Case registration refused: case-password checks at capacity")
        flash(_MSG_BUSY, "danger")
        return _form_page(registrar, 503, {"Retry-After": "1"})
    except PrivacyUnavailable:
        flash(_MSG_PRIVACY_KEYS_MISSING, "danger")
        return _form_page(registrar, 503)
    except Exception as exc:
        # A signed record's sync may have created the case after the check
        # above (F2): the insert then fails, and the answer is the same 409.
        if isinstance(exc, CaseInsertError) and find_case_by_seal_id(form["seal_id"]):
            flash("이미 등록된 봉인 ID입니다.", "warning")
            return _form_page(registrar, 409)
        logger.exception("사건 등록 실패")
        flash("사건 등록 중 오류가 발생했습니다.", "danger")
        return _form_page(registrar, 500)

    logger.info("Case registered by an administrator: seal_id=%r admin=%s",
                form["seal_id"][:200], registrar)
    flash("사건이 등록되었습니다.", "success")
    return redirect(url_for("investigator.register_case"))


def _reserve_registration() -> Optional[int]:
    """Reserve a place in the client address's registration budget.

    Only registrations that hash a case password are budgeted. The row (in
    ``auth_failures`` under a reserved key, as E4's login budget) is
    committed first and counted afterwards, so simultaneous requests cannot
    all see a count below the limit. It stays after a registration, which
    is what it limits; it is withdrawn at once beyond the budget, and when
    the request is refused as busy before any password work.

    Returns:
        The reservation's row id, or ``None`` when the budget is exhausted.
    """
    cfg = current_app.config
    client_ip = request.remote_addr or "unknown"
    row_id = record_auth_failure(_REGISTRATION_KEY, client_ip)
    if row_id is None:
        raise RuntimeError("auth_failures insert returned no row id")
    used = count_recent_auth_failures(_REGISTRATION_KEY, client_ip,
                                      cfg.get("CASE_REGISTRATION_WINDOW_SECONDS", 600))
    if used <= cfg.get("CASE_REGISTRATION_MAX_PER_ADDRESS", 10):
        return row_id
    delete_auth_failure(row_id)
    logger.warning("Case registration refused: address registration budget used up")
    return None


def _registration_form() -> dict[str, str]:
    """The submitted registration fields, stripped (the password as given)."""
    form = {name: (request.form.get(name) or "").strip() for name in _FORM_FIELDS}
    form["auth_level"] = form["auth_level"] or "basic"
    form["password"] = request.form.get("password") or ""
    return form


def _registration_errors(form: dict[str, str]) -> list[str]:
    """User-facing validation messages (Korean); empty when valid."""
    errors = [message for name, message in _REQUIRED_FIELDS if not form[name]]
    errors += [f"{label}은(는) {limit}자 이하로 입력해 주세요."
               for name, limit, label in _FIELD_LIMITS if len(form[name]) > limit]
    if form["seal_id"].startswith(_RESERVED_PREFIX):
        # '@'-keys in auth_failures count admin logins and registrations.
        errors.append("봉인 ID는 '@'로 시작할 수 없습니다.")
    if form["auth_level"] not in _AUTH_LEVELS:
        errors.append("인증 수준이 올바르지 않습니다.")
    elif _uses_factor(form["auth_level"], "password"):
        errors += _password_errors(form["password"])
    return errors


def _uses_factor(auth_level: str, factor: str) -> bool:
    return factor in auth_level.split("+")


def _password_errors(password: str) -> list[str]:
    if not password:
        return ["비밀번호 인증을 사용하려면 비밀번호를 입력해 주세요."]
    try:
        check_case_password_policy(password)
    except PasswordPolicyError as exc:
        return [str(exc)]
    return []


def _case_registration(form: dict[str, str], registrar: str) -> CaseRegistration:
    """The registration; a password is hashed only for a level that uses it."""
    stored_hash = (hash_case_password(form["password"])
                   if _uses_factor(form["auth_level"], "password") else "")
    return CaseRegistration(
        seal_id=form["seal_id"], case_number=form["case_number"],
        investigator=form["investigator"], name=form["suspect_name"],
        email=form["suspect_email"], birth=form["suspect_birth"],
        phone=form["suspect_phone"], auth_level=form["auth_level"],
        password_hash=stored_hash, registered_by=registrar,
    )


# ---------------------------------------------------------------------------
# POST /investigator/upload-share
# ---------------------------------------------------------------------------
@bp.route("/upload-share", methods=["GET", "POST"])
def upload_share() -> Any:
    """Upload investigator key share (키 조각 2).

    Neither investigator recovery route reads it (both take s2 from the
    request); the admin emergency path may use it as its second share.
    The share's format is checked first, then it is stored under the
    seal's current policy generation (stage F, F1; :mod:`web.share_upload`):
    400 for a malformed share, 409 when another share 2 is stored for that
    generation, success when it is stored now or the identical share
    already was.
    """
    # GET and HEAD show the page; only a POST submits (stage F, F5:
    # the CSRF hook lets HEAD through without a token).
    if request.method != "POST":
        return render_template("upload_share.html")

    seal_id = (request.form.get("seal_id") or "").strip()
    share_data = (request.form.get("share_data") or "").strip()

    if not seal_id or not share_data:
        flash("봉인 ID와 키 조각을 모두 입력해 주세요.", "danger")
        return render_template("upload_share.html"), 400

    share, reply = checked_share(share_data, 2)
    if reply is None:
        if not find_case_by_seal_id(seal_id):
            flash("해당 봉인 ID의 사건이 존재하지 않습니다.", "danger")
            return render_template("upload_share.html"), 404
        reply = store_uploaded_share(seal_id, 2, share, "investigator")
    flash(reply.message, reply.category)
    if not reply.ok:
        return render_template("upload_share.html"), reply.status
    return redirect(url_for("investigator.upload_share"))


# ---------------------------------------------------------------------------
# POST /investigator/recover-key
# ---------------------------------------------------------------------------
@bp.route("/recover-key", methods=["GET", "POST"])
def recover_key() -> Any:
    """Recover the AES key from the owner's s1 and the entered s2 (standard).

    The requester must enter the investigator share (s2): knowing the seal
    ID and waiting for the unlock time is not enough. Decided by
    :func:`web.release_gate.release_standard`: the server-side unlock-time
    gate and the key-commitment check of v1.0.1, with the values taken
    from the authenticated policy when the synced record carries one. A
    record without a key commitment is refused, because the entered share
    could not be verified. This path deliberately makes no TSA round trip,
    so a TSA outage does not block standard recovery. The entered share is
    never logged or audited.
    """
    # GET and HEAD show the page; only a POST submits (stage F, F5:
    # the CSRF hook lets HEAD through without a token).
    if request.method != "POST":
        return render_template("recover_key.html")

    seal_id = (request.form.get("seal_id") or "").strip()
    if not seal_id:
        flash("봉인 ID를 입력해 주세요.", "danger")
        return render_template("recover_key.html"), 400

    from ..release_gate import release_standard

    decision = release_standard(seal_id, request.form.get("share_data") or "")
    if not decision.allowed:
        status, message = denial_response(decision)
        flash(message, "danger")
        return render_template("recover_key.html"), status

    # Store temporarily in session for download
    session[f"recovered_key_{seal_id}"] = decision.key_hex
    return redirect(url_for("investigator.recovered", seal_id=seal_id))


# ---------------------------------------------------------------------------
# POST /investigator/recover-key-timelock
# ---------------------------------------------------------------------------
@bp.route("/recover-key-timelock", methods=["GET", "POST"])
def recover_key_timelock() -> Any:
    """Time-locked release: the investigator's s2 plus the system share s3.

    The requester must enter the investigator share (s2) in the form: this
    reference app has no investigator accounts, so holding the share is
    the credential. A share stored earlier in slot 2 plays no part in it.
    Decided by :func:`web.release_gate.release_timelock` (fail-closed):
    the synced record must carry a policy signed under a pinned CA, a
    fresh TSA token bound to that policy must verify with a genTime not
    before the unlock time, and only then is s3 unwrapped with the KMS
    master key and recombined (strict mode also needs the owner share).
    The entered share is never logged or audited.
    """
    # GET and HEAD show the page; only a POST submits (stage F, F5:
    # the CSRF hook lets HEAD through without a token).
    if request.method != "POST":
        return render_template("recover_key_timelock.html")

    seal_id = (request.form.get("seal_id") or "").strip()
    if not seal_id:
        flash("봉인 ID를 입력해 주세요.", "danger")
        return render_template("recover_key_timelock.html"), 400

    from ..release_gate import release_timelock

    decision = release_timelock(seal_id, request.form.get("share_data") or "")
    if not decision.allowed:
        status, message = denial_response(decision)
        flash(message, "danger")
        return render_template("recover_key_timelock.html"), status

    session[f"recovered_key_{seal_id}"] = decision.key_hex
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
