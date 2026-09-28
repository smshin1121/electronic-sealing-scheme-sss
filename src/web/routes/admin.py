"""Admin (관리자) Blueprint.

Endpoints
---------
GET/POST /admin/login           -- 관리자 로그인 (계정명 + 비밀번호)
GET  /admin/shares              -- 키 조각 4 목록
POST /admin/emergency-recover   -- 비상 복구 (관리자 승인)

Administrators are named accounts (``admin_accounts``, created with
``python -m src.web.admin_accounts``); the shared ``ADMIN_PASSWORD`` of
v1.0.1 no longer logs anyone in.

Login limits (each login attempt costs one scrypt derivation, ~32 MiB):

- Address budget, ``AUTH_MAX_FAILURES`` attempts per client address within
  ``AUTH_LOCKOUT_SECONDS``, counting failed attempts and attempts still in
  progress: every attempt first reserves a place, and one beyond the budget
  is refused (429) before any password work, also under concurrent
  requests. The refusal message says the address is locked only when the
  failed attempts alone reach the limit; a refusal caused by attempts in
  progress says so instead, since the address is not locked afterwards.
  The budget lives in the database (``auth_failures``), so it holds across
  worker processes and hosts that share the database. A burst may be
  refused early (reservations in flight count), never late. Behind a
  reverse proxy every client has the proxy's address.
- Process bound, ``ADMIN_LOGIN_MAX_CONCURRENT`` checks at once: a check
  beyond it is refused (503, "the server is busy") without password work.
  It is per process, so W worker processes allow W times as many.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

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

from ..auth.admin_auth import (
    DEFAULT_MAX_CONCURRENT_LOGINS,
    FAIL_BUSY,
    authenticate_admin,
    loggable_username,
    resolve_admin_session,
)
from ..models.admin_models import AdminAccount
from ..models.db_models import (
    count_recent_auth_failures,
    delete_auth_failure,
    find_admin_share_summaries,
    record_auth_failure,
    relabel_auth_failure,
)
from ..models.release_models import find_stored_shares
from .release_messages import denial_response

logger = logging.getLogger(__name__)

bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder="../templates/admin",
)

_SESSION_ID = "admin_id"
_SESSION_USERNAME = "admin_username"
_MSG_LOGIN_REQUIRED = "관리자 인증이 필요합니다."
_LOG_TEXT_LIMIT = 200
# Admin logins share the subject route's lockout table (auth_failures),
# counted per client address under reserved keys in its seal_id column:
# attempts still being checked (reservations) and failed attempts. Seal
# IDs are never checked against them; a case registered under one of these
# names would only share the counters per address.
_LOGIN_PENDING_KEY = "@admin-login-pending"
_LOGIN_FAILURE_KEY = "@admin-login"

# Refusals before any password work: (log cause, message, HTTP status).
_REFUSE_LOCKED = "locked"
_REFUSE_BURST = "burst"
_REFUSE_BUSY = "busy"
_REFUSALS: dict[str, tuple[str, str, int]] = {
    _REFUSE_LOCKED: ("too many recent failures from this client",
                     "로그인 실패 횟수 초과로 {minutes}분간 차단되었습니다. "
                     "잠시 후 다시 시도해 주세요.", 429),
    _REFUSE_BURST: ("too many attempts from this client in progress",
                    "동시에 처리 중인 로그인 요청이 많습니다. "
                    "잠시 후 다시 시도해 주세요.", 429),
    _REFUSE_BUSY: ("password checks at capacity",
                   "서버에서 처리 중인 로그인 요청이 많아 지금은 처리하지 "
                   "못했습니다. 잠시 후 다시 시도해 주세요.", 503),
}


@dataclass(frozen=True)
class _Reservation:
    """A reserved attempt (``row_id``), or why none was granted."""

    row_id: Optional[int] = None
    refusal: str = ""


def _require_admin() -> Optional[AdminAccount]:
    """The enabled account this session was opened for, else ``None``.

    The account is read again on every request: a session whose account
    has since been disabled, deleted or no longer matches is ended here
    (and logged at WARNING). The v1.0.1 ``is_admin`` flag counts for
    nothing.
    """
    account_id = session.get(_SESSION_ID)
    username = session.get(_SESSION_USERNAME)
    if account_id is None and username is None:
        return None
    account = resolve_admin_session(account_id, username)
    if account is None:
        session.pop(_SESSION_ID, None)
        session.pop(_SESSION_USERNAME, None)
        logger.warning(
            "Admin session refused (account disabled, deleted or changed): "
            "username=%s", loggable_username(username),
        )
    return account


def _to_login() -> Any:
    flash(_MSG_LOGIN_REQUIRED, "danger")
    return redirect(url_for("admin.login"))


def _reserve_login_attempt(client_ip: str) -> _Reservation:
    """Reserve one place in the address budget before any password work.

    The reservation (a pending row) is recorded and committed first and
    counted afterwards, so concurrent requests cannot all see a count below
    the limit: of two racing requests, the one that commits later counts the
    other's row. Pending rows are counted before failed ones, so an attempt
    that fails between the two reads is counted twice (refused early), never
    missed. Beyond the budget the reservation is withdrawn at once, and the
    refusal is a lockout only when the failed attempts alone reach the
    limit; otherwise it is due to attempts still in progress. The caller
    relabels the row as a failure when the login fails and withdraws it
    otherwise.
    """
    window = current_app.config.get("AUTH_LOCKOUT_SECONDS", 600)
    limit = current_app.config.get("AUTH_MAX_FAILURES", 5)
    row_id = record_auth_failure(_LOGIN_PENDING_KEY, client_ip)
    if row_id is None:
        raise RuntimeError("auth_failures insert returned no row id")
    pending = count_recent_auth_failures(_LOGIN_PENDING_KEY, client_ip, window)
    failed = count_recent_auth_failures(_LOGIN_FAILURE_KEY, client_ip, window)
    if pending + failed <= limit:
        return _Reservation(row_id)
    delete_auth_failure(row_id)
    return _Reservation(refusal=_REFUSE_LOCKED if failed >= limit else _REFUSE_BURST)


def _refuse_login(raw_username: object, refusal: str) -> Any:
    cause, message, status = _REFUSALS[refusal]
    minutes = current_app.config.get("AUTH_LOCKOUT_SECONDS", 600) // 60
    logger.warning("Admin login refused (%s): username=%s", cause,
                   loggable_username(raw_username))
    flash(message.format(minutes=minutes), "danger")
    headers = {"Retry-After": "1"} if status == 503 else {}
    return render_template("login.html"), status, headers


def _log_emergency(
    username: str, seal_id: str, reason: str, decision: Optional[Any]
) -> None:
    """One WARNING line per emergency attempt, released or denied.

    It names the administrator, the seal, the outcome, the share slots the
    gate selected (``shares=2+4``; ``none`` before selection), the gate's
    reason code and the administrator's stated reason. Share data and key
    material never reach it. Free text is logged with ``%r`` (control
    characters escaped) and clipped.
    """
    if decision is None:  # refused by the route before the release gate
        outcome, slots, code, status = "denied", "", "seal_id_missing", "-"
    else:
        outcome = "released" if decision.allowed else "denied"
        slots, code, status = decision.slots, decision.reason, decision.policy_status
    logger.warning(
        "Emergency recovery %s: admin=%s seal_id=%r shares=%s reason=%s "
        "policy_status=%s operator_reason=%r",
        outcome, username, seal_id[:_LOG_TEXT_LIMIT], slots or "none", code,
        status, reason[:_LOG_TEXT_LIMIT],
    )


# ---------------------------------------------------------------------------
# GET /admin/shares
# ---------------------------------------------------------------------------
@bp.route("/shares", methods=["GET"])
def shares() -> Any:
    """List admin key shares (키 조각 4) across all cases."""
    admin = _require_admin()
    if admin is None:
        return _to_login()

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

    return render_template("shares.html", shares=shares_list,
                           admin_username=admin.username)


# ---------------------------------------------------------------------------
# GET/POST /admin/emergency-recover
# ---------------------------------------------------------------------------
@bp.route("/emergency-recover", methods=["GET", "POST"])
def emergency_recover() -> Any:
    """Emergency key recovery using admin share (키 조각 4) + one other share.

    An override by design (no time gate), decided by
    :func:`web.release_gate.release_admin`: a reason is required; s4 and the
    lowest other stored slot are used, each holding a share of its own
    index; an authenticated policy (verified, or signed under a since
    expired certificate) supplies the mode and key commitment; a present
    policy that fails verification blocks the override; use on an
    unauthenticated record is flagged in the audit trail, or denied when
    ``RELEASE_REQUIRE_POLICY`` is set; every attempt that reaches the gate
    is audited (a POST without a seal ID is refused here and only logged).
    Under strict mode the mode dispatcher still REFUSES an s2+s4 coalition
    (CR-04). The signed-in administrator's username goes to the gate as
    the operator, is written to the attempt's audit row, and is logged at
    WARNING with the seal, outcome, share slots and reason.
    """
    admin = _require_admin()
    if admin is None:
        return _to_login()
    page = "emergency_recover.html"

    if request.method == "GET":
        return render_template(page, admin_username=admin.username)

    seal_id = (request.form.get("seal_id") or "").strip()
    reason = (request.form.get("reason") or "").strip()

    if not seal_id:
        _log_emergency(admin.username, seal_id, reason, None)
        flash("봉인 ID를 입력해 주세요.", "danger")
        return render_template(page, admin_username=admin.username), 400

    from ..release_gate import release_admin

    shares = find_stored_shares(seal_id)
    decision = release_admin(seal_id, reason, shares, operator=admin.username)
    _log_emergency(admin.username, seal_id, reason, decision)
    if not decision.allowed:
        status, message = denial_response(decision, len(shares))
        flash(message, "danger")
        return render_template(page, admin_username=admin.username), status

    return render_template(
        "emergency_result.html",
        seal_id=seal_id,
        recovered_key=decision.key_hex,
        reason=reason,
        operator=admin.username,
    )


# ---------------------------------------------------------------------------
# GET/POST /admin/login
# ---------------------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
def login() -> Any:
    """Named-account login: username and password (no shared password).

    Every failure gets one answer (401) so that the response does not show
    whether the account exists or is disabled; the WARNING log names the
    username (only when it is a possible username) and the cause, never
    the password. Password work is limited per address (429) and per
    process (503); see the module docstring.
    """
    if request.method == "GET":
        return render_template("login.html")

    raw_username = request.form.get("username", "")
    reservation = _reserve_login_attempt(request.remote_addr or "unknown")
    if reservation.row_id is None:
        return _refuse_login(raw_username, reservation.refusal)

    result = authenticate_admin(
        raw_username, request.form.get("password", ""),
        max_concurrent=current_app.config.get("ADMIN_LOGIN_MAX_CONCURRENT",
                                              DEFAULT_MAX_CONCURRENT_LOGINS))
    if result.failure == FAIL_BUSY:
        delete_auth_failure(reservation.row_id)
        return _refuse_login(raw_username, _REFUSE_BUSY)
    if result.account is None:
        relabel_auth_failure(reservation.row_id, _LOGIN_FAILURE_KEY)
        logger.warning("Admin login failed: username=%s cause=%s",
                       loggable_username(raw_username), result.failure)
        flash("관리자 계정명 또는 비밀번호가 올바르지 않습니다.", "danger")
        return render_template("login.html"), 401

    delete_auth_failure(reservation.row_id)
    session.pop("is_admin", None)  # v1.0.1 flag, no longer honoured
    session[_SESSION_ID] = result.account.id
    session[_SESSION_USERNAME] = result.account.username
    logger.info("Admin login: username=%s", result.account.username)
    flash("관리자 로그인 성공", "success")
    return redirect(url_for("admin.shares"))
