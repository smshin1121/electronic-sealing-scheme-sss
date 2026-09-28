"""Named administrator accounts: username rule, accounts, login, sessions.

There is no default account and no shared password: every account is
created explicitly (``python -m src.web.admin_accounts create``), with its
own scrypt hash (:mod:`web.auth.passwords`). ``ADMIN_PASSWORD`` from v1.0.1
is ignored; start-up logs a WARNING while it is still set.

Usernames are lower-case ASCII (``[a-z0-9][a-z0-9._-]{2,63}``) after the
input is stripped and lower-cased. That keeps matching identical on both
schema variants (SQLite's default BINARY collation; ``utf8mb4_bin`` on
MariaDB) and makes a username safe to write to logs and audit rows.

A login for a username with no account still costs one scrypt derivation,
and every failure (no account, wrong password, disabled account) gets the
same answer; only the server log names the cause. The session carries the
account id and username; :func:`resolve_admin_session` re-reads the
account on every admin request, so disabling or deleting it ends sessions
already open (Flask's session is a client-side signed cookie, so this
lookup is the only revocation).
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from ..models.admin_models import (
    AdminAccount,
    count_enabled_admin_accounts,
    find_admin_account_by_id,
    find_admin_account_by_username,
    insert_admin_account,
    mark_admin_account_disabled,
)
from .passwords import (
    PasswordPolicyError,
    burn_verification,
    check_password_policy,
    hash_password,
    verify_password,
)

logger = logging.getLogger(__name__)

USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")

FAIL_MALFORMED = "malformed_username"
FAIL_UNKNOWN = "unknown_account"
FAIL_MISMATCH = "wrong_password"
FAIL_DISABLED = "disabled_account"
FAIL_BUSY = "busy"  # not a failed login: refused before any password work
_CLI_HINT = "python -m src.web.admin_accounts create <username>"

DEFAULT_MAX_CONCURRENT_LOGINS = 4
# Per-process bound on login checks running at once, one semaphore per
# configured limit (a process normally runs one app, so one semaphore).
_SLOTS_LOCK = threading.Lock()
_SLOTS: dict[int, threading.BoundedSemaphore] = {}

_MSG_USERNAME_RULE = (
    "계정명은 3–64자의 영문 소문자·숫자·'.'·'_'·'-'로 쓰고, "
    "영문 소문자나 숫자로 시작해야 합니다."
)


class AccountError(ValueError):
    """An account request was refused; the message is user-facing."""


@dataclass(frozen=True)
class LoginResult:
    """The account on success; otherwise ``None`` and a failure code."""

    account: Optional[AdminAccount]
    failure: str = ""


def normalize_username(raw: object) -> str:
    """Strip and lower-case a submitted username ('' for non-strings)."""
    return raw.strip().lower() if isinstance(raw, str) else ""


def is_valid_username(username: str) -> bool:
    """Whether a normalized username follows the account rule."""
    return USERNAME_RE.fullmatch(username) is not None


def loggable_username(raw: object) -> str:
    """The normalized username if it follows the rule, else ``<malformed>``.

    Submitted text that is not a possible username (for example a
    password typed into the username field) never reaches the log.
    """
    username = normalize_username(raw)
    return username if is_valid_username(username) else "<malformed>"


def authenticate_admin(
    raw_username: object, password: object, *,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT_LOGINS,
) -> LoginResult:
    """Check a login; any failure costs one scrypt derivation.

    At most ``max_concurrent`` checks run at once in this process (each
    derivation holds about 32 MiB). A check beyond that is refused as
    ``FAIL_BUSY`` at once, without waiting and without password work.
    """
    slots = _login_slots(max_concurrent)
    if not slots.acquire(blocking=False):
        return LoginResult(None, FAIL_BUSY)
    try:
        return _check_login(raw_username, password)
    finally:
        slots.release()


def _login_slots(limit: int) -> threading.BoundedSemaphore:
    """The process-wide semaphore for ``limit`` concurrent login checks."""
    if type(limit) is not int or limit < 1:
        raise ValueError("ADMIN_LOGIN_MAX_CONCURRENT must be a positive integer")
    with _SLOTS_LOCK:
        slots = _SLOTS.get(limit)
        if slots is None:
            slots = _SLOTS[limit] = threading.BoundedSemaphore(limit)
        return slots


def _check_login(raw_username: object, password: object) -> LoginResult:
    username = normalize_username(raw_username)
    secret = password if isinstance(password, str) else ""
    well_formed = is_valid_username(username)
    account = find_admin_account_by_username(username) if well_formed else None
    if account is None:
        burn_verification(secret)
        return LoginResult(None, FAIL_UNKNOWN if well_formed else FAIL_MALFORMED)
    if not verify_password(secret, account.password_hash):
        return LoginResult(None, FAIL_MISMATCH)
    if account.disabled:
        return LoginResult(None, FAIL_DISABLED)
    return LoginResult(account)


def resolve_admin_session(account_id: Any, username: Any) -> Optional[AdminAccount]:
    """The enabled account a session names, or ``None``.

    Both values must be present with their exact types (``True`` is not
    the id 1, and SQLite would match the text ``"1"``), the id must still
    exist, and its username must be the one the session recorded.
    """
    if type(account_id) is not int or not isinstance(username, str):
        return None
    account = find_admin_account_by_id(account_id)
    if account is None or account.disabled or account.username != username:
        return None
    return account


def warn_about_admin_setup(config: Mapping[str, Any], environ: Mapping[str, str]) -> None:
    """Start-up WARNINGs (needs an app context): a leftover shared password,
    and no account that can log in. The password value is never logged."""
    if config.get("ADMIN_PASSWORD") or environ.get("ADMIN_PASSWORD"):
        logger.warning(
            "ADMIN_PASSWORD is set but ignored: administrators log in with "
            "named accounts (%s); remove ADMIN_PASSWORD from the environment",
            _CLI_HINT,
        )
    if count_enabled_admin_accounts() == 0:
        logger.warning(
            "No enabled administrator account: admin login is unavailable "
            "until one is created with %s", _CLI_HINT,
        )


def create_admin_account(raw_username: str, password: str) -> AdminAccount:
    """Create an enabled account; the password is hashed, never stored.

    Raises:
        AccountError: The username breaks the rule or is taken, or the
            password breaks the policy (at least 12 characters).
    """
    username = normalize_username(raw_username)
    if not is_valid_username(username):
        raise AccountError(_MSG_USERNAME_RULE)
    try:
        check_password_policy(password)
    except PasswordPolicyError as exc:
        raise AccountError(str(exc)) from exc
    if find_admin_account_by_username(username) is not None:
        raise AccountError(f"이미 있는 계정명입니다: {username}")
    try:
        insert_admin_account(username, hash_password(password), _utc_now_iso())
    except Exception as exc:
        # A concurrent creation of the same name hits the UNIQUE constraint.
        if find_admin_account_by_username(username) is not None:
            raise AccountError(f"이미 있는 계정명입니다: {username}") from exc
        raise
    account = find_admin_account_by_username(username)
    if account is None:
        raise RuntimeError(f"administrator account {username!r} was not stored")
    logger.info("Administrator account created: username=%s id=%d",
                account.username, account.id)
    return account


def disable_admin_account(raw_username: str) -> AdminAccount:
    """Disable an account: it can no longer log in, and open sessions end.

    Raises:
        AccountError: No such account, or it is already disabled.
    """
    username = normalize_username(raw_username)
    account = (find_admin_account_by_username(username)
               if is_valid_username(username) else None)
    if account is None:
        raise AccountError(f"없는 계정명입니다: {username}")
    if account.disabled or not mark_admin_account_disabled(
            username, _utc_now_iso()):
        raise AccountError(f"이미 비활성화된 계정입니다: {username}")
    logger.info("Administrator account disabled: username=%s id=%d",
                account.username, account.id)
    updated = find_admin_account_by_username(username)
    return updated if updated is not None else account


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
