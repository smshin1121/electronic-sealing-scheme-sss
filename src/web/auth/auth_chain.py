"""Authentication chain pattern for suspect identity verification.

Supports layered authentication:
  1. BasicAuthenticator  -- name + birth date + phone (always required)
  2. PasswordAuthenticator -- password (optional, per-case)
  3. OTPAuthenticator    -- email OTP (optional, per-case)

New authenticators can be added by subclassing BaseAuthenticator.
"""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


def normalize_birth_date(value: str) -> str:
    """Normalize a birth date string to canonical ``YYYYMMDD`` form.

    Accepts both legacy (``19900101``) and HTML ``<input type="date">``
    (``1990-01-01``) representations by extracting digits only, so that
    stored and submitted values compare equal regardless of formatting.

    Args:
        value: Raw birth date string (may contain separators).

    Returns:
        Digits-only canonical string (empty string if no digits).
    """
    return "".join(ch for ch in (value or "") if ch.isdigit())


@dataclass(frozen=True)
class AuthResult:
    """Immutable result of an authentication attempt."""

    success: bool
    step: str
    message: str


class BaseAuthenticator(ABC):
    """Abstract base for an authentication step."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable step name."""
        ...

    @abstractmethod
    def authenticate(
        self,
        case: dict[str, Any],
        credentials: dict[str, Any],
    ) -> AuthResult:
        """Validate credentials against stored case data.

        Args:
            case: Case row from the database (dict-like).
            credentials: User-submitted form data.

        Returns:
            AuthResult indicating success or failure.
        """
        ...


class BasicAuthenticator(BaseAuthenticator):
    """Verify name + birth date + phone number."""

    @property
    def name(self) -> str:
        return "basic"

    def authenticate(
        self,
        case: dict[str, Any],
        credentials: dict[str, Any],
    ) -> AuthResult:
        input_name = (credentials.get("name") or "").strip()
        input_birth = (credentials.get("birth_date") or "").strip()
        input_phone = (credentials.get("phone") or "").strip()

        if not input_name or not input_birth or not input_phone:
            return AuthResult(
                success=False,
                step=self.name,
                message="이름, 생년월일, 연락처를 모두 입력해 주세요.",
            )

        stored_name = case.get("suspect_name", "")
        stored_birth = case.get("suspect_birth", "")
        stored_phone = case.get("suspect_phone", "")

        if (
            input_name == stored_name
            and normalize_birth_date(input_birth) == normalize_birth_date(stored_birth)
            and input_phone == stored_phone
        ):
            return AuthResult(success=True, step=self.name, message="기본 인증 성공")

        return AuthResult(
            success=False,
            step=self.name,
            message="입력한 정보가 일치하지 않습니다.",
        )


class PasswordAuthenticator(BaseAuthenticator):
    """Verify password (SHA-256 hash comparison)."""

    @property
    def name(self) -> str:
        return "password"

    def authenticate(
        self,
        case: dict[str, Any],
        credentials: dict[str, Any],
    ) -> AuthResult:
        input_pw = credentials.get("password", "")
        if not input_pw:
            return AuthResult(
                success=False,
                step=self.name,
                message="비밀번호를 입력해 주세요.",
            )

        stored_hash = case.get("password_hash", "")
        input_hash = hashlib.sha256(input_pw.encode("utf-8")).hexdigest()

        if input_hash == stored_hash:
            return AuthResult(success=True, step=self.name, message="비밀번호 인증 성공")

        return AuthResult(
            success=False,
            step=self.name,
            message="비밀번호가 일치하지 않습니다.",
        )


class OTPAuthenticator(BaseAuthenticator):
    """Verify email OTP code."""

    @property
    def name(self) -> str:
        return "otp"

    def authenticate(
        self,
        case: dict[str, Any],
        credentials: dict[str, Any],
    ) -> AuthResult:
        from .otp_service import OTPService

        otp_code = (credentials.get("otp") or "").strip()
        session_id = credentials.get("session_id", "")

        if not otp_code:
            return AuthResult(
                success=False,
                step=self.name,
                message="OTP 코드를 입력해 주세요.",
            )

        service = OTPService()
        if service.verify_otp(session_id, otp_code):
            return AuthResult(success=True, step=self.name, message="OTP 인증 성공")

        return AuthResult(
            success=False,
            step=self.name,
            message="OTP 코드가 일치하지 않거나 만료되었습니다.",
        )


# ---------------------------------------------------------------------------
# Authenticator registry
# ---------------------------------------------------------------------------
_AUTHENTICATOR_REGISTRY: dict[str, type[BaseAuthenticator]] = {
    "basic": BasicAuthenticator,
    "password": PasswordAuthenticator,
    "otp": OTPAuthenticator,
}


def register_authenticator(key: str, cls: type[BaseAuthenticator]) -> None:
    """Register a custom authenticator type.

    Args:
        key: Short name used in auth_level strings.
        cls: Authenticator subclass.
    """
    _AUTHENTICATOR_REGISTRY[key] = cls


# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------

class AuthChain:
    """Execute a sequence of authenticators.

    The chain is built from the case's ``auth_level`` field, which is a
    ``+``-separated string of authenticator names, e.g. ``"basic+password+otp"``.

    Each step is executed in order. The chain short-circuits on the first
    failure and returns the failing AuthResult.
    """

    def __init__(self, auth_level: str) -> None:
        """Build the chain from an auth_level descriptor.

        Args:
            auth_level: ``"basic"`` | ``"basic+password"`` | ``"basic+otp"``
                        | ``"basic+password+otp"`` etc.
        """
        self._steps: list[BaseAuthenticator] = []
        for key in auth_level.split("+"):
            key = key.strip()
            cls = _AUTHENTICATOR_REGISTRY.get(key)
            if cls is None:
                logger.warning("Unknown authenticator '%s', skipping", key)
                continue
            self._steps.append(cls())

    @property
    def steps(self) -> list[BaseAuthenticator]:
        """Return the ordered list of authenticators."""
        return list(self._steps)

    def run(
        self,
        case: dict[str, Any],
        credentials: dict[str, Any],
    ) -> AuthResult:
        """Execute every step in the chain.

        Args:
            case: Case row (dict-like).
            credentials: User-submitted data.

        Returns:
            The first failing AuthResult, or the last successful one.
        """
        last_result = AuthResult(
            success=False, step="none", message="인증 단계가 없습니다."
        )

        for step in self._steps:
            result = step.authenticate(case, credentials)
            if not result.success:
                return result
            last_result = result

        return last_result
