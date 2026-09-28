"""Authentication chain pattern for suspect identity verification.

Supports layered authentication:
  1. BasicAuthenticator  -- name + birth date + phone (always required)
  2. PasswordAuthenticator -- password (optional, per-case)
  3. OTPAuthenticator    -- email OTP (optional, per-case)

New authenticators can be added by subclassing BaseAuthenticator.

Stage E (E3a): the basic step compares keyed digests of the normalised
inputs with the digests stored for the case (:mod:`web.privacy`), never
plaintext; the password step verifies a scrypt hash, or a v1.0.1 SHA-256
hash in constant time (:mod:`web.auth.case_passwords`).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

# web.privacy.case_identity is imported where it is used: it needs
# desktop.crypto, and the account CLI (python -m src.web.admin_accounts)
# imports this package without src/ on the import path.
from ..privacy.digests import normalize_birth_date, normalize_name, normalize_phone
from .case_passwords import verify_case_password

logger = logging.getLogger(__name__)

# The basic step's answer to a wrong credential; the subject route gives the
# same answer for a case whose identity was never converted (Fable gate,
# finding 10), so a response does not show which cases those are.
MSG_IDENTITY_MISMATCH = "입력한 정보가 일치하지 않습니다."

# Re-exported: callers of v1.0.1 import it from here.
__all__ = [
    "AuthChain", "AuthResult", "BaseAuthenticator", "BasicAuthenticator",
    "OTPAuthenticator", "PasswordAuthenticator", "normalize_birth_date",
    "register_authenticator",
]


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
    """Verify name + birth date + phone number against the stored digests.

    Each input is normalised (name: NFC, whitespace collapsed; birth date
    and phone: digits only, so formatting is ignored) and digested with
    the server pepper; all three digests are compared in constant time
    before the result is combined. An input with nothing left after
    normalisation counts as missing.

    Raises:
        PrivacyUnavailable: The identity-protection keys are not configured.
        LegacyIdentityError: The case's identity was never converted.
    """

    @property
    def name(self) -> str:
        return "basic"

    def authenticate(
        self,
        case: dict[str, Any],
        credentials: dict[str, Any],
    ) -> AuthResult:
        input_name = credentials.get("name") or ""
        input_birth = credentials.get("birth_date") or ""
        input_phone = credentials.get("phone") or ""

        if not (normalize_name(input_name) and normalize_birth_date(input_birth)
                and normalize_phone(input_phone)):
            return AuthResult(
                success=False,
                step=self.name,
                message="이름, 생년월일, 연락처를 모두 입력해 주세요.",
            )

        from ..privacy.case_identity import verify_basic_identity

        if verify_basic_identity(case, input_name, input_birth, input_phone):
            return AuthResult(success=True, step=self.name, message="기본 인증 성공")

        return AuthResult(
            success=False,
            step=self.name,
            message=MSG_IDENTITY_MISMATCH,
        )


class PasswordAuthenticator(BaseAuthenticator):
    """Verify the case password (scrypt, or a v1.0.1 SHA-256 hash).

    A legacy hash is compared in constant time; the route replaces it by a
    scrypt hash after a successful login (:mod:`web.auth.case_passwords`).
    """

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

        if verify_case_password(input_pw, case.get("password_hash", "")):
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
