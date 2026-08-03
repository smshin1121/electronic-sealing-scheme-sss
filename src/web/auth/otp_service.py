"""Email OTP generation, delivery and verification.

OTP codes are 6-digit numeric strings valid for 5 minutes.
In mock mode (SMTP_MOCK=true) the OTP is logged instead of emailed.
"""

from __future__ import annotations

import logging
import secrets
import smtplib
import time
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from threading import Lock
from typing import ClassVar

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _OTPEntry:
    """Immutable record of a generated OTP."""

    code: str
    created_at: float
    expiry_seconds: int


class OTPService:
    """Singleton-like OTP store.

    The store maps ``session_id -> _OTPEntry``.  Entries expire after
    ``OTP_EXPIRY_SECONDS`` (default 300 = 5 min).
    """

    _store: ClassVar[dict[str, _OTPEntry]] = {}
    _lock: ClassVar[Lock] = Lock()

    # ---- configuration (set from app config at startup) ----
    _otp_length: ClassVar[int] = 6
    _expiry_seconds: ClassVar[int] = 300
    _smtp_host: ClassVar[str] = "localhost"
    _smtp_port: ClassVar[int] = 587
    _smtp_user: ClassVar[str] = ""
    _smtp_password: ClassVar[str] = ""
    _smtp_from: ClassVar[str] = "seal-system@example.com"
    _smtp_use_tls: ClassVar[bool] = True
    _smtp_mock: ClassVar[bool] = True
    _smtp_timeout: ClassVar[int] = 10

    # ------------------------------------------------------------------
    @classmethod
    def configure(
        cls,
        *,
        otp_length: int = 6,
        expiry_seconds: int = 300,
        smtp_host: str = "localhost",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        smtp_from: str = "seal-system@example.com",
        smtp_use_tls: bool = True,
        smtp_mock: bool = True,
        smtp_timeout: int = 10,
    ) -> None:
        """Set OTP/SMTP parameters (typically called once at app startup)."""
        cls._otp_length = otp_length
        cls._expiry_seconds = expiry_seconds
        cls._smtp_host = smtp_host
        cls._smtp_port = smtp_port
        cls._smtp_user = smtp_user
        cls._smtp_password = smtp_password
        cls._smtp_from = smtp_from
        cls._smtp_use_tls = smtp_use_tls
        cls._smtp_mock = smtp_mock
        cls._smtp_timeout = smtp_timeout

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------
    def generate_otp(self) -> str:
        """Generate a cryptographically random numeric OTP code.

        Returns:
            A zero-padded numeric string of length ``_otp_length``.
        """
        upper = 10 ** self._otp_length
        code = str(secrets.randbelow(upper)).zfill(self._otp_length)
        return code

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------
    def send_otp(self, email: str, otp: str) -> bool:
        """Send the OTP code to the given email address.

        In mock mode, logs the code instead of sending real email.

        Args:
            email: Recipient email address.
            otp: The OTP code to deliver.

        Returns:
            True if delivery succeeded (or mock succeeded).
        """
        if not email:
            logger.error("Cannot send OTP: empty email address")
            return False

        if self._smtp_mock:
            logger.info(
                "[MOCK OTP] email=%s  code=%s  (유효시간: %d초)",
                email,
                otp,
                self._expiry_seconds,
            )
            return True

        try:
            msg = MIMEText(
                f"전자봉인시스템 인증번호: {otp}\n"
                f"유효시간: {self._expiry_seconds // 60}분\n\n"
                "본인이 요청하지 않은 경우 무시하세요.",
                "plain",
                "utf-8",
            )
            msg["Subject"] = "[전자봉인시스템] 본인확인 인증번호"
            msg["From"] = self._smtp_from
            msg["To"] = email

            server = smtplib.SMTP(
                self._smtp_host, self._smtp_port, timeout=self._smtp_timeout
            )
            if self._smtp_use_tls:
                server.ehlo()
                server.starttls()

            if self._smtp_user:
                server.login(self._smtp_user, self._smtp_password)

            server.sendmail(self._smtp_from, [email], msg.as_string())
            server.quit()
            logger.info("OTP sent to %s", email)
            return True
        except Exception:
            logger.exception("Failed to send OTP email to %s", email)
            return False

    # ------------------------------------------------------------------
    # Store & Verify
    # ------------------------------------------------------------------
    def store_otp(self, session_id: str, otp: str) -> None:
        """Store an OTP code for later verification.

        Args:
            session_id: Unique identifier for this verification attempt.
            otp: The OTP code.
        """
        entry = _OTPEntry(
            code=otp,
            created_at=time.time(),
            expiry_seconds=self._expiry_seconds,
        )
        with self._lock:
            self._store[session_id] = entry

    def verify_otp(self, session_id: str, input_otp: str) -> bool:
        """Verify an OTP code against the stored entry.

        The entry is consumed on successful verification or expiration.

        Args:
            session_id: The session identifier used when storing.
            input_otp: User-provided OTP code.

        Returns:
            True if the code matches and has not expired.
        """
        with self._lock:
            entry = self._store.pop(session_id, None)

        if entry is None:
            return False

        elapsed = time.time() - entry.created_at
        if elapsed > entry.expiry_seconds:
            logger.info("OTP expired for session %s", session_id)
            return False

        return secrets.compare_digest(entry.code, input_otp.strip())
