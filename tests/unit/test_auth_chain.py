"""Authentication chain unit tests.

Covers:
  - BasicAuthenticator: name + birth + phone match/mismatch
  - PasswordAuthenticator: SHA-256 password verification
  - OTPAuthenticator: generate -> verify -> expiry
  - AuthChain: chain combinations (basic only, basic+password, basic+otp)
  - Auth failure lockout: 5 failures -> block
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import pytest

from web.auth.auth_chain import (
    AuthChain,
    AuthResult,
    BasicAuthenticator,
    OTPAuthenticator,
    PasswordAuthenticator,
    normalize_birth_date,
)
from web.auth.otp_service import OTPService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_case(
    *,
    suspect_name: str = "홍길동",
    suspect_birth: str = "19900101",
    suspect_phone: str = "010-1234-5678",
    password_hash: str = "",
    auth_level: str = "basic",
) -> dict[str, Any]:
    """Build a minimal case dict matching DB column names."""
    return {
        "seal_id": "S-TEST-001",
        "suspect_name": suspect_name,
        "suspect_birth": suspect_birth,
        "suspect_phone": suspect_phone,
        "password_hash": password_hash,
        "auth_level": auth_level,
    }


# ===================================================================
# BasicAuthenticator
# ===================================================================

class TestBasicAuthenticator:
    """BasicAuthenticator: name + birth + phone."""

    def setup_method(self) -> None:
        self.auth = BasicAuthenticator()
        self.case = _make_case()

    def test_success(self) -> None:
        creds = {
            "name": "홍길동",
            "birth_date": "19900101",
            "phone": "010-1234-5678",
        }
        result = self.auth.authenticate(self.case, creds)
        assert result.success is True
        assert result.step == "basic"

    def test_name_mismatch(self) -> None:
        creds = {
            "name": "김철수",
            "birth_date": "19900101",
            "phone": "010-1234-5678",
        }
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False
        assert result.step == "basic"

    def test_birth_mismatch(self) -> None:
        creds = {
            "name": "홍길동",
            "birth_date": "20000101",
            "phone": "010-1234-5678",
        }
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False

    def test_phone_mismatch(self) -> None:
        creds = {
            "name": "홍길동",
            "birth_date": "19900101",
            "phone": "010-9999-9999",
        }
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False

    def test_empty_fields_rejected(self) -> None:
        creds = {"name": "", "birth_date": "", "phone": ""}
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False
        assert "모두 입력" in result.message

    def test_missing_keys_rejected(self) -> None:
        result = self.auth.authenticate(self.case, {})
        assert result.success is False

    def test_whitespace_stripped(self) -> None:
        creds = {
            "name": " 홍길동 ",
            "birth_date": " 19900101 ",
            "phone": " 010-1234-5678 ",
        }
        result = self.auth.authenticate(self.case, creds)
        assert result.success is True

    # --- Regression: legacy vs HTML date-input birth formats ---

    def test_legacy_stored_birth_with_date_input(self) -> None:
        """DB has legacy '19900101', <input type=date> submits '1990-01-01'."""
        case = _make_case(suspect_birth="19900101")
        creds = {
            "name": "홍길동",
            "birth_date": "1990-01-01",
            "phone": "010-1234-5678",
        }
        result = self.auth.authenticate(case, creds)
        assert result.success is True

    def test_dashed_stored_birth_with_legacy_input(self) -> None:
        """DB has '1990-01-01', user submits legacy '19900101'."""
        case = _make_case(suspect_birth="1990-01-01")
        creds = {
            "name": "홍길동",
            "birth_date": "19900101",
            "phone": "010-1234-5678",
        }
        result = self.auth.authenticate(case, creds)
        assert result.success is True

    def test_birth_mismatch_across_formats(self) -> None:
        """Normalization must not turn genuinely different dates into a match."""
        case = _make_case(suspect_birth="19900101")
        creds = {
            "name": "홍길동",
            "birth_date": "2000-01-01",
            "phone": "010-1234-5678",
        }
        result = self.auth.authenticate(case, creds)
        assert result.success is False


class TestNormalizeBirthDate:
    """normalize_birth_date: canonical YYYYMMDD extraction."""

    def test_dashed_form(self) -> None:
        assert normalize_birth_date("1990-01-01") == "19900101"

    def test_legacy_form(self) -> None:
        assert normalize_birth_date("19900101") == "19900101"

    def test_dotted_form(self) -> None:
        assert normalize_birth_date("1990.01.01") == "19900101"

    def test_empty(self) -> None:
        assert normalize_birth_date("") == ""


# ===================================================================
# PasswordAuthenticator
# ===================================================================

class TestPasswordAuthenticator:
    """PasswordAuthenticator: SHA-256 comparison."""

    def setup_method(self) -> None:
        self.auth = PasswordAuthenticator()
        self.raw_pw = "SecretPass123!"  # public-test-fixture
        self.pw_hash = hashlib.sha256(
            self.raw_pw.encode("utf-8")
        ).hexdigest()
        self.case = _make_case(password_hash=self.pw_hash)

    def test_correct_password(self) -> None:
        creds = {"password": self.raw_pw}
        result = self.auth.authenticate(self.case, creds)
        assert result.success is True
        assert result.step == "password"

    def test_wrong_password(self) -> None:
        creds = {"password": "WrongPassword"}  # public-test-fixture
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False
        assert "비밀번호" in result.message

    def test_empty_password(self) -> None:
        creds = {"password": ""}
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False
        assert "입력" in result.message

    def test_missing_password_key(self) -> None:
        result = self.auth.authenticate(self.case, {})
        assert result.success is False


# ===================================================================
# OTPAuthenticator
# ===================================================================

class TestOTPAuthenticator:
    """OTPAuthenticator: generate -> store -> verify -> expiry."""

    def setup_method(self) -> None:
        OTPService.configure(
            otp_length=6,
            expiry_seconds=300,
            smtp_mock=True,
        )
        self.auth = OTPAuthenticator()
        self.service = OTPService()
        self.case = _make_case()

    def test_generate_otp_format(self) -> None:
        code = self.service.generate_otp()
        assert len(code) == 6
        assert code.isdigit()

    def test_verify_correct_otp(self) -> None:
        session_id = "test-session-1"
        code = self.service.generate_otp()
        self.service.store_otp(session_id, code)

        creds = {"otp": code, "session_id": session_id}
        result = self.auth.authenticate(self.case, creds)
        assert result.success is True
        assert result.step == "otp"

    def test_verify_wrong_otp(self) -> None:
        session_id = "test-session-2"
        self.service.store_otp(session_id, "123456")

        creds = {"otp": "000000", "session_id": session_id}  # public-test-fixture
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False

    def test_otp_consumed_after_verification(self) -> None:
        session_id = "test-session-3"
        code = self.service.generate_otp()
        self.service.store_otp(session_id, code)

        # First verify: success
        assert self.service.verify_otp(session_id, code) is True
        # Second verify: consumed, fails
        assert self.service.verify_otp(session_id, code) is False

    def test_otp_expiry(self) -> None:
        OTPService.configure(
            otp_length=6,
            expiry_seconds=1,
            smtp_mock=True,
        )
        svc = OTPService()
        session_id = "test-session-expiry"
        code = svc.generate_otp()
        svc.store_otp(session_id, code)

        time.sleep(1.1)

        creds = {"otp": code, "session_id": session_id}
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False

        # Restore default
        OTPService.configure(otp_length=6, expiry_seconds=300, smtp_mock=True)

    def test_empty_otp_rejected(self) -> None:
        creds = {"otp": "", "session_id": "any"}
        result = self.auth.authenticate(self.case, creds)
        assert result.success is False
        assert "입력" in result.message

    def test_send_otp_mock(self) -> None:
        result = self.service.send_otp("test@example.com", "123456")
        assert result is True

    def test_send_otp_empty_email(self) -> None:
        result = self.service.send_otp("", "123456")
        assert result is False


# ===================================================================
# AuthChain
# ===================================================================

class TestAuthChain:
    """AuthChain: chain combination tests."""

    def _valid_basic_creds(self) -> dict[str, Any]:
        return {
            "name": "홍길동",
            "birth_date": "19900101",
            "phone": "010-1234-5678",
        }

    def test_basic_only_success(self) -> None:
        chain = AuthChain("basic")
        case = _make_case()
        result = chain.run(case, self._valid_basic_creds())
        assert result.success is True

    def test_basic_only_failure(self) -> None:
        chain = AuthChain("basic")
        case = _make_case()
        result = chain.run(case, {"name": "X", "birth_date": "X", "phone": "X"})
        assert result.success is False
        assert result.step == "basic"

    def test_basic_password_success(self) -> None:
        raw_pw = "TestPw1!"  # public-test-fixture
        pw_hash = hashlib.sha256(raw_pw.encode("utf-8")).hexdigest()
        case = _make_case(password_hash=pw_hash, auth_level="basic+password")

        chain = AuthChain("basic+password")
        creds = {**self._valid_basic_creds(), "password": raw_pw}
        result = chain.run(case, creds)
        assert result.success is True
        assert result.step == "password"

    def test_basic_password_fail_at_password(self) -> None:
        raw_pw = "TestPw1!"  # public-test-fixture
        pw_hash = hashlib.sha256(raw_pw.encode("utf-8")).hexdigest()
        case = _make_case(password_hash=pw_hash, auth_level="basic+password")

        chain = AuthChain("basic+password")
        creds = {**self._valid_basic_creds(), "password": "wrong"}  # public-test-fixture
        result = chain.run(case, creds)
        assert result.success is False
        assert result.step == "password"

    def test_basic_password_fail_at_basic(self) -> None:
        """Basic step fails -> password step never runs."""
        chain = AuthChain("basic+password")
        case = _make_case(auth_level="basic+password")
        creds = {"name": "X", "birth_date": "X", "phone": "X", "password": "any"}
        result = chain.run(case, creds)
        assert result.success is False
        assert result.step == "basic"

    def test_basic_otp_success(self) -> None:
        OTPService.configure(otp_length=6, expiry_seconds=300, smtp_mock=True)
        svc = OTPService()
        session_id = "chain-otp-sess"
        code = svc.generate_otp()
        svc.store_otp(session_id, code)

        case = _make_case(auth_level="basic+otp")
        chain = AuthChain("basic+otp")
        creds = {
            **self._valid_basic_creds(),
            "otp": code,
            "session_id": session_id,
        }
        result = chain.run(case, creds)
        assert result.success is True

    def test_empty_auth_level(self) -> None:
        """Empty auth_level -> no steps -> default failure result."""
        chain = AuthChain("")
        assert len(chain.steps) == 0
        result = chain.run({}, {})
        assert result.success is False

    def test_unknown_authenticator_skipped(self) -> None:
        chain = AuthChain("basic+fingerprint")
        assert len(chain.steps) == 1
        assert chain.steps[0].name == "basic"

    def test_steps_property_returns_copy(self) -> None:
        chain = AuthChain("basic+password")
        steps = chain.steps
        steps.clear()
        assert len(chain.steps) == 2  # original unaffected


# ===================================================================
# AuthResult immutability
# ===================================================================

class TestAuthResult:
    """AuthResult is a frozen dataclass."""

    def test_frozen(self) -> None:
        result = AuthResult(success=True, step="basic", message="ok")
        with pytest.raises(AttributeError):
            result.success = False  # type: ignore[misc]

    def test_equality(self) -> None:
        a = AuthResult(success=True, step="basic", message="ok")
        b = AuthResult(success=True, step="basic", message="ok")
        assert a == b


# ===================================================================
# Auth failure lockout (integration-like, uses Flask app)
# ===================================================================

class TestAuthFailureLockout:
    """5 consecutive failures within window -> lockout (429)."""

    @pytest.fixture(autouse=True)
    def _setup_app(self, tmp_path: Any) -> None:
        import os
        db_path = str(tmp_path / "lockout_test.db")
        os.environ["USE_SQLITE"] = "true"
        os.environ["SQLITE_PATH"] = db_path

        from web.config import TestingConfig
        original_path = TestingConfig.SQLITE_PATH
        TestingConfig.SQLITE_PATH = db_path

        from web.app import create_app

        self.app = create_app("testing")
        self.client = self.app.test_client()

        # Register a case for testing
        with self.app.app_context():
            from web.models.db_models import insert_case
            insert_case(
                seal_id="LOCK-001",
                case_number="2025-0001",
                investigator="수사관A",
                suspect_name="홍길동",
                suspect_birth="19900101",
                suspect_phone="010-1234-5678",
                auth_level="basic",
            )

        yield

        TestingConfig.SQLITE_PATH = original_path

    def test_lockout_after_5_failures(self) -> None:
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "test-token"  # public-test-fixture

        for _ in range(5):
            self.client.post(
                "/suspect/auth/LOCK-001",
                data={
                    "name": "wrong",
                    "birth_date": "wrong",
                    "phone": "wrong",
                    "csrf_token": "test-token",  # public-test-fixture
                },
            )

        # 6th attempt should be blocked (429)
        resp = self.client.post(
            "/suspect/auth/LOCK-001",
            data={
                "name": "홍길동",
                "birth_date": "19900101",
                "phone": "010-1234-5678",
                "csrf_token": "test-token",  # public-test-fixture
            },
        )
        assert resp.status_code == 429
