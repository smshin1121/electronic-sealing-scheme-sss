"""Tests for time-based access control (unlock_time verification).

Contract (fail-closed, CR-01):
- Future unlock_time -> denied early on local time (deny-only use of it)
- Past unlock_time WITHOUT a verifiable TSA -> denied (fail-closed)
- Past unlock_time WITH a verified TSA time -> allowed
- Invalid ISO 8601 -> AccessControlError

The deeper verified-TSA behavior (nonce echo, imprint, CMS signature)
is covered in test_time_access_failclosed.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from desktop.crypto import AccessControlError, check_unlock_time
from desktop.crypto.types import AccessCheckResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _past_iso(hours: int = 1) -> str:
    """Return an ISO 8601 timestamp *hours* in the past."""
    dt = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
    return dt.isoformat()


def _future_iso(hours: int = 1) -> str:
    """Return an ISO 8601 timestamp *hours* in the future."""
    dt = datetime.now(tz=timezone.utc) + timedelta(hours=hours)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Past unlock_time without TSA -> denied (fail-closed)
# ---------------------------------------------------------------------------

class TestPastUnlockTimeNoTsa:
    """Past unlock_time alone is NOT sufficient: release needs the TSA."""

    def test_denied_without_tsa(self) -> None:
        result = check_unlock_time(_past_iso(1))

        assert isinstance(result, AccessCheckResult)
        assert result.allowed is False
        assert result.method == "tsa_unavailable"

    def test_denied_far_past_without_tsa(self) -> None:
        result = check_unlock_time("2020-01-01T00:00:00+00:00")

        assert result.allowed is False

    def test_warning_present_without_tsa(self) -> None:
        result = check_unlock_time(_past_iso(1))

        assert result.warning is not None
        assert "TSA" in result.warning


# ---------------------------------------------------------------------------
# Future unlock_time -> denied
# ---------------------------------------------------------------------------

class TestFutureUnlockTime:
    """When unlock_time is in the future, access must be denied."""

    def test_access_denied_no_tsa(self) -> None:
        result = check_unlock_time(_future_iso(1))

        assert result.allowed is False
        assert result.method == "local_preliminary"

    def test_access_denied_far_future(self) -> None:
        result = check_unlock_time("2099-12-31T23:59:59+00:00")

        assert result.allowed is False

    def test_no_warning_on_local_denial(self) -> None:
        result = check_unlock_time(_future_iso(1))

        assert result.warning is None


# ---------------------------------------------------------------------------
# TSA URL provided but unreachable -> denied (fail-closed)
# ---------------------------------------------------------------------------

class TestTsaUnavailable:
    """When the TSA is unreachable, release must be denied."""

    def test_denied_on_tsa_failure(self) -> None:
        result = check_unlock_time(
            _past_iso(1),
            tsa_url="http://127.0.0.1:1/tsa",  # nothing listens here
            tsa_cert_path="nonexistent.pem",
        )

        assert result.allowed is False
        assert result.method == "tsa_unavailable"
        assert result.warning is not None

    def test_denied_without_cert_path(self) -> None:
        result = check_unlock_time(
            _past_iso(1), tsa_url="http://127.0.0.1:1/tsa"
        )

        assert result.allowed is False
        assert result.method == "tsa_unavailable"


# ---------------------------------------------------------------------------
# Result fields validation
# ---------------------------------------------------------------------------

class TestResultFields:
    """AccessCheckResult must have all required fields populated."""

    def test_current_time_is_iso8601(self) -> None:
        result = check_unlock_time(_past_iso(1))

        # Should parse without error
        dt = datetime.fromisoformat(result.current_time_iso)
        assert dt.tzinfo is not None

    def test_unlock_time_preserved(self) -> None:
        unlock = _past_iso(2)
        result = check_unlock_time(unlock)

        assert result.unlock_time_iso == unlock

    def test_frozen_dataclass(self) -> None:
        result = check_unlock_time(_past_iso(1))

        with pytest.raises(AttributeError):
            result.allowed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Invalid input
# ---------------------------------------------------------------------------

class TestInvalidInput:
    """Invalid ISO 8601 strings must raise AccessControlError."""

    def test_garbage_string_raises(self) -> None:
        with pytest.raises(AccessControlError):
            check_unlock_time("not-a-date")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(AccessControlError):
            check_unlock_time("")

    def test_none_raises(self) -> None:
        with pytest.raises((AccessControlError, TypeError)):
            check_unlock_time(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Verified TSA success (mocked)
# ---------------------------------------------------------------------------

class TestTsaSuccess:
    """When verified TSA time is available, method should be 'tsa'."""

    def test_tsa_method_on_success(self) -> None:
        past_time = _past_iso(1)
        fake_tsa_time = datetime.now(tz=timezone.utc)

        with patch(
            "desktop.crypto.time_access_control._request_verified_tsa_time",
            return_value=fake_tsa_time,
        ):
            result = check_unlock_time(
                past_time,
                tsa_url="http://example.com/tsa",
                tsa_cert_path="tsa.pem",
            )

        assert result.allowed is True
        assert result.method == "tsa"
        assert result.warning is None

    def test_tsa_denies_before_unlock(self) -> None:
        future_unlock = _future_iso(1)
        # Local clock manipulated forward cannot help: pretend local time
        # passed the gate but verified TSA time has not.
        fake_tsa_time = datetime.now(tz=timezone.utc) - timedelta(hours=2)

        with patch(
            "desktop.crypto.time_access_control._request_verified_tsa_time",
            return_value=fake_tsa_time,
        ), patch(
            "desktop.crypto.time_access_control.datetime",
        ) as mock_dt:
            mock_dt.now.return_value = datetime.now(
                tz=timezone.utc
            ) + timedelta(hours=3)
            mock_dt.fromisoformat = datetime.fromisoformat
            result = check_unlock_time(
                future_unlock,
                tsa_url="http://example.com/tsa",
                tsa_cert_path="tsa.pem",
            )

        assert result.allowed is False
        assert result.method == "tsa"
