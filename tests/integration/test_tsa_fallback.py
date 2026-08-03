"""Integration test: fail-closed behavior when the TSA is unavailable.

Contract (CR-01): the time-locked branch releases ONLY on a verified TSA
confirmation. A missing TSA URL, missing TSA certificate, or unreachable
TSA server must all DENY release, with a descriptive warning. Local time
is used only as an early deny.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from desktop.crypto import check_unlock_time
from desktop.crypto.types import AccessCheckResult


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTSAFailClosed:
    """TSA unavailability must deny time-locked release (fail-closed)."""

    def test_invalid_tsa_url_denies_despite_past_unlock(self) -> None:
        """A wrong TSA URL must deny even when unlock_time has passed."""

        past_time = datetime.now(tz=timezone.utc) - timedelta(days=1)
        unlock_iso = past_time.isoformat()

        result = check_unlock_time(
            unlock_time_iso=unlock_iso,
            tsa_url="https://invalid-tsa-server.example.com/tsa",
            tsa_cert_path="nonexistent-tsa-cert.pem",
        )

        assert isinstance(result, AccessCheckResult)
        assert result.allowed is False
        assert result.method == "tsa_unavailable"
        assert result.warning is not None
        assert "TSA" in result.warning

    def test_future_unlock_denied_before_tsa_attempt(self) -> None:
        """A future unlock_time is denied by the local preliminary check
        without a TSA round trip."""

        future_time = datetime.now(tz=timezone.utc) + timedelta(days=30)
        unlock_iso = future_time.isoformat()

        result = check_unlock_time(
            unlock_time_iso=unlock_iso,
            tsa_url="https://invalid-tsa-server.example.com/tsa",
            tsa_cert_path="nonexistent-tsa-cert.pem",
        )

        assert isinstance(result, AccessCheckResult)
        assert result.allowed is False
        assert result.method == "local_preliminary"
        # No warning: denial came from the local pre-check, not the TSA.
        assert result.warning is None

    def test_no_tsa_url_denies_with_warning(self) -> None:
        """Without a TSA URL, release is denied with a clear warning."""

        past_time = datetime.now(tz=timezone.utc) - timedelta(hours=1)
        unlock_iso = past_time.isoformat()

        result = check_unlock_time(
            unlock_time_iso=unlock_iso,
            tsa_url=None,
        )

        assert isinstance(result, AccessCheckResult)
        assert result.allowed is False
        assert result.method == "tsa_unavailable"
        assert result.warning is not None
        assert "TSA" in result.warning
        assert "fail-closed" in result.warning

    def test_missing_cert_denies_with_warning(self) -> None:
        """A TSA URL without a verification certificate must deny."""

        past_time = datetime.now(tz=timezone.utc) - timedelta(days=1)
        unlock_iso = past_time.isoformat()

        result = check_unlock_time(
            unlock_time_iso=unlock_iso,
            tsa_url="http://127.0.0.1:1/tsa",
        )

        assert result.allowed is False
        assert result.method == "tsa_unavailable"
        assert "certificate" in result.warning.lower()

    def test_denial_warnings_are_descriptive(self) -> None:
        """Denial warnings must explain the failed precondition."""

        past_time = datetime.now(tz=timezone.utc) - timedelta(days=1)
        unlock_iso = past_time.isoformat()

        result_invalid = check_unlock_time(
            unlock_time_iso=unlock_iso,
            tsa_url="https://invalid-tsa-server.example.com/tsa",
            tsa_cert_path="nonexistent-tsa-cert.pem",
        )
        assert result_invalid.warning is not None
        assert (
            "failed" in result_invalid.warning.lower()
            or "TSA" in result_invalid.warning
        )

        result_no_url = check_unlock_time(
            unlock_time_iso=unlock_iso,
            tsa_url=None,
        )
        assert result_no_url.warning is not None
        assert "No TSA URL" in result_no_url.warning

    def test_unlock_time_iso_format_variations_still_parse(self) -> None:
        """ISO 8601 variants parse correctly; outcome is fail-closed deny
        (no verifiable TSA in this test), never a parse error."""

        past = datetime.now(tz=timezone.utc) - timedelta(hours=2)

        result1 = check_unlock_time(
            unlock_time_iso=past.isoformat(),
            tsa_url=None,
        )
        assert result1.allowed is False
        assert result1.method == "tsa_unavailable"

        past_no_micro = past.replace(microsecond=0)
        result2 = check_unlock_time(
            unlock_time_iso=past_no_micro.isoformat(),
            tsa_url=None,
        )
        assert result2.allowed is False
        assert result2.method == "tsa_unavailable"
