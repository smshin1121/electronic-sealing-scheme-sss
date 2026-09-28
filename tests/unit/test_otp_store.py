"""OTP store housekeeping (stage E, E3a review).

Each OTP delivery stores a code under a fresh session key; a code that is
never verified used to stay in the process-wide store forever. Expired
entries are now dropped whenever a new code is stored.
"""

from __future__ import annotations

from typing import Iterator

import pytest

from web.auth.otp_service import OTPService


@pytest.fixture()
def clock(monkeypatch) -> Iterator[list[float]]:
    now = [1_000_000.0]
    monkeypatch.setattr("web.auth.otp_service.time.time", lambda: now[0])
    OTPService.configure(otp_length=6, expiry_seconds=300, smtp_mock=True)
    yield now
    for key in ("e3a-old", "e3a-fresh", "e3a-new"):
        OTPService._store.pop(key, None)


def test_expired_codes_are_dropped_when_a_new_one_is_stored(clock) -> None:
    service = OTPService()
    service.store_otp("e3a-old", service.generate_otp())
    clock[0] += 200
    service.store_otp("e3a-fresh", service.generate_otp())
    clock[0] += 101  # e3a-old is now 301 s old, e3a-fresh 101 s

    service.store_otp("e3a-new", service.generate_otp())

    assert "e3a-old" not in OTPService._store
    assert "e3a-fresh" in OTPService._store and "e3a-new" in OTPService._store


def test_a_code_within_its_lifetime_still_verifies(clock) -> None:
    service = OTPService()
    code = service.generate_otp()
    service.store_otp("e3a-fresh", code)
    clock[0] += 299
    service.store_otp("e3a-new", service.generate_otp())

    assert service.verify_otp("e3a-fresh", code) is True
