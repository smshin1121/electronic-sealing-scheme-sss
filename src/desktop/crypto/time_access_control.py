"""Time-based access control using verified TSA (RFC 3161) time.

Fail-closed contract (CR-01, manuscript 3.2 / 3.3.5 / Eq. 4 / Alg. S4):
the time-locked branch may release ONLY on a fully verified TSA response
--- fresh request nonce echoed inside the signed TSTInfo, message-imprint
equality, and CMS signature verification against the TSA certificate.
Every other outcome (no TSA configured, transport failure, parse failure,
verification failure) denies access. Local time is used solely as an
early *deny* (never as an allow path).
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from .exceptions import AccessControlError
from .types import AccessCheckResult

logger = logging.getLogger(__name__)


def check_unlock_time(
    unlock_time_iso: str,
    tsa_url: Optional[str] = None,
    tsa_cert_path: Optional[str] = None,
) -> AccessCheckResult:
    """Check whether verified current time has passed unlock_time.

    Args:
        unlock_time_iso: The unlock time in ISO 8601 UTC format.
        tsa_url: TSA server URL for RFC 3161 time verification.
        tsa_cert_path: PEM path of the TSA certificate used to verify
            the CMS signature of the timestamp token.

    Returns:
        AccessCheckResult; ``allowed`` is True only on a verified TSA
        confirmation that gen_time >= unlock_time.

    Raises:
        AccessControlError: If unlock_time_iso is invalid.
    """
    unlock_time = _parse_iso_time(unlock_time_iso)
    local_now = datetime.now(tz=timezone.utc)

    # Early deny on local time: if even the (untrusted, but only ever
    # deny-capable) local clock is before the unlock time, no TSA round
    # trip is needed.
    if local_now < unlock_time:
        return AccessCheckResult(
            allowed=False,
            method="local_preliminary",
            current_time_iso=local_now.isoformat(),
            unlock_time_iso=unlock_time_iso,
            warning=None,
        )

    if not tsa_url:
        return AccessCheckResult(
            allowed=False,
            method="tsa_unavailable",
            current_time_iso=local_now.isoformat(),
            unlock_time_iso=unlock_time_iso,
            warning="No TSA URL configured; time-locked release denied "
                    "(fail-closed)",
        )

    if not tsa_cert_path:
        return AccessCheckResult(
            allowed=False,
            method="tsa_unavailable",
            current_time_iso=local_now.isoformat(),
            unlock_time_iso=unlock_time_iso,
            warning="No TSA certificate configured for verification; "
                    "time-locked release denied (fail-closed)",
        )

    try:
        gen_time = _request_verified_tsa_time(tsa_url, tsa_cert_path)
    except Exception as exc:
        logger.warning(
            "Verified TSA time unavailable (%s); denying time-locked "
            "release (fail-closed)", exc,
        )
        return AccessCheckResult(
            allowed=False,
            method="tsa_unavailable",
            current_time_iso=local_now.isoformat(),
            unlock_time_iso=unlock_time_iso,
            warning=f"TSA verification failed: {exc}",
        )

    return AccessCheckResult(
        allowed=gen_time >= unlock_time,
        method="tsa",
        current_time_iso=gen_time.isoformat(),
        unlock_time_iso=unlock_time.isoformat(),
        warning=None,
    )


def _request_verified_tsa_time(
    tsa_url: str, tsa_cert_path: str
) -> datetime:
    """Obtain a fully verified TSA genTime (nonce, imprint, signature).

    Raises on any failure; callers translate that into a denial.
    """
    from desktop.signature.tsa_client import request_timestamp_verified

    digest = hashlib.sha256(os.urandom(16)).digest()
    return request_timestamp_verified(digest, tsa_url, tsa_cert_path)


def _parse_iso_time(iso_string: str) -> datetime:
    """Parse an ISO 8601 string to a timezone-aware datetime.

    Raises:
        AccessControlError: If parsing fails.
    """
    try:
        dt = datetime.fromisoformat(iso_string)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError) as exc:
        raise AccessControlError(
            f"Invalid ISO 8601 time: {iso_string}"
        ) from exc
