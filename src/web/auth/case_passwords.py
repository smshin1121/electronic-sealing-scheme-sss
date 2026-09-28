"""The subject's optional case password (stage E, E3a).

New case passwords are scrypt hashes from :mod:`web.auth.passwords` (the
administrators' scheme and bounds) and follow the same policy: 12 to 1024
characters, checked at case registration, which refuses a shorter password
with 400 and the policy message. The password is a second factor next to
the name, birth date and phone number; the case is registered by the
investigator, who hands the password to the subject, so the length asks
nothing of the subject's memory that an administrator is not asked.

v1.0.1 stored an unsalted SHA-256 hex digest. Such a legacy hash is still
verified, with :func:`hmac.compare_digest`, whatever the password's length
(after one dummy scrypt derivation, so that it takes as long as a scrypt
check);
after a successful login the route replaces it by a scrypt hash of the
submitted password (:func:`upgraded_hash`), on a best-effort basis, so a
legacy hash is normally used only until the subject's first successful
login.

These paths are public (case registration is unauthenticated, and the
subject's password factor runs for anyone who knows the other factors), so
every derivation here -- hashing, verifying (including the dummy
derivation for a legacy hash) and the upgrade -- holds a slot of the
``case-password`` pool (:mod:`web.auth.kdf_slots`), at most
``CASE_PASSWORD_MAX_CONCURRENT`` at once per process. Beyond that the
request is refused with :class:`web.auth.kdf_slots.DerivationBusy` before
any password work.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from contextlib import AbstractContextManager

from flask import current_app, has_app_context

from .kdf_slots import derivation_slot
from .passwords import (
    burn_verification,
    check_password_policy,
    hash_password,
    rehash_password,
    verify_password,
)

_LEGACY_SHA256_RE = re.compile(r"[0-9a-f]{64}")
POOL = "case-password"
DEFAULT_MAX_CONCURRENT = 4

__all__ = [
    "check_case_password_policy",
    "hash_case_password",
    "is_legacy_password_hash",
    "upgraded_hash",
    "verify_case_password",
]

check_case_password_policy = check_password_policy


def _slot() -> AbstractContextManager[None]:
    """One slot of the case-password pool (the app's configured limit)."""
    limit =(current_app.config.get("CASE_PASSWORD_MAX_CONCURRENT", DEFAULT_MAX_CONCURRENT)
             if has_app_context() else DEFAULT_MAX_CONCURRENT)
    return derivation_slot(POOL, limit)


def hash_case_password(password: str) -> str:
    """A scrypt hash of a new case password (policy-checked).

    Raises:
        DerivationBusy: The case-password pool is full; nothing was derived.
    """
    check_password_policy(password)
    with _slot():
        return hash_password(password)


def is_legacy_password_hash(stored: object) -> bool:
    """Whether ``stored`` is a v1.0.1 unsalted SHA-256 hex digest."""
    return isinstance(stored, str) and _LEGACY_SHA256_RE.fullmatch(stored) is not None


def verify_case_password(password: object, stored: object) -> bool:
    """Whether ``password`` matches a stored scrypt or legacy SHA-256 hash.

    An empty or unrecognised stored value is a mismatch (it still costs one
    scrypt derivation, like a wrong password).

    Raises:
        DerivationBusy: The case-password pool is full; nothing was derived.
    """
    if not isinstance(password, str) or not password:
        return False
    with _slot():
        return _verify(password, stored)


def _verify(password: str, stored: object) -> bool:
    if is_legacy_password_hash(stored):
        # One dummy scrypt derivation, so that response times do not show
        # which cases still carry a legacy (offline-crackable) hash.
        burn_verification(password)
        computed = hashlib.sha256(password.encode("utf-8", "surrogatepass")).hexdigest()
        return hmac.compare_digest(computed.encode("ascii"), stored.encode("ascii"))
    if not isinstance(stored, str) or not stored.startswith("scrypt$"):
        return burn_verification(password)
    return verify_password(password, stored)


def upgraded_hash(password: str) -> str:
    """The scrypt hash that replaces a legacy hash after a successful login.

    Raises:
        DerivationBusy: The case-password pool is full; nothing was derived.
    """
    with _slot():
        return rehash_password(password)
