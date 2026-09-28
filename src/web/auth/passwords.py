"""Administrator password hashing: scrypt with the parameters stored in the hash.

Encoded form (one ASCII string, stored in ``admin_accounts.password_hash``)::

    scrypt$<n>$<r>$<p>$<salt: 32 hex>$<derived key: 64 hex>

New hashes use a random 16-byte salt and n=2**15, r=8, p=1 (32 MiB, about
twice the cost of the n=2**14 floor). Verification reads the parameters
back from the stored string, so the cost can be raised later without
invalidating existing accounts. It accepts them only within fixed bounds
(never below the floor, never above a memory ceiling, so a crafted row
cannot exhaust memory), treats any malformed or foreign string as a
mismatch (fail-closed), and compares the derived keys with
:func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass

SCHEME = "scrypt"
MIN_PASSWORD_LENGTH = 12
# An upper bound keeps the PBKDF2 pre-hash inside scrypt from being a
# cheap way to make the server work.
MAX_PASSWORD_LENGTH = 1024
SALT_BYTES = 16
KEY_BYTES = 32

_MIN_N, _MAX_N = 2 ** 14, 2 ** 20
_MIN_R, _MAX_R = 8, 32
_MIN_P, _MAX_P = 1, 16
_MAX_MEMORY = 2 ** 28  # 256 MiB for the scrypt V array (128 * r * n)

_ENCODED_RE = re.compile(
    r"scrypt\$([0-9]{1,8})\$([0-9]{1,3})\$([0-9]{1,3})"
    r"\$([0-9a-f]{32})\$([0-9a-f]{64})"
)

_MSG_TOO_SHORT = f"비밀번호는 {MIN_PASSWORD_LENGTH}자 이상이어야 합니다."
_MSG_TOO_LONG = f"비밀번호는 {MAX_PASSWORD_LENGTH}자 이하여야 합니다."


class PasswordPolicyError(ValueError):
    """The password does not meet the policy; the message is user-facing."""


@dataclass(frozen=True)
class ScryptParams:
    """scrypt cost parameters."""

    n: int
    r: int
    p: int


DEFAULT_PARAMS = ScryptParams(n=2 ** 15, r=8, p=1)

# Salt for the dummy derivation run for unknown usernames (no account has it).
_DUMMY_SALT = os.urandom(SALT_BYTES)


def check_password_policy(password: object) -> str:
    """Return the password if it meets the policy, else raise."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(_MSG_TOO_SHORT)
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(_MSG_TOO_LONG)
    return password


def hash_password(password: str) -> str:
    """Hash a new password (policy-checked) with a fresh random salt."""
    check_password_policy(password)
    return _encode_new(password)


def rehash_password(password: str) -> str:
    """Hash a password that was just verified against an older stored form.

    Used to replace a legacy hash after a successful login (stage E, E3a:
    unsalted SHA-256 case passwords). The minimum length governs newly
    chosen passwords only, so a password accepted under the old rules keeps
    working; it must still be non-empty and within the upper bound.
    """
    if not isinstance(password, str) or not password:
        raise PasswordPolicyError(_MSG_TOO_SHORT)
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(_MSG_TOO_LONG)
    return _encode_new(password)


def _encode_new(password: str) -> str:
    params, salt = DEFAULT_PARAMS, os.urandom(SALT_BYTES)
    key = _derive(password, salt, params)
    return f"{SCHEME}${params.n}${params.r}${params.p}${salt.hex()}${key.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Whether ``password`` matches ``encoded``; False on any malformed input."""
    parsed = _parse(encoded)
    if parsed is None or not _acceptable_input(password):
        return False
    params, salt, expected = parsed
    return hmac.compare_digest(_derive(password, salt, params), expected)


def burn_verification(password: str) -> bool:
    """Run one scrypt derivation at the default cost and return False.

    Called for a username with no account, so that such a login costs about
    what a wrong password for an existing account costs.
    """
    if _acceptable_input(password):
        _derive(password, _DUMMY_SALT, DEFAULT_PARAMS)
    return False


def _acceptable_input(password: object) -> bool:
    return isinstance(password, str) and len(password) <= MAX_PASSWORD_LENGTH


def _parse(encoded: object) -> tuple[ScryptParams, bytes, bytes] | None:
    """Parameters, salt and key of a stored hash; None unless well-formed."""
    if not isinstance(encoded, str):
        return None
    match = _ENCODED_RE.fullmatch(encoded)
    if match is None:
        return None
    params = ScryptParams(int(match[1]), int(match[2]), int(match[3]))
    if not _within_bounds(params):
        return None
    return params, bytes.fromhex(match[4]), bytes.fromhex(match[5])


def _within_bounds(params: ScryptParams) -> bool:
    n, r, p = params.n, params.r, params.p
    power_of_two = n & (n - 1) == 0
    return (
        power_of_two
        and _MIN_N <= n <= _MAX_N
        and _MIN_R <= r <= _MAX_R
        and _MIN_P <= p <= _MAX_P
        and 128 * r * n <= _MAX_MEMORY
    )


def _derive(password: str, salt: bytes, params: ScryptParams) -> bytes:
    # OpenSSL's default limit (32 MiB) is below what n=2**15, r=8 needs.
    maxmem = 2 * 128 * params.r * (params.n + params.p + 2)
    return hashlib.scrypt(
        password.encode("utf-8", "surrogatepass"), salt=salt,
        n=params.n, r=params.r, p=params.p, maxmem=maxmem, dklen=KEY_BYTES,
    )
