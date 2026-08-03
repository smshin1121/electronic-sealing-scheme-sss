"""SSS (Shamir's Secret Sharing) key recovery."""

from __future__ import annotations

from ._vendor.secretsharing import SecretSharer

from .exceptions import KeyRecoveryError


def recover_key(shares: list[str]) -> str:
    """Recover the original hex key from 2 or more SSS shares.

    Args:
        shares: List of at least 2 SSS share strings.

    Returns:
        The recovered hex key string.

    Raises:
        KeyRecoveryError: If fewer than 2 shares provided or recovery fails.
    """
    if not shares or len(shares) < 2:
        raise KeyRecoveryError("At least 2 shares are required for recovery")

    for i, share in enumerate(shares):
        if not share or not isinstance(share, str):
            raise KeyRecoveryError(f"Invalid share at index {i}")

    try:
        recovered = SecretSharer.recover_secret(shares[:])
    except Exception as exc:
        raise KeyRecoveryError(f"SSS recovery failed: {exc}") from exc

    # Validate and normalize: ensure consistent zero-padded 64-char hex for AES-256
    try:
        key_int = int(recovered, 16)
    except ValueError as exc:
        raise KeyRecoveryError("Recovered value is not a valid hex string") from exc

    # Zero-pad to 64 hex chars (32 bytes for AES-256)
    normalized = format(key_int, '064x')
    return normalized
