"""SSS (Shamir's Secret Sharing) 2-of-4 key splitting."""

from __future__ import annotations

import itertools
import random

from ._vendor.secretsharing import SecretSharer

from .exceptions import KeySplitError


def split_key(hex_key: str) -> tuple[str, str, str, str]:
    """Split a hex-encoded AES-256 key into 4 shares (threshold=2).

    After splitting, automatically verifies recovery by testing
    a random combination of 2 shares.

    Args:
        hex_key: The AES-256 key as a hex string (64 hex chars for 32 bytes).

    Returns:
        Tuple of 4 share strings.

    Raises:
        KeySplitError: If splitting or verification fails.
    """
    if not hex_key or not isinstance(hex_key, str):
        raise KeySplitError("hex_key must be a non-empty hex string")

    try:
        int(hex_key, 16)
    except ValueError as exc:
        raise KeySplitError(f"Invalid hex string: {hex_key[:8]}...") from exc

    try:
        shares = SecretSharer.split_secret(hex_key, 2, 4)
    except Exception as exc:
        raise KeySplitError(f"SSS split failed: {exc}") from exc

    if len(shares) != 4:
        raise KeySplitError(f"Expected 4 shares, got {len(shares)}")

    _verify_recovery(hex_key, shares)

    return (shares[0], shares[1], shares[2], shares[3])


def _verify_recovery(original_hex: str, shares: list[str]) -> None:
    """Verify that any 2 shares can recover the original key.

    Tests one random 2-share combination.

    Raises:
        KeySplitError: If recovery verification fails.
    """
    all_pairs = list(itertools.combinations(range(4), 2))
    pair = random.choice(all_pairs)
    test_shares = [shares[pair[0]], shares[pair[1]]]

    try:
        recovered = SecretSharer.recover_secret(test_shares)
    except Exception as exc:
        raise KeySplitError(f"Recovery verification failed: {exc}") from exc

    # Normalize both to same format: strip leading zeros, compare as integers
    try:
        original_int = int(original_hex, 16)
        recovered_int = int(recovered, 16)
    except ValueError as exc:
        raise KeySplitError(f"Hex comparison failed: {exc}") from exc

    if recovered_int != original_int:
        raise KeySplitError(
            "Recovery verification mismatch: recovered key does not match original"
        )
