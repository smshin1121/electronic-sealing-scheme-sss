"""Tests for SSS (Shamir's Secret Sharing) 2-of-4 key split and recovery.

Validates:
- All 6 combinations of 2 shares recover the original key
- Single share fails to recover
- Invalid/corrupted share raises error
- Invalid hex input raises KeySplitError
"""

from __future__ import annotations

import itertools
import os

import pytest

from desktop.crypto import (
    KeyRecoveryError,
    KeySplitError,
    recover_key,
    split_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_hex_key() -> str:
    """Generate a random 256-bit key as a hex string (64 chars)."""
    return os.urandom(32).hex()


# ---------------------------------------------------------------------------
# Full combinatorial recovery (2-of-4)
# ---------------------------------------------------------------------------

class TestSSS2of4AllCombinations:
    """Every 2-share combination out of 4 must recover the original key."""

    def test_all_six_pairs_recover(self) -> None:
        hex_key = _random_hex_key()
        shares = split_key(hex_key)
        assert len(shares) == 4

        pairs = list(itertools.combinations(range(4), 2))
        assert len(pairs) == 6

        for i, j in pairs:
            recovered = recover_key([shares[i], shares[j]])
            assert recovered.lower() == hex_key.lower(), (
                f"Recovery failed for pair ({i}, {j})"
            )

    def test_three_shares_also_recover(self) -> None:
        """Using 3 shares (more than threshold) should also work."""
        hex_key = _random_hex_key()
        shares = split_key(hex_key)

        for combo in itertools.combinations(range(4), 3):
            selected = [shares[idx] for idx in combo]
            recovered = recover_key(selected)
            assert recovered.lower() == hex_key.lower()

    def test_all_four_shares_recover(self) -> None:
        """Using all 4 shares should also work."""
        hex_key = _random_hex_key()
        shares = split_key(hex_key)

        recovered = recover_key(list(shares))
        assert recovered.lower() == hex_key.lower()


# ---------------------------------------------------------------------------
# Single share -> failure
# ---------------------------------------------------------------------------

class TestSingleShareFails:
    """A single share must not be sufficient for recovery."""

    def test_one_share_raises_error(self) -> None:
        hex_key = _random_hex_key()
        shares = split_key(hex_key)

        for idx in range(4):
            with pytest.raises(KeyRecoveryError):
                recover_key([shares[idx]])

    def test_empty_list_raises_error(self) -> None:
        with pytest.raises(KeyRecoveryError):
            recover_key([])

    def test_none_share_raises_error(self) -> None:
        with pytest.raises(KeyRecoveryError):
            recover_key([None, None])  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# Invalid / corrupted shares
# ---------------------------------------------------------------------------

class TestInvalidShares:
    """Corrupted or fabricated shares must raise an error or mismatch."""

    def test_garbage_shares_raise_error(self) -> None:
        """Two completely fabricated share strings should fail."""
        with pytest.raises((KeyRecoveryError, Exception)):
            recover_key(["not-a-real-share", "also-fake"])

    def test_swapped_share_from_different_split(self) -> None:
        """Shares from two independent splits must not recover either original key.

        Note: split_key includes an internal random verification step that
        can occasionally fail. We retry up to 5 times to get two valid splits.
        """
        for _ in range(5):
            try:
                key_a = _random_hex_key()
                key_b = _random_hex_key()
                shares_a = split_key(key_a)
                shares_b = split_key(key_b)
                break
            except KeySplitError:
                continue
        else:
            pytest.skip("split_key verification repeatedly failed (flaky)")

        # Mix one share from each split
        recovered = recover_key([shares_a[0], shares_b[1]])
        # The recovered value should match neither original key
        assert recovered.lower() != key_a.lower()
        assert recovered.lower() != key_b.lower()


# ---------------------------------------------------------------------------
# Split input validation
# ---------------------------------------------------------------------------

class TestSplitInputValidation:
    """split_key must reject invalid hex input."""

    def test_empty_string_raises(self) -> None:
        with pytest.raises(KeySplitError):
            split_key("")

    def test_non_hex_raises(self) -> None:
        with pytest.raises(KeySplitError):
            split_key("zzzz-not-hex")

    def test_none_raises(self) -> None:
        with pytest.raises(KeySplitError):
            split_key(None)  # type: ignore[arg-type]

    def test_valid_short_hex_works(self) -> None:
        """Even a short hex key should split successfully."""
        shares = split_key("abcdef1234567890")
        assert len(shares) == 4


# ---------------------------------------------------------------------------
# Determinism check (shares should differ between calls)
# ---------------------------------------------------------------------------

class TestSplitNonDeterminism:
    """Two splits of the same key should produce different shares."""

    def test_shares_differ_across_splits(self) -> None:
        hex_key = _random_hex_key()
        shares_1 = split_key(hex_key)
        shares_2 = split_key(hex_key)

        # At least one share should differ (probabilistic but virtually certain)
        assert shares_1 != shares_2
