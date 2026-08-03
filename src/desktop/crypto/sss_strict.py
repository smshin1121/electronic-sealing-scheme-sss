"""Strict-mode key splitting with an outer 2-of-2 XOR wrap.

Deployment-selectable design:

    K = R xor X

where ``R`` is held only by the subject of seizure as the owner share
(s1) and ``X`` is replicated to the three institutional channels
(s2 investigator, s3 time-locked system, s4 admin — the latter two are
envelope-wrapped by the existing KMS layer, unchanged). Because ``R``
is drawn uniformly at random, ``X`` alone is statistically independent
of ``K``; therefore NO coalition of institutional channels can recover
the key without s1, while s1 plus any single channel suffices. This is
the conjunctive access structure discussed (and rejected as the
*default*) in §3.3.2 of the manuscript.

Transport format is identical to standard SSS shares (``"N-<hex>"``,
N in 1..4), so share submission flows — including the remote portal —
need no UI branch. Recovery-side dispatch on the sealing record's
``seal_mode`` field is provided by :func:`recover_key_for_mode`.
"""

from __future__ import annotations

import os

from .exceptions import KeyRecoveryError, KeySplitError

SEAL_MODE_STANDARD = "standard"
SEAL_MODE_STRICT = "strict"
VALID_SEAL_MODES = frozenset({SEAL_MODE_STANDARD, SEAL_MODE_STRICT})

_KEY_BYTES = 32
_OWNER_INDEX = 1
_CHANNEL_INDICES = frozenset({2, 3, 4})


def split_key_strict(hex_key: str) -> tuple[str, str, str, str]:
    """Split a hex AES-256 key into strict-mode shares (K = R xor X).

    Args:
        hex_key: The AES-256 key as a hex string (up to 64 hex chars).

    Returns:
        Tuple of 4 index-prefixed shares: s1 carries the random pad R,
        s2/s3/s4 each carry the identical complement X.

    Raises:
        KeySplitError: If the key is invalid or self-verification fails.
    """
    key = _parse_hex_key(hex_key)

    pad = os.urandom(_KEY_BYTES)
    complement = bytes(k ^ p for k, p in zip(key, pad))

    shares = (
        f"1-{pad.hex()}",
        f"2-{complement.hex()}",
        f"3-{complement.hex()}",
        f"4-{complement.hex()}",
    )

    recovered = recover_key_strict([shares[0], shares[1]])
    if recovered != key.hex():
        raise KeySplitError(
            "Strict-mode self-verification mismatch after split"
        )
    return shares


def recover_key_strict(shares: list[str]) -> str:
    """Recover the key from strict-mode shares (requires s1 + a channel).

    Args:
        shares: Index-prefixed share strings; must include the owner
            share (index 1) and at least one channel share (index 2-4).

    Returns:
        The recovered key as zero-padded 64-char hex.

    Raises:
        KeyRecoveryError: If s1 or every channel is missing, shares are
            malformed, or channel payloads disagree.
    """
    if not shares or len(shares) < 2:
        raise KeyRecoveryError(
            "Strict mode requires at least 2 shares (s1 and one channel)"
        )

    pad: bytes | None = None
    complements: dict[int, bytes] = {}
    for i, share in enumerate(shares):
        index, payload = _parse_share(share, position=i)
        if index == _OWNER_INDEX:
            if pad is not None and payload != pad:
                raise KeyRecoveryError("Conflicting s1 payloads provided")
            pad = payload
        else:
            complements[index] = payload

    if pad is None:
        raise KeyRecoveryError(
            "Strict mode requires the owner share (s1) in every recovery"
        )
    if not complements:
        raise KeyRecoveryError(
            "Strict mode requires at least one channel share (s2-s4)"
        )

    unique_payloads = set(complements.values())
    if len(unique_payloads) > 1:
        raise KeyRecoveryError(
            "Channel share payload mismatch: shares disagree on X"
        )

    complement = unique_payloads.pop()
    key = bytes(p ^ c for p, c in zip(pad, complement))
    return key.hex()


def recover_key_for_mode(mode: str, shares: list[str]) -> str:
    """Dispatch key recovery according to the record's ``seal_mode``.

    Args:
        mode: ``"standard"`` (SSS 2-of-4) or ``"strict"`` (s1 + channel).
        shares: Share strings collected for recovery.

    Returns:
        The recovered key as zero-padded 64-char hex.

    Raises:
        KeyRecoveryError: On an unknown mode (fail-closed) or any
            underlying recovery failure.
    """
    if mode == SEAL_MODE_STANDARD:
        from .sss_recover import recover_key

        return recover_key(shares)
    if mode == SEAL_MODE_STRICT:
        return recover_key_strict(shares)
    raise KeyRecoveryError(
        f"Unknown seal mode '{mode}': refusing recovery (fail-closed)"
    )


def _parse_hex_key(hex_key: str) -> bytes:
    """Validate and normalize a hex key to 32 bytes."""
    if not hex_key or not isinstance(hex_key, str):
        raise KeySplitError("hex_key must be a non-empty hex string")
    try:
        int(hex_key, 16)
    except ValueError as exc:
        raise KeySplitError(f"Invalid hex string: {hex_key[:8]}...") from exc
    if len(hex_key) > _KEY_BYTES * 2:
        raise KeySplitError(
            f"Key too large: {len(hex_key)} hex chars (max {_KEY_BYTES * 2})"
        )
    return bytes.fromhex(hex_key.zfill(_KEY_BYTES * 2))


def _parse_share(share: str, *, position: int) -> tuple[int, bytes]:
    """Parse an ``"N-<hex>"`` strict-mode share into (index, payload)."""
    if not share or not isinstance(share, str):
        raise KeyRecoveryError(f"Invalid share at index {position}")
    prefix, sep, payload_hex = share.partition("-")
    if not sep:
        raise KeyRecoveryError(
            f"Share at index {position} is not in 'N-<hex>' format"
        )
    try:
        index = int(prefix)
    except ValueError as exc:
        raise KeyRecoveryError(
            f"Share at index {position} has a non-numeric prefix"
        ) from exc
    if index != _OWNER_INDEX and index not in _CHANNEL_INDICES:
        raise KeyRecoveryError(
            f"Share at index {position} has out-of-range prefix {index}"
        )
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as exc:
        raise KeyRecoveryError(
            f"Share at index {position} payload is not valid hex"
        ) from exc
    if len(payload) != _KEY_BYTES:
        raise KeyRecoveryError(
            f"Share at index {position} payload must be {_KEY_BYTES} bytes"
        )
    return index, payload
