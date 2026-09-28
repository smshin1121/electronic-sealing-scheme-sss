"""Wrapping of the time-locked system share (s3) at sealing/resealing.

When the record carries an authenticated policy, s3 is envelope-encrypted
under the local-KMS master key with associated data binding it to the
seal and the policy digest
(:func:`desktop.signature.seal_policy.s3_wrap_aad`). That single
ciphertext is stored as share 3 in the desktop DB and synced to the
release host as ``wrapped_s3``; it only unwraps under the exact policy it
was created with. Without a policy the legacy unbound wrap is kept and no
``wrapped_s3`` is produced (the time-locked path would refuse the record).
"""

from __future__ import annotations

import base64
from typing import Optional, Sequence

from .crypto import encrypt_envelope
from .signature.seal_policy import s3_wrap_aad


def wrap_system_share(
    share3: str,
    master_key_path: str,
    *,
    seal_id: str,
    policy_digest: Optional[bytes],
) -> bytes:
    """Envelope-encrypt s3, bound to (seal_id, policy digest) if given."""
    plaintext = share3.encode("utf-8")
    if policy_digest is None:
        return encrypt_envelope(plaintext, master_key_path)
    return encrypt_envelope(
        plaintext, master_key_path, aad=s3_wrap_aad(seal_id, policy_digest)
    )


def wrapped_s3_for_sync(
    wrapped: bytes, policy_digest: Optional[bytes]
) -> Optional[str]:
    """Base64 ``wrapped_s3`` for the sync payload; ``None`` when legacy."""
    if policy_digest is None:
        return None
    return base64.b64encode(wrapped).decode("ascii")


def wrap_institutional_shares(
    shares: Sequence[str],
    master_key_path: str,
    *,
    seal_id: str,
    policy_digest: Optional[bytes],
) -> tuple[dict[int, bytes], Optional[str]]:
    """Envelope-wrap s3 (policy-bound when signed) and s4 (unchanged).

    Returns:
        ``({3: wrapped_s3, 4: wrapped_s4}, wrapped_s3_b64_or_None)``.
    """
    wrapped_3 = wrap_system_share(
        shares[2], master_key_path,
        seal_id=seal_id, policy_digest=policy_digest,
    )
    wrapped_4 = encrypt_envelope(shares[3].encode("utf-8"), master_key_path)
    return (
        {3: wrapped_3, 4: wrapped_4},
        wrapped_s3_for_sync(wrapped_3, policy_digest),
    )
