"""Hostile-network helpers for TSA replay and substitution tests.

The helpers replace the TSA client's transport (``tsa_client._send_tsq``)
with a function that rewrites the outgoing TimeStampReq before forwarding
it to the real local TSA, or returns a previously captured token. The
client-side verification code under test stays unmodified.
"""

from __future__ import annotations

from typing import Callable, Optional

from asn1crypto import algos, tsp

SendTsq = Callable[[bytes, str], bytes]


def rebuild_tsq(
    tsq_bytes: bytes,
    *,
    nonce: Optional[int] = None,
    hashed_message: Optional[bytes] = None,
    algorithm: Optional[str] = None,
) -> bytes:
    """Return a copy of a TSQ with selected fields replaced."""
    tsq = tsp.TimeStampReq.load(tsq_bytes)
    imprint = tsq["message_imprint"]
    new_imprint = tsp.MessageImprint({
        "hash_algorithm": algos.DigestAlgorithm({
            "algorithm": (
                algorithm or imprint["hash_algorithm"]["algorithm"].native
            ),
        }),
        "hashed_message": (
            hashed_message
            if hashed_message is not None
            else imprint["hashed_message"].native
        ),
    })
    return tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": new_imprint,
        "cert_req": True,
        "nonce": nonce if nonce is not None else tsq["nonce"].native,
    }).dump()


def forwarding_proxy(
    original_send: SendTsq,
    *,
    nonce: Optional[int] = None,
    hashed_message: Optional[bytes] = None,
    algorithm: Optional[str] = None,
) -> SendTsq:
    """Transport that forwards a rewritten TSQ to the real TSA."""

    def _send(tsq_bytes: bytes, tsa_url: str) -> bytes:
        rewritten = rebuild_tsq(
            tsq_bytes,
            nonce=nonce,
            hashed_message=hashed_message,
            algorithm=algorithm,
        )
        return original_send(rewritten, tsa_url)

    return _send


def replaying_transport(captured_token: bytes) -> SendTsq:
    """Transport that ignores the request and replays an old token."""

    def _send(_tsq_bytes: bytes, _tsa_url: str) -> bytes:
        return captured_token

    return _send


def counting_transport(original_send: SendTsq, calls: list[str]) -> SendTsq:
    """Transport that records each call and forwards unchanged."""

    def _send(tsq_bytes: bytes, tsa_url: str) -> bytes:
        calls.append(tsa_url)
        return original_send(tsq_bytes, tsa_url)

    return _send


# A fixed nonce standing in for "the nonce of an earlier exchange": the
# client draws a fresh 64-bit nonce per request, so a collision with this
# value has probability 2**-64.
STALE_NONCE = 1
