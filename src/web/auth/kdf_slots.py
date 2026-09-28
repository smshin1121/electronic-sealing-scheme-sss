"""Per-process bounds on concurrent scrypt derivations (stage E, E3a review N3).

Every scrypt derivation of :mod:`web.auth.passwords` holds about 32 MiB.
A pool admits at most ``limit`` derivations at once in this process; a
request beyond that is refused at once (:class:`DerivationBusy`), without
waiting and without any password work. Pools are separate by name, so the
public case-password paths cannot use up the slots of administrator logins
(which keep their own bound in :mod:`web.auth.admin_auth`).

The bound is per process: W worker processes allow W times as many.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

_LOCK = threading.Lock()
_POOLS: dict[tuple[str, int], threading.BoundedSemaphore] = {}


class DerivationBusy(RuntimeError):
    """No derivation slot is free; the request was refused without KDF work."""


def derivation_pool(name: str, limit: int) -> threading.BoundedSemaphore:
    """The process-wide semaphore of pool ``name`` with ``limit`` slots."""
    if type(limit) is not int or limit < 1:
        raise ValueError(f"the derivation limit of {name!r} must be a positive integer")
    with _LOCK:
        pool = _POOLS.get((name, limit))
        if pool is None:
            pool = _POOLS[(name, limit)] = threading.BoundedSemaphore(limit)
        return pool


@contextmanager
def derivation_slot(name: str, limit: int) -> Iterator[None]:
    """Hold one slot of pool ``name`` for the body.

    Raises:
        DerivationBusy: All ``limit`` slots are taken (nothing was derived).
    """
    pool = derivation_pool(name, limit)
    if not pool.acquire(blocking=False):
        raise DerivationBusy(name)
    try:
        yield
    finally:
        pool.release()
