"""Run test requests at the same moment, one thread each (synthetic tests)."""

from __future__ import annotations

import threading
from typing import Any, Callable, Iterable

_TIMEOUT_SECONDS = 60


def run_concurrently(work: Callable[[Any], Any], items: Iterable[Any]) -> list[Any]:
    """Call ``work(item)`` for every item in its own thread, released together
    by a barrier; returns the results in item order (an exception is returned
    in place of its result)."""
    items = list(items)
    barrier = threading.Barrier(len(items))
    results: list[Any] = [None] * len(items)

    def run(index: int, item: Any) -> None:
        barrier.wait(timeout=_TIMEOUT_SECONDS)
        try:
            results[index] = work(item)
        except Exception as exc:  # reported to the caller, never swallowed
            results[index] = exc

    threads = [threading.Thread(target=run, args=(i, item)) for i, item in enumerate(items)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=_TIMEOUT_SECONDS * 2)
    assert not any(thread.is_alive() for thread in threads), "a request hung"
    return results
