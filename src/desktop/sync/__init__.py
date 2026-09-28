"""Desktop sync client (stage E, E2a): one outbox, two backends.

Backends: the reference web application (``/sync/upload-record``, signed
per event) and the separately operated portal (HMAC contract). See
:mod:`desktop.sync.client`; command line: ``python -m desktop.sync
status|retry``.
"""

from .client import (
    PushSummary,
    SyncClient,
    SyncConflictError,
    SyncIntent,
    SyncItem,
    SyncItemError,
    build_sync_item,
    prepare_sync,
    sync_after_completion,
)

__all__ = [
    "PushSummary",
    "SyncClient",
    "SyncConflictError",
    "SyncIntent",
    "SyncItem",
    "SyncItemError",
    "build_sync_item",
    "prepare_sync",
    "sync_after_completion",
]
