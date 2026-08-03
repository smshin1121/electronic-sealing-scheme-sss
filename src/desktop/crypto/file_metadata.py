"""File metadata collection: hashes, size, timestamps."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from .exceptions import MetadataError
from .types import FileMetadata

_HASH_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB streaming chunks


def collect_metadata(filepath: str) -> FileMetadata:
    """Collect MD5, SHA-256, size, and timestamps for a file.

    Args:
        filepath: Absolute path to the target file.

    Returns:
        FileMetadata with all fields populated.

    Raises:
        MetadataError: If the file cannot be read or metadata cannot be collected.
    """
    if not os.path.isfile(filepath):
        raise MetadataError(f"File not found: {filepath}")

    try:
        md5_hash, sha256_hash = _compute_hashes(filepath)
        stat = os.stat(filepath)

        return FileMetadata(
            filename=os.path.basename(filepath),
            size=stat.st_size,
            md5=md5_hash,
            sha256=sha256_hash,
            mtime=_timestamp_to_iso(stat.st_mtime),
            ctime=_timestamp_to_iso(stat.st_ctime),
            atime=_timestamp_to_iso(stat.st_atime),
        )
    except OSError as exc:
        raise MetadataError(f"Failed to collect metadata for {filepath}: {exc}") from exc


def _compute_hashes(filepath: str) -> tuple[str, str]:
    """Compute MD5 and SHA-256 hashes using streaming reads.

    Returns:
        Tuple of (md5_hex, sha256_hex).
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def _timestamp_to_iso(ts: float) -> str:
    """Convert a Unix timestamp to ISO 8601 UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
