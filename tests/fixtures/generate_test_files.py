"""Utility for generating random binary files for testing."""

from __future__ import annotations

import os
from pathlib import Path

# Preset sizes
SIZE_1MB = 1 * 1024 * 1024
SIZE_10MB = 10 * 1024 * 1024
SIZE_100MB = 100 * 1024 * 1024

_WRITE_CHUNK = 1 * 1024 * 1024  # 1 MB write buffer


def create_random_file(path: str | Path, size_bytes: int) -> str:
    """Create a file filled with cryptographically random bytes.

    Writes in 1 MB chunks to avoid allocating the entire buffer at once
    for large files.

    Args:
        path: Destination file path.
        size_bytes: Desired file size in bytes (must be > 0).

    Returns:
        The absolute path of the created file as a string.

    Raises:
        ValueError: If size_bytes is not positive.
        OSError: If file creation fails.
    """
    if size_bytes <= 0:
        raise ValueError(f"size_bytes must be positive, got {size_bytes}")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    remaining = size_bytes
    with open(path, "wb") as f:
        while remaining > 0:
            chunk = min(_WRITE_CHUNK, remaining)
            f.write(os.urandom(chunk))
            remaining -= chunk

    return str(path.resolve())
