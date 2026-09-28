"""Unambiguous byte framing for digest messages and associated data."""

from __future__ import annotations

import struct


def frame(*parts: bytes) -> bytes:
    """Concatenate parts, each preceded by its 4-byte big-endian length."""
    return b"".join(struct.pack(">I", len(part)) + part for part in parts)


def utf8(text: str) -> bytes:
    """UTF-8 bytes of ``text`` (lone surrogates passed through, never lost)."""
    return text.encode("utf-8", "surrogatepass")
