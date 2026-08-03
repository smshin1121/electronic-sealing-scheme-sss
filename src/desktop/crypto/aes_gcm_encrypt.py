"""AES-256-GCM segmented file encryption with resume support."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import struct
from datetime import datetime, timezone
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import EncryptionError
from .file_metadata import _timestamp_to_iso, collect_metadata
from .types import EncryptionResult, FileMetadata

logger = logging.getLogger(__name__)

# GCM can authenticate at most 2^39 - 256 bits (64 GiB - 32 B) of plaintext
# per (key, nonce). Keep a 16 MiB safety margin below that hard limit.
_GCM_SAFETY_MARGIN = 16 * 1024 * 1024   # 16 MiB
_MIN_CHUNK_SIZE = 1 * 1024**3           # 1 GiB
_MAX_CHUNK_SIZE = 64 * 1024**3 - _GCM_SAFETY_MARGIN  # 64 GiB - 16 MiB
# 1 GiB is the default: it is the fastest configuration at the largest
# measured input (where the workload is I/O-bound) and gives the finest
# resume granularity, at no measurable memory cost.
_DEFAULT_CHUNK_SIZE = _MIN_CHUNK_SIZE
_OFFSET_SIZE = 8                        # bytes (uint64 LE)
_META_SIZE_FIELD = 4                    # bytes (uint32 LE)
_NONCE_SIZE = 12
_TAG_SIZE = 16
_STREAM_BUFFER = 8 * 1024 * 1024        # 8 MiB streaming buffer

# Public aliases for orchestrators (seal/reseal) that need to clamp
# user-configured chunk sizes to the allowed range.
MIN_CHUNK_SIZE = _MIN_CHUNK_SIZE
MAX_CHUNK_SIZE = _MAX_CHUNK_SIZE
DEFAULT_CHUNK_SIZE = _DEFAULT_CHUNK_SIZE


def encrypt_file(
    filepath: str,
    aes_key: bytes,
    output_path: str,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    seal_id: str = "",
    metadata: Optional[FileMetadata] = None,
) -> EncryptionResult:
    """Encrypt a file using AES-256-GCM with segmented processing.

    Each segment gets an independent nonce and produces an auth tag.
    The output .enc file structure:
        [8B offset LE] [encrypted data] [JSON metadata] [4B meta_size LE]

    Encryption streams the plaintext in 8 MiB buffers through an
    incremental GCM encryptor, so memory usage stays constant even for
    multi-gigabyte segments. The ciphertext and tag are byte-identical
    to a one-shot ``AESGCM.encrypt`` call, keeping the .enc format
    unchanged.

    Supports resume via .enc.progress file.

    Args:
        filepath: Path to the source file.
        aes_key: 32-byte AES-256 key.
        output_path: Path for the output .enc file.
        chunk_size: Segment size in bytes (1 GiB .. 64 GiB - 16 MiB,
            default 64 GiB - 16 MiB).
        progress_cb: Optional callback(completed_bytes, total_bytes),
            invoked per 8 MiB buffer (byte-level progress). Raising an
            exception from the callback cancels the encryption; the
            .enc.progress file of completed segments is preserved.
        seal_id: Optional seal identifier for metadata.
        metadata: Optional pre-collected FileMetadata. When provided,
            the internal hash pass is skipped entirely; when omitted,
            MD5/SHA-256 are computed inline during the encryption read
            (single pass over the source file).

    Returns:
        EncryptionResult with encryption details.

    Raises:
        EncryptionError: On any encryption failure.
    """
    _validate_inputs(filepath, aes_key, chunk_size)

    file_stat = os.stat(filepath)
    file_size = file_stat.st_size
    num_chunks = max(1, math.ceil(file_size / chunk_size))
    progress_path = output_path + ".progress"

    # Bind the progress file to this exact source file so a resume can
    # never continue onto a *different* (renamed/modified) source.
    source_binding = {
        "source_path": _normalize_source_path(filepath),
        "source_size": file_size,
        "source_mtime_ns": file_stat.st_mtime_ns,
    }

    # Load resume state if available
    resume = _load_progress(
        progress_path, filepath, chunk_size,
        aes_key=aes_key, output_path=output_path,
        source_binding=source_binding,
    )
    start_chunk = resume["completed_chunks"] if resume else 0
    nonces: list[str] = resume["nonces"][:] if resume else []
    tags: list[str] = resume["tags"][:] if resume else []
    chunk_lengths: list[int] = resume["chunk_lengths"][:] if resume else []

    # Hash strategy: inline single-pass hashing during encryption when
    # possible. On resume the already-encrypted prefix is skipped, so a
    # separate full hash pass is required instead.
    hashers: Optional[tuple[hashlib._Hash, hashlib._Hash]] = None
    if metadata is None:
        if start_chunk > 0:
            try:
                metadata = collect_metadata(filepath)
            except Exception as exc:
                raise EncryptionError(
                    f"Metadata collection failed: {exc}"
                ) from exc
        else:
            hashers = (hashlib.md5(), hashlib.sha256())

    try:
        _write_encrypted_data(
            filepath=filepath,
            output_path=output_path,
            aes_key=aes_key,
            file_size=file_size,
            chunk_size=chunk_size,
            num_chunks=num_chunks,
            start_chunk=start_chunk,
            nonces=nonces,
            tags=tags,
            chunk_lengths=chunk_lengths,
            progress_path=progress_path,
            progress_cb=progress_cb,
            hashers=hashers,
            source_binding=source_binding,
        )

        if metadata is None:
            assert hashers is not None
            metadata = FileMetadata(
                filename=os.path.basename(filepath),
                size=file_size,
                md5=hashers[0].hexdigest(),
                sha256=hashers[1].hexdigest(),
                mtime=_timestamp_to_iso(file_stat.st_mtime),
                ctime=_timestamp_to_iso(file_stat.st_ctime),
                atime=_timestamp_to_iso(file_stat.st_atime),
            )

        _write_metadata_and_finalize(
            output_path=output_path,
            metadata=metadata,
            nonces=nonces,
            tags=tags,
            chunk_lengths=chunk_lengths,
            seal_id=seal_id,
        )

        # Clean up progress file on success
        if os.path.exists(progress_path):
            os.remove(progress_path)

    except EncryptionError:
        raise
    except Exception as exc:
        raise EncryptionError(f"Encryption failed: {exc}") from exc

    return EncryptionResult(
        enc_filepath=output_path,
        original_filepath=filepath,
        metadata=metadata,
        chunk_count=num_chunks,
    )


def _validate_inputs(filepath: str, aes_key: bytes, chunk_size: int) -> None:
    """Validate encryption inputs."""
    if not os.path.isfile(filepath):
        raise EncryptionError(f"Source file not found: {filepath}")
    if len(aes_key) != 32:
        raise EncryptionError(f"AES key must be 32 bytes, got {len(aes_key)}")
    if not (_MIN_CHUNK_SIZE <= chunk_size <= _MAX_CHUNK_SIZE):
        raise EncryptionError(
            f"chunk_size must be between {_MIN_CHUNK_SIZE} and {_MAX_CHUNK_SIZE}"
        )


def _write_encrypted_data(
    *,
    filepath: str,
    output_path: str,
    aes_key: bytes,
    file_size: int,
    chunk_size: int,
    num_chunks: int,
    start_chunk: int,
    nonces: list[str],
    tags: list[str],
    chunk_lengths: list[int],
    progress_path: str,
    progress_cb: Optional[Callable[[int, int], None]],
    hashers: Optional[tuple[hashlib._Hash, hashlib._Hash]] = None,
    source_binding: Optional[dict] = None,
) -> None:
    """Encrypt file data chunk by chunk, streaming 8 MiB buffers.

    Each chunk uses an incremental GCM encryptor so only one buffer is
    resident in memory at a time. ``progress_cb`` fires per buffer; at
    chunk boundaries the .enc.progress file is saved *before* the
    callback so a cancellation never loses a completed segment.
    """
    # Calculate write position for resume
    data_offset = _OFFSET_SIZE  # skip the 8-byte offset header
    for cl in chunk_lengths:
        data_offset += cl + _TAG_SIZE  # each chunk produces ciphertext + tag

    mode = "r+b" if (start_chunk > 0 and os.path.exists(output_path)) else "wb"

    with open(filepath, "rb") as src:
        with open(output_path, mode) as dst:
            if mode == "wb":
                # Write placeholder offset (will be updated later)
                dst.write(struct.pack("<Q", 0))
            else:
                dst.seek(data_offset)

            # Seek source to the right position
            src.seek(start_chunk * chunk_size)
            completed_bytes = start_chunk * chunk_size

            for chunk_idx in range(start_chunk, num_chunks):
                remaining = file_size - (chunk_idx * chunk_size)
                current_chunk_size = min(chunk_size, remaining)

                nonce = os.urandom(_NONCE_SIZE)
                encryptor = Cipher(
                    algorithms.AES(aes_key), modes.GCM(nonce)
                ).encryptor()

                ciphertext_len = 0
                chunk_done = 0
                while chunk_done < current_chunk_size:
                    to_read = min(
                        _STREAM_BUFFER, current_chunk_size - chunk_done
                    )
                    plaintext = src.read(to_read)
                    if not plaintext:
                        raise EncryptionError(
                            f"Unexpected EOF while reading {filepath}"
                        )
                    if hashers is not None:
                        hashers[0].update(plaintext)
                        hashers[1].update(plaintext)

                    ciphertext = encryptor.update(plaintext)
                    dst.write(ciphertext)
                    ciphertext_len += len(ciphertext)
                    chunk_done += len(plaintext)
                    completed_bytes += len(plaintext)

                    # Byte-level progress + cancellation point (mid-chunk)
                    if chunk_done < current_chunk_size and progress_cb is not None:
                        progress_cb(completed_bytes, file_size)

                final_ct = encryptor.finalize()
                if final_ct:
                    dst.write(final_ct)
                    ciphertext_len += len(final_ct)
                tag = encryptor.tag
                dst.write(tag)

                nonces.append(nonce.hex())
                tags.append(tag.hex())
                chunk_lengths.append(ciphertext_len)

                # Save progress after each chunk (before the callback so a
                # cancellation raised there never loses this segment)
                _save_progress(
                    progress_path, filepath, chunk_size,
                    len(nonces), nonces, tags, chunk_lengths,
                    key_fingerprint=_key_fingerprint(aes_key),
                    source_binding=source_binding or {},
                )

                if progress_cb is not None:
                    progress_cb(completed_bytes, file_size)


def _write_metadata_and_finalize(
    *,
    output_path: str,
    metadata: FileMetadata,
    nonces: list[str],
    tags: list[str],
    chunk_lengths: list[int],
    seal_id: str,
) -> None:
    """Write JSON metadata and update the offset header."""
    meta_dict = {
        "filename": metadata.filename,
        "size": metadata.size,
        "encryption_algo": "AES-256-GCM",
        "mtime": metadata.mtime,
        "ctime": metadata.ctime,
        "atime": metadata.atime,
        "enc_ended_time": datetime.now(tz=timezone.utc).isoformat(),
        "seal_id": seal_id,
        "nonces": nonces,
        "tags": tags,
        "chunk_lengths": chunk_lengths,
        "hash_before_sha256": metadata.sha256,
        "hash_before_md5": metadata.md5,
    }

    meta_json = json.dumps(meta_dict, ensure_ascii=False).encode("utf-8")
    meta_size = len(meta_json)

    with open(output_path, "r+b") as f:
        # Find current end of encrypted data
        f.seek(0, 2)
        meta_offset = f.tell()

        # Write metadata JSON
        f.write(meta_json)

        # Write meta_size (4 bytes LE)
        f.write(struct.pack("<I", meta_size))

        # Update offset at file start
        f.seek(0)
        f.write(struct.pack("<Q", meta_offset))


def _normalize_source_path(path: str) -> str:
    """Return a normalized absolute path for source-binding comparison."""
    return os.path.normcase(os.path.abspath(path))


def _key_fingerprint(aes_key: bytes) -> str:
    """Return a short one-way fingerprint of the AES key.

    Stored in the .enc.progress file so a resume attempt with a
    *different* key (e.g. a retry that regenerated the key) is detected
    and rejected instead of appending chunks encrypted under a second
    key — which would make the earlier chunks permanently undecryptable.
    The fingerprint is a truncated SHA-256 digest; the key itself is
    never written or logged.
    """
    return hashlib.sha256(aes_key).hexdigest()[:16]


def _discard_partial(progress_path: str, output_path: Optional[str]) -> None:
    """Delete a stale progress file and (optionally) the partial .enc.

    Failures are logged only — a leftover file must never abort the
    fresh re-encryption that follows.
    """
    for path in (progress_path, output_path):
        if not path:
            continue
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError as exc:
            logger.warning("Failed to remove stale file %s: %s", path, exc)


def _save_progress(
    path: str,
    target_file: str,
    chunk_size: int,
    completed_chunks: int,
    nonces: list[str],
    tags: list[str],
    chunk_lengths: list[int],
    *,
    key_fingerprint: str,
    source_binding: Optional[dict] = None,
) -> None:
    """Save encryption progress to a JSON file.

    ``source_binding`` carries the normalized source path, size, and
    mtime_ns captured at encryption start so a later resume can verify
    it targets the exact same source content.
    """
    progress = {
        "target_file": os.path.basename(target_file),
        "completed_chunks": completed_chunks,
        "chunk_size": chunk_size,
        "key_fingerprint": key_fingerprint,
        "nonces": nonces,
        "tags": tags,
        "chunk_lengths": chunk_lengths,
        **(source_binding or {}),
    }
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(progress, f)
    os.replace(tmp_path, path)


def _load_progress(
    path: str,
    target_file: str,
    chunk_size: int,
    *,
    aes_key: bytes,
    output_path: str,
    source_binding: Optional[dict] = None,
) -> Optional[dict]:
    """Load resume progress if valid. Returns None if no valid progress.

    Beyond basic parameter matching, this enforces three safety guards:

    1. Source binding — the progress file must carry the normalized
       path, size, and mtime_ns of the *same* source file being
       encrypted now. A mismatching or missing binding (legacy progress
       file) discards both the progress file and the partial .enc so
       encryption restarts from scratch. Resuming onto a renamed or
       modified source would splice ciphertext of different plaintexts
       into one .enc.
    2. Key fingerprint — the progress file must carry the fingerprint of
       the *same* AES key being used now. A mismatching or missing
       fingerprint (legacy progress file) discards both the progress
       file and the partial .enc so encryption restarts from scratch
       with a single key. Mixing keys across chunks would leave the
       earlier chunks permanently undecryptable.
    3. Output consistency — completed_chunks must be structurally sane
       (0 <= completed <= num_chunks) and the partial .enc must exist
       and be at least as large as the completed chunks claim.
       Otherwise the progress file is orphaned/stale and resume is
       refused.

    Note: the completed chunks' plaintext is NOT re-hashed on resume —
    the size/mtime_ns binding is the tamper/change signal for the
    source side, and the GCM tags cover the ciphertext side.
    """
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            progress = json.load(f)

        if (
            progress.get("target_file") != os.path.basename(target_file)
            or progress.get("chunk_size") != chunk_size
        ):
            logger.warning("Progress file mismatch, starting fresh")
            return None

        required = ["completed_chunks", "nonces", "tags", "chunk_lengths"]
        if not all(k in progress for k in required):
            return None

        # Guard 1: source binding (normalized path + size + mtime_ns)
        # must match the current source file. Missing fields (legacy
        # progress file) cannot prove the source is unchanged — discard.
        expected_binding = source_binding or {}
        for field in ("source_path", "source_size", "source_mtime_ns"):
            if progress.get(field) != expected_binding.get(field):
                logger.warning(
                    "Progress file source binding mismatch or missing "
                    "(%s) — discarding partial output and restarting "
                    "fresh to avoid resuming onto a different source",
                    field,
                )
                _discard_partial(path, output_path)
                return None

        # Guard 2: key fingerprint must match the current key.
        # A missing fingerprint (legacy progress file) is also unsafe —
        # the original key cannot be verified, so discard everything.
        if progress.get("key_fingerprint") != _key_fingerprint(aes_key):
            logger.warning(
                "Progress file key fingerprint mismatch or missing — "
                "discarding partial output and restarting fresh to avoid "
                "mixed-key chunks (would be permanently undecryptable)"
            )
            _discard_partial(path, output_path)
            return None

        # Guard 3: structural sanity — completed_chunks must be an int
        # within [0, num_chunks] for this source size and chunk size.
        completed = progress["completed_chunks"]
        chunk_lengths = progress["chunk_lengths"]
        source_size = expected_binding.get(
            "source_size", os.path.getsize(target_file)
        )
        num_chunks = max(1, math.ceil(source_size / chunk_size))
        if (
            isinstance(completed, bool)
            or not isinstance(completed, int)
            or not (0 <= completed <= num_chunks)
        ):
            logger.warning(
                "Progress file completed_chunks (%r) out of range "
                "[0, %d] — discarding partial output, starting fresh",
                completed, num_chunks,
            )
            _discard_partial(path, output_path)
            return None

        # Guard 4: the partial .enc must exist and cover the completed
        # chunks recorded in the progress file.
        if completed > 0:
            if (
                completed != len(chunk_lengths)
                or completed != len(progress["nonces"])
                or completed != len(progress["tags"])
            ):
                logger.warning(
                    "Progress file internally inconsistent — starting fresh"
                )
                _discard_partial(path, None)
                return None
            expected_size = _OFFSET_SIZE + sum(
                cl + _TAG_SIZE for cl in chunk_lengths
            )
            if (
                not os.path.exists(output_path)
                or os.path.getsize(output_path) < expected_size
            ):
                logger.warning(
                    "Partial .enc missing or smaller than progress claims "
                    "(expected >= %d bytes) — refusing resume, starting fresh",
                    expected_size,
                )
                _discard_partial(path, output_path)
                return None

        return progress
    except (json.JSONDecodeError, OSError):
        logger.warning("Corrupt progress file, starting fresh")
        return None
