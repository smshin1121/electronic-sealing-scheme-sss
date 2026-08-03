"""AES-256-GCM segmented file decryption with tag verification."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
import tempfile
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import DecryptionError, TamperDetectedError
from .types import DecryptionResult

logger = logging.getLogger(__name__)

_OFFSET_SIZE = 8
_META_SIZE_FIELD = 4
_TAG_SIZE = 16
_STREAM_BUFFER = 8 * 1024 * 1024  # 8 MiB streaming buffer


def decrypt_file(
    enc_filepath: str,
    aes_key: bytes,
    output_dir: str,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    *,
    expected_sha256: Optional[str] = None,
    expected_md5: Optional[str] = None,
) -> DecryptionResult:
    """Decrypt an .enc file produced by encrypt_file.

    Reads metadata from file tail, decrypts each segment with its
    nonce and verifies its auth tag. Segments are streamed in 8 MiB
    buffers through an incremental GCM decryptor, and the plaintext
    MD5/SHA-256 hashes are computed inline during the same pass, then
    compared against a selected reference (no separate hash pass over the
    output file).

    The reference is the pair of original plaintext hashes supplied by the
    caller via ``expected_md5`` / ``expected_sha256``; otherwise it falls back
    to the copy embedded in the container metadata. An independently selected
    external reference is the stronger anchor: the
    per-segment GCM tags authenticate each segment in isolation but bind
    neither the segment order nor the whole-file digest, so an attacker who
    reorders segments and rewrites the container's own ``hash_before_*``
    fields would pass a metadata-only check. Comparing against a separately
    held reference defeats that manipulation, provided the caller has
    authenticated the reference's source.

    Plaintext is written to a temporary file (restricted permissions,
    same directory) and only moved to the final path via an atomic
    ``os.replace`` after ALL segment auth tags verified and the hash
    comparison passed. Tampered or cancelled decryptions never leave
    plaintext at the final output path.

    Args:
        enc_filepath: Path to the .enc file.
        aes_key: 32-byte AES-256 key.
        output_dir: Directory to write the decrypted file.
        progress_cb: Optional callback(completed_bytes, total_bytes),
            invoked per 8 MiB buffer (byte-level progress). Raising an
            exception from the callback cancels the decryption.
        expected_md5: Externally supplied original plaintext MD5 as a hex
            string. When provided it takes precedence over the container's
            embedded copy. The caller is responsible for authenticating its
            source. Omit (None) for utility callers with no external record.
        expected_sha256: Externally supplied original plaintext SHA-256 as a
            hex string, with the same caller responsibility as
            ``expected_md5``.

    Returns:
        DecryptionResult with verification details.

    Raises:
        DecryptionError: On decryption failure.
        TamperDetectedError: If any auth tag verification fails, the
            recovered plaintext hashes do not match the selected reference,
            or (when the record reference is supplied) the container's own
            embedded hashes disagree with the record.
    """
    _validate_inputs(enc_filepath, aes_key, output_dir)

    meta = _read_metadata(enc_filepath)
    output_path = os.path.join(output_dir, meta["filename"])

    nonces = [bytes.fromhex(n) for n in meta["nonces"]]
    tags = [bytes.fromhex(t) for t in meta["tags"]]
    chunk_lengths = meta["chunk_lengths"]
    num_chunks = len(nonces)

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    # Write plaintext to a temp file in the SAME directory (so the
    # final os.replace is atomic on the same filesystem). mkstemp
    # creates it with restricted permissions (0600 where supported).
    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix=meta["filename"] + ".", suffix=".part", dir=output_dir
    )
    os.close(tmp_fd)

    try:
        _decrypt_chunks(
            enc_filepath=enc_filepath,
            output_path=tmp_path,
            aes_key=aes_key,
            nonces=nonces,
            tags=tags,
            chunk_lengths=chunk_lengths,
            num_chunks=num_chunks,
            total_original_size=meta["size"],
            hashers=(md5, sha256),
            progress_cb=progress_cb,
        )

        # Choose the reference hashes for the integrity gate. An externally
        # supplied reference is independent of the container's embedded copy,
        # which travels inside the .enc and can be rewritten by an attacker
        # who reorders or edits ciphertext. The caller is responsible for
        # authenticating the external record from which expected_* is read.
        # Utility callers with no external record fall back to the container
        # metadata (unchanged legacy, fail-closed behavior).
        meta_md5 = meta.get("hash_before_md5")
        meta_sha256 = meta.get("hash_before_sha256")
        external_reference_supplied = (
            expected_md5 is not None or expected_sha256 is not None
        )
        ref_md5 = expected_md5 if expected_md5 is not None else meta_md5
        ref_sha256 = (
            expected_sha256 if expected_sha256 is not None else meta_sha256
        )

        # Verify hashes computed inline during decryption BEFORE the
        # plaintext is exposed at the final path.
        md5_match, sha256_match = _compare_hashes(
            md5.hexdigest(),
            sha256.hexdigest(),
            ref_md5,
            ref_sha256,
        )

        # When an external record supplied the reference, additionally
        # cross-check the container's self-declared hashes against it: a
        # container whose embedded hash disagrees with the record has been
        # altered, even if the recovered plaintext happens to match the
        # record. A container that merely omits its copy is still covered by
        # the record, so an absent (None) embedded hash is not a conflict.
        container_consistent = True
        if external_reference_supplied:
            if (
                expected_sha256 is not None
                and meta_sha256 is not None
                and meta_sha256 != expected_sha256
            ):
                container_consistent = False
            if (
                expected_md5 is not None
                and meta_md5 is not None
                and meta_md5 != expected_md5
            ):
                container_consistent = False
            if not container_consistent:
                logger.error(
                    "Container metadata hash disagrees with the external "
                    "record reference: the .enc container may have been altered"
                )

        if not (md5_match and sha256_match and container_consistent):
            reference = (
                "the external record reference"
                if external_reference_supplied
                else "metadata"
            )
            raise TamperDetectedError(
                f"Plaintext hash mismatch against {reference}: "
                "data or metadata may have been tampered with"
            )

        # All tags verified + hashes match — atomically publish.
        os.replace(tmp_path, output_path)
    except TamperDetectedError:
        _cleanup_partial(tmp_path)
        raise
    except DecryptionError:
        _cleanup_partial(tmp_path)
        raise
    except Exception as exc:
        _cleanup_partial(tmp_path)
        raise DecryptionError(f"Decryption failed: {exc}") from exc

    return DecryptionResult(
        output_filepath=output_path,
        original_filename=meta["filename"],
        hash_verified=md5_match and sha256_match,
        sha256_match=sha256_match,
        md5_match=md5_match,
        metadata=meta,
    )


def _validate_inputs(
    enc_filepath: str, aes_key: bytes, output_dir: str
) -> None:
    """Validate decryption inputs."""
    if not os.path.isfile(enc_filepath):
        raise DecryptionError(f"Encrypted file not found: {enc_filepath}")
    if len(aes_key) != 32:
        raise DecryptionError(f"AES key must be 32 bytes, got {len(aes_key)}")
    if not os.path.isdir(output_dir):
        raise DecryptionError(f"Output directory not found: {output_dir}")


def _read_metadata(enc_filepath: str) -> dict:
    """Read and parse metadata JSON from the .enc file tail.

    Reads the last 4 bytes for meta_size, then reads the JSON block.
    Also reads the first 8 bytes for offset verification.
    """
    try:
        file_size = os.path.getsize(enc_filepath)
        if file_size < _OFFSET_SIZE + _META_SIZE_FIELD:
            raise DecryptionError("File too small to be a valid .enc file")

        with open(enc_filepath, "rb") as f:
            # Read offset from header
            offset_bytes = f.read(_OFFSET_SIZE)
            meta_offset = struct.unpack("<Q", offset_bytes)[0]

            # Read meta_size from tail
            f.seek(file_size - _META_SIZE_FIELD)
            meta_size_bytes = f.read(_META_SIZE_FIELD)
            meta_size = struct.unpack("<I", meta_size_bytes)[0]

            # Validate offset
            expected_offset = file_size - _META_SIZE_FIELD - meta_size
            if meta_offset != expected_offset:
                raise DecryptionError(
                    f"Metadata offset mismatch: header={meta_offset}, "
                    f"calculated={expected_offset}"
                )

            # Read metadata JSON
            f.seek(meta_offset)
            meta_json = f.read(meta_size)

        return json.loads(meta_json.decode("utf-8"))

    except (json.JSONDecodeError, struct.error) as exc:
        raise DecryptionError(f"Failed to parse metadata: {exc}") from exc
    except DecryptionError:
        raise
    except OSError as exc:
        raise DecryptionError(f"Failed to read .enc file: {exc}") from exc


def _decrypt_chunks(
    *,
    enc_filepath: str,
    output_path: str,
    aes_key: bytes,
    nonces: list[bytes],
    tags: list[bytes],
    chunk_lengths: list[int],
    num_chunks: int,
    total_original_size: int,
    hashers: Optional[tuple[hashlib._Hash, hashlib._Hash]],
    progress_cb: Optional[Callable[[int, int], None]],
) -> None:
    """Decrypt all chunks and write to output file, streaming buffers.

    Each chunk is decrypted with an incremental GCM decryptor bound to
    the stored (nonce, tag) pair; ``finalize()`` performs the GCM tag
    verification. The tag read from the file is additionally compared
    against the stored tag to detect tampering of the trailing bytes.
    """
    completed_bytes = 0

    with open(enc_filepath, "rb") as src:
        src.seek(_OFFSET_SIZE)  # skip the 8-byte offset header

        with open(output_path, "wb") as dst:
            for i in range(num_chunks):
                stored_tag = tags[i]
                decryptor = Cipher(
                    algorithms.AES(aes_key), modes.GCM(nonces[i], stored_tag)
                ).decryptor()

                remaining = chunk_lengths[i]
                while remaining > 0:
                    to_read = min(_STREAM_BUFFER, remaining)
                    ciphertext = src.read(to_read)
                    if not ciphertext:
                        raise DecryptionError(
                            f"Unexpected EOF in chunk {i} of {enc_filepath}"
                        )
                    plaintext = decryptor.update(ciphertext)
                    if hashers is not None:
                        hashers[0].update(plaintext)
                        hashers[1].update(plaintext)
                    dst.write(plaintext)
                    completed_bytes += len(plaintext)
                    remaining -= len(ciphertext)

                    # Byte-level progress + cancellation point (mid-chunk)
                    if remaining > 0 and progress_cb is not None:
                        progress_cb(completed_bytes, total_original_size)

                # Verify the stored tag matches the tag in the file
                actual_tag = src.read(_TAG_SIZE)
                if actual_tag != stored_tag:
                    raise TamperDetectedError(
                        f"Auth tag mismatch at chunk {i}: "
                        f"data may have been tampered with"
                    )

                try:
                    final = decryptor.finalize()
                except Exception as exc:
                    raise TamperDetectedError(
                        f"GCM decryption failed at chunk {i}: {exc}"
                    ) from exc
                if final:
                    if hashers is not None:
                        hashers[0].update(final)
                        hashers[1].update(final)
                    dst.write(final)
                    completed_bytes += len(final)

                if progress_cb is not None:
                    progress_cb(completed_bytes, total_original_size)


def _compare_hashes(
    actual_md5: str,
    actual_sha256: str,
    expected_md5: Optional[str],
    expected_sha256: Optional[str],
) -> tuple[bool, bool]:
    """Compare inline-computed hashes against the expected originals.

    Fail-closed: ``encrypt_file`` always records both plaintext hashes in
    the container metadata, so a missing expected value means the
    metadata was truncated or rewritten. Treating that as a match would
    let an attacker disable integrity verification simply by deleting the
    fields, so an absent expected hash counts as a mismatch.
    """
    if expected_md5 is None:
        logger.error("Expected MD5 absent from container metadata")
    if expected_sha256 is None:
        logger.error("Expected SHA-256 absent from container metadata")

    md5_match = (expected_md5 is not None) and (actual_md5 == expected_md5)
    sha256_match = (
        expected_sha256 is not None
    ) and (actual_sha256 == expected_sha256)

    if not md5_match:
        logger.error(
            "MD5 mismatch: expected=%s, actual=%s", expected_md5, actual_md5
        )
    if not sha256_match:
        logger.error(
            "SHA-256 mismatch: expected=%s, actual=%s",
            expected_sha256, actual_sha256,
        )

    return md5_match, sha256_match


def _cleanup_partial(path: str) -> None:
    """Remove partially decrypted file."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        logger.warning("Failed to clean up partial file: %s", path)
