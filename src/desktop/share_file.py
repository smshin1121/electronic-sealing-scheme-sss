"""Share files handed out after a key split (stage E, E1b).

Share 1 goes to the subject of the seizure and share 2 to the investigator.
Each is saved to its own file in the format of the portal's share-file
contract (portal sync interface contract, section 5): one UTF-8 line ``N-<hex>`` plus a
newline, at most 4 KB, extension ``.share``.

A file is written to a temporary file in the target directory and synced,
then published under the chosen name without ever replacing an existing
file (Windows: rename; elsewhere: hard link, or ``O_CREAT | O_EXCL`` where
the file system has no hard links), read back and compared. The temporary
file is removed afterwards; a removal the operating system refuses does not
undo a verified save, but is logged with the file name and reported in
:attr:`SavedShare.temp_left`. Share text never appears in a log record or an
error message; one INFO line per saved share names the index and the
fingerprint.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Union

logger = logging.getLogger(__name__)

SHARE_FILE_SUFFIX = ".share"
SHARE_FILE_MAX_BYTES = 4096
# Handed out: 1 = subject of the seizure, 2 = investigator (3/4 stay wrapped).
_ROLES = {1: "subject", 2: "investigator"}
# Contract §5 (^[1-4]-[0-9a-fA-F]+$); shares are generated in lower case.
_SHARE_RE = re.compile(r"[1-4]-[0-9a-f]{1,128}")
# Windows: os.rename never replaces an existing file (FileExistsError).
# Elsewhere rename would replace it, so a hard link or O_EXCL is used.
_RENAME_PUBLISH = os.name == "nt"
_EXCL_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)

PathLike = Union[str, "os.PathLike[str]"]


@dataclass(frozen=True)
class SavedShare:
    """A share file that was written and read back.

    Attributes:
        index: 1 (subject) or 2 (investigator).
        path: Where the file was saved.
        fingerprint: :func:`fingerprint_of` the share (not the share).
        temp_left: Normally empty. The path of a temporary copy of the share
            that the operating system refused to delete after the save; the
            operator must delete it.
    """

    index: int
    path: str
    fingerprint: str
    temp_left: str = ""


class ShareFileError(Exception):
    """A share file was not written. The message never contains the share.

    Attributes:
        reason: ``format``, ``index``, ``extension``, ``same_path``,
            ``exists``, ``io`` or ``verify``.
        path: The path that was chosen.
        detail: The operating-system message for ``io``.
    """

    def __init__(self, reason: str, path: str = "", detail: str = "") -> None:
        message = f"share file not written ({reason}): {path}"
        super().__init__(f"{message}: {detail}" if detail else message)
        self.reason = reason
        self.path = path
        self.detail = detail


def fingerprint_of(share: str) -> str:
    """Display fingerprint of a share: the first 16 hex of its SHA-256.

    Share contents are never shown: in strict mode K = R xor X, so any
    visible prefixes of s1 (R) and of s2-s4 (X) XOR to key bytes.
    """
    return hashlib.sha256(share.encode("utf-8")).hexdigest()[:16]


def default_share_filename(seal_id: str, index: int) -> str:
    """``<seal_id>_share1_subject.share`` / ``<seal_id>_share2_investigator.share``.

    The seal_id is checked here as well (defence in depth): the sealing
    record format (S4) and the plain-token checks at R1 and U3 already
    refuse anything else before a wizard gets here. Without a seal_id the
    name is ``share1_subject.share`` / ``share2_investigator.share``.

    Raises:
        ValueError: For a share other than 1 or 2, or a seal_id that is not
            a plain token (letters, digits and hyphens; see
            :func:`desktop.record.is_safe_seal_id`).
    """
    from .record.record_builder import is_safe_seal_id

    if index not in _ROLES:
        raise ValueError(f"only shares 1 and 2 are handed out, not {index}")
    name = f"share{index}_{_ROLES[index]}{SHARE_FILE_SUFFIX}"
    if seal_id == "":
        return name
    if not is_safe_seal_id(seal_id):
        raise ValueError(f"seal_id is not a plain token: {seal_id!r}")
    return f"{seal_id}_{name}"


def share_file_bytes(share: str, index: int) -> bytes:
    """The file content for ``share``: ``N-<hex>`` and a newline.

    Raises:
        ShareFileError: ``format`` for anything but a share line, ``index``
            when the share does not carry ``index``.
    """
    if not isinstance(share, str) or not _SHARE_RE.fullmatch(share):
        raise ShareFileError("format")
    if not share.startswith(f"{index}-"):
        raise ShareFileError("index")
    data = f"{share}\n".encode("utf-8")
    if len(data) > SHARE_FILE_MAX_BYTES:
        raise ShareFileError("format")
    return data


def write_share_file(
    path: PathLike,
    share: str,
    *,
    index: int,
    taken_paths: Iterable[PathLike] = (),
) -> SavedShare:
    """Save one share to a new file and verify it by reading it back.

    Args:
        path: The file chosen by the operator; it must end in ``.share`` and
            must not exist yet.
        share: The share line, ``N-<hex>``.
        index: The share the file is for (1 or 2); the share must carry it.
        taken_paths: Files already chosen for the other share (refused).

    Returns:
        The saved file, with the share's fingerprint.

    Raises:
        ShareFileError: Nothing was written (or the written file failed its
            read-back and was removed); ``reason`` names why. ``exists`` also
            covers a name taken between the check and the publish.
    """
    target = Path(path)
    data = share_file_bytes(share, index)
    if target.suffix.lower() != SHARE_FILE_SUFFIX:
        raise ShareFileError("extension", str(target))
    if _same_file_name(target, taken_paths):
        raise ShareFileError("same_path", str(target))
    if _target_exists(target):
        raise ShareFileError("exists", str(target))
    tmp = _write_temp(target, data)
    try:
        _publish(tmp, target, data)
        _verify(target, data)  # the save stands or falls on the target alone
    finally:
        removed = _remove_quietly(tmp)  # best effort, after the verdict
    fingerprint = fingerprint_of(share)
    logger.info("Share %d saved to a file (fingerprint %s)", index, fingerprint)
    return SavedShare(
        index=index, path=str(target), fingerprint=fingerprint,
        temp_left="" if removed else str(tmp),
    )


def _same_file_name(target: Path, taken_paths: Iterable[PathLike]) -> bool:
    key = _path_key(target)
    return any(_path_key(Path(other)) == key for other in taken_paths)


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.realpath(path))


def _target_exists(path: Path) -> bool:
    """Early check only; the publish itself never replaces (patched in tests)."""
    return os.path.lexists(path)


def _write_temp(target: Path, data: bytes) -> Path:
    """The share in a synced temporary file in the target directory."""
    try:
        fd, tmp = tempfile.mkstemp(
            dir=str(target.parent), prefix=".share-", suffix=".tmp"
        )
    except OSError as exc:
        raise ShareFileError("io", str(target), exc.strerror or "") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        _remove_quietly(Path(tmp))
        raise ShareFileError("io", str(target), exc.strerror or "") from exc
    return Path(tmp)


def _publish(tmp: Path, target: Path, data: bytes) -> None:
    """Put the share at ``target``; never replace an existing file.

    Raises:
        ShareFileError: ``exists`` when the name is taken, also when it was
            taken after the early check; ``io`` for other failures.
    """
    try:
        if _RENAME_PUBLISH:
            os.rename(tmp, target)  # Windows: FileExistsError if it exists
        else:
            _publish_by_link(str(tmp), str(target), data)
    except FileExistsError as exc:
        raise ShareFileError("exists", str(target)) from exc
    except OSError as exc:
        raise ShareFileError("io", str(target), exc.strerror or "") from exc


def _publish_by_link(tmp: str, target: str, data: bytes) -> None:
    """POSIX publish: a hard link fails atomically if ``target`` exists.

    On a file system without hard links (e.g. FAT/exFAT media) the name is
    claimed with ``O_CREAT | O_EXCL``, which is atomic as well, and ``data``
    is written through that descriptor. The temporary file stays for the
    caller to remove.
    """
    try:
        os.link(tmp, target)
        return
    except FileExistsError:
        raise
    except OSError:
        pass  # no hard links here; claim the name instead
    _claim_and_write(target, data)


def _claim_and_write(target: str, data: bytes) -> None:
    """Create ``target`` exclusively and write ``data`` through it."""
    fd = os.open(target, _EXCL_FLAGS, 0o600)  # FileExistsError if taken
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        _remove_quietly(Path(target))  # created above: ours to remove
        raise


def _verify(target: Path, data: bytes) -> None:
    """Read the published file back; remove it and refuse on a mismatch."""
    try:
        written = _read_back(target)
    except OSError as exc:
        written = b""
        logger.warning("Share file read-back failed: %s", exc.strerror)
    if written != data:
        _remove_quietly(target)
        raise ShareFileError("verify", str(target))


def _read_back(path: Path) -> bytes:
    """The saved bytes, read fresh from the file (patched in tests)."""
    return path.read_bytes()


def _remove_quietly(path: Path) -> bool:
    """Delete ``path`` if present. False (and a warning) when it stays."""
    try:
        path.unlink()
    except FileNotFoundError:
        return True
    except OSError as exc:
        logger.warning("Share file copy not removed: %s (%s)", path, exc.strerror)
        return False
    return True
