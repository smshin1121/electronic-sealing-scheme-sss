"""Unknown file identification for resealing procedures.

Compares the current directory contents against the previous record's
file list to identify files that were not present during the last seal.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from .exceptions import UnknownClassificationError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HASH_BUFFER_SIZE = 8 * 1024 * 1024  # 8 MB read buffer

# Extension-based category hints for classification suggestions
_EXTENSION_CATEGORIES: dict[str, str] = {
    # Analysis / forensic artifacts
    ".log": "analysis_log",
    ".txt": "analysis_note",
    ".csv": "export_data",
    ".xlsx": "export_data",
    ".json": "export_data",
    ".xml": "export_data",
    ".html": "report",
    ".pdf": "report",
    # Image captures / screenshots
    ".png": "screenshot",
    ".jpg": "screenshot",
    ".jpeg": "screenshot",
    ".bmp": "screenshot",
    # Database / index files
    ".db": "analysis_database",
    ".sqlite": "analysis_database",
    ".idx": "index_file",
    # Executable / script artifacts
    ".py": "analysis_script",
    ".ps1": "analysis_script",
    ".bat": "analysis_script",
    ".sh": "analysis_script",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def identify_unknown_files(
    prev_record: dict,
    current_dir: str,
) -> tuple[list[dict], list[dict]]:
    """Identify known and unknown files by comparing against previous record.

    Walks ``current_dir`` and computes SHA-256 hashes.  Files whose
    hash matches an entry in the previous record's ``original_files``
    are classified as *known*; all others are *unknown*.

    Args:
        prev_record: The most recent seal/reseal record dict.
        current_dir: Path to the directory to scan.

    Returns:
        A tuple of ``(known_files, unknown_files)``.  Each list
        contains dicts with ``filename``, ``size``, ``sha256``,
        ``path``, and (for unknown files) ``suggested_category``.

    Raises:
        UnknownClassificationError: If the directory is invalid or
            the previous record is missing file information.
    """
    if not os.path.isdir(current_dir):
        raise UnknownClassificationError(
            f"Directory does not exist: {current_dir}"
        )

    prev_file_info = prev_record.get("file_info")
    if prev_file_info is None:
        raise UnknownClassificationError(
            "Previous record is missing 'file_info'"
        )

    # Build a set of known SHA-256 hashes from the previous record
    known_hashes = _build_known_hash_set(prev_file_info)

    known_files: list[dict] = []
    unknown_files: list[dict] = []

    for filepath in _walk_files(current_dir):
        file_entry = _build_file_entry(filepath, current_dir)
        if file_entry is None:
            continue

        sha = file_entry["sha256"]
        if sha in known_hashes:
            known_files.append(file_entry)
        else:
            file_entry["suggested_category"] = _suggest_category(
                file_entry["filename"],
                file_entry["size"],
                file_entry["path"],
            )
            unknown_files.append(file_entry)

    logger.info(
        "Classification result: %d known, %d unknown files in '%s'",
        len(known_files),
        len(unknown_files),
        current_dir,
    )
    return known_files, unknown_files


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_known_hash_set(file_info: dict) -> frozenset[str]:
    """Extract all SHA-256 hashes from the previous record's file lists."""
    hashes: set[str] = set()

    for f in file_info.get("original_files", []):
        sha = f.get("sha256", "")
        if sha:
            hashes.add(sha.lower())

    for f in file_info.get("derived_files", []):
        sha = f.get("sha256", "")
        if sha:
            hashes.add(sha.lower())

    return frozenset(hashes)


def _walk_files(directory: str) -> list[str]:
    """Recursively collect all file paths under a directory."""
    file_paths: list[str] = []
    for root, _dirs, files in os.walk(directory):
        for name in sorted(files):
            full_path = os.path.join(root, name)
            if os.path.isfile(full_path):
                file_paths.append(full_path)
    return file_paths


def _build_file_entry(
    filepath: str,
    base_dir: str,
) -> dict | None:
    """Build a file info dict with hash.  Returns None on read error."""
    try:
        stat = os.stat(filepath)
        sha256 = _compute_sha256(filepath)
        rel_path = os.path.relpath(filepath, base_dir)

        return {
            "filename": os.path.basename(filepath),
            "size": stat.st_size,
            "sha256": sha256,
            "path": rel_path,
            # Absolute path — consumed by ResealProcess.run_r5_encrypt and
            # the reseal wizard R3 classification (same shape as the
            # _fallback_classify entries in reseal_process).
            "filepath": os.path.abspath(filepath),
        }
    except OSError as exc:
        logger.warning("Cannot read file '%s': %s", filepath, exc)
        return None


def _compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(_HASH_BUFFER_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _suggest_category(
    filename: str,
    size: int,
    rel_path: str,
) -> str:
    """Suggest a classification category based on file attributes.

    This is a heuristic suggestion.  The investigator makes the final
    decision.
    """
    ext = Path(filename).suffix.lower()
    if ext in _EXTENSION_CATEGORIES:
        return _EXTENSION_CATEGORIES[ext]

    # Path-based heuristics
    path_lower = rel_path.lower()
    if "report" in path_lower or "output" in path_lower:
        return "report"
    if "log" in path_lower:
        return "analysis_log"
    if "export" in path_lower:
        return "export_data"
    if "temp" in path_lower or "tmp" in path_lower:
        return "temporary_artifact"

    # Size-based heuristics: very small files are likely logs/notes
    if size < 1024:
        return "small_artifact"
    if size > 100 * 1024 * 1024:
        return "large_artifact"

    return "uncategorized"
