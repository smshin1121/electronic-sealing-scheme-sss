"""Fallback classification of files for resealing (R2).

Used by :meth:`desktop.reseal_process.ResealProcess.run_r2_compare` only
when :func:`desktop.record.identify_unknown_files` cannot be imported.
Moved unchanged out of ``reseal_process.py`` (stage E, E1) to keep that
module under 800 lines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _sha256_of_file(filepath: Path) -> str:
    """Compute the SHA-256 hex digest of a file with 8 MiB reads."""
    import hashlib

    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _suggest_category(filepath: Path, size: int) -> str:
    """Suggest a fallback classification category for an unknown file."""
    ext = filepath.suffix.lower()
    if ext in (".log", ".txt"):
        return "analysis_log"
    if ext in (".pdf", ".docx", ".xlsx"):
        return "report"
    if size < 1024:
        return "small_artifact"
    if size > 100 * 1024 * 1024:
        return "large_artifact"
    return "uncategorized"


def _fallback_classify(
    prev_record: dict[str, Any],
    target_dir: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Simple fallback file classification when record module is unavailable.

    A hash can only match a known file when the sizes match, so files
    whose size matches no known file are classified unknown without
    hashing (size pre-filter). Size-matching candidates are hashed in
    parallel (hashlib releases the GIL for large buffers).
    """
    from concurrent.futures import ThreadPoolExecutor

    # Build known hash / size sets from the previous record
    known_hashes: set[str] = set()
    known_sizes: set[int] = set()
    sizes_complete = True

    def _register_known(entry: dict[str, Any]) -> None:
        nonlocal sizes_complete
        if entry.get("sha256"):
            known_hashes.add(entry["sha256"])
            if isinstance(entry.get("size"), int):
                known_sizes.add(entry["size"])
            else:
                # Legacy record without size: the pre-filter would
                # misclassify, so fall back to hashing every file.
                sizes_complete = False

    _register_known(prev_record.get("original_file", {}))
    file_info = prev_record.get("file_info", {})
    for f in file_info.get("original_files", []):
        _register_known(f)

    known_files: list[dict[str, Any]] = []
    unknown_files: list[dict[str, Any]] = []

    target = Path(target_dir)
    if not target.exists():
        return known_files, unknown_files

    # Single stat per file, cached alongside the path
    candidates: list[tuple[Path, int]] = [
        (fp, fp.stat().st_size)
        for fp in sorted(target.rglob("*"))
        if fp.is_file()
    ]

    # Size pre-filter: only size-matching files can be known -> hash them
    if sizes_complete:
        to_hash = [
            (fp, size) for fp, size in candidates if size in known_sizes
        ]
    else:
        to_hash = candidates

    hashes: dict[Path, str] = {}
    if to_hash:
        with ThreadPoolExecutor(max_workers=4) as pool:
            digests = pool.map(_sha256_of_file, (fp for fp, _ in to_hash))
            hashes = {fp: digest for (fp, _), digest in zip(to_hash, digests)}

    for filepath, size in candidates:
        file_hash = hashes.get(filepath, "")
        file_entry = {
            "filepath": str(filepath),
            "filename": filepath.name,
            "size": size,
            "sha256": file_hash,
        }

        if file_hash and file_hash in known_hashes:
            known_files.append(file_entry)
        else:
            file_entry["suggested_category"] = _suggest_category(
                filepath, size
            )
            unknown_files.append(file_entry)

    return known_files, unknown_files
