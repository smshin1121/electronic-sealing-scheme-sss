"""Removal of a stored key share by an administrator, audited (stage F, gate fix).

Fable gate review of stage F, finding 1: ``key_shares`` keeps one share per
(seal, slot, generation) and the upload routes never replace it
(:mod:`web.models.share_models`). One wrong upload into the slot of a
seal's current generation (the share of an earlier generation, or garbage
from someone who passed the subject's authentication) therefore refused the
genuine share for good, and the releases that combine the stored share 1
with the new policy ended in ``commitment_mismatch``. An administrator can
now remove that row (:func:`remove_key_share`); the genuine share can then
be uploaded again.

A removal runs in one transaction under the seal's write lock
(:func:`web.models.release_models.seal_write_transaction`, the lock the
uploads and sync admission take), so it cannot interleave with an upload of
that seal. The row is deleted and its audit row (``share_removal_audit``,
:mod:`web.models.share_removal_schema`) is inserted in that transaction:
when the audit row cannot be written the transaction rolls back and nothing
is removed. The audit row keeps the SHA-256 of the removed share, never its
value. The readers here return no share value either.

A removal names the row the administrator saw (``expected_row_id``, the
row id on the share list) and removes nothing when another row occupies
the slot and generation by then (Codex review R3, finding 1: a stale form,
or a repeated POST, after the genuine share was uploaded again would
otherwise remove the genuine share). Row ids are never reused:
``key_shares.id`` is ``INTEGER PRIMARY KEY AUTOINCREMENT`` on SQLite, and
the F1 rebuild keeps its sequence (:mod:`web.models.share_schema`); on
MariaDB it is an InnoDB ``AUTO_INCREMENT`` column, whose counter persists
across restarts (MariaDB 10.2.4 and later). A share uploaded after a
removal therefore gets a new id.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from flask import g

from .db_models import execute_query, get_db
from .release_models import seal_write_transaction
from .share_models import MAX_GENERATION, SHARE_SLOTS

MAX_REASON_LENGTH = 2000

_SELECT_ROW_SQL = """SELECT id, seal_id, share_data, uploaded_by, uploaded_at FROM key_shares
                     WHERE seal_id = ? AND share_index = ? AND generation = ?"""
_DELETE_SQL = "DELETE FROM key_shares WHERE id = ?"
_AUDIT_COLUMNS = ("seal_id", "share_index", "generation", "uploaded_by",
                  "uploaded_at", "share_sha256", "operator", "reason", "removed_at")
_INSERT_AUDIT_SQL = ("INSERT INTO share_removal_audit (" + ", ".join(_AUDIT_COLUMNS)
                     + ") VALUES (" + ", ".join("?" for _ in _AUDIT_COLUMNS) + ")")


@dataclass(frozen=True)
class ShareSummary:
    """One stored share without its value (the administrator's list)."""

    row_id: int
    seal_id: str
    index: int
    generation: int
    uploaded_by: str
    uploaded_at: str


REMOVED = "removed"
NOT_FOUND = "not_found"
CHANGED = "changed"


@dataclass(frozen=True)
class ShareRemoval:
    """What :func:`remove_key_share` did (``status``): :data:`REMOVED`;
    :data:`NOT_FOUND` when no share is stored for that slot and generation;
    :data:`CHANGED` when a share other than the expected row is stored
    there. Only :data:`REMOVED` wrote anything."""

    status: str
    index: int
    generation: int
    uploaded_by: str = ""
    uploaded_at: str = ""
    share_sha256: str = ""

    @property
    def removed(self) -> bool:
        return self.status == REMOVED


def remove_key_share(
    seal_id: str, share_index: int, generation: int, *, expected_row_id: int,
    operator: str, reason: str, removed_at: str,
) -> ShareRemoval:
    """Remove the share stored for (seal, slot, generation) and audit it,
    if it is still the row ``expected_row_id``.

    Raises:
        ValueError: The slot, generation, expected row id, operator or
            reason is invalid (the reason must be non-empty, at most
            :data:`MAX_REASON_LENGTH` characters). Nothing is written.
    """
    _check(share_index, generation, expected_row_id, operator, reason)
    with seal_write_transaction(seal_id):
        row = execute_query(_SELECT_ROW_SQL, (seal_id, share_index, generation),
                            fetch_one=True)
        if row is None:
            return ShareRemoval(NOT_FOUND, share_index, generation)
        row_id, stored_seal_id, data, uploaded_by, uploaded_at = _row_values(row)
        if row_id != expected_row_id:
            return ShareRemoval(CHANGED, share_index, generation)
        removal = ShareRemoval(REMOVED, share_index, generation, uploaded_by,
                               uploaded_at, _sha256(data))
        # The audit names the seal as stored: on MariaDB the form's seal id
        # matches it case-insensitively (Fable re-check, finding 3).
        _delete_and_audit(row_id, stored_seal_id, removal, operator, reason, removed_at)
        return removal


def list_share_summaries(seal_id: str) -> tuple[ShareSummary, ...]:
    """Every stored share of the seal without its value, by slot, then
    generation (highest first)."""
    rows = execute_query(
        """SELECT id, seal_id, share_index, generation, uploaded_by, uploaded_at
           FROM key_shares WHERE seal_id = ?
           ORDER BY share_index, generation DESC""",
        (seal_id,), fetch_all=True,
    ) or []
    return tuple(ShareSummary(int(r[0]), str(r[1]), int(r[2]), int(r[3]), str(r[4]),
                              _text(r[5]))
                 for r in (_tuple(row, ("id", "seal_id", "share_index", "generation",
                                        "uploaded_by", "uploaded_at")) for row in rows))


def find_share_removals(seal_id: str) -> list[dict[str, Any]]:
    """The seal's removal audit rows, oldest first."""
    columns = ("id",) + _AUDIT_COLUMNS
    rows = execute_query(
        "SELECT " + ", ".join(columns) + " FROM share_removal_audit "
        "WHERE seal_id = ? ORDER BY id", (seal_id,), fetch_all=True) or []
    return [dict(zip(columns, _tuple(row, columns))) for row in rows]


def _check(share_index: Any, generation: Any, expected_row_id: Any, operator: str,
           reason: str) -> None:
    if type(share_index) is not int or share_index not in SHARE_SLOTS:
        raise ValueError("share_index must be 1, 2, 3 or 4")
    if type(generation) is not int or not 0 <= generation <= MAX_GENERATION:
        raise ValueError("generation must be an int from 0 to 2^31 - 1")
    if type(expected_row_id) is not int or expected_row_id < 1:
        raise ValueError("expected_row_id must be a positive int")
    if not operator:
        raise ValueError("an operator is required")
    if not reason.strip() or len(reason) > MAX_REASON_LENGTH:
        raise ValueError(f"a reason of 1 to {MAX_REASON_LENGTH} characters is required")


def _delete_and_audit(row_id: int, seal_id: str, removal: ShareRemoval,
                      operator: str, reason: str, removed_at: str) -> None:
    """Both writes, no commit (the seal's write transaction commits)."""
    mariadb = g.get("db_type", "sqlite") == "mariadb"
    delete_sql = _DELETE_SQL.replace("?", "%s") if mariadb else _DELETE_SQL
    audit_sql = _INSERT_AUDIT_SQL.replace("?", "%s") if mariadb else _INSERT_AUDIT_SQL
    cursor = get_db().cursor()
    try:
        cursor.execute(delete_sql, (row_id,))
        if cursor.rowcount != 1:
            raise RuntimeError("the share row changed during its removal")
        cursor.execute(audit_sql, (
            seal_id, removal.index, removal.generation, removal.uploaded_by,
            removal.uploaded_at, removal.share_sha256, operator, reason.strip(),
            removed_at))
    finally:
        cursor.close()


def _sha256(share: Any) -> str:
    return hashlib.sha256(str(share or "").strip().lower().encode("utf-8")).hexdigest()


def _row_values(row: Any) -> tuple[int, str, str, str, str]:
    row_id, seal_id, data, uploaded_by, uploaded_at = _tuple(
        row, ("id", "seal_id", "share_data", "uploaded_by", "uploaded_at"))
    return (int(row_id), str(seal_id), str(data or ""), str(uploaded_by or ""),
            _text(uploaded_at))


def _tuple(row: Any, names: tuple[str, ...]) -> tuple[Any, ...]:
    if hasattr(row, "keys"):
        return tuple(row[name] for name in names)
    return tuple(row)


def _text(value: Any) -> str:
    """A time column as text (MariaDB returns DATETIME as ``datetime``)."""
    if value is None:
        return ""
    return value.isoformat(sep=" ") if hasattr(value, "isoformat") else str(value)
