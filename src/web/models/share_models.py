"""Stored key shares, versioned by policy generation (stage F, F1).

``key_shares`` keeps at most one share per (seal, slot, generation): the
unique key is ``(seal_id, share_index, generation)`` (DDL in
:mod:`web.models.db_models`, migration in :mod:`web.models.share_schema`).
A share's generation is the generation of the seal's newest authenticated
policy when it was stored (:mod:`web.share_upload`), 0 for version-1
policies, for seals without an authenticated policy and for every share
stored before F1.

:func:`store_key_share` decides and writes in one transaction serialized
per seal (:func:`web.models.release_models.seal_write_transaction`), the
lock sync admission raises the seal's high-water mark under, and it
reports what it did instead of ignoring a duplicate silently:

  - ``stored``: the slot had no share for that generation; the new row;
  - ``identical``: the same share (compared stripped and lower-cased) is
    already stored for that generation; nothing is written;
  - ``conflict``: another share is stored for that generation; nothing is
    written.

The insert is a plain ``INSERT``: ``INSERT IGNORE`` would also turn a
foreign-key failure (no case row) into "nothing written" on MariaDB. No
function here logs, and none returns a share value except the readers
used by the release gate.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Union

from flask import g

from .db_models import execute_query, get_db
from .release_models import seal_write_transaction

SHARE_STORED = "stored"
SHARE_IDENTICAL = "identical"
SHARE_CONFLICT = "conflict"
SHARE_SLOTS = (1, 2, 3, 4)
MAX_GENERATION = 2 ** 31 - 1  # the policy's bound; fits INT in both schemas

GenerationSource = Union[int, Callable[[], int]]

_SELECT_AT_SQL = """SELECT share_data FROM key_shares
                    WHERE seal_id = ? AND share_index = ? AND generation = ?"""
_INSERT_SQL = """INSERT INTO key_shares
                 (seal_id, share_index, share_data, uploaded_by, generation)
                 VALUES (?, ?, ?, ?, ?)"""


@dataclass(frozen=True)
class StoredShare:
    """One stored share: its slot (``index``), policy generation and value."""

    index: int
    generation: int
    data: str = field(repr=False)


@dataclass(frozen=True)
class ShareWrite:
    """What :func:`store_key_share` did: ``outcome`` (stored, identical or
    conflict), the generation it stored or compared under, and the new
    row's id (``stored`` only)."""

    outcome: str
    generation: int
    row_id: Optional[int] = None

    @property
    def stored(self) -> bool:
        return self.outcome == SHARE_STORED


def store_key_share(
    seal_id: str,
    share_index: int,
    share_data: str,
    uploaded_by: str,
    *,
    generation: GenerationSource,
) -> ShareWrite:
    """Store a share for one generation of its slot, or report why not.

    Runs in its own transaction under the seal's write lock (an open
    transaction of the connection is rolled back first). ``generation`` is
    an int, or a function called under that lock that returns one (the
    upload routes read the seal's current generation there, so the tag is
    consistent with what sync admission has committed).

    Raises:
        ValueError: ``share_index`` is not 1 to 4, or the generation is not
            an int from 0 to :data:`MAX_GENERATION`. Nothing is written.
    """
    if type(share_index) is not int or share_index not in SHARE_SLOTS:
        raise ValueError("share_index must be 1, 2, 3 or 4")
    if not callable(generation):
        _check_generation(generation)
    with seal_write_transaction(seal_id):
        resolved = generation() if callable(generation) else generation
        _check_generation(resolved)
        existing = _share_at(seal_id, share_index, resolved)
        if existing is not None:
            same = _same_share(existing, share_data)
            return ShareWrite(SHARE_IDENTICAL if same else SHARE_CONFLICT, resolved)
        row_id = _insert(seal_id, share_index, share_data, uploaded_by, resolved)
        return ShareWrite(SHARE_STORED, resolved, row_id)


def find_share_rows(
    seal_id: str, share_index: Optional[int] = None
) -> tuple[StoredShare, ...]:
    """The seal's stored shares (of one slot, or all), highest generation
    first, the lower slot first within a generation."""
    sql = ("SELECT share_index, generation, share_data FROM key_shares "
           "WHERE seal_id = ?")
    params: tuple[Any, ...] = (seal_id,)
    if share_index is not None:
        sql += " AND share_index = ?"
        params += (share_index,)
    rows = execute_query(sql + " ORDER BY generation DESC, share_index",
                         params, fetch_all=True) or []
    return tuple(StoredShare(int(index), int(gen), data or "")
                 for index, gen, data in (_values(row) for row in rows))


def _check_generation(generation: Any) -> None:
    if type(generation) is not int or not 0 <= generation <= MAX_GENERATION:
        raise ValueError("generation must be an int from 0 to 2^31 - 1")


def _same_share(stored: str, incoming: str) -> bool:
    """Equal once stripped and lower-cased (one comparison of fixed cost
    per length; a share stored before F1 may keep its original case)."""
    return hmac.compare_digest(_normal(stored), _normal(incoming))


def _normal(share: Any) -> bytes:
    return str(share or "").strip().lower().encode("utf-8")


def _share_at(seal_id: str, share_index: int, generation: int) -> Optional[str]:
    row = execute_query(_SELECT_AT_SQL, (seal_id, share_index, generation),
                        fetch_one=True)
    if row is None:
        return None
    return str((row["share_data"] if hasattr(row, "keys") else row[0]) or "")


def _insert(seal_id: str, share_index: int, share_data: str,
            uploaded_by: str, generation: int) -> Optional[int]:
    """The new row (no commit: the seal's write transaction commits)."""
    sql = _INSERT_SQL.replace("?", "%s") if _dialect() == "mariadb" else _INSERT_SQL
    cursor = get_db().cursor()
    try:
        cursor.execute(sql, (seal_id, share_index, share_data, uploaded_by,
                             generation))
        return cursor.lastrowid
    finally:
        cursor.close()


def _values(row: Any) -> tuple[Any, Any, Any]:
    if hasattr(row, "keys"):
        return row["share_index"], row["generation"], row["share_data"]
    return row[0], row[1], row[2]


def _dialect() -> str:
    return "mariadb" if g.get("db_type", "sqlite") == "mariadb" else "sqlite"
