"""Persistence of sync nonces and policy generation marks (stage E, E2a).

Tables: :mod:`web.models.sync_schema`. The writers used by the sync route
(:func:`claim_sync_nonce`, :func:`seed_high_water`, :func:`raise_high_water`)
do not commit: they run inside
:func:`web.models.release_models.seal_write_transaction`, which commits the
nonce, the record and the mark together or rolls all of them back.
:func:`prune_sync_nonces` runs on its own, after that transaction, and the
release gate seeds a missing mark in its own transaction
(``seed_high_water(..., commit=True)``, insert-if-absent only).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from flask import g

from .db_models import execute_query, get_db

_CLAIM_NONCE_SQL = {
    "sqlite": """INSERT OR IGNORE INTO sync_nonces
                 (nonce, seal_id, event_id, sent_at, expires_at, received_at)
                 VALUES (?, ?, ?, ?, ?, ?)""",
    "mariadb": """INSERT IGNORE INTO sync_nonces
                  (nonce, seal_id, event_id, sent_at, expires_at, received_at)
                  VALUES (%s, %s, %s, %s, %s, %s)""",
}
_INSERT_MARK_SQL = {
    "sqlite": """INSERT OR IGNORE INTO policy_high_water
                 (seal_id, generation, policy_digest, event_id, updated_at)
                 VALUES (?, ?, ?, ?, ?)""",
    "mariadb": """INSERT IGNORE INTO policy_high_water
                  (seal_id, generation, policy_digest, event_id, updated_at)
                  VALUES (%s, %s, %s, %s, %s)""",
}
_RAISE_MARK_SQL = """UPDATE policy_high_water
                     SET generation = ?, policy_digest = ?, event_id = ?,
                         updated_at = ?
                     WHERE seal_id = ? AND generation < ?"""


@dataclass(frozen=True)
class HighWaterMark:
    """The highest policy generation sync has admitted for a seal."""

    generation: int
    policy_digest: str
    event_id: int


def _dialect() -> str:
    return "mariadb" if g.get("db_type", "sqlite") == "mariadb" else "sqlite"


def _marks(sql: str) -> str:
    return sql.replace("?", "%s") if _dialect() == "mariadb" else sql


def find_high_water(seal_id: str) -> Optional[HighWaterMark]:
    """The seal's mark, or ``None`` when sync never admitted a verified policy."""
    row = execute_query(
        """SELECT generation, policy_digest, event_id FROM policy_high_water
           WHERE seal_id = ?""",
        (seal_id,),
        fetch_one=True,
    )
    if row is None:
        return None
    values = ((row["generation"], row["policy_digest"], row["event_id"])
              if hasattr(row, "keys") else (row[0], row[1], row[2]))
    return HighWaterMark(int(values[0]), str(values[1]), int(values[2]))


def find_high_water_generation(seal_id: str) -> Optional[int]:
    """Generation of the seal's mark, if any."""
    mark = find_high_water(seal_id)
    return None if mark is None else mark.generation


def raise_high_water(
    *,
    seal_id: str,
    generation: int,
    policy_digest: str,
    event_id: int,
    updated_at: str,
) -> None:
    """Set the seal's mark, or raise it when ``generation`` is higher.

    Call inside ``seal_write_transaction`` (no commit here). A lower or
    equal generation leaves the mark as it is.
    """
    cursor = get_db().cursor()
    try:
        cursor.execute(_INSERT_MARK_SQL[_dialect()],
                       (seal_id, generation, policy_digest, event_id,
                        updated_at))
        if cursor.rowcount == 0:
            cursor.execute(_marks(_RAISE_MARK_SQL),
                           (generation, policy_digest, event_id, updated_at,
                            seal_id, generation))
    finally:
        cursor.close()


def seed_high_water(
    *,
    seal_id: str,
    generation: int,
    policy_digest: str,
    event_id: int,
    updated_at: str,
    commit: bool = False,
) -> None:
    """Create the seal's mark when it has none (an existing one is kept).

    Used to bootstrap the mark from records already stored: by the sync
    route inside ``seal_write_transaction`` (``commit=False``), and by the
    release gate after a full scan (``commit=True``, its own transaction).
    """
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(_INSERT_MARK_SQL[_dialect()],
                       (seal_id, generation, policy_digest, event_id,
                        updated_at))
        if commit:
            db.commit()
    except Exception:
        if commit:
            db.rollback()
        raise
    finally:
        cursor.close()


def claim_sync_nonce(
    *,
    nonce: str,
    seal_id: str,
    event_id: int,
    sent_at: str,
    expires_at: int,
    received_at: str,
) -> bool:
    """Record a nonce; ``False`` when it was used before (nothing written).

    Call inside ``seal_write_transaction`` (no commit here).
    """
    cursor = get_db().cursor()
    try:
        cursor.execute(_CLAIM_NONCE_SQL[_dialect()],
                       (nonce, seal_id, event_id, sent_at, expires_at,
                        received_at))
        return cursor.rowcount == 1
    finally:
        cursor.close()


def prune_sync_nonces(now_epoch: int) -> int:
    """Delete nonces whose retention has ended; returns how many."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(_marks("DELETE FROM sync_nonces WHERE expires_at < ?"),
                       (now_epoch,))
        deleted = cursor.rowcount
        db.commit()
        return deleted
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()
