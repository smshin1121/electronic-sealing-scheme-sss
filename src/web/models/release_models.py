"""Persistence for sync and the release gate: records, wrapped s3, enrollment, audit.

Tables (both schema variants live in :mod:`web.models.db_models`):

  - ``seal_records`` -- the synced records. Since stage E, E3b, every
    writer here stores ``record_json`` and ``record_pdf`` encrypted under
    the seal's data key (``record_scheme = 'v1'``,
    :func:`web.privacy.record_store.protect_record`), and every reader
    decrypts, returning the exact text that was received. A record that
    does not decrypt is read as :data:`web.privacy.record_store.UNREADABLE_RECORD`
    (never as absent); a row stored before E3b raises
    :class:`web.privacy.record_store.LegacyRecordError`, and missing keys
    raise :class:`web.privacy.keys.PrivacyUnavailable`. These readers are
    system reads (sync admission, the release gate) and are not audited
    per read; a person sees a record only through
    :mod:`web.privacy.record_access`, which audits every decryption;
  - ``wrapped_s3_shares`` -- the envelope ciphertext of s3 synced with a
    Sealing/Resealing record, keyed by (seal_id, event_id);
  - ``policy_enrollment`` -- seals that have synced a record whose policy
    verified; from then on the sync route refuses records without a
    verifiable policy and releases ignore them;
  - ``release_audit`` -- one row per release attempt on any path; its
    ``operator`` column (stage E, E4) names the administrator on the
    admin path (see :class:`ReleaseAuditEntry`).

The audit trail is application-level: this module offers no UPDATE or
DELETE helper, but the database itself does not enforce append-only
behaviour (no triggers, grants or external anchoring).
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from flask import g

from ..privacy.record_store import (
    SealedRecord,
    is_unreadable,
    protect_record,
    readable_record_text,
    record_pdf_bytes,
)
from .db_models import execute_query, get_db
from .record_models import (
    RECORD_SCHEME_V1,
    StoredRecord,
    find_latest_stored_record,
    find_stored_record,
    find_stored_records,
    scheme_equals,
)

_AUDIT_COLUMNS = (
    "seal_id", "path", "policy_status", "policy_digest", "outcome",
    "reason", "detail", "operator_reason", "tsa_token_sha256", "tsa_token",
    "tsa_challenge", "tsa_gen_time", "created_at", "operator",
)

# record_json and record_pdf are always the encrypted forms (E3b).
_INSERT_RECORD_SQL = {
    "sqlite": """INSERT OR IGNORE INTO seal_records
                 (seal_id, event_id, event_type, record_json, record_pdf,
                  record_scheme)
                 VALUES (?, ?, ?, ?, ?, ?)""",
    "mariadb": """INSERT IGNORE INTO seal_records
                  (seal_id, event_id, event_type, record_json, record_pdf,
                   record_scheme)
                  VALUES (%s, %s, %s, %s, %s, %s)""",
}
_INSERT_WRAPPED_SQL = {
    "sqlite": """INSERT OR IGNORE INTO wrapped_s3_shares
                 (seal_id, event_id, wrapped_s3) VALUES (?, ?, ?)""",
    "mariadb": """INSERT IGNORE INTO wrapped_s3_shares
                  (seal_id, event_id, wrapped_s3) VALUES (%s, %s, %s)""",
}
_INSERT_ENROLLMENT_SQL = {
    "sqlite": """INSERT OR IGNORE INTO policy_enrollment
                 (seal_id, event_id, policy_digest) VALUES (?, ?, ?)""",
    "mariadb": """INSERT IGNORE INTO policy_enrollment
                  (seal_id, event_id, policy_digest) VALUES (%s, %s, %s)""",
}
_INSERT_AUDIT_SQL = (
    "INSERT INTO release_audit (" + ", ".join(_AUDIT_COLUMNS) + ") VALUES ("
    + ", ".join("?" for _ in _AUDIT_COLUMNS) + ")"
)
_SELECT_AUDIT_SQL = (
    "SELECT id, " + ", ".join(_AUDIT_COLUMNS)
    + " FROM release_audit WHERE seal_id = ? ORDER BY id"
)


SYNC_COMPLETED = "completed"
SYNC_UNCHANGED = "unchanged"
SYNC_ENVELOPE_CONFLICT = "envelope_conflict"


class DuplicateEventError(Exception):
    """A record already exists for this (seal_id, event_id); nothing was written."""


@dataclass(frozen=True)
class ReleaseAuditEntry:
    """One release attempt, as written to ``release_audit``.

    ``operator`` is the username of the administrator account that made an
    admin-path attempt. The release gate denies an admin attempt with a
    blank or over-long operator (``operator_required``, the one admin row
    written with ``''`` since the column exists), so no key is released on
    the admin path without a named operator, and the emergency route
    always passes the signed-in account. ``operator`` is also ``''`` on the
    standard and time-locked paths (the reference app has no investigator
    accounts; those paths authenticate by possession of s2) and on admin
    rows written before the column was added. Usernames are unique, and no
    command in this codebase renames or deletes an account, so a name maps
    to one account; there is no foreign key, so a row keeps the name even
    if the account row is removed by other means.
    """

    seal_id: str
    path: str
    policy_status: str
    outcome: str
    reason: str
    created_at: str
    policy_digest: str = ""
    detail: str = ""
    operator_reason: str = ""
    tsa_token_sha256: str = ""
    tsa_token: str = ""
    tsa_challenge: str = ""
    tsa_gen_time: str = ""
    operator: str = ""


def insert_seal_record_with_wrapped_s3(
    *,
    seal_id: str,
    event_id: int,
    event_type: str,
    record_json: str,
    record_pdf: Optional[bytes],
    wrapped_s3: bytes,
) -> None:
    """Store a record (encrypted) and its wrapped s3 in one transaction.

    Duplicate (seal_id, event_id) rows are ignored in both tables, as for
    plain record sync; any error rolls back both inserts (and a data key
    created for the seal). Serialized per seal, so two first writes for a
    seal without a data key cannot both create one.
    """
    with seal_write_transaction(seal_id):
        cursor = get_db().cursor()
        try:
            cursor.execute(_INSERT_RECORD_SQL[_dialect()], _record_params(
                seal_id, event_id, event_type, record_json, record_pdf))
            cursor.execute(
                _INSERT_WRAPPED_SQL[_dialect()], (seal_id, event_id, wrapped_s3)
            )
        finally:
            cursor.close()


def insert_protected_record(
    seal_id: str,
    event_id: int,
    event_type: str,
    record_json: str,
    record_pdf: Optional[bytes] = None,
) -> Optional[int]:
    """Store one record, encrypted, in its own transaction (duplicates ignored).

    Backs the v1.0.1 helper :func:`web.models.db_models.insert_seal_record`.
    Serialized per seal like the sync writers. Returns the cursor's last
    row id.
    """
    with seal_write_transaction(seal_id):
        cursor = get_db().cursor()
        try:
            cursor.execute(_INSERT_RECORD_SQL[_dialect()], _record_params(
                seal_id, event_id, event_type, record_json, record_pdf))
            return cursor.lastrowid
        finally:
            cursor.close()


def _record_params(
    seal_id: str, event_id: int, event_type: str, record_json: str,
    record_pdf: Optional[bytes],
) -> tuple[Any, ...]:
    """Insert parameters with both columns encrypted (may add a data key)."""
    sealed = protect_record(seal_id, event_id, record_json, record_pdf)
    return (seal_id, event_id, event_type, sealed.sealed_json, sealed.sealed_pdf,
            RECORD_SCHEME_V1)


@contextmanager
def seal_write_transaction(seal_id: str) -> Iterator[None]:
    """One write transaction per sync submission, serialized per seal.

    A submission's admission check, its conflict decision and its writes
    all run inside, so two submissions for the same seal cannot
    interleave. SQLite takes the database write lock up front (``BEGIN
    IMMEDIATE``); MariaDB locks the parent case row (``FOR UPDATE``; a seal
    without a case row gets only a gap lock, and since E3b its record
    writers refuse it first, :class:`web.privacy.record_store.CaseNotRegistered`,
    as the foreign key would). The writers below do not commit: this
    commits on success and rolls back on any exception. A helper that
    commits by itself (``execute_query`` on a write) ends the transaction,
    and with it the lock, at that point.
    """
    db = get_db()
    # End any transaction an earlier read of this request left open. On
    # MariaDB (REPEATABLE READ) its read view predates the lock, and reads
    # inside the lock would not see what another submission committed.
    db.rollback()
    cursor = db.cursor()
    try:
        if _dialect() == "mariadb":
            cursor.execute(
                "SELECT seal_id FROM cases WHERE seal_id = %s FOR UPDATE",
                (seal_id,),
            )
            cursor.fetchall()
        else:
            cursor.execute("BEGIN IMMEDIATE")
    finally:
        cursor.close()
    try:
        yield
        db.commit()
    except BaseException:
        db.rollback()
        raise


def _dialect() -> str:
    return "mariadb" if g.get("db_type", "sqlite") == "mariadb" else "sqlite"


def store_synced_record(
    *,
    seal_id: str,
    event_id: int,
    event_type: str,
    record_json: str,
    record_pdf: Optional[bytes],
    wrapped_s3: Optional[bytes] = None,
    enrolled_digest: Optional[str] = None,
) -> None:
    """Store a synced record, its wrapped s3 and its enrollment.

    Call inside :func:`seal_write_transaction`, which makes the three
    writes atomic. ``enrolled_digest`` (hex) is given when the record's
    policy verified; the first such record enrolls the seal.

    Raises:
        DuplicateEventError: A record already exists for (seal_id,
            event_id). Nothing was written, so the caller can decide on
            the resubmission inside the same transaction.
    """
    dialect = _dialect()
    params = _record_params(seal_id, event_id, event_type, record_json, record_pdf)
    cursor = get_db().cursor()
    try:
        cursor.execute(_INSERT_RECORD_SQL[dialect], params)
        if cursor.rowcount == 0:
            raise DuplicateEventError(f"{seal_id}#{event_id}")
        if wrapped_s3 is not None:
            cursor.execute(
                _INSERT_WRAPPED_SQL[dialect], (seal_id, event_id, wrapped_s3)
            )
        if enrolled_digest:
            cursor.execute(
                _INSERT_ENROLLMENT_SQL[dialect],
                (seal_id, event_id, enrolled_digest),
            )
    finally:
        cursor.close()


def replace_synced_record(
    *,
    seal_id: str,
    event_id: int,
    event_type: str,
    record_json: str,
    record_pdf: Optional[bytes],
    wrapped_s3: Optional[bytes],
    enrolled_digest: str,
    expected_record_json: str,
) -> bool:
    """Replace the record (and wrapped s3) of an event with an authenticated one.

    Call inside :func:`seal_write_transaction`. Used only when the stored
    record of that event carries no authenticated policy and the new one
    does: an authenticated record displaces an unauthenticated one that
    occupied its event first. The replacement applies only while the
    event still holds ``expected_record_json``, the record that decision
    was made on; otherwise nothing is written and ``False`` is returned.
    Since E3b the stored ciphertext is decrypted and compared byte for byte
    (one that does not decrypt never matches), and the update requires that
    ciphertext to be still stored. A row stored before E3b raises
    :class:`web.privacy.record_store.LegacyRecordError`.
    """
    current = _holding(seal_id, event_id, expected_record_json)
    if current is None:
        return False
    sealed = protect_record(seal_id, event_id, record_json, record_pdf)
    dialect = _dialect()
    mark = "%s" if dialect == "mariadb" else "?"
    cursor = get_db().cursor()
    try:
        if not _swap_sealed_record(cursor, current, event_type, sealed):
            return False
        cursor.execute(
            f"DELETE FROM wrapped_s3_shares WHERE seal_id = {mark} AND event_id = {mark}",
            (seal_id, event_id),
        )
        if wrapped_s3 is not None:
            cursor.execute(
                _INSERT_WRAPPED_SQL[dialect], (seal_id, event_id, wrapped_s3)
            )
        cursor.execute(
            _INSERT_ENROLLMENT_SQL[dialect], (seal_id, event_id, enrolled_digest)
        )
        return True
    finally:
        cursor.close()


def _holding(seal_id: str, event_id: int, expected_record_json: str) -> Optional[StoredRecord]:
    """The stored row, if it still decrypts to exactly ``expected_record_json``."""
    current = find_stored_record(seal_id, event_id)
    if current is None or is_unreadable(expected_record_json):
        return None
    text = readable_record_text(current)
    if is_unreadable(text) or text != expected_record_json:
        return None
    return current


def _swap_sealed_record(
    cursor: Any, current: StoredRecord, event_type: str, sealed: SealedRecord
) -> bool:
    """Write the new ciphertexts while the row still holds ``current``'s."""
    mariadb = _dialect() == "mariadb"
    mark = "%s" if mariadb else "?"
    # MariaDB compares TEXT under a case-insensitive collation; the stored
    # ciphertext (and the scheme) must match byte for byte.
    same_record = "BINARY record_json = %s" if mariadb else "record_json = ?"
    protected = scheme_equals().replace("?", mark)
    cursor.execute(
        f"""UPDATE seal_records SET event_type = {mark}, record_json = {mark},
            record_pdf = {mark}, record_scheme = {mark}
            WHERE seal_id = {mark} AND event_id = {mark}
            AND {protected} AND {same_record}""",
        (event_type, sealed.sealed_json, sealed.sealed_pdf, RECORD_SCHEME_V1,
         current.seal_id, current.event_id, RECORD_SCHEME_V1, current.record_json),
    )
    return cursor.rowcount == 1


def complete_synced_record(
    *,
    seal_id: str,
    event_id: int,
    wrapped_s3: Optional[bytes],
    enrolled_digest: Optional[str],
) -> str:
    """Add what an identical resubmission brings to an existing event.

    Call inside :func:`seal_write_transaction`. A missing wrapped s3 is
    stored, and the seal is enrolled when the record now authenticates
    (for example once a CA has been pinned).

    Returns:
        ``SYNC_COMPLETED`` when something was added, ``SYNC_UNCHANGED``
        when nothing was, or ``SYNC_ENVELOPE_CONFLICT`` (nothing written)
        when a different wrapped s3 is already stored for the event.
    """
    dialect = _dialect()
    mark = "%s" if dialect == "mariadb" else "?"
    cursor = get_db().cursor()
    try:
        added = False
        if wrapped_s3 is not None:
            cursor.execute(
                _INSERT_WRAPPED_SQL[dialect], (seal_id, event_id, wrapped_s3)
            )
            added = cursor.rowcount > 0
            if not added:
                cursor.execute(
                    f"""SELECT wrapped_s3 FROM wrapped_s3_shares
                        WHERE seal_id = {mark} AND event_id = {mark}""",
                    (seal_id, event_id),
                )
                row = cursor.fetchone()
                if row is None or bytes(row[0]) != wrapped_s3:
                    return SYNC_ENVELOPE_CONFLICT
        if enrolled_digest:
            cursor.execute(
                _INSERT_ENROLLMENT_SQL[dialect],
                (seal_id, event_id, enrolled_digest),
            )
            added = added or cursor.rowcount > 0
        return SYNC_COMPLETED if added else SYNC_UNCHANGED
    finally:
        cursor.close()


def enroll_seal(seal_id: str, event_id: int, policy_digest: str) -> None:
    """Record that the seal has an authenticated policy (idempotent)."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(_INSERT_ENROLLMENT_SQL[_dialect()],
                       (seal_id, event_id, policy_digest))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()


def find_record_at(seal_id: str, event_id: int) -> Optional[tuple[str, str]]:
    """``(event_type, record_json)`` stored for (seal_id, event_id), if any.

    The record is decrypted (system read); one that does not decrypt is
    :data:`web.privacy.record_store.UNREADABLE_RECORD`.
    """
    stored = find_stored_record(seal_id, event_id)
    if stored is None:
        return None
    return stored.event_type, readable_record_text(stored)


def find_record_json_at(seal_id: str, event_id: int) -> Optional[str]:
    """``record_json`` stored for (seal_id, event_id), decrypted, if any.

    A record that does not decrypt is returned as
    :data:`web.privacy.record_store.UNREADABLE_RECORD` (never ``None``).
    """
    stored = find_stored_record(seal_id, event_id)
    return None if stored is None else readable_record_text(stored)


def find_record_pdf_at(seal_id: str, event_id: int) -> Optional[bytes]:
    """``record_pdf`` of (seal_id, event_id), decrypted; ``None`` if none.

    A system read, not audited: to show a PDF to a person use
    :func:`web.privacy.record_access.reveal_record_pdf`.

    Raises:
        FieldCryptoError: The stored PDF does not decrypt.
    """
    stored = find_stored_record(seal_id, event_id, with_pdf=True)
    return None if stored is None else record_pdf_bytes(stored)


def find_latest_record_json(seal_id: str) -> Optional[str]:
    """The newest record of the seal, decrypted (unreadable stand-in if not)."""
    stored = find_latest_stored_record(seal_id)
    return None if stored is None else readable_record_text(stored)


def find_seal_records(seal_id: str) -> list[dict[str, Any]]:
    """Every record of the seal by event, decrypted, as plain dicts.

    A system read, not audited (person-facing reads go through
    :mod:`web.privacy.record_access`). Backs the v1.0.1 helper :func:`web.models.db_models.find_seal_records_by_seal_id`
    (keys ``id, seal_id, event_id, event_type, record_json, record_pdf,
    synced_at``).

    Raises:
        FieldCryptoError: A stored PDF does not decrypt.
    """
    return [{
        "id": stored.row_id, "seal_id": stored.seal_id,
        "event_id": stored.event_id, "event_type": stored.event_type,
        "record_json": readable_record_text(stored),
        "record_pdf": record_pdf_bytes(stored), "synced_at": stored.synced_at,
    } for stored in find_stored_records(seal_id)]


def is_policy_enrolled(seal_id: str) -> bool:
    """Whether the seal has synced a record whose policy verified."""
    row = execute_query(
        "SELECT seal_id FROM policy_enrollment WHERE seal_id = ?",
        (seal_id,),
        fetch_one=True,
    )
    return row is not None


def find_record_jsons_newest_first(seal_id: str) -> Iterator[tuple[int, str]]:
    """``(event_id, record_json)`` of the synced records, newest first.

    Only the event ids are read up front; each record is read when the
    caller reaches it, so a caller that stops early never loads the rest.
    """
    rows = execute_query(
        """SELECT event_id FROM seal_records
           WHERE seal_id = ? ORDER BY event_id DESC""",
        (seal_id,),
        fetch_all=True,
    ) or []
    for row in rows:
        event_id = int(row["event_id"] if hasattr(row, "keys") else row[0])
        record_json = find_record_json_at(seal_id, event_id)
        if record_json is not None:
            yield event_id, record_json


def has_wrapped_s3(seal_id: str) -> bool:
    """Whether any wrapped s3 is stored for the seal (no envelope is read)."""
    row = execute_query(
        "SELECT 1 FROM wrapped_s3_shares WHERE seal_id = ? LIMIT 1",
        (seal_id,),
        fetch_one=True,
    )
    return row is not None


def find_wrapped_s3_newest_first(seal_id: str) -> Iterator[bytes]:
    """The stored wrapped s3 of the seal, newest event first.

    Only the event ids are read up front; each envelope is read when the
    caller reaches it, so a caller that stops at the first usable one
    never loads the older ones.
    """
    rows = execute_query(
        """SELECT event_id FROM wrapped_s3_shares
           WHERE seal_id = ? ORDER BY event_id DESC""",
        (seal_id,),
        fetch_all=True,
    ) or []
    for row in rows:
        event_id = int(row["event_id"] if hasattr(row, "keys") else row[0])
        wrapped = _find_wrapped_s3_at(seal_id, event_id)
        if wrapped is not None:
            yield wrapped


def _find_wrapped_s3_at(seal_id: str, event_id: int) -> Optional[bytes]:
    row = execute_query(
        """SELECT wrapped_s3 FROM wrapped_s3_shares
           WHERE seal_id = ? AND event_id = ?""",
        (seal_id, event_id),
        fetch_one=True,
    )
    if row is None:
        return None
    return bytes(row["wrapped_s3"] if hasattr(row, "keys") else row[0])


def find_latest_wrapped_s3(seal_id: str) -> Optional[bytes]:
    """The wrapped s3 of the latest synced event carrying one, if any."""
    row = execute_query(
        """SELECT wrapped_s3 FROM wrapped_s3_shares
           WHERE seal_id = ? ORDER BY event_id DESC LIMIT 1""",
        (seal_id,),
        fetch_one=True,
    )
    if row is None:
        return None
    value = row["wrapped_s3"] if hasattr(row, "keys") else row[0]
    return bytes(value)


def find_stored_shares(seal_id: str) -> dict[int, str]:
    """Submitted shares (``key_shares``) of a seal, keyed by slot index."""
    rows = execute_query(
        "SELECT share_index, share_data FROM key_shares WHERE seal_id = ?",
        (seal_id,),
        fetch_all=True,
    ) or []
    shares: dict[int, str] = {}
    for row in rows:
        index, data = ((row["share_index"], row["share_data"])
                       if hasattr(row, "keys") else (row[0], row[1]))
        shares[int(index)] = data
    return shares


def find_share_by_index(seal_id: str, share_index: int) -> Optional[str]:
    """A submitted share (``key_shares``) by index, if present."""
    row = execute_query(
        """SELECT share_data FROM key_shares
           WHERE seal_id = ? AND share_index = ?""",
        (seal_id, share_index),
        fetch_one=True,
    )
    if row is None:
        return None
    value = row["share_data"] if hasattr(row, "keys") else row[0]
    return value or None


def insert_release_audit(entry: ReleaseAuditEntry) -> int:
    """Append one audit row and return its id."""
    values = tuple(getattr(entry, column) for column in _AUDIT_COLUMNS)
    return execute_query(_INSERT_AUDIT_SQL, values)


def find_release_audit(seal_id: str) -> list[dict[str, Any]]:
    """All audit rows of a seal, oldest first, as plain dicts."""
    rows = execute_query(_SELECT_AUDIT_SQL, (seal_id,), fetch_all=True) or []
    columns = ("id",) + _AUDIT_COLUMNS
    return [
        {k: row[k] for k in row.keys()} if hasattr(row, "keys")
        else dict(zip(columns, row))
        for row in rows
    ]
