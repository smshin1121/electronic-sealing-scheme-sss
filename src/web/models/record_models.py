"""Stored columns of synced seal records, read and written as they are (E3b).

Since stage E, E3b, ``seal_records.record_json`` and ``record_pdf`` hold
AES-256-GCM ciphertexts when ``record_scheme = 'v1'``: written through
:func:`web.privacy.record_store.protect_record` by the writers of
:mod:`web.models.release_models`, opened by :mod:`web.privacy.record_store`.
``record_scheme = ''`` marks a row stored before E3b, whose columns still
hold the plaintext until ``python -m src.web.privacy.migrate --apply``
converts it; no reader returns such a plaintext at run time.

This module does no cryptography: it reads the stored values (with their
scheme) and writes already encrypted ones. Rows are read with explicit
column lists and mapped by position (MariaDB returns tuples). The writers
used by the conversion do not commit: they run inside
:func:`web.models.release_models.seal_write_transaction`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from flask import g

from .db_models import execute_query, get_db
from .privacy_models import dialect_sql

RECORD_SCHEME_V1 = "v1"

_COLUMNS = "id, seal_id, event_id, event_type, record_json, record_scheme, synced_at"
_SELECT_AT = (f"SELECT {_COLUMNS}, {{pdf}} FROM seal_records "
              "WHERE seal_id = ? AND event_id = ?")
_SELECT_LATEST = (f"SELECT {_COLUMNS}, NULL FROM seal_records WHERE seal_id = ? "
                  "ORDER BY event_id DESC LIMIT 1")
_SELECT_ALL = (f"SELECT {_COLUMNS}, record_pdf FROM seal_records WHERE seal_id = ? "
               "ORDER BY event_id")
_SELECT_BY_ID = f"SELECT {_COLUMNS}, record_pdf FROM seal_records WHERE id = ?"
_SURVEY = "SELECT id, seal_id, event_id, record_scheme FROM seal_records ORDER BY id"
_COUNT_PLAINTEXT = "SELECT COUNT(*) FROM seal_records WHERE {differs}"
_WRITE_SEALED = (
    "UPDATE seal_records SET record_json = ?, record_pdf = ?, record_scheme = ? "
    "WHERE id = ? AND {differs}"
)


@dataclass(frozen=True)
class StoredRecord:
    """One ``seal_records`` row as stored (ciphertexts, or pre-E3b plaintext)."""

    row_id: int
    seal_id: str
    event_id: int
    event_type: str
    record_json: Any = field(repr=False)
    scheme: str
    synced_at: Any = ""
    record_pdf: Any = field(default=None, repr=False)

    @property
    def protected(self) -> bool:
        """Whether the row holds ciphertexts (``record_scheme = 'v1'``)."""
        return self.scheme == RECORD_SCHEME_V1


@dataclass(frozen=True)
class RecordSurveyRow:
    """A row as the conversion lists it (no content)."""

    row_id: int
    seal_id: str
    event_id: int
    scheme: str


def find_stored_record(
    seal_id: str, event_id: int, *, with_pdf: bool = False
) -> Optional[StoredRecord]:
    """The stored row of (seal, event); ``record_pdf`` only when asked for."""
    sql = _SELECT_AT.format(pdf="record_pdf" if with_pdf else "NULL")
    return _stored(execute_query(sql, (seal_id, event_id), fetch_one=True))


def find_latest_stored_record(seal_id: str) -> Optional[StoredRecord]:
    """The stored row of the seal's newest event (without the PDF)."""
    return _stored(execute_query(_SELECT_LATEST, (seal_id,), fetch_one=True))


def find_stored_records(seal_id: str) -> list[StoredRecord]:
    """Every stored row of the seal, by event, PDFs included."""
    rows = execute_query(_SELECT_ALL, (seal_id,), fetch_all=True) or []
    return [_stored(row) for row in rows]


def find_stored_record_by_id(row_id: int) -> Optional[StoredRecord]:
    """One stored row by its id, PDF included (the conversion's re-read)."""
    return _stored(execute_query(_SELECT_BY_ID, (row_id,), fetch_one=True))


def survey_record_rows() -> list[RecordSurveyRow]:
    """Every row's id, seal, event and scheme, by id (no content)."""
    rows = execute_query(_SURVEY, fetch_all=True) or []
    return [RecordSurveyRow(*tuple(row)) for row in rows]


def count_plaintext_record_rows() -> int:
    """Rows still stored before E3b (``record_scheme`` not exactly ``'v1'``)."""
    row = execute_query(_COUNT_PLAINTEXT.format(differs=scheme_differs()),
                        (RECORD_SCHEME_V1,), fetch_one=True)
    return 0 if row is None else int(tuple(row)[0])


def write_sealed_record(row_id: int, sealed_json: str, sealed_pdf: Optional[bytes]) -> int:
    """Replace a pre-E3b row's columns by their ciphertexts (no commit).

    Returns the number of rows changed (0 when the row is already protected).
    """
    cursor = get_db().cursor()
    try:
        cursor.execute(dialect_sql(_WRITE_SEALED.format(differs=scheme_differs())), (
            sealed_json, sealed_pdf, RECORD_SCHEME_V1, row_id, RECORD_SCHEME_V1,
        ))
        return cursor.rowcount
    finally:
        cursor.close()


def scheme_differs() -> str:
    """``record_scheme <> ?``, compared byte for byte on both variants.

    MariaDB's default collations ignore case and trailing spaces, so a value
    such as ``'V1'`` or ``'v1 '`` (only by direct database edits) would
    otherwise count as protected in SQL but not in Python; ``BINARY`` keeps
    SQL and :attr:`StoredRecord.protected` in agreement.
    """
    return "BINARY record_scheme <> ?" if _mariadb() else "record_scheme <> ?"


def scheme_equals() -> str:
    """``record_scheme = ?``, compared byte for byte (see :func:`scheme_differs`)."""
    return "BINARY record_scheme = ?" if _mariadb() else "record_scheme = ?"


def _mariadb() -> bool:
    """The backend of this context's connection (opened first if needed:
    ``g.db_type`` is only set once :func:`get_db` has run)."""
    get_db()
    return g.get("db_type", "sqlite") == "mariadb"


def _stored(row: Any) -> Optional[StoredRecord]:
    if row is None:
        return None
    (row_id, seal_id, event_id, event_type, record_json, scheme, synced_at,
     record_pdf) = tuple(row)
    return StoredRecord(
        row_id=int(row_id), seal_id=seal_id, event_id=int(event_id),
        event_type=event_type, record_json=record_json, scheme=scheme or "",
        synced_at=synced_at, record_pdf=_binary(record_pdf),
    )


def _binary(value: Any) -> Any:
    """A BLOB value as ``bytes`` (drivers may return bytearray or memoryview)."""
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    return value
