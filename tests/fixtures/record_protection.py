"""Synthetic seal records that carry signer identity (stage E, E3b tests).

A record synced by the desktop carries ``signer_info`` (name, e-mail, birth
date, phone) and the rendered PDF. These helpers build such records from a
synthetic seal, read ``seal_records`` rows and the SQLite file directly
(bypassing the code under test), and list the byte strings that no stored
column may contain. Synthetic values only.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

SIGNER_INFO = {
    "name": "박서준",
    "email": "park.sj@example.org",
    "birth_date": "1988-03-14",
    "phone": "010-3141-5926",
    "cert_fingerprint": "ab" * 32,
}
IDENTITY_VALUES = (
    "박서준", "park.sj@example.org", "park.sj", "1988-03-14", "19880314",
    "010-3141-5926", "01031415926",
)
PDF_MARKER = b"E3B-SYNTHETIC-RECORD-PDF"

# ``cases`` as v1.0.1 created it, and ``seal_records`` as stage D/E2a did
# (SQLite): the database a conversion starts from.
V101_CASES_DDL = """
CREATE TABLE cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL UNIQUE,
    case_number TEXT    NOT NULL,
    investigator TEXT   NOT NULL,
    suspect_name TEXT   NOT NULL,
    suspect_email TEXT  NOT NULL DEFAULT '',
    suspect_birth TEXT  NOT NULL DEFAULT '',
    suspect_phone TEXT  NOT NULL DEFAULT '',
    auth_level  TEXT    NOT NULL DEFAULT 'basic',
    password_hash TEXT  NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""
PRE_E3B_RECORDS_DDL = """
CREATE TABLE seal_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    event_id    INTEGER NOT NULL,
    event_type  TEXT    NOT NULL CHECK(event_type IN ('Sealing','Unsealing','Resealing')),
    record_json TEXT    NOT NULL,
    record_pdf  BLOB,
    synced_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id),
    UNIQUE(seal_id, event_id)
);
"""


def write_pre_e3b_database(path: Path, seal_id: str, record_text: str,
                           pdf: Optional[bytes]) -> None:
    """A v1.0.1 case row and a pre-E3b plaintext record in a new SQLite file."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(V101_CASES_DDL + PRE_E3B_RECORDS_DDL)
        conn.execute("""INSERT INTO cases (seal_id, case_number, investigator, suspect_name,
                        suspect_birth, suspect_phone) VALUES (?, '2026-OLD', 'old', ?, ?, ?)""",
                     (seal_id, SIGNER_INFO["name"], SIGNER_INFO["birth_date"],
                      SIGNER_INFO["phone"]))
        conn.execute("""INSERT INTO seal_records (seal_id, event_id, event_type, record_json,
                        record_pdf) VALUES (?, 1, 'Sealing', ?, ?)""",
                     (seal_id, record_text, pdf))
        conn.commit()
    finally:
        conn.close()


def synthetic_pdf(label: str = "") -> bytes:
    """PDF-like bytes naming the signer (not a real PDF; never rendered)."""
    return (b"%PDF-1.7\n" + PDF_MARKER + b" " + label.encode("ascii") + b"\n("
            + SIGNER_INFO["name"].encode("utf-8") + b" "
            + SIGNER_INFO["email"].encode("ascii") + b")\n%%EOF\n")


def identity_record(material: Any, **extra: Any) -> dict:
    """The seal's record with the subject in ``case_info`` and ``signer_info``."""
    record = dict(material.record)
    case_info = {**(record.get("case_info") or {}), "suspect": SIGNER_INFO["name"]}
    return {**record, "case_info": case_info, "signer_info": dict(SIGNER_INFO),
            **extra}


def needles(record_text: str, pdf: Optional[bytes] = None) -> list[bytes]:
    """Byte strings that no stored column (or database file) may contain."""
    found = [value.encode("utf-8") for value in IDENTITY_VALUES]
    # The \\uXXXX form, should a client send ASCII-escaped JSON.
    found += [json.dumps(value)[1:-1].encode("ascii") for value in IDENTITY_VALUES]
    found += [record_text.encode("utf-8"), b'"signer_info"']
    if pdf:
        found += [pdf, PDF_MARKER]
    return found


def column_bytes(value: Any) -> bytes:
    """A stored value as bytes, for a substring scan."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return str(value).encode("utf-8", "surrogatepass")


def leaks(row: dict, patterns: Iterable[bytes]) -> list[str]:
    """``column: pattern`` for every pattern found in any column of ``row``."""
    patterns = list(patterns)
    return [f"{column}: {pattern[:40]!r}" for column, value in row.items()
            for pattern in patterns if pattern in column_bytes(value)]


def sql_rows(app: Any, sql: str, params: tuple = ()) -> list[dict]:
    """Rows of a statement on the app's SQLite file, on a separate connection."""
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(row) for row in conn.execute(sql, params)]
        conn.commit()
        return rows
    finally:
        conn.close()


def sql_execute(app: Any, sql: str, params: tuple = (), *,
                foreign_keys: bool = True) -> None:
    """Run one write on the app's SQLite file (direct database access)."""
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    try:
        conn.execute(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def stored_row(app: Any, seal_id: str, event_id: int) -> dict:
    """The raw ``seal_records`` row of an event (every column)."""
    [row] = sql_rows(app, "SELECT * FROM seal_records WHERE seal_id = ? AND event_id = ?",
                     (seal_id, event_id))
    return row


def database_file_bytes(app: Any) -> bytes:
    """The SQLite file with its WAL and journal, as stored on disk."""
    path = Path(app.config["SQLITE_PATH"])
    return b"".join(part.read_bytes() for part in (
        path, Path(f"{path}-wal"), Path(f"{path}-journal")) if part.exists())


def insert_plaintext_row(
    app: Any, seal_id: str, event_id: int, record_text: str,
    pdf: Optional[bytes] = None, *, scheme: str = "", event_type: str = "Sealing",
    foreign_keys: bool = True,
) -> None:
    """A row as stored before E3b (``record_scheme = ''``), or a plaintext row
    marked protected (``scheme='v1'``), written with direct database access."""
    sql_execute(app, """INSERT INTO seal_records
                        (seal_id, event_id, event_type, record_json, record_pdf,
                         record_scheme) VALUES (?, ?, ?, ?, ?, ?)""",
                (seal_id, event_id, event_type, record_text, pdf, scheme),
                foreign_keys=foreign_keys)


def copy_column(app: Any, source: tuple[str, int, str],
                target: tuple[str, int, str]) -> None:
    """Copy one stored column value to another row or column, as is."""
    (src_seal, src_event, src_column), (dst_seal, dst_event, dst_column) = source, target
    [row] = sql_rows(app, f"SELECT {src_column} AS value FROM seal_records "
                          "WHERE seal_id = ? AND event_id = ?", (src_seal, src_event))
    value = row["value"]
    if dst_column == "record_json" and isinstance(value, bytes):
        value = value.decode("latin-1")
    elif dst_column == "record_pdf" and isinstance(value, str):
        value = value.encode("utf-8")
    sql_execute(app, f"UPDATE seal_records SET {dst_column} = ? "
                     "WHERE seal_id = ? AND event_id = ?", (value, dst_seal, dst_event))


def access_rows(app: Any, seal_id: str) -> list[dict]:
    """The ``identity_access_audit`` rows of a seal, oldest first."""
    return sql_rows(app, "SELECT seal_id, field, purpose, actor_role, actor, "
                         "client_address, outcome FROM identity_access_audit "
                         "WHERE seal_id = ? ORDER BY id", (seal_id,))
