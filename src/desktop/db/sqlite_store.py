"""SQLite storage for seal records, key shares, and certificates.

All database operations use context-managed connections with
automatic commit on success and rollback on failure.

Tables:
    seal_records  — seal record JSON + PDF path per seal_id
    key_shares    — encrypted key shares (index 3 and 4)
    certificates  — X.509 certificate + encrypted private key
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional

# Written inside a save's transaction, on its connection (for example the
# sync outbox rows of the saved event, stage E E2d).
ExtraWrites = Callable[[sqlite3.Connection], None]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_CREATE_SEAL_RECORDS = """
CREATE TABLE IF NOT EXISTS seal_records (
    seal_id     TEXT PRIMARY KEY,
    record_json TEXT    NOT NULL,
    pdf_path    TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""

_CREATE_KEY_SHARES = """
CREATE TABLE IF NOT EXISTS key_shares (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    share_index INTEGER NOT NULL,
    share_data  BLOB    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (seal_id, share_index)
);
"""

_CREATE_CERTIFICATES = """
CREATE TABLE IF NOT EXISTS certificates (
    seal_id           TEXT PRIMARY KEY,
    cert_pem          TEXT NOT NULL,
    key_pem_encrypted BLOB NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_seal_records_created_at
    ON seal_records (created_at);
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

@contextmanager
def _connect(db_path: str) -> Iterator[sqlite3.Connection]:
    """Open a connection with auto-commit/rollback semantics."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db(db_path: str) -> None:
    """Create tables if they do not exist.

    Args:
        db_path: Path to the SQLite database file.  The parent
            directory must exist.
    """
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.executescript(
            _CREATE_SEAL_RECORDS
            + _CREATE_KEY_SHARES
            + _CREATE_CERTIFICATES
            + _CREATE_INDEXES
        )
        _ensure_case_columns(conn, db_path, force=True)
    logger.info("DB 초기화 완료: %s", db_path)


def save_key_shares(
    db_path: str,
    seal_id: str,
    shares: dict[int, bytes],
) -> None:
    """Persist encrypted key shares (typically indices 3 and 4).

    Args:
        db_path: Database file path.
        seal_id: The seal identifier.
        shares: Mapping of share_index -> encrypted share bytes.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")
    if not shares:
        raise ValueError("저장할 키 조각이 없습니다.")

    with _connect(db_path) as conn:
        for idx, data in shares.items():
            conn.execute(
                """
                INSERT OR REPLACE INTO key_shares (seal_id, share_index, share_data)
                VALUES (?, ?, ?)
                """,
                (seal_id, idx, data),
            )
    logger.info("키 조각 저장 완료: seal_id=%s, indices=%s", seal_id, list(shares.keys()))


def save_seal_record(
    db_path: str,
    seal_id: str,
    record_json: str,
    pdf_path: str,
    *,
    require_lineage: bool = False,
    extra_writes: Optional[ExtraWrites] = None,
) -> None:
    """Save a seal record (JSON + PDF path).

    Args:
        db_path: Database file path.
        seal_id: The seal identifier.
        record_json: JSON-serialized seal record.
        pdf_path: Absolute path to the generated PDF file.
        require_lineage: Apply :func:`save_seal_bundle`'s replacement rule
            inside the write transaction (``BEGIN IMMEDIATE``); U7 since
            stage E, E2e. Raises ``SealIdConflictError`` (another seal, an
            unclaimed placeholder) or ``StaleRecordError`` (an older
            record of the same seal).
        extra_writes: Called with the connection after the record is
            written, in the same transaction (U7 writes its sync outbox rows
            here); an exception rolls the record back too.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")
    if not record_json:
        raise ValueError("기록 JSON이 비어 있을 수 없습니다.")

    # Validate JSON structure
    try:
        record = json.loads(record_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"유효하지 않은 JSON입니다: {exc}") from exc

    with _connect(db_path) as conn:
        if require_lineage:
            conn.execute("BEGIN IMMEDIATE")
            _require_same_seal(conn, seal_id, record)
        conn.execute(
            """
            INSERT OR REPLACE INTO seal_records (seal_id, record_json, pdf_path)
            VALUES (?, ?, ?)
            """,
            (seal_id, record_json, pdf_path),
        )
        if extra_writes is not None:
            extra_writes(conn)
    logger.info("봉인 기록 저장: seal_id=%s", seal_id)


def save_certificate(
    db_path: str,
    seal_id: str,
    cert_pem: str,
    key_pem_encrypted: bytes,
) -> None:
    """Save an X.509 certificate and its encrypted private key.

    Args:
        db_path: Database file path.
        seal_id: The seal identifier.
        cert_pem: PEM-encoded certificate string.
        key_pem_encrypted: Encrypted private key bytes (envelope-encrypted).
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")
    if not cert_pem:
        raise ValueError("인증서가 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO certificates (seal_id, cert_pem, key_pem_encrypted)
            VALUES (?, ?, ?)
            """,
            (seal_id, cert_pem, key_pem_encrypted),
        )
    logger.info("인증서 저장: seal_id=%s", seal_id)


def save_seal_bundle(
    db_path: str,
    seal_id: str,
    record_json: str,
    pdf_path: str,
    shares: dict[int, bytes],
    cert_pem: str = "",
    key_pem_encrypted: bytes = b"",
    *,
    case_meta: Optional[dict[str, str]] = None,
    registered_case_id: Optional[str] = None,
    extra_writes: Optional[ExtraWrites] = None,
) -> None:
    """Persist a seal record, key shares, and certificate atomically.

    All inserts run inside a single transaction so a failure in any
    statement rolls back the whole bundle (no partial seal state). The
    transaction takes SQLite's write lock first (``BEGIN IMMEDIATE``), and
    the same-seal check runs inside it, so no other save can write the row
    between the check and the write (stage E, E2d; F9).

    Args:
        db_path: Database file path.
        seal_id: The seal identifier.
        record_json: JSON-serialized seal record.
        pdf_path: Absolute path to the generated PDF file.
        shares: Mapping of share_index -> encrypted share bytes.
        cert_pem: Optional PEM-encoded certificate. When empty the
            certificate insert is skipped.
        key_pem_encrypted: Encrypted private key bytes (required when
            ``cert_pem`` is provided).
        case_meta: Optional searchable case columns (``case_number``,
            ``suspect_name``, ``investigator``, ``status``) written in the
            same transaction. ``INSERT OR REPLACE`` resets them otherwise,
            e.g. on the row a case registration created.
        registered_case_id: The seal_id of the registered case this bundle
            seals (S7 of a wizard started from the case manager). Only then
            may the case's placeholder row be filled.
        extra_writes: Called with the connection after the bundle is
            written, in the same transaction (S7 and R8 write their sync
            outbox rows here); an exception rolls the bundle back too.

    Raises:
        SealIdConflictError: The row for ``seal_id`` belongs to a different
            seal, or is the placeholder of a case this bundle does not claim
            (see :func:`_require_same_seal`); nothing was saved.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")
    if not record_json:
        raise ValueError("기록 JSON이 비어 있을 수 없습니다.")
    if not shares:
        raise ValueError("저장할 키 조각이 없습니다.")

    try:
        record = json.loads(record_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"유효하지 않은 JSON입니다: {exc}") from exc

    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        _require_same_seal(conn, seal_id, record,
                           registered_case_id=registered_case_id)
        _write_bundle_rows(conn, seal_id, record_json, pdf_path, shares,
                           cert_pem, key_pem_encrypted)
        if case_meta is not None:
            _ensure_case_columns(conn, db_path)
            _write_case_meta(conn, seal_id, case_meta)
        if extra_writes is not None:
            extra_writes(conn)
    logger.info(
        "봉인 번들 저장 완료: seal_id=%s, shares=%s, cert=%s, case_meta=%s",
        seal_id, list(shares.keys()), bool(cert_pem), case_meta is not None,
    )


def _write_bundle_rows(
    conn: sqlite3.Connection, seal_id: str, record_json: str, pdf_path: str,
    shares: dict[int, bytes], cert_pem: str, key_pem_encrypted: bytes,
) -> None:
    """The record, key shares and certificate rows of a bundle."""
    conn.execute(
        """
        INSERT OR REPLACE INTO seal_records (seal_id, record_json, pdf_path)
        VALUES (?, ?, ?)
        """,
        (seal_id, record_json, pdf_path),
    )
    for idx, data in shares.items():
        conn.execute(
            """
            INSERT OR REPLACE INTO key_shares (seal_id, share_index, share_data)
            VALUES (?, ?, ?)
            """,
            (seal_id, idx, data),
        )
    if cert_pem:
        conn.execute(
            """
            INSERT OR REPLACE INTO certificates (seal_id, cert_pem, key_pem_encrypted)
            VALUES (?, ?, ?)
            """,
            (seal_id, cert_pem, key_pem_encrypted),
        )


def _write_case_meta(
    conn: sqlite3.Connection, seal_id: str, case_meta: dict[str, str]
) -> None:
    """The searchable case columns of the seal's row."""
    conn.execute(
        """
        UPDATE seal_records
        SET case_number = ?, suspect_name = ?, investigator = ?, status = ?
        WHERE seal_id = ?
        """,
        (
            case_meta.get("case_number", ""),
            case_meta.get("suspect_name", ""),
            case_meta.get("investigator", ""),
            case_meta.get("status", ""),
            seal_id,
        ),
    )


# Databases whose seal_records table has already been migrated in this
# process. Avoids re-running PRAGMA table_info on every query.
_MIGRATED_DBS: set[str] = set()
_MIGRATION_LOCK = threading.Lock()


def _ensure_case_columns(
    conn: sqlite3.Connection,
    db_path: str = "",
    *,
    force: bool = False,
) -> None:
    """Add search-optimized columns if they don't exist yet (migration).

    The migration check runs once per database path per process; later
    calls are no-ops unless ``force`` is True (used by ``init_db`` so a
    re-created database file is migrated again).
    """
    cache_key = os.path.abspath(db_path) if db_path else ""
    if cache_key and not force:
        with _MIGRATION_LOCK:
            if cache_key in _MIGRATED_DBS:
                return

    cursor = conn.execute("PRAGMA table_info(seal_records)")
    existing = {row["name"] for row in cursor.fetchall()}
    migrations: list[str] = []
    for col, typedef in [
        ("case_number", "TEXT DEFAULT ''"),
        ("suspect_name", "TEXT DEFAULT ''"),
        ("investigator", "TEXT DEFAULT ''"),
        ("status", "TEXT DEFAULT 'S1U0R0'"),
    ]:
        if col not in existing:
            migrations.append(
                f"ALTER TABLE seal_records ADD COLUMN {col} {typedef}"
            )
    for sql in migrations:
        conn.execute(sql)

    if cache_key:
        with _MIGRATION_LOCK:
            _MIGRATED_DBS.add(cache_key)


# ---------------------------------------------------------------------------
# Case management queries
# ---------------------------------------------------------------------------

def list_all_cases(db_path: str) -> list[dict]:
    """Return all cases with summary columns for the case manager list.

    Each dict contains: seal_id, case_number, suspect_name,
    investigator, created_at, status, file_count.
    """
    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        rows = conn.execute(
            """
            SELECT seal_id, case_number, suspect_name, investigator,
                   created_at, status, record_json
            FROM seal_records
            ORDER BY created_at DESC
            """
        ).fetchall()

    results: list[dict] = []
    for row in rows:
        file_count = 0
        try:
            record = json.loads(row["record_json"])
            fi = record.get("file_info", {})
            if isinstance(fi, dict):
                file_count = len(fi.get("original_files", fi.get("files", [])))
                if file_count == 0 and fi.get("original_name"):
                    file_count = 1
        except (json.JSONDecodeError, TypeError):
            pass

        results.append({
            "seal_id": row["seal_id"],
            "case_number": row["case_number"] or "",
            "suspect_name": row["suspect_name"] or "",
            "investigator": row["investigator"] or "",
            "created_at": row["created_at"],
            "status": row["status"] or "S1U0R0",
            "file_count": file_count,
        })
    return results


def get_case_detail(db_path: str, seal_id: str) -> Optional[dict]:
    """Return full parsed record for a seal_id, or None."""
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT record_json, pdf_path, created_at FROM seal_records WHERE seal_id = ?",
            (seal_id,),
        ).fetchone()

    if row is None:
        return None

    try:
        record = json.loads(row["record_json"])
    except (json.JSONDecodeError, TypeError):
        record = {}

    return {
        "seal_id": seal_id,
        "record": record,
        "pdf_path": row["pdf_path"],
        "created_at": row["created_at"],
    }


def get_case_artifacts(db_path: str, seal_id: str) -> list[dict]:
    """Return list of artifact files for a case.

    Each dict: file_path, file_type, created_at, size_bytes.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT record_json, pdf_path, created_at FROM seal_records WHERE seal_id = ?",
            (seal_id,),
        ).fetchone()

    if row is None:
        return []

    artifacts: list[dict] = []
    created_at = row["created_at"]

    # PDF file
    pdf_path = row["pdf_path"]
    if pdf_path:
        artifacts.append(_make_artifact(pdf_path, "PDF", created_at))

    # Parse record JSON for other artifact paths
    try:
        record = json.loads(row["record_json"])
    except (json.JSONDecodeError, TypeError):
        return artifacts

    # Encrypted file
    enc_path = _extract_enc_filepath(record, pdf_path or "")
    if enc_path:
        artifacts.append(_make_artifact(enc_path, "enc", created_at))

    # JSON record file (same directory as PDF)
    if pdf_path:
        json_path = str(Path(pdf_path).parent / f"{seal_id}_record.json")
        artifacts.append(_make_artifact(json_path, "JSON", created_at))

    # Key file
    if pdf_path:
        key_path = str(Path(pdf_path).parent / f"{seal_id}_key.pem")
        artifacts.append(_make_artifact(key_path, "key", created_at))

    return artifacts


def _extract_enc_filepath(record: dict, pdf_path: str) -> str:
    """Extract the .enc file path from a record JSON.

    Prefers the legacy flat ``encryption.enc_filepath`` key; falls back
    to the canonical schema's ``file_info.result_files[0].filename``
    (written by build_seal_record / ResealProcess). A bare basename is
    resolved against the pdf_path parent directory — seal artifacts are
    written to the same output directory as the PDF.
    """
    enc_info = record.get("encryption") or {}
    if isinstance(enc_info, dict):
        enc_path = enc_info.get("enc_filepath", "")
        if enc_path:
            return enc_path

    file_info = record.get("file_info") or {}
    result_files = file_info.get("result_files") or []
    first = result_files[0] if result_files else {}
    if not isinstance(first, dict):
        return ""
    name = first.get("filename", "")
    if not name:
        return ""
    if Path(name).name != name:
        return name  # already a (relative or absolute) path
    if pdf_path:
        return str(Path(pdf_path).parent / name)
    return name


def _make_artifact(file_path: str, file_type: str, created_at: str) -> dict:
    """Build an artifact dict, checking file existence for size."""
    p = Path(file_path)
    size = p.stat().st_size if p.exists() else 0
    return {
        "file_path": file_path,
        "file_type": file_type,
        "created_at": created_at,
        "size_bytes": size,
    }


def get_case_history(db_path: str, seal_id: str) -> list[dict]:
    """Return history events list for a case."""
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT record_json FROM seal_records WHERE seal_id = ?",
            (seal_id,),
        ).fetchone()

    if row is None:
        return []

    try:
        record = json.loads(row["record_json"])
    except (json.JSONDecodeError, TypeError):
        return []

    history = record.get("history", {})
    if isinstance(history, dict):
        return list(history.get("events", []))
    if isinstance(history, list):
        return list(history)
    return []


def search_cases(db_path: str, keyword: str) -> list[dict]:
    """Search cases by keyword across seal_id, case_number, suspect_name, investigator."""
    if not keyword or not keyword.strip():
        return list_all_cases(db_path)

    kw = f"%{keyword.strip()}%"
    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        rows = conn.execute(
            """
            SELECT seal_id, case_number, suspect_name, investigator,
                   created_at, status, record_json
            FROM seal_records
            WHERE seal_id LIKE ?
               OR case_number LIKE ?
               OR suspect_name LIKE ?
               OR investigator LIKE ?
            ORDER BY created_at DESC
            """,
            (kw, kw, kw, kw),
        ).fetchall()

    results: list[dict] = []
    for row in rows:
        file_count = 0
        try:
            record = json.loads(row["record_json"])
            fi = record.get("file_info", {})
            if isinstance(fi, dict):
                file_count = len(fi.get("original_files", fi.get("files", [])))
                if file_count == 0 and fi.get("original_name"):
                    file_count = 1
        except (json.JSONDecodeError, TypeError):
            pass

        results.append({
            "seal_id": row["seal_id"],
            "case_number": row["case_number"] or "",
            "suspect_name": row["suspect_name"] or "",
            "investigator": row["investigator"] or "",
            "created_at": row["created_at"],
            "status": row["status"] or "S1U0R0",
            "file_count": file_count,
        })
    return results


def delete_case(db_path: str, seal_id: str) -> bool:
    """Delete a case record from DB (files are preserved on disk).

    Returns True if a row was deleted, False if not found.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM seal_records WHERE seal_id = ?",
            (seal_id,),
        )
        deleted = cursor.rowcount > 0

    if deleted:
        logger.info("케이스 삭제: seal_id=%s", seal_id)
    return deleted


def update_case_meta(
    db_path: str,
    seal_id: str,
    *,
    case_number: str = "",
    suspect_name: str = "",
    investigator: str = "",
    status: str = "",
    record_json: str = "",
    pdf_path: str = "",
) -> None:
    """Update searchable metadata columns for a seal record.

    If *record_json* or *pdf_path* are non-empty they are updated as well,
    so that case-workflow seals keep the record/PDF in sync.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        if record_json or pdf_path:
            # Build dynamic SET clause to also update record_json / pdf_path
            params: list[str | bytes] = [case_number, suspect_name, investigator, status]
            set_clause = "case_number = ?, suspect_name = ?, investigator = ?, status = ?"
            if record_json:
                set_clause += ", record_json = ?"
                params.append(record_json)
            if pdf_path:
                set_clause += ", pdf_path = ?"
                params.append(pdf_path)
            params.append(seal_id)
            conn.execute(
                f"UPDATE seal_records SET {set_clause} WHERE seal_id = ?",
                tuple(params),
            )
        else:
            conn.execute(
                """
                UPDATE seal_records
                SET case_number = ?, suspect_name = ?, investigator = ?, status = ?
                WHERE seal_id = ?
                """,
                (case_number, suspect_name, investigator, status, seal_id),
            )
    logger.info("케이스 메타 업데이트: seal_id=%s", seal_id)


# ---------------------------------------------------------------------------
# seal_id ownership (stage E, E1 fix round: Codex F9)
# ---------------------------------------------------------------------------

# ``S-YYYYMMDD-XXXXXX`` (portal contract) has 24 random bits per day, so an
# ID is drawn again when the drawn one is taken, this many times at most.
_SEAL_ID_ATTEMPTS = 8


class SealIdConflictError(ValueError):
    """The seal_id belongs to a different seal; nothing was saved."""


class StaleRecordError(SealIdConflictError):
    """The same seal, but the stored record has events the new one lacks.

    The new record was built from an older record of the seal (for example
    a second unsealing from the sealing record); nothing was saved.
    """


def seal_id_in_use(db_path: str, seal_id: str) -> bool:
    """Whether ``db_path`` has a row for ``seal_id``.

    A database file or table that does not exist yet has no rows; the file
    is not created by asking.
    """
    if not db_path or not os.path.exists(db_path):
        return False
    with _connect(db_path) as conn:
        try:
            row = conn.execute(
                "SELECT 1 FROM seal_records WHERE seal_id = ?", (seal_id,)
            ).fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):
                return False
            raise
    return row is not None


def unused_seal_id(db_path: str) -> str:
    """A new record-format seal_id with no row in ``db_path`` yet.

    For sealing without a registered case, where S4 fixes the ID long
    before S7 stores the row; :func:`save_seal_bundle` still refuses to
    replace another seal's row should the ID be taken in between.

    Raises:
        SealIdConflictError: Every draw was taken.
    """
    from ..record.record_builder import create_seal_id

    for _attempt in range(_SEAL_ID_ATTEMPTS):
        seal_id = create_seal_id()
        if not seal_id_in_use(db_path, seal_id):
            return seal_id
        logger.warning("seal_id 충돌: %s 사용 중, 새로 생성합니다", seal_id)
    raise SealIdConflictError(
        f"사용하지 않은 seal_id를 {_SEAL_ID_ATTEMPTS}회 안에 만들지 못했습니다."
    )


def _require_same_seal(
    conn: sqlite3.Connection, seal_id: str, record: object, *,
    registered_case_id: Optional[str] = None,
) -> None:
    """Refuse to replace the row of a different seal that has ``seal_id``.

    The row may be replaced when it does not exist; when it is the
    placeholder a case registration wrote (no PDF, no history) and the
    bundle claims that registration (``registered_case_id == seal_id``);
    or when its history events are the first events of ``record``
    unchanged: the same seal, unsealed or resealed since (history events
    are only ever appended). An unreadable stored row is never replaced.
    Run it inside the write transaction (``BEGIN IMMEDIATE``) so that
    nothing can write the row between this check and the caller's write.

    Raises:
        StaleRecordError: The first events agree (the same seal) but the
            stored record has events ``record`` lacks: ``record`` was built
            from an older record of the seal (stage E, E2e).
        SealIdConflictError: Otherwise.
    """
    row = conn.execute(
        "SELECT record_json, pdf_path FROM seal_records WHERE seal_id = ?",
        (seal_id,),
    ).fetchone()
    if row is None:
        return
    try:
        stored = json.loads(row["record_json"])
    except (json.JSONDecodeError, TypeError):
        stored = None
    if _is_registration_placeholder(stored, row["pdf_path"]):
        if registered_case_id == seal_id:
            return
        logger.warning("seal_id %s: 등록된 다른 사건의 자리를 채우지 않았습니다",
                       seal_id)
        raise SealIdConflictError(
            f"seal_id {seal_id}는 이 PC에 등록된 다른 사건이 쓰고 있습니다. "
            "그 사건의 자리를 채우지 않았습니다.")
    stored_events = _history_events(stored)
    new_events = _history_events(record) or []
    if stored_events is not None and new_events[: len(stored_events)] == stored_events:
        return
    raise _replacement_refused(seal_id, stored_events, new_events)


def _replacement_refused(
    seal_id: str, stored_events: Optional[list], new_events: list,
) -> SealIdConflictError:
    """The (logged) error for a stored row the new record may not replace."""
    if stored_events and new_events and stored_events[0] == new_events[0]:
        logger.warning("seal_id %s: 저장된 기록보다 이전 기록에서 만든 기록이라 "
                       "저장하지 않았습니다", seal_id)
        return StaleRecordError(
            f"seal_id {seal_id}: 이 PC에 저장된 이 봉인의 최신 기록에 새 기록에 "
            f"없는 이벤트가 있습니다 (저장된 이력 {len(stored_events)}건). 이전 "
            "기록지로 작업한 것으로 보여 저장하지 않았습니다. 이 봉인의 마지막 "
            "작업에서 만든 기록지로 다시 진행하세요.")
    logger.warning("seal_id %s: 다른 봉인의 기록을 대체하지 않았습니다", seal_id)
    return SealIdConflictError(
        f"seal_id {seal_id}는 이 PC에 저장된 다른 봉인 기록이 쓰고 있습니다 "
        "(이력 불일치). 기존 기록을 대체하지 않았습니다."
    )


def _is_registration_placeholder(stored: object, pdf_path: object) -> bool:
    """The row :func:`create_case` writes: no PDF path and no history."""
    return (isinstance(stored, dict) and "history" not in stored
            and not pdf_path)


def _history_events(record: object) -> Optional[list]:
    """History events of a parsed record; [] without history; None if malformed."""
    if not isinstance(record, dict):
        return None
    history = record.get("history")
    if history is None:
        return []
    events = history.get("events", []) if isinstance(history, dict) else None
    return events if isinstance(events, list) else None


def create_case(
    db_path: str,
    case_number: str,
    investigator: str,
    suspect_name: str = "",
) -> str:
    """Create a new case (before sealing). Generates and returns a seal_id.

    Inserts a row into seal_records with empty record_json and pdf_path
    so the case appears in the case list immediately. The seal_id has the
    record format (``S-YYYYMMDD-XXXXXX``) because the sealing process
    writes it into the record, whose schema requires that format. A drawn
    ID that is taken is drawn again inside the same transaction; an
    existing row is never replaced.

    Raises:
        SealIdConflictError: Every draw was taken.
    """
    from ..record.record_builder import create_seal_id

    if not case_number:
        raise ValueError("case_number는 비어 있을 수 없습니다.")
    if not investigator:
        raise ValueError("investigator는 비어 있을 수 없습니다.")

    empty_record = json.dumps({
        "case_info": {
            "case_number": case_number,
            "investigator": investigator,
            "suspect": suspect_name,
        },
    })

    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        for _attempt in range(_SEAL_ID_ATTEMPTS):
            seal_id = create_seal_id()
            try:
                conn.execute(
                    """
                    INSERT INTO seal_records
                        (seal_id, record_json, pdf_path, case_number, suspect_name,
                         investigator, status)
                    VALUES (?, ?, '', ?, ?, ?, '')
                    """,
                    (seal_id, empty_record, case_number, suspect_name, investigator),
                )
            except sqlite3.IntegrityError:  # the primary key: seal_id taken
                logger.warning("seal_id 충돌: %s 사용 중, 새로 생성합니다", seal_id)
                continue
            break
        else:
            raise SealIdConflictError(
                f"사용하지 않은 seal_id를 {_SEAL_ID_ATTEMPTS}회 안에 만들지 못했습니다."
            )
    logger.info("케이스 생성: seal_id=%s, case_number=%s", seal_id, case_number)
    return seal_id


def get_case_for_seal(db_path: str, seal_id: str) -> Optional[dict]:
    """Return case info for the seal wizard prefill.

    Returns case_number, investigator, suspect_name, seal_id.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        row = conn.execute(
            """
            SELECT seal_id, case_number, suspect_name, investigator, record_json
            FROM seal_records WHERE seal_id = ?
            """,
            (seal_id,),
        ).fetchone()

    if row is None:
        return None

    result = {
        "seal_id": row["seal_id"],
        "case_number": row["case_number"] or "",
        "investigator": row["investigator"] or "",
        "suspect_name": row["suspect_name"] or "",
    }

    # Try to extract more detail from record_json
    try:
        record = json.loads(row["record_json"])
        case_info = record.get("case_info", {})
        if not result["case_number"]:
            result["case_number"] = case_info.get("case_number", "")
        if not result["investigator"]:
            result["investigator"] = case_info.get("investigator", "")
        if not result["suspect_name"]:
            result["suspect_name"] = case_info.get("suspect", "")
    except (json.JSONDecodeError, TypeError):
        pass

    return result


def get_case_for_unseal(db_path: str, seal_id: str) -> Optional[dict]:
    """Return info for the unseal wizard prefill.

    Extracts enc_filepath, pdf_path, record_json_path from record_json.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT seal_id, record_json, pdf_path FROM seal_records WHERE seal_id = ?",
            (seal_id,),
        ).fetchone()

    if row is None:
        return None

    result: dict = {
        "seal_id": row["seal_id"],
        "pdf_path": row["pdf_path"] or "",
    }

    try:
        record = json.loads(row["record_json"])
    except (json.JSONDecodeError, TypeError):
        record = {}

    # Extract encryption info (legacy flat key first, then canonical
    # file_info.result_files fallback)
    result["enc_filepath"] = _extract_enc_filepath(record, row["pdf_path"] or "")

    # The record JSON of the stored record's last event, beside its PDF
    result["record_json_path"] = _latest_record_file(
        seal_id, record, row["pdf_path"] or "")

    return result


# The record JSON each step writes beside its PDF (S5, U6 and R6).
_RECORD_FILE_NAMES = {
    "Sealing": "{seal_id}_record.json",
    "Unsealing": "{seal_id}_unseal_record.json",
    "Resealing": "{seal_id}_reseal_record.json",
}


def _latest_record_file(seal_id: str, record: object, pdf_path: str) -> str:
    """The record file of the stored record's last event, beside its PDF.

    Stage E, E2f: before, the sealing record's name was always proposed,
    so after an unsealing the case manager's unseal and reseal prefills
    proposed the sealing record (or a file that does not exist). An
    unknown step keeps the sealing name.
    """
    if not pdf_path:
        return ""
    template = _RECORD_FILE_NAMES.get(_last_step(record) or "Sealing")
    return str(Path(pdf_path).parent / template.format(seal_id=seal_id))


def _last_step(record: object) -> Optional[str]:
    """The last history event's ``seal_type``, else ``process_info.type``."""
    events = _history_events(record) or []
    last = events[-1] if events and isinstance(events[-1], dict) else {}
    if last.get("seal_type") in _RECORD_FILE_NAMES:
        return last["seal_type"]
    process_info = record.get("process_info") if isinstance(record, dict) else None
    step = process_info.get("type") if isinstance(process_info, dict) else None
    return step if step in _RECORD_FILE_NAMES else None


def get_sealable_cases(db_path: str) -> list[dict]:
    """Return cases that can be sealed (status is empty — pre-created cases)."""
    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        rows = conn.execute(
            """
            SELECT seal_id, case_number, suspect_name, investigator, created_at, status
            FROM seal_records
            WHERE status = '' OR status IS NULL
            ORDER BY created_at DESC
            """,
        ).fetchall()

    return [
        {
            "seal_id": row["seal_id"],
            "case_number": row["case_number"] or "",
            "suspect_name": row["suspect_name"] or "",
            "investigator": row["investigator"] or "",
            "created_at": row["created_at"],
            "status": row["status"] or "",
        }
        for row in rows
    ]


def get_unsealable_cases(db_path: str) -> list[dict]:
    """Return cases that can be unsealed (sealed but not yet unsealed)."""
    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        rows = conn.execute(
            """
            SELECT seal_id, case_number, suspect_name, investigator, created_at, status
            FROM seal_records
            WHERE status LIKE '%S1%' AND (status LIKE '%U0%' OR status NOT LIKE '%U%')
            ORDER BY created_at DESC
            """,
        ).fetchall()

    return [
        {
            "seal_id": row["seal_id"],
            "case_number": row["case_number"] or "",
            "suspect_name": row["suspect_name"] or "",
            "investigator": row["investigator"] or "",
            "created_at": row["created_at"],
            "status": row["status"] or "",
        }
        for row in rows
    ]


def get_resealable_cases(db_path: str) -> list[dict]:
    """Return cases that can be resealed (unsealed, status contains U1)."""
    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        rows = conn.execute(
            """
            SELECT seal_id, case_number, suspect_name, investigator, created_at, status
            FROM seal_records
            WHERE status LIKE '%U1%'
            ORDER BY created_at DESC
            """,
        ).fetchall()

    return [
        {
            "seal_id": row["seal_id"],
            "case_number": row["case_number"] or "",
            "suspect_name": row["suspect_name"] or "",
            "investigator": row["investigator"] or "",
            "created_at": row["created_at"],
            "status": row["status"] or "",
        }
        for row in rows
    ]


def get_seal_record(db_path: str, seal_id: str) -> Optional[dict]:
    """Retrieve a seal record by its ID.

    Returns:
        A dict with keys ``seal_id``, ``record_json`` (parsed),
        ``pdf_path``, ``created_at``, or None if not found.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM seal_records WHERE seal_id = ?",
            (seal_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "seal_id": row["seal_id"],
        "record_json": json.loads(row["record_json"]),
        "pdf_path": row["pdf_path"],
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# Dashboard queries
# ---------------------------------------------------------------------------


def get_dashboard_stats(db_path: str) -> dict:
    """Return seal / unseal / reseal counts for the dashboard.

    Returns:
        A dict with keys ``total``, ``sealed_only``, ``unsealed``, ``resealed``.
        ``sealed_only`` counts records where status contains U0 and R0
        (sealed but never unsealed/resealed).
    """
    result = {"total": 0, "sealed_only": 0, "unsealed": 0, "resealed": 0}
    if not db_path:
        return result

    try:
        with _connect(db_path) as conn:
            _ensure_case_columns(conn, db_path)
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status LIKE '%U0%' AND status LIKE '%R0%'
                        THEN 1 ELSE 0 END) AS sealed_only,
                    SUM(CASE WHEN status LIKE '%U%' AND status NOT LIKE '%U0%'
                        THEN 1 ELSE 0 END) AS unsealed,
                    SUM(CASE WHEN status LIKE '%R%' AND status NOT LIKE '%R0%'
                        THEN 1 ELSE 0 END) AS resealed
                FROM seal_records
                """
            ).fetchone()
            if row is not None:
                result["total"] = row["total"] or 0
                result["sealed_only"] = row["sealed_only"] or 0
                result["unsealed"] = row["unsealed"] or 0
                result["resealed"] = row["resealed"] or 0
    except Exception as exc:
        logger.warning("대시보드 통계 조회 실패: %s", exc)

    return result


def get_recent_cases(db_path: str, limit: int = 5) -> list[dict]:
    """Return the most recent N cases for the dashboard history.

    Each dict contains: seal_id, status, created_at.
    """
    if not db_path:
        return []

    try:
        with _connect(db_path) as conn:
            _ensure_case_columns(conn, db_path)
            rows = conn.execute(
                """
                SELECT seal_id, status, created_at
                FROM seal_records
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "seal_id": row["seal_id"],
                "status": row["status"] or "S1U0R0",
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    except Exception as exc:
        logger.warning("최근 케이스 조회 실패: %s", exc)
        return []


def get_expiring_seals(db_path: str, days: int = 3) -> list[dict]:
    """Return seals whose unlock_time is within N days from now.

    Parses ``unlock_time_iso`` from ``record_json``.
    Falls back to legacy ``unlock_time`` for older records.

    Each dict contains: seal_id, unlock_time.
    """
    if not db_path:
        return []

    try:
        with _connect(db_path) as conn:
            rows = conn.execute(
                "SELECT seal_id, record_json FROM seal_records"
            ).fetchall()
    except Exception as exc:
        logger.warning("만료 임박 봉인 조회 실패: %s", exc)
        return []

    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    threshold = now + timedelta(days=days)
    expiring: list[dict] = []

    for row in rows:
        try:
            record = json.loads(row["record_json"])
        except (json.JSONDecodeError, TypeError):
            continue

        unlock_str = (
            record.get("unlock_time_iso")
            or record.get("unlock_time")
            or ""
        )
        if not unlock_str:
            continue

        try:
            # Try ISO format with timezone
            unlock_dt = datetime.fromisoformat(unlock_str)
            if unlock_dt.tzinfo is None:
                unlock_dt = unlock_dt.replace(tzinfo=timezone.utc)
            if now <= unlock_dt <= threshold:
                expiring.append({
                    "seal_id": row["seal_id"],
                    "unlock_time": unlock_str,
                })
        except (ValueError, TypeError):
            continue

    return expiring


def get_key_share(
    db_path: str,
    seal_id: str,
    share_index: int,
) -> Optional[bytes]:
    """Retrieve a single encrypted key share.

    Args:
        db_path: Database file path.
        seal_id: The seal identifier.
        share_index: The share index (e.g. 3 or 4).

    Returns:
        The encrypted share bytes, or None if not found.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT share_data FROM key_shares WHERE seal_id = ? AND share_index = ?",
            (seal_id, share_index),
        ).fetchone()

    if row is None:
        return None

    return bytes(row["share_data"])
