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
from typing import Iterator, Optional

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
) -> None:
    """Save a seal record (JSON + PDF path).

    Args:
        db_path: Database file path.
        seal_id: The seal identifier.
        record_json: JSON-serialized seal record.
        pdf_path: Absolute path to the generated PDF file.
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")
    if not record_json:
        raise ValueError("기록 JSON이 비어 있을 수 없습니다.")

    # Validate JSON structure
    try:
        json.loads(record_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"유효하지 않은 JSON입니다: {exc}") from exc

    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO seal_records (seal_id, record_json, pdf_path)
            VALUES (?, ?, ?)
            """,
            (seal_id, record_json, pdf_path),
        )
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
) -> None:
    """Persist a seal record, key shares, and certificate atomically.

    All inserts run inside a single transaction so a failure in any
    statement rolls back the whole bundle (no partial seal state).

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
    """
    if not seal_id:
        raise ValueError("seal_id는 비어 있을 수 없습니다.")
    if not record_json:
        raise ValueError("기록 JSON이 비어 있을 수 없습니다.")
    if not shares:
        raise ValueError("저장할 키 조각이 없습니다.")

    try:
        json.loads(record_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"유효하지 않은 JSON입니다: {exc}") from exc

    with _connect(db_path) as conn:
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
    logger.info(
        "봉인 번들 저장 완료: seal_id=%s, shares=%s, cert=%s",
        seal_id, list(shares.keys()), bool(cert_pem),
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


def create_case(
    db_path: str,
    case_number: str,
    investigator: str,
    suspect_name: str = "",
) -> str:
    """Create a new case (before sealing). Generates and returns a seal_id.

    Inserts a row into seal_records with empty record_json and pdf_path
    so the case appears in the case list immediately.
    """
    import uuid

    if not case_number:
        raise ValueError("case_number는 비어 있을 수 없습니다.")
    if not investigator:
        raise ValueError("investigator는 비어 있을 수 없습니다.")

    seal_id = f"SEAL-{uuid.uuid4().hex[:12].upper()}"
    empty_record = json.dumps({
        "case_info": {
            "case_number": case_number,
            "investigator": investigator,
            "suspect": suspect_name,
        },
    })

    with _connect(db_path) as conn:
        _ensure_case_columns(conn, db_path)
        conn.execute(
            """
            INSERT INTO seal_records
                (seal_id, record_json, pdf_path, case_number, suspect_name, investigator, status)
            VALUES (?, ?, '', ?, ?, ?, '')
            """,
            (seal_id, empty_record, case_number, suspect_name, investigator),
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

    # Derive record JSON path from pdf_path
    pdf_path = row["pdf_path"] or ""
    if pdf_path:
        json_path = str(Path(pdf_path).parent / f"{seal_id}_record.json")
        result["record_json_path"] = json_path
    else:
        result["record_json_path"] = ""

    return result


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
