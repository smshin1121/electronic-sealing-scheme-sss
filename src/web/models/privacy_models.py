"""Persistence for identity protection (stage E, E3a).

Tables: ``seal_data_keys`` and ``identity_access_audit`` (DDL in
:mod:`web.models.privacy_schema`) and the protected columns of ``cases``
(``suspect_{name,birth,phone}_digest``, ``suspect_{name,email}_enc``,
``identity_scheme``; DDL in :mod:`web.models.db_models`).

No function here writes a plaintext identity value: a new case row gets
'' in ``suspect_name``, ``suspect_email``, ``suspect_birth`` and
``suspect_phone``, and ``identity_scheme = 'v1'``. Rows are read with
explicit column lists and mapped by position (MariaDB returns tuples).
The access audit is application-level: no helper updates or deletes its
rows, but the database does not enforce append-only behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from flask import g

from .db_models import execute_query, get_db

IDENTITY_SCHEME_V1 = "v1"
PLAINTEXT_IDENTITY_COLUMNS = (
    "suspect_name", "suspect_email", "suspect_birth", "suspect_phone",
)
# The identity fields that are stored encrypted, and their columns.
ENCRYPTED_FIELDS = {"suspect_name": "suspect_name_enc",
                    "suspect_email": "suspect_email_enc"}
ACTOR_ROLES = ("subject", "admin", "system")
OUTCOME_REVEALED = "revealed"
OUTCOME_FAILED = "failed"

_CASE_IDENTITY_COLUMNS = (
    "seal_id", "auth_level", "password_hash", "suspect_name_digest",
    "suspect_birth_digest", "suspect_phone_digest", "suspect_name_enc",
    "suspect_email_enc", "identity_scheme",
)
_SELECT_CASE_IDENTITY = (
    "SELECT " + ", ".join(_CASE_IDENTITY_COLUMNS) + " FROM cases WHERE seal_id = ?"
)
_INSERT_CASE = """INSERT INTO cases
    (seal_id, case_number, investigator, suspect_name, suspect_email,
     suspect_birth, suspect_phone, auth_level, password_hash,
     suspect_name_digest, suspect_birth_digest, suspect_phone_digest,
     suspect_name_enc, suspect_email_enc, identity_scheme)
    VALUES (?, ?, ?, '', '', '', '', ?, ?, ?, ?, ?, ?, ?, ?)"""
INSERT_DATA_KEY = (
    "INSERT INTO seal_data_keys (seal_id, wrapped_key, created_at) VALUES (?, ?, ?)"
)
_SELECT_DATA_KEY = "SELECT wrapped_key FROM seal_data_keys WHERE seal_id = ?"
# Whether data of a seal is stored under its data key (see find_data_key_use).
_SELECT_DATA_KEY_USE = (
    "SELECT CASE WHEN LENGTH(identity_scheme) > 0 OR LENGTH(suspect_name_enc) > 0 "
    "OR LENGTH(suspect_email_enc) > 0 THEN 1 ELSE 0 END, "
    "(SELECT COUNT(*) FROM seal_records WHERE seal_records.seal_id = cases.seal_id "
    "AND LENGTH(seal_records.record_scheme) > 0) "
    "FROM cases WHERE seal_id = ?"
)
_AUDIT_COLUMNS = (
    "seal_id", "field", "purpose", "actor_role", "actor", "client_address",
    "outcome", "created_at",
)
INSERT_ACCESS_AUDIT = (
    "INSERT INTO identity_access_audit (" + ", ".join(_AUDIT_COLUMNS)
    + ") VALUES (" + ", ".join("?" for _ in _AUDIT_COLUMNS) + ")"
)
_SELECT_ACCESS_AUDIT = (
    "SELECT id, " + ", ".join(_AUDIT_COLUMNS)
    + " FROM identity_access_audit WHERE seal_id = ? ORDER BY id"
)
_REPLACE_PASSWORD_HASH = (
    "UPDATE cases SET password_hash = ? WHERE seal_id = ? AND password_hash = ?"
)
# created_at is ISO 8601 UTC to the second, written by the app, so the
# text comparison orders it correctly.
_COUNT_RECENT_ACCESS = (
    "SELECT COUNT(*) FROM identity_access_audit WHERE seal_id = ? "
    "AND purpose = ? AND outcome = ? AND created_at >= ?"
)


@dataclass(frozen=True)
class ProtectedIdentity:
    """The stored form of a subject's identity: digests and ciphertexts."""

    name_digest: str = ""
    birth_digest: str = ""
    phone_digest: str = ""
    name_enc: str = ""
    email_enc: str = ""


@dataclass(frozen=True)
class NewCase:
    """A case row to insert (the identity already protected)."""

    seal_id: str
    case_number: str
    investigator: str
    auth_level: str
    password_hash: str = field(repr=False)
    identity: ProtectedIdentity = field(default_factory=ProtectedIdentity)


@dataclass(frozen=True)
class CaseIdentityRow:
    """The columns of a case that the subject routes need."""

    seal_id: str
    auth_level: str
    password_hash: str = field(repr=False)
    identity: ProtectedIdentity = field(default_factory=ProtectedIdentity)
    identity_scheme: str = ""

    def as_auth_case(self) -> dict[str, Any]:
        """The case as the authentication chain reads it (column names)."""
        return {
            "seal_id": self.seal_id,
            "auth_level": self.auth_level,
            "password_hash": self.password_hash,
            "suspect_name_digest": self.identity.name_digest,
            "suspect_birth_digest": self.identity.birth_digest,
            "suspect_phone_digest": self.identity.phone_digest,
            "identity_scheme": self.identity_scheme,
        }


@dataclass(frozen=True)
class IdentityAccessEntry:
    """One decryption of a protected identity field (never its value)."""

    seal_id: str
    field_name: str
    purpose: str
    actor_role: str
    outcome: str
    created_at: str
    actor: str = ""
    client_address: str = ""

    def params(self) -> tuple[str, ...]:
        """Values in the order of the audit table's columns."""
        return (self.seal_id, self.field_name, self.purpose, self.actor_role,
                self.actor[:64], self.client_address[:45], self.outcome,
                self.created_at)


def insert_protected_case(case: NewCase, wrapped_key: bytes, created_at: str) -> int:
    """Insert the case row and its wrapped data key in one transaction.

    Any error rolls back both inserts, so a case never exists without its
    data key.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(dialect_sql(_INSERT_CASE), (
            case.seal_id, case.case_number, case.investigator, case.auth_level,
            case.password_hash, case.identity.name_digest,
            case.identity.birth_digest, case.identity.phone_digest,
            case.identity.name_enc, case.identity.email_enc, IDENTITY_SCHEME_V1,
        ))
        case_id = cursor.lastrowid
        cursor.execute(dialect_sql(INSERT_DATA_KEY),
                       (case.seal_id, wrapped_key, created_at))
        db.commit()
        return case_id
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()


def find_case_identity(seal_id: str) -> Optional[CaseIdentityRow]:
    """The protected identity columns of a case, or ``None``."""
    row = execute_query(_SELECT_CASE_IDENTITY, (seal_id,), fetch_one=True)
    if row is None:
        return None
    values = tuple(row)
    return CaseIdentityRow(
        seal_id=values[0], auth_level=values[1], password_hash=values[2],
        identity=ProtectedIdentity(*values[3:8]), identity_scheme=values[8],
    )


def find_wrapped_data_key(seal_id: str) -> Optional[bytes]:
    """The wrapped data key of a seal, or ``None``."""
    row = execute_query(_SELECT_DATA_KEY, (seal_id,), fetch_one=True)
    return None if row is None else bytes(tuple(row)[0])


@dataclass(frozen=True)
class DataKeyUse:
    """What of a seal's data is stored under its data key (no values)."""

    identity_protected: bool
    protected_records: int

    @property
    def protected(self) -> bool:
        """Whether anything of the seal needs its existing data key."""
        return self.identity_protected or self.protected_records > 0


def find_data_key_use(seal_id: str) -> Optional[DataKeyUse]:
    """Whether a seal holds data under its data key; ``None`` without a case.

    The case identity counts as protected when ``identity_scheme`` or either
    identity ciphertext column is non-empty; a record counts when its
    ``record_scheme`` is non-empty (``LENGTH() > 0``, so MariaDB's
    trailing-space rules cannot hide a value). Any such value, even one
    written by hand, means the seal's key must not be replaced. Call under
    the seal's write lock.
    """
    row = execute_query(_SELECT_DATA_KEY_USE, (seal_id,), fetch_one=True)
    if row is None:
        return None
    identity, records = tuple(row)
    return DataKeyUse(identity_protected=bool(identity), protected_records=int(records))


def find_encrypted_field(seal_id: str, field_name: str) -> Optional[str]:
    """The stored ciphertext of one encrypted identity field ('' if empty).

    Raises:
        ValueError: ``field_name`` is not an encrypted identity field.
    """
    column = ENCRYPTED_FIELDS.get(field_name)
    if column is None:
        raise ValueError(f"not an encrypted identity field: {field_name!r}")
    row = execute_query(f"SELECT {column} FROM cases WHERE seal_id = ?",
                        (seal_id,), fetch_one=True)
    return None if row is None else tuple(row)[0]


def insert_identity_access(entry: IdentityAccessEntry) -> int:
    """Append one access-audit row (committed); returns its id."""
    return execute_query(INSERT_ACCESS_AUDIT, entry.params())


def find_identity_access(seal_id: str) -> list[dict[str, Any]]:
    """All access-audit rows of a seal, oldest first."""
    rows = execute_query(_SELECT_ACCESS_AUDIT, (seal_id,), fetch_all=True) or []
    names = ("id",) + _AUDIT_COLUMNS
    return [dict(zip(names, tuple(row))) for row in rows]


def count_recent_reveals(seal_id: str, purpose: str, since_iso: str) -> int:
    """Successful decryptions of a seal for ``purpose`` at or after ``since_iso``."""
    return _count(_COUNT_RECENT_ACCESS, (seal_id, purpose, OUTCOME_REVEALED, since_iso))


def replace_case_password_hash(seal_id: str, new_hash: str, expected_hash: str) -> bool:
    """Replace a case's password hash if it is still ``expected_hash``."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(dialect_sql(_REPLACE_PASSWORD_HASH),
                       (new_hash, seal_id, expected_hash))
        replaced = cursor.rowcount == 1
        db.commit()
        return replaced
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()


def dialect_sql(statement: str) -> str:
    """``?`` placeholders for SQLite, ``%s`` for MariaDB."""
    if g.get("db_type", "sqlite") == "mariadb":
        return statement.replace("?", "%s")
    return statement


# ---------------------------------------------------------------------------
# Conversion of existing rows (web.privacy.migrate). The writers below do
# not commit: they run inside release_models.seal_write_transaction.
# ---------------------------------------------------------------------------
_SURVEY_CASES = "SELECT id, seal_id, identity_scheme FROM cases ORDER BY id"
# LENGTH() > 0, not <> '': MariaDB's PAD SPACE collations treat '  ' as ''.
_PLAINTEXT_PRESENT = " OR ".join(
    f"LENGTH({column}) > 0" for column in PLAINTEXT_IDENTITY_COLUMNS
)
_COUNT_PLAINTEXT_ROWS = f"SELECT COUNT(*) FROM cases WHERE {_PLAINTEXT_PRESENT}"
_SELECT_LEGACY_IDENTITY = (
    "SELECT id, seal_id, identity_scheme, suspect_name, suspect_email, "
    "suspect_birth, suspect_phone FROM cases WHERE id = ?"
)
_SELECT_PROTECTED_IDENTITY = (
    "SELECT suspect_name_digest, suspect_birth_digest, suspect_phone_digest, "
    "suspect_name_enc, suspect_email_enc FROM cases WHERE id = ?"
)
_WRITE_PROTECTED_IDENTITY = (
    "UPDATE cases SET suspect_name_digest = ?, suspect_birth_digest = ?, "
    "suspect_phone_digest = ?, suspect_name_enc = ?, suspect_email_enc = ? "
    "WHERE id = ?"
)
_BLANK_PLAINTEXT_IDENTITY = (
    "UPDATE cases SET suspect_name = '', suspect_email = '', "
    "suspect_birth = '', suspect_phone = '', identity_scheme = ? WHERE id = ?"
)


@dataclass(frozen=True)
class CaseSurveyRow:
    """A case row as the migration lists it (no identity values)."""

    case_id: int
    seal_id: str
    identity_scheme: str


@dataclass(frozen=True)
class LegacyIdentity:
    """The plaintext identity of a row still to convert."""

    case_id: int
    seal_id: str
    identity_scheme: str
    name: str = field(repr=False)
    email: str = field(repr=False)
    birth: str = field(repr=False)
    phone: str = field(repr=False)


def survey_cases() -> list[CaseSurveyRow]:
    """Every case row's id, seal ID and identity scheme, by id."""
    rows = execute_query(_SURVEY_CASES, fetch_all=True) or []
    return [CaseSurveyRow(*tuple(row)) for row in rows]


def count_plaintext_identity_rows() -> int:
    """Case rows with any non-empty plaintext identity column."""
    return _count(_COUNT_PLAINTEXT_ROWS)


def count_user_rows() -> int:
    """Rows of the ``users`` table (declared in v1.0.1, never written)."""
    return _count("SELECT COUNT(*) FROM users")


def read_legacy_identity(case_id: int) -> Optional[LegacyIdentity]:
    """The plaintext identity of one case row (inside the transaction)."""
    row = execute_query(_SELECT_LEGACY_IDENTITY, (case_id,), fetch_one=True)
    if row is None:
        return None
    values = tuple(row)
    return LegacyIdentity(*values[:3], *((value or "") for value in values[3:]))


def read_protected_identity(case_id: int) -> ProtectedIdentity:
    """The protected identity columns of one case row, as stored."""
    row = execute_query(_SELECT_PROTECTED_IDENTITY, (case_id,), fetch_one=True)
    return ProtectedIdentity(*tuple(row))


def write_protected_identity(case_id: int, identity: ProtectedIdentity) -> None:
    """Store digests and ciphertexts on a row (no commit)."""
    _execute_uncommitted(_WRITE_PROTECTED_IDENTITY, (
        identity.name_digest, identity.birth_digest, identity.phone_digest,
        identity.name_enc, identity.email_enc, case_id,
    ))


def blank_plaintext_identity(case_id: int) -> None:
    """Empty the plaintext identity columns and mark the row 'v1' (no commit)."""
    _execute_uncommitted(_BLANK_PLAINTEXT_IDENTITY, (IDENTITY_SCHEME_V1, case_id))


def insert_data_key_uncommitted(seal_id: str, wrapped_key: bytes, created_at: str) -> None:
    """Store a seal's wrapped data key (no commit)."""
    _execute_uncommitted(INSERT_DATA_KEY, (seal_id, wrapped_key, created_at))


def insert_identity_access_uncommitted(entry: IdentityAccessEntry) -> None:
    """Append an access-audit row (no commit)."""
    _execute_uncommitted(INSERT_ACCESS_AUDIT, entry.params())


def _count(statement: str, params: tuple[Any, ...] = ()) -> int:
    row = execute_query(statement, params, fetch_one=True)
    return 0 if row is None else int(tuple(row)[0])


def _execute_uncommitted(statement: str, params: tuple[Any, ...]) -> int:
    cursor = get_db().cursor()
    try:
        cursor.execute(dialect_sql(statement), params)
        return cursor.rowcount
    finally:
        cursor.close()
