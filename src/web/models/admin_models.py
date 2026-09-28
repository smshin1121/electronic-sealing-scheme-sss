"""Persistence for named administrator accounts (``admin_accounts``).

Both schema variants live in :mod:`web.models.db_models`. Rows are read
back as frozen :class:`AdminAccount` objects whose password hash is kept
out of ``repr``. There is deliberately no delete or rename helper, so
within this codebase a username keeps naming one account and the
``operator`` recorded in ``release_audit`` keeps pointing at that account
(an account, not a person; this is a convention of the code, not a
database constraint). Accounts are retired by disabling them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from flask import g

from .db_models import execute_query, get_db

_FIELDS = ("id", "username", "password_hash", "disabled", "created_at",
           "disabled_at")
_SELECT = "SELECT " + ", ".join(_FIELDS) + " FROM admin_accounts"


@dataclass(frozen=True)
class AdminAccount:
    """One administrator account."""

    id: int
    username: str
    disabled: bool
    created_at: str
    disabled_at: str = ""
    password_hash: str = field(default="", repr=False)


def insert_admin_account(username: str, password_hash: str, created_at: str) -> int:
    """Insert an enabled account; the UNIQUE constraint refuses a duplicate."""
    return execute_query(
        """INSERT INTO admin_accounts (username, password_hash, created_at)
           VALUES (?, ?, ?)""",
        (username, password_hash, created_at),
    )


def find_admin_account_by_username(username: str) -> Optional[AdminAccount]:
    """The account with this exact username, if any."""
    row = execute_query(_SELECT + " WHERE username = ?", (username,),
                        fetch_one=True)
    return _to_account(row) if row is not None else None


def find_admin_account_by_id(account_id: int) -> Optional[AdminAccount]:
    """The account with this id, if any."""
    row = execute_query(_SELECT + " WHERE id = ?", (account_id,), fetch_one=True)
    return _to_account(row) if row is not None else None


def list_admin_accounts() -> list[AdminAccount]:
    """Every account, oldest first."""
    rows = execute_query(_SELECT + " ORDER BY id", fetch_all=True) or []
    return [_to_account(row) for row in rows]


def count_enabled_admin_accounts() -> int:
    """How many accounts can log in."""
    row = execute_query(
        "SELECT COUNT(*) FROM admin_accounts WHERE disabled = 0", fetch_one=True
    )
    return int(row[0]) if row is not None else 0


def mark_admin_account_disabled(username: str, disabled_at: str) -> bool:
    """Disable an enabled account; True when a row changed."""
    db = get_db()
    mark = "%s" if g.get("db_type", "sqlite") == "mariadb" else "?"
    cursor = db.cursor()
    try:
        cursor.execute(
            f"""UPDATE admin_accounts SET disabled = 1, disabled_at = {mark}
                WHERE username = {mark} AND disabled = 0""",
            (disabled_at, username),
        )
        changed = cursor.rowcount == 1
        db.commit()
        return changed
    except Exception:
        db.rollback()
        raise
    finally:
        cursor.close()


def _to_account(row: Any) -> AdminAccount:
    values = ({name: row[name] for name in _FIELDS} if hasattr(row, "keys")
              else dict(zip(_FIELDS, row)))
    return AdminAccount(
        id=int(values["id"]),
        username=str(values["username"]),
        disabled=bool(values["disabled"]),
        created_at=str(values["created_at"]),
        disabled_at=str(values["disabled_at"] or ""),
        password_hash=str(values["password_hash"]),
    )
