"""Named administrator accounts: table, service and CLI (stage E, E4).

Accounts live in ``admin_accounts`` (both schema variants). No default
account is created anywhere; the CLI (``python -m src.web.admin_accounts``)
creates, disables and lists accounts, reads the password with ``getpass``
or, with ``--password-stdin``, from one line of standard input, and never
echoes or logs it. Every password here is generated per test (synthetic).
"""

from __future__ import annotations

import io
import logging
import os
import secrets
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from tests.fixtures.release_web import make_release_app
from web.auth.passwords import verify_password

_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def app(tmp_path, monkeypatch):
    return make_release_app(tmp_path, monkeypatch)


def _password() -> str:
    return secrets.token_urlsafe(18)


def _run(
    app: Any,
    *argv: str,
    stdin: str = "",
    getpass_fn: Optional[Callable[[str], str]] = None,
) -> tuple[int, str, str]:
    from web.admin_accounts import main

    out, err = io.StringIO(), io.StringIO()
    extra = {"getpass_fn": getpass_fn} if getpass_fn else {}
    code = main(list(argv), app=app, stdin=io.StringIO(stdin), stdout=out,
                stderr=err, **extra)
    return code, out.getvalue(), err.getvalue()


def _create(app: Any, username: str, password: str) -> tuple[int, str, str]:
    return _run(app, "create", username, "--password-stdin",
                stdin=password + "\n")


def _accounts(app: Any) -> list:
    with app.app_context():
        from web.models.admin_models import list_admin_accounts

        return list_admin_accounts()


def _stored_hashes(app: Any) -> list[str]:
    with app.app_context():
        from web.models.db_models import get_db

        rows = get_db().execute(
            "SELECT password_hash FROM admin_accounts ORDER BY id").fetchall()
    return [row[0] for row in rows]


class TestAccountTable:
    def test_no_default_account_exists(self, app) -> None:
        assert _accounts(app) == []

    def test_sqlite_table_columns(self, app) -> None:
        with app.app_context():
            from web.models.db_models import get_db

            columns = [row[1] for row in get_db().execute(
                "PRAGMA table_info(admin_accounts)").fetchall()]

        assert columns == ["id", "username", "password_hash", "disabled",
                           "created_at", "disabled_at"]

    def test_both_schema_variants_declare_the_table(self) -> None:
        from web.models import db_models

        blocks = []
        for ddl in (db_models._SQLITE_SCHEMA, db_models._MARIADB_SCHEMA):
            head = "CREATE TABLE IF NOT EXISTS admin_accounts"
            assert head in ddl
            blocks.append(ddl.split(head, 1)[1].split(";", 1)[0])
        for block in blocks:
            for column in ("username", "password_hash", "disabled",
                           "created_at", "disabled_at", "UNIQUE"):
                assert column in block
        # Exact matching on MariaDB, as SQLite's default BINARY collation.
        assert "utf8mb4_bin" in blocks[1]


class TestCreate:
    def test_create_stores_a_scrypt_hash_not_the_password(self, app) -> None:
        password = _password()

        code, out, err = _create(app, "alice", password)

        assert code == 0, err
        assert "alice" in out
        [account] = _accounts(app)
        assert (account.username, account.disabled) == ("alice", False)
        assert account.created_at and account.disabled_at == ""
        [stored] = _stored_hashes(app)
        assert stored.startswith("scrypt$") and password not in stored
        assert verify_password(password, stored)
        assert account.password_hash == stored
        assert stored not in repr(account) and password not in repr(account)

    def test_same_password_gets_a_different_salt_per_account(self, app) -> None:
        password = _password()

        assert _create(app, "alice", password)[0] == 0
        assert _create(app, "bob", password)[0] == 0

        first, second = _stored_hashes(app)
        assert first.split("$")[4] != second.split("$")[4]
        assert first != second

    def test_short_password_is_refused(self, app) -> None:
        code, _out, err = _create(app, "alice", secrets.token_hex(6)[:11])

        assert code == 1
        assert "12" in err
        assert _accounts(app) == []

    def test_duplicate_username_is_refused(self, app) -> None:
        assert _create(app, "alice", _password())[0] == 0

        code, _out, err = _create(app, "ALICE", _password())

        assert code == 1
        assert "alice" in err
        assert len(_accounts(app)) == 1

    @pytest.mark.parametrize("name", [
        "", "ab", "a" * 65, "-alice", ".alice", "alice bob", "alice!",
        "관리자", "alice\nbob",
    ])
    def test_invalid_username_is_refused(self, app, name: str) -> None:
        code, _out, _err = _create(app, name, _password())

        assert code in (1, 2)
        assert _accounts(app) == []

    def test_username_is_normalized_to_lower_case(self, app) -> None:
        assert _create(app, "  Alice.Kim  ", _password())[0] == 0

        assert [a.username for a in _accounts(app)] == ["alice.kim"]

    def test_interactive_create_asks_twice(self, app) -> None:
        password = _password()
        prompts: list[str] = []
        answers = iter([password, password])

        def fake_getpass(prompt: str = "") -> str:
            prompts.append(prompt)
            return next(answers)

        code, _out, err = _run(app, "create", "alice", getpass_fn=fake_getpass)

        assert code == 0, err
        assert len(prompts) == 2
        assert verify_password(password, _stored_hashes(app)[0])

    def test_interactive_mismatch_is_refused(self, app) -> None:
        answers = iter([_password(), _password()])

        code, _out, _err = _run(app, "create", "alice",
                                getpass_fn=lambda prompt="": next(answers))

        assert code == 1
        assert _accounts(app) == []

    def test_empty_stdin_is_refused(self, app) -> None:
        code, _out, _err = _run(app, "create", "alice", "--password-stdin")

        assert code == 1
        assert _accounts(app) == []

    def test_only_the_line_terminator_is_stripped(self, app) -> None:
        password = " " + _password() + " "

        assert _run(app, "create", "alice", "--password-stdin",
                    stdin=password + "\r\n")[0] == 0

        assert verify_password(password, _stored_hashes(app)[0])

    def test_password_never_reaches_output_or_logs(self, app, caplog) -> None:
        caplog.set_level(logging.DEBUG)
        password = _password()
        answers = iter([password, password])

        results = [
            _create(app, "alice", password),
            _run(app, "create", "bob", getpass_fn=lambda prompt="": next(answers)),
            _create(app, "carol", password[:11]),
            _run(app, "list"),
            _run(app, "disable", "alice"),
        ]

        assert [code for code, _o, _e in results] == [0, 0, 1, 0, 0]
        # The 11-character prefix is also the refused short password, and
        # its absence implies the full password's absence.
        secret = password[:11]
        for _code, out, err in results:
            assert secret not in out
            assert secret not in err
        assert caplog.records, "nothing was captured; the check would be vacuous"
        for record in caplog.records:
            assert secret not in record.getMessage()


class TestDisableAndList:
    def test_disable_marks_the_account(self, app) -> None:
        assert _create(app, "alice", _password())[0] == 0

        code, out, err = _run(app, "disable", "alice")

        assert code == 0, err
        assert "alice" in out
        [account] = _accounts(app)
        assert account.disabled and account.disabled_at

    def test_disable_unknown_or_already_disabled_account_fails(self, app) -> None:
        assert _run(app, "disable", "nobody")[0] == 1
        assert _create(app, "alice", _password())[0] == 0
        assert _run(app, "disable", "alice")[0] == 0

        code, _out, err = _run(app, "disable", "alice")

        assert code == 1
        assert "alice" in err

    def test_list_shows_accounts_and_state_without_hashes(self, app) -> None:
        assert _create(app, "alice", _password())[0] == 0
        assert _create(app, "bob", _password())[0] == 0
        assert _run(app, "disable", "bob")[0] == 0

        code, out, _err = _run(app, "list")

        assert code == 0
        lines = out.strip().splitlines()
        assert any("alice" in line and "활성" in line and "비활성" not in line
                   for line in lines)
        assert any("bob" in line and "비활성" in line for line in lines)
        assert "scrypt$" not in out

    def test_list_with_no_account(self, app) -> None:
        code, out, _err = _run(app, "list")

        assert code == 0
        assert "없습니다" in out


class TestBackendSafety:
    def test_refuses_a_sqlite_fallback_when_mariadb_is_configured(
        self, tmp_path, monkeypatch
    ) -> None:
        from web import admin_accounts
        from web.config import TestingConfig
        from web.models import db_models

        fallback = tmp_path / "fallback.db"
        monkeypatch.setattr(TestingConfig, "USE_SQLITE", False)
        monkeypatch.setattr(TestingConfig, "SQLITE_PATH", str(fallback))

        def unreachable(_app: Any) -> Any:
            raise RuntimeError("synthetic: MariaDB unreachable")

        monkeypatch.setattr(db_models, "_connect_mariadb", unreachable)
        monkeypatch.setattr(db_models, "_HAS_MARIADB", True)
        out, err = io.StringIO(), io.StringIO()

        code = admin_accounts.main(
            ["--env", "testing", "create", "alice", "--password-stdin"],
            stdin=io.StringIO(_password() + "\n"), stdout=out, stderr=err,
        )

        assert code == 1
        assert "MariaDB" in err.getvalue()
        if fallback.exists():
            with sqlite3.connect(fallback) as conn:
                tables = {row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
            assert "admin_accounts" not in tables


class TestModuleEntryPoint:
    def test_python_m_creates_and_lists_without_echo(self, tmp_path) -> None:
        env = {**os.environ, "USE_SQLITE": "true",
               "SQLITE_PATH": str(tmp_path / "cli.db"),
               "FLASK_ENV": "testing", "PYTHONIOENCODING": "utf-8"}
        env.pop("ADMIN_PASSWORD", None)
        password = _password()

        def run(*args: str, stdin: str = "") -> subprocess.CompletedProcess:
            return subprocess.run(
                [sys.executable, "-m", "src.web.admin_accounts", *args],
                input=stdin, capture_output=True, text=True, encoding="utf-8",
                cwd=_REPO_ROOT, env=env, timeout=180,
            )

        created = run("create", "carol", "--password-stdin", stdin=password + "\n")
        listed = run("list")

        assert created.returncode == 0, created.stderr
        assert listed.returncode == 0, listed.stderr
        assert "carol" in listed.stdout
        for stream in (created.stdout, created.stderr, listed.stdout,
                       listed.stderr):
            assert password not in stream
