"""Manage named administrator accounts of the reference web app (stage E, E4).

Run from the repository root, with the same environment as the web app
(``FLASK_ENV``, ``USE_SQLITE``/``SQLITE_PATH`` or ``DB_*``)::

    python -m src.web.admin_accounts create <username>
    python -m src.web.admin_accounts create <username> --password-stdin
    python -m src.web.admin_accounts disable <username>
    python -m src.web.admin_accounts list

No account exists until one is created here. ``create`` asks for the
password twice with :func:`getpass.getpass` (no echo); ``--password-stdin``
reads it from the first line of standard input instead, for scripts. The
password is never printed or logged. The tool refuses to run when the
configuration asks for MariaDB but the connection helper fell back to
SQLite, so that an account is never created in the wrong database.

Exit status: 0 done, 1 refused, 2 usage error.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Callable, Optional, Sequence, TextIO

from flask import Flask

from .auth.admin_auth import (
    AccountError,
    create_admin_account,
    disable_admin_account,
)
from .cli_support import BackendError, build_cli_app, open_backend
from .models.admin_models import list_admin_accounts

EXIT_OK = 0
EXIT_REFUSED = 1

_PROMPT = "새 관리자 비밀번호: "
_PROMPT_AGAIN = "비밀번호 확인: "


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    app: Optional[Flask] = None,
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
    getpass_fn: Callable[[str], str] = getpass.getpass,
) -> int:
    """Run one command; returns the exit status."""
    out, err = stdout or sys.stdout, stderr or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse has printed the usage error
        return int(exc.code or 0)
    target = app or build_cli_app(args.env)
    with target.app_context():
        try:
            err.write(f"데이터베이스: {open_backend(target)}\n")
            return _dispatch(args, stdin or sys.stdin, out, getpass_fn)
        except (AccountError, BackendError) as exc:
            err.write(f"{exc}\n")
            return EXIT_REFUSED


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.web.admin_accounts",
        description="참조 웹 앱의 관리자 계정을 만들고, 비활성화하고, 나열합니다.",
    )
    parser.add_argument("--env", choices=("development", "production", "testing"),
                        help="설정 환경 (기본: FLASK_ENV, 없으면 development)")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="관리자 계정 만들기")
    create.add_argument("username")
    create.add_argument("--password-stdin", action="store_true",
                        help="비밀번호를 표준 입력의 첫 줄에서 읽기")
    disable = commands.add_parser("disable", help="관리자 계정 비활성화")
    disable.add_argument("username")
    commands.add_parser("list", help="관리자 계정 나열")
    return parser


def _dispatch(
    args: argparse.Namespace, stdin: TextIO, out: TextIO,
    getpass_fn: Callable[[str], str],
) -> int:
    if args.command == "create":
        password = _read_password(args.password_stdin, stdin, getpass_fn)
        account = create_admin_account(args.username, password)
        out.write(f"관리자 계정을 만들었습니다: {account.username} (id {account.id})\n")
    elif args.command == "disable":
        account = disable_admin_account(args.username)
        out.write(f"관리자 계정을 비활성화했습니다: {account.username}\n")
    else:
        _print_accounts(out)
    return EXIT_OK


def _read_password(
    from_stdin: bool, stdin: TextIO, getpass_fn: Callable[[str], str]
) -> str:
    """One line of stdin (only its terminator stripped), or getpass twice."""
    if from_stdin:
        password = stdin.readline().rstrip("\r\n")
        if not password:
            raise AccountError("표준 입력에서 비밀번호를 읽지 못했습니다.")
        return password
    first = getpass_fn(_PROMPT)
    if getpass_fn(_PROMPT_AGAIN) != first:
        raise AccountError("두 비밀번호가 일치하지 않습니다.")
    return first


def _print_accounts(out: TextIO) -> None:
    accounts = list_admin_accounts()
    if not accounts:
        out.write("관리자 계정이 없습니다.\n")
        return
    out.write("id\t계정명\t상태\t만든 시각\t비활성화 시각\n")
    for account in accounts:
        state = "비활성" if account.disabled else "활성"
        out.write(f"{account.id}\t{account.username}\t{state}\t"
                  f"{account.created_at}\t{account.disabled_at or '-'}\n")


if __name__ == "__main__":
    sys.exit(main())
