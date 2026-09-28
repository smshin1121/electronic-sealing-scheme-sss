"""Sync outbox command line (stage E, E2a).

Usage (``src`` on ``PYTHONPATH``)::

    python -m desktop.sync [--db PATH] status
    python -m desktop.sync [--db PATH] retry [--seal SEAL_ID]

``status`` lists the queued records (seal, event, backend, status,
attempts, last attempt, last error; never their contents). ``retry`` pushes
the pending ones with the backends configured in the environment
(``ENC_ENVELOPE_SYNC_WEB_URL``; ``ENC_ENVELOPE_SYNC_PORTAL_URL`` and
``SYNC_SHARED_SECRET``) and the institutional key of
``ENC_ENVELOPE_POLICY_KEY_PATH`` / ``_CERT_PATH`` / ``_KEY_PASSWORD``;
every attempt is signed anew. The database defaults to the desktop
application's (``~/.enc_envelope/seal_system.db``).

Exit status: 0 done (``retry``: nothing left pending), 1 records left
pending or no database, 2 usage error.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

from .client import SyncClient
from .outbox import OutboxEntry

DEFAULT_DB_PATH = Path.home() / ".enc_envelope" / "seal_system.db"
_ERROR_WIDTH = 60


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m desktop.sync",
        description="봉인 기록 동기화 대기함(outbox)을 확인하고 다시 보냅니다.")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH),
                        help="데스크톱 DB 경로 (기본: %(default)s)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="대기함의 항목을 보여 줍니다.")
    retry = commands.add_parser("retry", help="대기 중인 항목을 다시 보냅니다.")
    retry.add_argument("--seal", default=None,
                       help="이 봉인 ID의 항목만 보냅니다.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Run the command; returns the exit status."""
    args = _parser().parse_args(argv)
    if not Path(args.db).is_file():
        sys.stderr.write(f"데스크톱 DB가 없습니다: {args.db}\n")
        return 1
    client = SyncClient.from_env(args.db)
    if args.command == "status":
        _print_status(client.entries())
        return 0
    summary = client.push_pending(seal_id=args.seal)
    sys.stdout.write(f"재전송 결과: sent={summary.sent} "
                     f"failed={summary.failed} pending={summary.pending}\n")
    return 0 if summary.pending == 0 else 1


def _print_status(entries: list[OutboxEntry]) -> None:
    header = ("id", "seal_id", "event", "type", "backend", "status",
              "attempts", "last_attempt", "last_error")
    rows = [header] + [
        (str(e.id), e.seal_id, str(e.event_id), e.event_type, e.backend,
         e.status, str(e.attempts), e.last_attempt_at or "-",
         _clip(e.last_error) or "-")
        for e in entries
    ]
    for row in rows:
        sys.stdout.write("  ".join(row) + "\n")
    pending = sum(1 for e in entries if e.status == "pending")
    sys.stdout.write(f"합계: {len(entries)}건 (pending={pending}, "
                     f"sent={len(entries) - pending})\n")


def _clip(text: str) -> str:
    return text if len(text) <= _ERROR_WIDTH else text[:_ERROR_WIDTH] + "..."


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    sys.exit(main())
