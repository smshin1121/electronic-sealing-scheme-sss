"""Convert existing ``cases`` rows to the protected identity form (E3a).

Run from the repository root with the web app's environment (``FLASK_ENV``,
``USE_SQLITE``/``SQLITE_PATH`` or ``DB_*``, and the two identity-protection
keys) and, as for the web app itself, ``src`` on the import path::

    PYTHONPATH=src python -m src.web.privacy.migrate --dry-run
    PYTHONPATH=src python -m src.web.privacy.migrate --apply

``--apply`` converts every row whose identity is still in plaintext
(``identity_scheme != 'v1'``), each in one transaction with the case row
locked (:func:`web.models.release_models.seal_write_transaction`):

  1. unwrap the seal's data key, or create and store one -- but only for a
     seal with nothing protected yet: a seal whose records are protected
     and whose key row is missing is refused, not given a new key (the
     run names it; restore the key row from a backup);
  2. write the keyed digests of name, birth date and phone and the
     ciphertexts of name and e-mail;
  3. read the row back and verify the round trip: each digest equals a
     fresh digest of the plaintext, and each ciphertext decrypts to it
     (one ``identity_access_audit`` row per decryption: purpose
     ``migration_verify``, actor role ``system``, actor ``privacy-migrate``,
     written in the same transaction);
  4. blank the four plaintext columns and set ``identity_scheme = 'v1'``.

A row that fails any step is rolled back, keeps its plaintext and is
reported by seal ID; the run then exits 1. Converted rows are never
touched again, so a second run changes no row.

``--apply`` then converts the synced seal records stored before E3b
(``seal_records.record_scheme <> 'v1'``): each row's ``record_json`` and
``record_pdf`` are encrypted under the seal's data key, read back and
verified byte for byte, and only then committed in place of the
plaintext (:mod:`web.privacy.record_migration`). A row whose seal has no
case is reported and skipped; the run then exits 1.

On SQLite ``--apply`` converts with ``secure_delete`` on and ends by
checkpointing and vacuuming the file. Every WAL checkpoint's result is
checked, and the WAL must end truncated: only then does the run report the
file clean. While another connection (the running web app, for example)
keeps an older snapshot, the old pages cannot be removed; the run then
says so and exits 1, and rerunning ``--apply`` once the database is
quiescent scrubs again. A VACUUM failure is reported the same way. On
MariaDB, earlier copies can remain in InnoDB pages, logs and backups (the
run says so).
``--dry-run`` only counts. Both modes first run the idempotent schema step of the app's
start-up (adding missing columns and tables). No identity value and no
record content is ever printed or logged.

Exit status: 0 done, 1 refused or a row failed, 2 usage error.
"""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import sys
from typing import Optional, Sequence, TextIO

from flask import Flask, g

from ..cli_support import BackendError, build_cli_app, open_backend
from ..models.db_models import get_db
from ..models.privacy_models import (
    ENCRYPTED_FIELDS,
    IDENTITY_SCHEME_V1,
    OUTCOME_REVEALED,
    IdentityAccessEntry,
    LegacyIdentity,
    blank_plaintext_identity,
    count_plaintext_identity_rows,
    count_user_rows,
    insert_identity_access_uncommitted,
    read_legacy_identity,
    read_protected_identity,
    survey_cases,
    write_protected_identity,
)
from ..models.release_models import seal_write_transaction
from .case_identity import (
    CASES_TABLE,
    PURPOSE_MIGRATION_CHECK,
    protect_identity,
    utc_now_iso,
)
from .digests import FIELD_BIRTH, FIELD_NAME, FIELD_PHONE, identity_digest
from .field_crypto import decrypt_field
from .keys import (
    PrivacyConfigError,
    PrivacyKeys,
    PrivacyUnavailable,
    load_privacy_keys,
    validate_privacy_config,
)
from .record_migration import (
    KEY_MISSING,
    convert_records,
    write_missing_keys,
    write_results,
    write_survey,
)
from .record_store import data_key_for_write

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_REFUSED = 1
ACTOR = "privacy-migrate"


class RoundTripError(Exception):
    """A converted row does not read back as its plaintext (no values here)."""


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    app: Optional[Flask] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Run the conversion (or the count); returns the exit status."""
    out, err = stdout or sys.stdout, stderr or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse has printed the usage error
        return int(exc.code or 0)
    target = app or build_cli_app(args.env)
    with target.app_context():
        try:
            validate_privacy_config(target.config)
            keys = load_privacy_keys(target.config)
            err.write(f"데이터베이스: {open_backend(target)}\n")
        except (PrivacyConfigError, PrivacyUnavailable):
            err.write("개인정보 보호 키(IDENTITY_PEPPER_PATH, PRIVACY_KMS_MASTER_KEY_PATH)가 "
                      "설정되지 않았거나 쓸 수 없어 중단합니다.\n")
            return EXIT_REFUSED
        except BackendError as exc:
            err.write(f"{exc}\n")
            return EXIT_REFUSED
        return _migrate(keys, apply=args.apply, out=out)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.web.privacy.migrate",
        description="사건 표의 평문 신원과 동기화된 봉인 기록(JSON·PDF)을 "
                    "다이제스트·암호문으로 바꾸고 평문을 지웁니다.",
    )
    parser.add_argument("--env", choices=("development", "production", "testing"),
                        help="설정 환경 (기본: FLASK_ENV, 없으면 development)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="세기만 하고 바꾸지 않기")
    mode.add_argument("--apply", action="store_true", help="변환하기")
    return parser


def _migrate(keys: PrivacyKeys, *, apply: bool, out: TextIO) -> int:
    cases = survey_cases()
    pending = [row for row in cases if row.identity_scheme != IDENTITY_SCHEME_V1]
    out.write(f"사건 {len(cases)}건: 보호됨 {len(cases) - len(pending)}건, "
              f"변환 대상 {len(pending)}건\n")
    out.write(f"users 표: {count_user_rows()}건 (이 표에 쓰는 코드가 없어 변환 대상이 아닙니다)\n")
    write_survey(out)
    if not apply:
        out.write("세기만 했습니다 (--dry-run). 변환하려면 --apply로 실행해 주세요.\n")
        return EXIT_OK
    if g.get("db_type") == "sqlite":
        # Zero the space the blanked values free, from the first row on.
        get_db().execute("PRAGMA secure_delete = ON")
    failed = [row.seal_id for row in pending if not _convert(row.case_id, row.seal_id, keys)]
    record_outcomes = convert_records(keys)
    scrubbed = _scrub_old_copies(out)
    remaining = count_plaintext_identity_rows()
    out.write(f"변환 {len(pending) - len(failed)}건, 실패 {len(failed)}건\n")
    for seal_id in failed:
        out.write(f"  실패 (평문 유지): {seal_id!r}\n")
    out.write(f"평문 신원이 남은 사건 행: {remaining}건\n")
    records_done = write_results(record_outcomes, out)
    write_missing_keys(failed + [o.seal_id for o in record_outcomes
                                 if o.status == KEY_MISSING], out)
    ok = scrubbed and not failed and remaining == 0 and records_done
    return EXIT_OK if ok else EXIT_REFUSED


def _convert(case_id: int, seal_id: str, keys: PrivacyKeys) -> bool:
    """Convert one row in one transaction; False (rolled back) on any error."""
    try:
        with seal_write_transaction(seal_id):
            legacy = read_legacy_identity(case_id)
            if legacy is None or legacy.identity_scheme == IDENTITY_SCHEME_V1:
                return True  # removed or converted meanwhile: nothing to do
            data_key = _data_key_for(seal_id, keys)
            write_protected_identity(case_id, protect_identity(
                keys.pepper, data_key, seal_id, name=legacy.name,
                email=legacy.email, birth=legacy.birth, phone=legacy.phone,
            ))
            _verify_round_trip(legacy, keys.pepper, data_key)
            blank_plaintext_identity(case_id)
    except Exception as exc:
        logger.error("Identity migration failed for seal_id=%r (%s); the row keeps "
                     "its plaintext", seal_id[:200], type(exc).__name__)
        return False
    logger.info("Identity migrated: seal_id=%r", seal_id[:200])
    return True


def _data_key_for(seal_id: str, keys: PrivacyKeys) -> bytes:
    """The seal's data key: the stored one unwrapped, or a new one stored.

    A new key only for a seal with nothing protected yet; a seal whose
    records are protected but whose key row is missing is refused
    (:func:`web.privacy.record_store.data_key_for_write`).
    """
    data_key, _created = data_key_for_write(seal_id, keys)
    return data_key


def _verify_round_trip(legacy: LegacyIdentity, pepper: bytes, data_key: bytes) -> None:
    """Read the row back; digests and decryptions must match the plaintext."""
    stored = read_protected_identity(legacy.case_id)
    seal_id = legacy.seal_id
    expected_digests = (
        identity_digest(pepper, FIELD_NAME, seal_id, legacy.name),
        identity_digest(pepper, FIELD_BIRTH, seal_id, legacy.birth),
        identity_digest(pepper, FIELD_PHONE, seal_id, legacy.phone),
    )
    if (stored.name_digest, stored.birth_digest, stored.phone_digest) != expected_digests:
        raise RoundTripError("a stored digest does not match its plaintext")
    for field_name, token, original in (("suspect_name", stored.name_enc, legacy.name),
                                        ("suspect_email", stored.email_enc, legacy.email)):
        _verify_ciphertext(seal_id, field_name, token, original.strip(), data_key)


def _verify_ciphertext(
    seal_id: str, field_name: str, token: str, expected: str, data_key: bytes
) -> None:
    if not expected:
        if token:
            raise RoundTripError("a ciphertext was stored for an empty value")
        return
    value = decrypt_field(data_key, CASES_TABLE, seal_id, ENCRYPTED_FIELDS[field_name], token)
    insert_identity_access_uncommitted(IdentityAccessEntry(
        seal_id=seal_id, field_name=field_name, purpose=PURPOSE_MIGRATION_CHECK,
        actor_role="system", outcome=OUTCOME_REVEALED, created_at=utc_now_iso(),
        actor=ACTOR,
    ))
    if value != expected:
        raise RoundTripError("a ciphertext does not decrypt to its plaintext")


def _scrub_old_copies(out: TextIO) -> bool:
    """Remove earlier copies of the plaintext where the backend allows it.

    SQLite: every ``--apply`` ends with :func:`_scrub_freed_pages`, so a
    rerun also scrubs after an earlier failure. MariaDB: only a notice.
    Returns False when the SQLite scrub failed.
    """
    if g.get("db_type") == "mariadb":
        out.write("MariaDB: 이전 평문이 InnoDB 페이지·로그·백업에 남을 수 있습니다. "
                  "OPTIMIZE TABLE cases, seal_records와 백업·바이너리 로그 정리를 "
                  "검토해 주세요.\n")
        return True
    try:
        _scrub_freed_pages()
    except ScrubIncomplete as exc:
        logger.error("SQLite scrub after the migration incomplete: %s", exc)
        out.write("다른 연결이 데이터베이스를 읽고 있어 이전 평문이 파일에 남아 있을 수 "
                  "있습니다. 이 데이터베이스를 여는 웹 앱과 다른 프로그램을 모두 멈춘 "
                  "뒤(데이터베이스를 쓰는 곳이 없을 때) --apply를 다시 실행해 주세요.\n")
        return False
    except sqlite3.Error as exc:
        logger.error("SQLite scrub after the identity migration failed (%s)",
                     type(exc).__name__)
        out.write("SQLite 파일 정리(VACUUM)에 실패해 이전 평문이 파일에 남아 있을 수 "
                  "있습니다. 앱을 멈춘 뒤 --apply를 다시 실행해 주세요.\n")
        return False
    return True


class ScrubIncomplete(Exception):
    """A WAL checkpoint could not complete, so old pages may remain on disk."""


def _scrub_freed_pages() -> None:
    """SQLite: overwrite freed content, checkpoint the WAL and vacuum.

    Each checkpoint's result is checked: a reader that still holds an older
    snapshot keeps the checkpoint from copying (and the WAL from being
    truncated), and the pages it may still read, old plaintext included,
    stay in the database file. That is reported (:class:`ScrubIncomplete`)
    rather than taken for a clean file.
    """
    db = get_db()
    db.commit()
    db.execute("PRAGMA secure_delete = ON")
    _checkpoint(db)
    db.execute("VACUUM")
    _checkpoint(db)
    _require_empty_wal(db)


def _checkpoint(db: sqlite3.Connection) -> None:
    """``wal_checkpoint(TRUNCATE)``, which must copy every frame back."""
    busy, frames, copied = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    # (0, 0, 0) in WAL mode after a complete TRUNCATE; (0, -1, -1) without WAL.
    if busy != 0 or frames != copied:
        raise ScrubIncomplete(f"WAL checkpoint incomplete (busy={busy}, "
                              f"frames={frames}, checkpointed={copied})")


def _require_empty_wal(db: sqlite3.Connection) -> None:
    """The WAL file of the main database must be gone or truncated to 0 bytes."""
    path = db.execute("PRAGMA database_list").fetchone()[2]
    wal = f"{path}-wal" if path else ""
    if wal and os.path.exists(wal) and os.path.getsize(wal) != 0:
        raise ScrubIncomplete("the WAL file was not truncated")


if __name__ == "__main__":
    sys.exit(main())
