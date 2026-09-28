"""Conversion of existing ``cases`` rows to the protected form (stage E, E3a).

``python -m src.web.privacy.migrate --apply`` converts each row whose
identity is still in plaintext in one transaction: it digests and encrypts
the identity, reads the row back and verifies the round trip (each
verification decryption audited), then blanks the plaintext and marks the
row ``v1``. ``--dry-run`` only counts. A second run changes nothing, a row
that fails verification keeps its plaintext, and no identity value is ever
printed. On SQLite the converted file keeps no copy of the old plaintext.
Synthetic data only.
"""

from __future__ import annotations

import io
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.privacy_keys import read_pepper, without_privacy_keys
from tests.fixtures.release_web import make_release_app, post_form

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
ROWS = (
    ("S-20260101-MIG001", "김철수", "kim.cs@example.org", "19850505", "010-9876-5432"),
    ("S-20260101-MIG002", "이영희", "", "1992-12-31", "01055512345"),
)
PLAINTEXTS = ("김철수", "kim.cs@example.org", "kim.cs", "19850505", "010-9876-5432",
              "01098765432", "이영희", "1992-12-31", "19921231", "01055512345")

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


@pytest.fixture()
def db_path(tmp_path) -> Path:
    """A v1.0.1-era database: the old ``cases`` table with plaintext rows."""
    path = tmp_path / "v101.db"
    conn = sqlite3.connect(path)
    conn.executescript(V101_CASES_DDL)
    conn.executemany(
        """INSERT INTO cases (seal_id, case_number, investigator, suspect_name,
               suspect_email, suspect_birth, suspect_phone)
           VALUES (?, '2026-OLD', '수사관B', ?, ?, ?, ?)""", ROWS)
    conn.commit()
    conn.close()
    return path


@pytest.fixture()
def cli_app(db_path, monkeypatch) -> Any:
    from web.cli_support import build_cli_app
    from web.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "SQLITE_PATH", str(db_path))
    return build_cli_app("testing")


def _run(app: Any, *argv: str) -> tuple[int, str, str]:
    from web.privacy.migrate import main

    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), app=app, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _rows(db_path: Path, sql: str, params: tuple = ()) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(sql, params)]
    finally:
        conn.close()


def _snapshot(db_path: Path) -> tuple[list[dict], ...]:
    return tuple(_rows(db_path, f"SELECT * FROM {table} ORDER BY 1")
                 for table in ("cases", "seal_data_keys", "identity_access_audit"))


def _assert_no_identity(*texts: str) -> None:
    for text in texts:
        for plaintext in PLAINTEXTS:
            assert plaintext not in text, plaintext


class TestDryRun:
    def test_counts_and_leaves_the_rows(self, cli_app, db_path) -> None:
        code, out, err = _run(cli_app, "--dry-run")

        assert code == 0, err
        assert "사건 2건: 보호됨 0건, 변환 대상 2건" in out
        assert "users 표: 0건" in out
        _assert_no_identity(out, err)
        cases = _rows(db_path, "SELECT suspect_name, identity_scheme FROM cases ORDER BY id")
        assert [(c["suspect_name"], c["identity_scheme"]) for c in cases] == [
            ("김철수", ""), ("이영희", "")]
        assert _rows(db_path, "SELECT * FROM seal_data_keys") == []
        assert _rows(db_path, "SELECT * FROM identity_access_audit") == []

    def test_a_mode_is_required(self, cli_app) -> None:
        code, _out, _err = _run(cli_app)
        assert code == 2


class TestApply:
    def test_converts_verifies_and_blanks_every_row(self, cli_app, db_path) -> None:
        code, out, err = _run(cli_app, "--apply")

        assert code == 0, out + err
        assert "변환 2건, 실패 0건" in out
        assert "평문 신원이 남은 사건 행: 0건" in out
        _assert_no_identity(out, err)
        cases = _rows(db_path, "SELECT * FROM cases ORDER BY id")
        for row in cases:
            assert row["identity_scheme"] == "v1"
            for column in ("suspect_name", "suspect_email", "suspect_birth", "suspect_phone"):
                assert row[column] == ""
        keys = _rows(db_path, "SELECT seal_id FROM seal_data_keys ORDER BY seal_id")
        assert [k["seal_id"] for k in keys] == [r[0] for r in ROWS]

    def test_stored_values_round_trip(self, cli_app, db_path) -> None:
        _run(cli_app, "--apply")

        with cli_app.app_context():
            from web.privacy.case_identity import load_seal_data_key
            from web.privacy.digests import identity_digest
            from web.privacy.field_crypto import decrypt_field

            pepper = read_pepper(cli_app)
            for seal_id, name, email, birth, phone in ROWS:
                [row] = _rows(db_path, "SELECT * FROM cases WHERE seal_id = ?", (seal_id,))
                key = load_seal_data_key(seal_id)
                assert decrypt_field(key, "cases", seal_id, "suspect_name_enc",
                                     row["suspect_name_enc"]) == name
                if email:
                    assert decrypt_field(key, "cases", seal_id, "suspect_email_enc",
                                         row["suspect_email_enc"]) == email
                else:
                    assert row["suspect_email_enc"] == ""
                assert row["suspect_birth_digest"] == identity_digest(pepper, "birth_date", seal_id, birth)
                assert row["suspect_phone_digest"] == identity_digest(pepper, "phone", seal_id, phone)

    def test_each_verification_decryption_is_audited(self, cli_app, db_path) -> None:
        _run(cli_app, "--apply")

        audit = _rows(db_path, "SELECT * FROM identity_access_audit ORDER BY id")
        assert [(a["seal_id"], a["field"]) for a in audit] == [
            ("S-20260101-MIG001", "suspect_name"), ("S-20260101-MIG001", "suspect_email"),
            ("S-20260101-MIG002", "suspect_name")]
        assert {(a["purpose"], a["actor_role"], a["actor"], a["outcome"]) for a in audit} == {
            ("migration_verify", "system", "privacy-migrate", "revealed")}

    def test_the_database_file_keeps_no_old_plaintext(self, cli_app, db_path) -> None:
        _run(cli_app, "--apply")

        stored = b"".join(p.read_bytes() for p in (
            db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-journal")) if p.exists())
        for plaintext in PLAINTEXTS:
            assert plaintext.encode("utf-8") not in stored, plaintext

    def test_secure_delete_is_on_while_rows_are_converted(self, cli_app, monkeypatch) -> None:
        import web.privacy.migrate as migrate
        from web.models.db_models import get_db

        seen: list[int] = []
        original = migrate._convert

        def spying(*args: Any) -> bool:
            seen.append(get_db().execute("PRAGMA secure_delete").fetchone()[0])
            return original(*args)

        monkeypatch.setattr(migrate, "_convert", spying)
        code, _out, err = _run(cli_app, "--apply")

        assert code == 0, err
        assert seen == [1, 1]

    def test_a_failed_scrub_is_reported_and_a_rerun_scrubs(self, cli_app, db_path, monkeypatch) -> None:
        import web.privacy.migrate as migrate

        original = migrate._scrub_freed_pages

        def locked() -> None:
            raise sqlite3.OperationalError("database is locked (synthetic)")

        monkeypatch.setattr(migrate, "_scrub_freed_pages", locked)
        code, out, _err = _run(cli_app, "--apply")
        assert code == 1 and "VACUUM" in out and "변환 2건, 실패 0건" in out

        monkeypatch.setattr(migrate, "_scrub_freed_pages", original)
        code, out, _err = _run(cli_app, "--apply")

        assert code == 0 and "변환 대상 0건" in out
        stored = b"".join(p.read_bytes() for p in (db_path, Path(f"{db_path}-wal")) if p.exists())
        assert not any(t.encode("utf-8") in stored for t in PLAINTEXTS)

    def test_a_second_run_changes_nothing(self, cli_app, db_path) -> None:
        _run(cli_app, "--apply")
        before = _snapshot(db_path)

        code, out, _err = _run(cli_app, "--apply")

        assert code == 0
        assert "변환 대상 0건" in out and "변환 0건, 실패 0건" in out
        assert _snapshot(db_path) == before

    def test_converted_subjects_authenticate(self, cli_app, db_path, tmp_path, monkeypatch) -> None:
        _run(cli_app, "--apply")
        target = tmp_path / "release_web.db"
        target.write_bytes(db_path.read_bytes())
        app = make_release_app(tmp_path, monkeypatch)

        resp = post_form(app.test_client(), "/suspect/auth/S-20260101-MIG001",
                         {"name": "김철수", "birth_date": "1985-05-05", "phone": "01098765432"})

        assert resp.status_code == 302

    def test_an_existing_data_key_is_reused(self, cli_app, db_path) -> None:
        with cli_app.app_context():
            from web.privacy.field_crypto import new_data_key, wrap_data_key

            wrapped = wrap_data_key(new_data_key(), cli_app.config["PRIVACY_KMS_MASTER_KEY_PATH"],
                                    "S-20260101-MIG001")
        _run(cli_app, "--dry-run")  # creates the table
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO seal_data_keys VALUES (?, ?, 'synthetic')",
                      ("S-20260101-MIG001", wrapped))
        conn.commit()
        conn.close()

        code, _out, err = _run(cli_app, "--apply")

        assert code == 0, err
        [key] = _rows(db_path, "SELECT wrapped_key FROM seal_data_keys WHERE seal_id = ?",
                      ("S-20260101-MIG001",))
        assert bytes(key["wrapped_key"]) == wrapped


class TestRefusals:
    def test_a_failed_verification_keeps_the_plaintext(self, cli_app, db_path, monkeypatch) -> None:
        monkeypatch.setattr("web.privacy.migrate.decrypt_field",
                            lambda *args: "not the original")

        code, out, err = _run(cli_app, "--apply")

        assert code == 1
        assert "실패 2건" in out and "S-20260101-MIG001" in out
        _assert_no_identity(out, err)
        cases = _rows(db_path, "SELECT suspect_name, identity_scheme, suspect_name_enc FROM cases")
        assert [(c["suspect_name"], c["identity_scheme"], c["suspect_name_enc"]) for c in cases] == [
            ("김철수", "", ""), ("이영희", "", "")]
        assert _rows(db_path, "SELECT * FROM seal_data_keys") == []
        assert _rows(db_path, "SELECT * FROM identity_access_audit") == []

    def test_missing_keys_refuse(self, db_path, monkeypatch) -> None:
        from web.cli_support import build_cli_app
        from web.config import TestingConfig

        monkeypatch.setattr(TestingConfig, "SQLITE_PATH", str(db_path))
        without_privacy_keys(monkeypatch)

        code, out, err = _run(build_cli_app("testing"), "--apply")

        assert code == 1
        assert "개인정보 보호 키" in err
        assert _rows(db_path, "SELECT suspect_name FROM cases ORDER BY id")[0]["suspect_name"] == "김철수"

    def test_a_fallback_from_mariadb_to_sqlite_is_refused(self, cli_app, db_path) -> None:
        cli_app.config["USE_SQLITE"] = False
        import web.models.db_models as db_models

        if db_models._HAS_MARIADB:
            pytest.skip("the MariaDB driver is installed here; the fallback needs its absence")

        code, _out, err = _run(cli_app, "--apply")

        assert code == 1 and "MariaDB" in err
        # Refused before the schema step: the v1.0.1 table is untouched.
        columns = [r["name"] for r in _rows(db_path, "PRAGMA table_info(cases)")]
        assert "identity_scheme" not in columns
        assert _rows(db_path, "SELECT suspect_name FROM cases ORDER BY id")[0]["suspect_name"] == "김철수"


class TestModuleEntryPoint:
    def test_python_m_runs_with_src_on_the_path(self, db_path, privacy_key_files) -> None:
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "USE_SQLITE": "true",
               "SQLITE_PATH": str(db_path), "IDENTITY_PEPPER_PATH": privacy_key_files[0],
               "PRIVACY_KMS_MASTER_KEY_PATH": privacy_key_files[1],
               "PYTHONIOENCODING": "utf-8"}

        done = subprocess.run(
            [sys.executable, "-m", "src.web.privacy.migrate", "--env", "testing", "--apply"],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120,
        )

        assert done.returncode == 0, done.stderr
        assert "변환 2건, 실패 0건" in done.stdout
        _assert_no_identity(done.stdout, done.stderr)
