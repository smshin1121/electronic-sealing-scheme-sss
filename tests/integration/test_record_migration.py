"""Conversion of stored seal records to the encrypted form (stage E, E3b).

``python -m src.web.privacy.migrate --apply`` also converts every
``seal_records`` row stored before E3b (``record_scheme = ''``), each in
one transaction under the seal's write lock: it encrypts ``record_json``
and ``record_pdf`` under the seal's data key (created if the seal's case
has none), writes the ciphertexts, reads the row back and checks that each
decrypts to the original bytes (each verification decryption audited),
and only then commits, so the plaintext is replaced. A row whose seal has
no case is reported and skipped; a failed row keeps its plaintext. A second
run changes nothing, no record content is printed, and on SQLite the file
keeps no copy of the old plaintext. Synthetic data only.
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import (
    IDENTITY_VALUES,
    PDF_MARKER,
    SIGNER_INFO,
    identity_record,
    insert_plaintext_row,
    leaks,
    needles,
    sql_execute,
    sql_rows,
    synthetic_pdf,
    write_pre_e3b_database,
)
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    ensure_case,
    make_release_app,
    recover_standard,
    recovered_key,
    store_share,
)

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
SEAL = "S-20260928-E3BM01"
LEGACY_CASE = "S-20260928-E3BM02"
ORPHAN = "S-20260928-E3BM03"


@pytest.fixture()
def release_master(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(tmp_path, monkeypatch, release_pki, release_master):
    return make_release_app(tmp_path, monkeypatch,
                            ca_cert_path=str(release_pki.ca_cert_path),
                            master_key_path=release_master)


@pytest.fixture()
def seeded(app, release_master, release_pki) -> dict[tuple[str, int], tuple[str, Any]]:
    """Records stored before E3b: a signed seal with two events (one with a
    PDF) whose case has a data key, and a v1.0.1 case with no data key."""
    signer = load_test_signer(release_pki)
    seal = make_seal_material(seal_id=SEAL, master_key_path=release_master,
                              signer=signer, generation=1)
    ensure_case(app, SEAL)
    rows = {
        (SEAL, 1): (json.dumps(identity_record(seal), ensure_ascii=False),
                    synthetic_pdf("sealing")),
        (SEAL, 2): (json.dumps(identity_record(seal, note="unsealed"), indent=1), None),
    }
    sql_execute(app, """INSERT INTO cases (seal_id, case_number, investigator,
                        suspect_name) VALUES (?, '2026-OLD', 'old', 'x')""",
                (LEGACY_CASE,))
    legacy = make_seal_material(seal_id=LEGACY_CASE, master_key_path=release_master,
                                signer=None)
    rows[(LEGACY_CASE, 1)] = (json.dumps(identity_record(legacy), ensure_ascii=False),
                              synthetic_pdf("legacy"))
    for (seal_id, event_id), (text, pdf) in rows.items():
        insert_plaintext_row(app, seal_id, event_id, text, pdf,
                             event_type="Sealing" if event_id == 1 else "Unsealing")
    app.config["TEST_SEAL"] = seal
    return rows


@pytest.fixture()
def cli_app(app, monkeypatch) -> Any:
    from web.cli_support import build_cli_app
    from web.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "SQLITE_PATH", app.config["SQLITE_PATH"])
    return build_cli_app("testing")


def _run(cli_app: Any, *argv: str) -> tuple[int, str, str]:
    from web.privacy.migrate import main

    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), app=cli_app, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _records(app: Any) -> list[dict]:
    return sql_rows(app, "SELECT * FROM seal_records ORDER BY seal_id, event_id")


def _snapshot(app: Any) -> tuple[list[dict], ...]:
    return tuple(sql_rows(app, f"SELECT * FROM {table} ORDER BY 1")
                 for table in ("seal_records", "seal_data_keys", "identity_access_audit"))


def _assert_no_content(*texts: str) -> None:
    for text in texts:
        for value in IDENTITY_VALUES:
            assert value not in text, value
        assert PDF_MARKER.decode("ascii") not in text


def _decrypted(cli_app: Any, row: dict) -> tuple[str, Any]:
    with cli_app.app_context():
        from web.privacy.case_identity import load_seal_data_key
        from web.privacy.record_crypto import open_record_json, open_record_pdf

        key = load_seal_data_key(row["seal_id"])
        pdf = row["record_pdf"]
        return (open_record_json(key, row["seal_id"], row["event_id"], row["record_json"]),
                None if pdf is None else open_record_pdf(key, row["seal_id"],
                                                         row["event_id"], pdf))


class TestDryRun:
    def test_counts_the_records_and_changes_nothing(self, cli_app, app, seeded) -> None:
        before = _snapshot(app)

        code, out, err = _run(cli_app, "--dry-run")

        assert code == 0, err
        assert "봉인 기록 3건: 보호됨 0건, 암호화 대상 3건" in out
        _assert_no_content(out, err)
        assert _snapshot(app) == before


class TestApply:
    def test_converts_verifies_and_replaces_every_row(self, cli_app, app, seeded) -> None:
        code, out, err = _run(cli_app, "--apply")

        assert code == 0, out + err
        assert "봉인 기록: 암호화 3건, 실패 0건, 사건 없어 건너뜀 0건" in out
        assert "평문이 남은 봉인 기록 행: 0건" in out
        _assert_no_content(out, err)
        for row in _records(app):
            text, pdf = seeded[(row["seal_id"], row["event_id"])]
            assert row["record_scheme"] == "v1"
            assert leaks(row, needles(text, pdf)) == []
            assert _decrypted(cli_app, row) == (text, pdf)

    def test_each_verification_is_audited(self, cli_app, app, seeded) -> None:
        _run(cli_app, "--apply")

        audit = sql_rows(app, """SELECT seal_id, field, purpose, actor_role, actor,
                                 outcome FROM identity_access_audit
                                 WHERE field LIKE 'record_%' ORDER BY id""")
        assert [(a["seal_id"], a["field"]) for a in audit] == [
            (SEAL, "record_json"), (SEAL, "record_pdf"), (SEAL, "record_json"),
            (LEGACY_CASE, "record_json"), (LEGACY_CASE, "record_pdf")]
        assert {(a["purpose"], a["actor_role"], a["actor"], a["outcome"]) for a in audit} == {
            ("migration_verify", "system", "privacy-migrate", "revealed")}

    def test_a_case_without_a_data_key_gets_one(
        self, cli_app, app, seeded, monkeypatch
    ) -> None:
        # The identity conversion of the v1.0.1 case fails (so it creates no
        # data key); the record conversion creates the seal's key itself.
        import web.privacy.migrate as migrate

        original = migrate._convert
        monkeypatch.setattr(migrate, "_convert", lambda *_args: False)
        assert sql_rows(app, "SELECT * FROM seal_data_keys WHERE seal_id = ?",
                        (LEGACY_CASE,)) == []

        code, out, _err = _run(cli_app, "--apply")

        assert code == 1  # the identity conversion failed
        assert "봉인 기록: 암호화 3건, 실패 0건, 사건 없어 건너뜀 0건" in out
        assert "데이터 키를 새로 만든 봉인: 1건" in out
        [key] = sql_rows(app, "SELECT wrapped_key FROM seal_data_keys WHERE seal_id = ?",
                         (LEGACY_CASE,))
        monkeypatch.setattr(migrate, "_convert", original)

        code, _out, err = _run(cli_app, "--apply")

        assert code == 0, err
        # The identity conversion reused that key; the records still open.
        assert sql_rows(app, "SELECT wrapped_key FROM seal_data_keys WHERE seal_id = ?",
                        (LEGACY_CASE,)) == [key]
        [case] = sql_rows(app, "SELECT identity_scheme FROM cases WHERE seal_id = ?",
                          (LEGACY_CASE,))
        assert case["identity_scheme"] == "v1"
        [row] = sql_rows(app, "SELECT * FROM seal_records WHERE seal_id = ?", (LEGACY_CASE,))
        assert _decrypted(cli_app, row) == seeded[(LEGACY_CASE, 1)]

    def test_a_second_run_changes_nothing(self, cli_app, app, seeded) -> None:
        _run(cli_app, "--apply")
        before = _snapshot(app)

        code, out, _err = _run(cli_app, "--apply")

        assert code == 0
        assert "봉인 기록 3건: 보호됨 3건, 암호화 대상 0건" in out
        assert "봉인 기록: 암호화 0건, 실패 0건, 사건 없어 건너뜀 0건" in out
        assert _snapshot(app) == before

    def test_the_database_file_keeps_no_plaintext(self, cli_app, app, seeded) -> None:
        _run(cli_app, "--apply")

        path = Path(app.config["SQLITE_PATH"])
        stored = b"".join(p.read_bytes() for p in (path, Path(f"{path}-wal"))
                          if p.exists())
        for text, pdf in seeded.values():
            for pattern in needles(text, pdf):
                assert pattern not in stored, pattern[:40]

    def test_converted_records_serve_the_gate_and_the_subject(
        self, cli_app, app, seeded
    ) -> None:
        _run(cli_app, "--apply")
        seal = app.config["TEST_SEAL"]
        store_share(app, SEAL, 1, seal.shares[0])
        client = app.test_client()
        with client.session_transaction() as sess:
            sess[f"auth_{SEAL}"] = True

        released = recover_standard(client, seal)
        detail = client.get(f"/suspect/records/{SEAL}/detail/1",
                            headers={"Accept": "application/json"})

        assert released.status_code == 302
        assert recovered_key(client, SEAL) == seal.key_hex
        assert detail.status_code == 200
        assert detail.get_json()["record_json"] == seeded[(SEAL, 1)][0]


class TestRefusals:
    def test_rows_without_a_case_are_reported_and_skipped(self, cli_app, app, seeded) -> None:
        text = json.dumps({"seal_id": ORPHAN, "signer_info": SIGNER_INFO}, ensure_ascii=False)
        insert_plaintext_row(app, ORPHAN, 4, text, foreign_keys=False)

        code, out, err = _run(cli_app, "--apply")

        assert code == 1
        assert "사건 없어 건너뜀 1건" in out and ORPHAN in out
        assert "평문이 남은 봉인 기록 행: 1건" in out
        _assert_no_content(out, err)
        [row] = sql_rows(app, "SELECT record_json, record_scheme FROM seal_records "
                              "WHERE seal_id = ?", (ORPHAN,))
        assert (row["record_json"], row["record_scheme"]) == (text, "")
        assert sql_rows(app, "SELECT * FROM seal_data_keys WHERE seal_id = ?",
                        (ORPHAN,)) == []

    def test_a_failed_verification_keeps_the_plaintext(
        self, cli_app, app, seeded, monkeypatch
    ) -> None:
        monkeypatch.setattr("web.privacy.record_migration.open_record_json",
                            lambda *args: "not the original")
        # The identity conversion of the legacy case runs as usual.
        before = {(r["seal_id"], r["event_id"]): r for r in _records(app)}

        code, out, err = _run(cli_app, "--apply")

        assert code == 1
        assert "실패 3건" in out and SEAL in out and LEGACY_CASE in out
        _assert_no_content(out, err)
        for row in _records(app):
            assert row == before[(row["seal_id"], row["event_id"])]
        assert sql_rows(app, "SELECT * FROM identity_access_audit "
                             "WHERE field LIKE 'record_%'") == []

    def test_missing_keys_refuse_before_any_change(
        self, cli_app, app, seeded
    ) -> None:
        before = _snapshot(app)
        cli_app.config["PRIVACY_KMS_MASTER_KEY_PATH"] = ""

        code, _out, err = _run(cli_app, "--apply")

        assert code == 1 and "개인정보 보호 키" in err
        assert _snapshot(app) == before


# ===================================================================
# A database created before E3b (seal_records without record_scheme)
# ===================================================================

OLD_TEXT = json.dumps({"seal_id": "S-20260928-E3BM09", "signer_info": SIGNER_INFO},
                      ensure_ascii=False)
OLD_PDF = synthetic_pdf("old")


@pytest.fixture()
def old_db(tmp_path) -> Path:
    path = tmp_path / "pre_e3b.db"
    write_pre_e3b_database(path, "S-20260928-E3BM09", OLD_TEXT, OLD_PDF)
    return path


def _old_rows(path: Path, sql: str) -> list[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(sql)]
    finally:
        conn.close()


class TestPreE3bDatabase:
    def test_the_table_gains_the_column_and_is_converted(self, old_db, monkeypatch) -> None:
        from web.cli_support import build_cli_app
        from web.config import TestingConfig

        monkeypatch.setattr(TestingConfig, "SQLITE_PATH", str(old_db))
        cli_app = build_cli_app("testing")

        code, out, err = _run(cli_app, "--apply")

        assert code == 0, out + err
        columns = [r["name"] for r in _old_rows(old_db, "PRAGMA table_info(seal_records)")]
        assert columns[-1] == "record_scheme"
        [row] = _old_rows(old_db, "SELECT * FROM seal_records")
        assert row["record_scheme"] == "v1"
        assert leaks(row, needles(OLD_TEXT, OLD_PDF)) == []
        assert _decrypted(cli_app, row) == (OLD_TEXT, OLD_PDF)
        stored = old_db.read_bytes()
        assert SIGNER_INFO["email"].encode() not in stored and PDF_MARKER not in stored

    def test_python_m_converts_the_records(self, old_db, privacy_key_files) -> None:
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "USE_SQLITE": "true",
               "SQLITE_PATH": str(old_db), "IDENTITY_PEPPER_PATH": privacy_key_files[0],
               "PRIVACY_KMS_MASTER_KEY_PATH": privacy_key_files[1],
               "PYTHONIOENCODING": "utf-8"}

        done = subprocess.run(
            [sys.executable, "-m", "src.web.privacy.migrate", "--env", "testing", "--apply"],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120,
        )

        assert done.returncode == 0, done.stderr
        assert "봉인 기록: 암호화 1건, 실패 0건, 사건 없어 건너뜀 0건" in done.stdout
        _assert_no_content(done.stdout, done.stderr)
        [row] = _old_rows(old_db, "SELECT record_scheme FROM seal_records")
        assert row["record_scheme"] == "v1"
