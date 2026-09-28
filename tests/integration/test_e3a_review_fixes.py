"""Fixes to E3a after the independent review (gpt-6-astra, stage E round 2).

  - N1: the per-seal OTP delivery cap holds under simultaneous requests:
    the count and the audit row of a delivery are one step serialized per
    seal (the seal's write lock), so no two requests see the same count.
  - N2: the SQLite scrub of the migration checks every WAL checkpoint; a
    reader that keeps an old snapshot (and with it old plaintext pages) makes
    the run fail with a retry message instead of reporting a clean file.
  - N3: public case-password work (registration and the subject's password
    factor) runs within a per-process bound on concurrent scrypt
    derivations, and registrations that hash a password first reserve a
    place in a per-address budget; excess requests never reach the KDF.

Since stage F, F2 the registration form needs a signed-in administrator:
the ``app`` fixture creates the account once, and every registration here
comes from a client signed in to it. Synthetic data only.
"""

from __future__ import annotations

import io
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.concurrency import run_concurrently
from tests.fixtures.record_protection import (
    IDENTITY_VALUES,
    PDF_MARKER,
    SIGNER_INFO,
    synthetic_pdf,
    write_pre_e3b_database,
)
from tests.fixtures.release_web import CSRF_TOKEN, login_admin, make_release_app, post_form

pytestmark = pytest.mark.integration

NAME, EMAIL = "최민서", "choi.ms@example.org"
BIRTH, PHONE = "1979-11-02", "010-7531-8642"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    application = make_release_app(tmp_path, monkeypatch)
    # The administrator account the registrations use (stage F, F2), made
    # once here: threads that registered at once would race to create it.
    login_admin(application.test_client())
    return application


@pytest.fixture()
def sent(monkeypatch) -> list[tuple[str, str]]:
    """Every (recipient, code) the OTP service was asked to send."""
    from web.auth.otp_service import OTPService

    calls: list[tuple[str, str]] = []

    def record(self: Any, email: str, otp: str) -> bool:
        calls.append((email, otp))
        return True

    monkeypatch.setattr(OTPService, "send_otp", record)
    return calls


def _register(client: Any, seal_id: str, **overrides: str) -> Any:
    form = {"seal_id": seal_id, "case_number": "2026-N-001", "investigator": "수사관N",
            "suspect_name": NAME, "suspect_email": EMAIL, "suspect_birth": BIRTH,
            "suspect_phone": PHONE, "auth_level": "basic", **overrides}
    login_admin(client)
    return _registered(post_form(client, "/investigator/register-case", form))


def _registered(resp: Any) -> Any:
    """The answer; a redirect must lead back to the form, not to the login."""
    if resp.status_code == 302:
        assert resp.headers["Location"].endswith("/investigator/register-case")
    return resp


def _send_otp(client: Any, seal_id: str, ip: str) -> Any:
    with client.session_transaction() as sess:
        sess["csrf_token"] = CSRF_TOKEN
    return client.post(
        f"/suspect/send-otp/{seal_id}",
        data={"name": NAME, "birth_date": BIRTH, "phone": PHONE, "csrf_token": CSRF_TOKEN},
        headers={"Accept": "application/json"}, environ_base={"REMOTE_ADDR": ip},
    )


def _revealed(app: Any, seal_id: str) -> int:
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    try:
        return conn.execute("SELECT COUNT(*) FROM identity_access_audit WHERE seal_id = ? "
                            "AND outcome = 'revealed'", (seal_id,)).fetchone()[0]
    finally:
        conn.close()


def slow_email_decryption(monkeypatch: pytest.MonkeyPatch, delay: float) -> None:
    """Hold every e-mail decryption for ``delay`` seconds (widens the race)."""
    from web.privacy import case_identity

    real = case_identity.decrypt_field

    def slow(*args: Any) -> str:
        time.sleep(delay)
        return real(*args)

    monkeypatch.setattr(case_identity, "decrypt_field", slow)


# ===================================================================
# N1: the OTP delivery cap under simultaneous requests
# ===================================================================

class TestConcurrentOtpDeliveries:
    def test_simultaneous_requests_respect_the_per_seal_cap(self, app, sent, monkeypatch) -> None:
        seal_id = "S-20260928-N1C001"
        app.config.update(OTP_MAX_DELIVERIES_PER_SEAL=2, OTP_DELIVERY_WINDOW_SECONDS=600)
        assert _register(app.test_client(), seal_id, auth_level="basic+otp").status_code == 302
        slow_email_decryption(monkeypatch, delay=0.3)

        codes = run_concurrently(
            lambda i: _send_otp(app.test_client(), seal_id, f"198.51.100.{20 + i}").status_code,
            range(6))

        # Exactly two deliveries; the others are refused by the cap (429), or,
        # should one wait past the database's lock timeout, with 503.
        assert codes.count(200) == 2 and set(codes) <= {200, 429, 503}, codes
        assert len(sent) == 2
        assert _revealed(app, seal_id) == 2

    def test_a_delivery_that_fails_before_its_audit_row_consumes_nothing(
        self, app, sent, monkeypatch
    ) -> None:
        seal_id = "S-20260928-N1C002"
        app.config.update(OTP_MAX_DELIVERIES_PER_SEAL=1, OTP_DELIVERY_WINDOW_SECONDS=600)
        assert _register(app.test_client(), seal_id, auth_level="basic+otp").status_code == 302

        from web.privacy import case_identity

        def broken(*_args: Any) -> int:
            raise sqlite3.OperationalError("synthetic audit failure")

        real = case_identity.insert_identity_access
        monkeypatch.setattr(case_identity, "insert_identity_access", broken)
        failed = _send_otp(app.test_client(), seal_id, "198.51.100.40")
        monkeypatch.setattr(case_identity, "insert_identity_access", real)
        delivered = _send_otp(app.test_client(), seal_id, "198.51.100.41")

        assert failed.status_code == 503 and delivered.status_code == 200
        assert [email for email, _ in sent] == [EMAIL]

    def test_a_database_error_under_the_lock_is_a_controlled_refusal(
        self, app, sent, monkeypatch
    ) -> None:
        seal_id = "S-20260928-N1C003"
        assert _register(app.test_client(), seal_id, auth_level="basic+otp").status_code == 302

        def locked(*_args: Any, **_kwargs: Any) -> int:
            raise sqlite3.OperationalError("database is locked (synthetic)")

        monkeypatch.setattr("web.routes.suspect.recent_reveals", locked)
        resp = _send_otp(app.test_client(), seal_id, "198.51.100.42")

        assert resp.status_code == 503
        assert sent == [] and _revealed(app, seal_id) == 0


# ===================================================================
# N2: the SQLite scrub checks its WAL checkpoints
# ===================================================================

OLD_SEAL = "S-20260928-N2S001"
OLD_TEXT = json.dumps({"seal_id": OLD_SEAL, "signer_info": SIGNER_INFO}, ensure_ascii=False)
OLD_PDF = synthetic_pdf("n2")


@pytest.fixture()
def old_db(tmp_path) -> Path:
    path = tmp_path / "n2.db"
    write_pre_e3b_database(path, OLD_SEAL, OLD_TEXT, OLD_PDF)
    return path


@pytest.fixture()
def cli_app(old_db, monkeypatch) -> Any:
    from web.cli_support import build_cli_app
    from web.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "SQLITE_PATH", str(old_db))
    return build_cli_app("testing")


def _migrate(cli_app: Any, *argv: str) -> tuple[int, str]:
    from web.privacy.migrate import main

    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), app=cli_app, stdout=out, stderr=err)
    return code, out.getvalue() + err.getvalue()


def _stored_plaintext(path: Path) -> list[str]:
    """Which old plaintext values the database file or its WAL still hold."""
    stored = b"".join(p.read_bytes() for p in (path, Path(f"{path}-wal")) if p.exists())
    values = [v.encode("utf-8") for v in IDENTITY_VALUES] + [PDF_MARKER]
    return [v.decode("utf-8") for v in values if v in stored]


class TestScrubCheckpoints:
    def test_a_reader_keeping_an_old_snapshot_fails_the_scrub(self, cli_app, old_db) -> None:
        # The CLI's first connection switches the file to WAL; then a reader
        # opens a snapshot that predates the conversion and keeps it.
        assert _migrate(cli_app, "--dry-run")[0] == 0
        reader = sqlite3.connect(old_db)
        try:
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM seal_records").fetchone()

            code, out = _migrate(cli_app, "--apply")
            held = _stored_plaintext(old_db)
        finally:
            reader.rollback()
            reader.close()

        assert code == 1
        assert "다시 실행" in out and "봉인 기록: 암호화 1건, 실패 0건" in out
        assert held, "the reader should keep old pages in the file while it is open"
        for value in IDENTITY_VALUES:
            assert value not in out

        code, out = _migrate(cli_app, "--apply")

        assert code == 0, out
        assert _stored_plaintext(old_db) == []
        wal = Path(f"{old_db}-wal")
        assert not wal.exists() or wal.stat().st_size == 0

    def test_an_idle_database_is_scrubbed_and_reported_clean(self, cli_app, old_db) -> None:
        code, out = _migrate(cli_app, "--apply")

        assert code == 0, out
        assert _stored_plaintext(old_db) == []


# ===================================================================
# N3: public case-password work is bounded
# ===================================================================

def _register_from(client: Any, seal_id: str, ip: str, **overrides: str) -> Any:
    login_admin(client)
    with client.session_transaction() as sess:
        sess["csrf_token"] = CSRF_TOKEN
    form = {"seal_id": seal_id, "case_number": "2026-N3-001", "investigator": "수사관N",
            "suspect_name": NAME, "suspect_email": EMAIL, "suspect_birth": BIRTH,
            "suspect_phone": PHONE, "auth_level": "basic", "csrf_token": CSRF_TOKEN,
            **overrides}
    return _registered(client.post("/investigator/register-case", data=form,
                                   environ_base={"REMOTE_ADDR": ip}))


def _login_from(client: Any, seal_id: str, ip: str, secret: str) -> Any:
    with client.session_transaction() as sess:
        sess["csrf_token"] = CSRF_TOKEN
    return client.post(f"/suspect/auth/{seal_id}",
                       data={"name": NAME, "birth_date": BIRTH, "phone": PHONE,
                             "password": secret, "csrf_token": CSRF_TOKEN},
                       environ_base={"REMOTE_ADDR": ip})


def _rows(app: Any, sql: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    try:
        return list(conn.execute(sql, params))
    finally:
        conn.close()


@pytest.fixture()
def secret() -> str:
    import secrets

    return secrets.token_urlsafe(16)


@pytest.fixture()
def derivations(monkeypatch):
    """Count scrypt derivations and their peak overlap (each held 0.5 s)."""
    from tests.fixtures.release_web import SlowDerivations
    from web.auth import passwords

    slow = SlowDerivations(passwords._derive, delay=0.5)
    monkeypatch.setattr(passwords, "_derive", slow)
    return slow


class TestCasePasswordAdmission:
    def test_concurrent_registrations_stay_within_the_derivation_bound(
        self, app, secret, derivations
    ) -> None:
        app.config.update(CASE_PASSWORD_MAX_CONCURRENT=2, CASE_REGISTRATION_MAX_PER_ADDRESS=50)

        codes = run_concurrently(lambda i: _register_from(
            app.test_client(), f"S-20260928-N3R{i:03d}", "198.51.100.80",
            auth_level="basic+password", password=secret).status_code, range(6))

        registered = codes.count(302)
        assert set(codes) <= {302, 503} and registered >= 2, codes
        assert derivations.peak <= 2
        assert derivations.calls == registered  # a refused request never derived
        assert len(_rows(app, "SELECT seal_id FROM cases WHERE seal_id LIKE 'S-20260928-N3R%'")
                   ) == registered
        # A request refused as busy gives its place in the budget back.
        assert _rows(app, "SELECT COUNT(*) FROM auth_failures WHERE seal_id = "
                          "'@case-registration'")[0][0] == registered

    def test_the_address_budget_refuses_before_any_derivation(
        self, app, secret, derivations
    ) -> None:
        app.config.update(CASE_REGISTRATION_MAX_PER_ADDRESS=2, CASE_REGISTRATION_WINDOW_SECONDS=600)
        client = app.test_client()

        codes = [_register_from(client, f"S-20260928-N3B{i:03d}", "198.51.100.81",
                                auth_level="basic+password", password=secret).status_code
                 for i in range(3)]
        other = _register_from(client, "S-20260928-N3B100", "198.51.100.82",
                               auth_level="basic+password", password=secret)
        plain = _register_from(client, "S-20260928-N3B101", "198.51.100.81")

        assert codes == [302, 302, 429]
        assert derivations.calls == 3  # two from the first address, one from the other
        assert other.status_code == 302
        assert plain.status_code == 302  # no password, no derivation, not budgeted
        assert "잠시 후" in _refusal_text(app, client, "198.51.100.81", secret)

    def test_simultaneous_registrations_respect_the_budget(
        self, app, secret, derivations
    ) -> None:
        app.config.update(CASE_REGISTRATION_MAX_PER_ADDRESS=2, CASE_PASSWORD_MAX_CONCURRENT=16)

        codes = run_concurrently(lambda i: _register_from(
            app.test_client(), f"S-20260928-N3S{i:03d}", "198.51.100.83",
            auth_level="basic+password", password=secret).status_code, range(6))

        # Reservations still in flight count, so a burst may be refused
        # early, never late (E4's budget): at most two registrations.
        registered = codes.count(302)
        assert set(codes) <= {302, 429} and registered <= 2, codes
        assert derivations.calls == registered

    def test_the_subject_password_factor_is_bounded_and_not_counted(
        self, app, secret, monkeypatch
    ) -> None:
        seal_id = "S-20260928-N3L001"
        assert _register_from(app.test_client(), seal_id, "198.51.100.84",
                              auth_level="basic+password", password=secret).status_code == 302
        from tests.fixtures.release_web import SlowDerivations
        from web.auth import passwords

        slow = SlowDerivations(passwords._derive, delay=0.5)
        monkeypatch.setattr(passwords, "_derive", slow)
        app.config.update(CASE_PASSWORD_MAX_CONCURRENT=1, AUTH_MAX_FAILURES=50)

        codes = run_concurrently(lambda i: _login_from(
            app.test_client(), seal_id, f"198.51.100.{90 + i}", secret).status_code, range(4))

        passed = codes.count(302)
        assert set(codes) <= {302, 503} and passed >= 1, codes
        assert slow.peak <= 1 and slow.calls == passed
        assert _rows(app, "SELECT COUNT(*) FROM auth_failures WHERE seal_id = ?",
                     (seal_id,))[0][0] == 0

    def test_a_busy_legacy_upgrade_keeps_the_login(self, app, secret, monkeypatch, caplog) -> None:
        import hashlib
        import logging

        seal_id = "S-20260928-N3U001"
        legacy = hashlib.sha256(secret.encode()).hexdigest()
        with app.app_context():
            from web.models.db_models import insert_case

            insert_case(seal_id=seal_id, case_number="C-N3", investigator="수사관N",
                        suspect_name=NAME, suspect_birth=BIRTH, suspect_phone=PHONE,
                        auth_level="basic+password", password_hash=legacy)
        from web.auth.kdf_slots import DerivationBusy

        def busy(_secret: str) -> str:
            raise DerivationBusy("case-password")

        monkeypatch.setattr("web.routes.suspect.upgraded_hash", busy)
        caplog.set_level(logging.WARNING)

        resp = _login_from(app.test_client(), seal_id, "198.51.100.99", secret)

        assert resp.status_code == 302
        assert _rows(app, "SELECT password_hash FROM cases WHERE seal_id = ?",
                     (seal_id,))[0][0] == legacy
        assert not any(r.exc_info for r in caplog.records)


def _refusal_text(app: Any, client: Any, ip: str, secret: str) -> str:
    resp = _register_from(client, "S-20260928-N3B999", ip, auth_level="basic+password",
                          password=secret)
    assert resp.status_code == 429
    return resp.get_data(as_text=True)


class TestReservedSealIds:
    @pytest.mark.parametrize("seal_id", ["@case-registration", "@admin-login", "@x"])
    def test_a_seal_id_starting_with_at_is_refused(self, app, seal_id) -> None:
        # The lockout and budget counters use '@'-keys in auth_failures.
        resp = _register_from(app.test_client(), seal_id, "198.51.100.150")

        assert resp.status_code == 400
        assert _rows(app, "SELECT COUNT(*) FROM cases WHERE seal_id = ?", (seal_id,))[0][0] == 0
