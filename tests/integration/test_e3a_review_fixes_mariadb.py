"""Fixes to E3a after the independent review (round 2) on the MariaDB variant.

  - N1: simultaneous OTP requests on separate connections respect the
    per-seal delivery cap (the case row ``FOR UPDATE`` serializes them).
  - N3: the per-address registration budget (reservation rows committed
    before any password work) holds on MariaDB, also for simultaneous
    registrations.

Since stage F, F2 the registration form needs a signed-in administrator:
the ``app`` fixture creates the account once, and every registration here
comes from a client signed in to it.

Skipped unless ``RELEASE_TEST_MARIADB_HOST`` is set. The server must be a
throwaway test instance: the module drops and recreates its own database
(``enc_release_test_e3a_fixes``). Synthetic data only. Environment as in
``test_release_mariadb.py``.
"""

from __future__ import annotations

import os
import time
from typing import Any

import pytest

from tests.fixtures.concurrency import run_concurrently
from tests.fixtures.release_web import CSRF_TOKEN, SlowDerivations, login_admin

HOST = os.environ.get("RELEASE_TEST_MARIADB_HOST", "")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HOST, reason="RELEASE_TEST_MARIADB_HOST not set (needs a throwaway MariaDB server)"),
]
PORT = int(os.environ.get("RELEASE_TEST_MARIADB_PORT", "3306"))
USER = os.environ.get("RELEASE_TEST_MARIADB_USER", "root")
PASSWORD = os.environ.get("RELEASE_TEST_MARIADB_PASSWORD", "")
DB = "enc_release_test_e3a_fixes"

NAME, EMAIL = "최민서", "choi.ms@example.org"
BIRTH, PHONE = "1979-11-02", "010-7531-8642"


def _server(database: str | None = None) -> Any:
    import mariadb

    return mariadb.connect(host=HOST, port=PORT, user=USER, password=PASSWORD,
                           database=database)


def _count(sql: str, params: tuple = ()) -> int:
    conn = _server(DB)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return int(cur.fetchone()[0])
    finally:
        conn.close()


@pytest.fixture(scope="module", autouse=True)
def fresh_database() -> None:
    assert DB.startswith("enc_release_test"), "refusing to drop a non-test database"
    conn = _server()
    try:
        cur = conn.cursor()
        cur.execute(f"DROP DATABASE IF EXISTS `{DB}`")
        cur.execute(f"CREATE DATABASE `{DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def app(monkeypatch):
    from web.config import TestingConfig

    for name, value in (("USE_SQLITE", False), ("DB_HOST", HOST), ("DB_PORT", PORT),
                        ("DB_USER", USER), ("DB_PASSWORD", PASSWORD), ("DB_NAME", DB)):
        monkeypatch.setattr(TestingConfig, name, value)
    monkeypatch.setenv("USE_SQLITE", "false")
    from web.app import create_app

    application = create_app("testing")
    with application.app_context():
        from flask import g

        from web.models.db_models import get_db

        get_db()
        assert g.db_type == "mariadb", "the app fell back to SQLite; the MariaDB path was not exercised"
    # The administrator account the registrations use (stage F, F2), made
    # once here: threads that registered at once would race to create it.
    login_admin(application.test_client())
    return application


@pytest.fixture()
def sent(monkeypatch) -> list[tuple[str, str]]:
    from web.auth.otp_service import OTPService

    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(OTPService, "send_otp",
                        lambda self, email, otp: calls.append((email, otp)) or True)
    return calls


def _register(client: Any, seal_id: str, ip: str = "127.0.0.1", **overrides: str) -> Any:
    login_admin(client)
    with client.session_transaction() as sess:
        sess["csrf_token"] = CSRF_TOKEN
    form = {"seal_id": seal_id, "case_number": "2026-N-M01", "investigator": "수사관N",
            "suspect_name": NAME, "suspect_email": EMAIL, "suspect_birth": BIRTH,
            "suspect_phone": PHONE, "auth_level": "basic", "csrf_token": CSRF_TOKEN,
            **overrides}
    resp = client.post("/investigator/register-case", data=form,
                       environ_base={"REMOTE_ADDR": ip})
    if resp.status_code == 302:  # back to the form, not to the admin login
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


class TestMariadbConcurrentOtp:
    def test_simultaneous_requests_respect_the_per_seal_cap(self, app, sent, monkeypatch) -> None:
        seal_id = "S-20260928-N1M001"
        app.config.update(OTP_MAX_DELIVERIES_PER_SEAL=2, OTP_DELIVERY_WINDOW_SECONDS=600)
        assert _register(app.test_client(), seal_id, auth_level="basic+otp").status_code == 302
        from web.privacy import case_identity

        real = case_identity.decrypt_field

        def slow(*args: Any) -> str:
            time.sleep(0.3)
            return real(*args)

        monkeypatch.setattr(case_identity, "decrypt_field", slow)

        codes = run_concurrently(
            lambda i: _send_otp(app.test_client(), seal_id, f"198.51.100.{60 + i}").status_code,
            range(6))

        # Exactly two deliveries; the others are refused by the cap (429), or,
        # should one wait past the database's lock timeout, with 503.
        assert codes.count(200) == 2 and set(codes) <= {200, 429, 503}, codes
        assert len(sent) == 2
        assert _count("SELECT COUNT(*) FROM identity_access_audit WHERE seal_id = %s "
                      "AND outcome = 'revealed'", (seal_id,)) == 2


@pytest.fixture()
def secret() -> str:
    import secrets

    return secrets.token_urlsafe(16)


class TestMariadbRegistrationAdmission:
    def test_simultaneous_registrations_respect_the_address_budget(
        self, app, secret, monkeypatch
    ) -> None:
        from web.auth import passwords

        app.config.update(CASE_REGISTRATION_MAX_PER_ADDRESS=2, CASE_PASSWORD_MAX_CONCURRENT=16)
        slow = SlowDerivations(passwords._derive, delay=0.3)
        monkeypatch.setattr(passwords, "_derive", slow)

        codes = run_concurrently(lambda i: _register(
            app.test_client(), f"S-20260928-N3M{i:03d}", "198.51.100.120",
            auth_level="basic+password", password=secret).status_code, range(6))

        # Reservations in flight count: a burst may be refused early, never late.
        registered = codes.count(302)
        assert set(codes) <= {302, 429} and registered <= 2, codes
        assert slow.calls == registered
        assert _count("SELECT COUNT(*) FROM auth_failures WHERE seal_id = %s "
                      "AND ip_address = %s",
                      ("@case-registration", "198.51.100.120")) == registered

    def test_concurrent_derivations_stay_within_the_pool(self, app, secret, monkeypatch) -> None:
        from web.auth import passwords

        app.config.update(CASE_REGISTRATION_MAX_PER_ADDRESS=50, CASE_PASSWORD_MAX_CONCURRENT=2)
        slow = SlowDerivations(passwords._derive, delay=0.5)
        monkeypatch.setattr(passwords, "_derive", slow)

        codes = run_concurrently(lambda i: _register(
            app.test_client(), f"S-20260928-N3P{i:03d}", "198.51.100.121",
            auth_level="basic+password", password=secret).status_code, range(6))

        registered = codes.count(302)
        assert set(codes) <= {302, 503} and registered >= 2, codes
        assert slow.peak <= 2 and slow.calls == registered
