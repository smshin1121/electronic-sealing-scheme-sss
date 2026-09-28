"""Administrator identity (stage E, E4): named-account login and audit.

The admin login takes a username and a password checked against the
account's scrypt hash; the shared ``ADMIN_PASSWORD`` of v1.0.1 no longer
logs anyone in and only draws a start-up WARNING. The session holds the
account id and username, and every admin request re-reads the account, so
disabling or deleting it ends open sessions. Failed logins are logged at
WARNING with the username only.

Every emergency release attempt that reaches the release gate writes the
administrator's username to ``release_audit.operator`` (the gate refuses
an admin attempt without one), and the route logs one WARNING line with
the username, seal, outcome, share slots and reason, never share or key
text. The standard and time-locked paths record an empty operator. An
existing ``release_audit`` table gains the column at start-up. Synthetic
data; every password here is generated per test.
"""

from __future__ import annotations

import logging
import re
import secrets
import sqlite3
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import (
    load_test_signer,
    make_seal_material,
    tsa_trust_settings,
)
from tests.fixtures.release_web import (
    ADMIN_USERNAME,
    SlowDerivations,
    add_pending_logins,
    admin_login_failures,
    admin_login_pending,
    audit_rows,
    create_admin,
    ensure_case,
    login_admin,
    login_burst,
    login_from,
    login_with_password,
    make_release_app,
    post_form,
    recover_standard,
    recovered_key,
    store_share,
    sync_seal,
)

pytestmark = pytest.mark.integration

LOGIN_URL = "/admin/login"
SHARES_URL = "/admin/shares"
ADMIN_URL = "/admin/emergency-recover"
ROUTE_LOGGER = "web.routes.admin"

# Refusal messages, one per cause (the default window is 600 s).
_MSG_LOCKED = "로그인 실패 횟수 초과로 10분간 차단되었습니다"
_MSG_BURST = "동시에 처리 중인 로그인 요청이 많습니다"
_MSG_BUSY = "서버에서 처리 중인 로그인 요청이 많아"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    return make_release_app(tmp_path, monkeypatch)


@pytest.fixture()
def client(app):
    return app.test_client()


def _password() -> str:
    return secrets.token_urlsafe(18)


def _session(client: Any) -> dict:
    with client.session_transaction() as sess:
        return dict(sess)


def _disable(app: Any, username: str) -> None:
    with app.app_context():
        from web.auth.admin_auth import disable_admin_account

        disable_admin_account(username)


def _warnings(caplog: Any, logger_name: str = ROUTE_LOGGER) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.name == logger_name and r.levelno == logging.WARNING]


def _all_messages(caplog: Any) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


def _redirects_to_login(resp: Any) -> bool:
    return resp.status_code == 302 and resp.headers["Location"].endswith(LOGIN_URL)


# ===================================================================
# Login with a named account
# ===================================================================

class TestLogin:
    def test_named_account_logs_in(self, app, client) -> None:
        password = create_admin(app, "alice")

        resp = login_with_password(client, "alice", password)

        assert resp.status_code == 302
        assert resp.headers["Location"].endswith(SHARES_URL)
        sess = _session(client)
        assert sess["admin_username"] == "alice"
        assert type(sess["admin_id"]) is int
        assert "is_admin" not in sess
        page = client.get(SHARES_URL)
        assert page.status_code == 200
        assert "alice" in page.get_data(as_text=True)

    def test_username_is_matched_after_normalization(self, app, client) -> None:
        password = create_admin(app, "alice")

        resp = login_with_password(client, "  ALICE ", password)

        assert resp.status_code == 302
        assert _session(client)["admin_username"] == "alice"

    def test_login_page_asks_for_username_and_password(self, client) -> None:
        html = client.get(LOGIN_URL).get_data(as_text=True)

        assert 'name="username"' in html
        assert 'name="password"' in html
        assert "관리자 계정명" in html

    def test_wrong_password_is_refused_and_logged_without_it(
        self, app, client, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        password = create_admin(app, "alice")
        wrong = _password()

        resp = login_with_password(client, "alice", wrong)

        assert resp.status_code == 401
        assert "admin_id" not in _session(client)
        warnings = _warnings(caplog)
        assert any("username=alice" in m for m in warnings), warnings
        logged = _all_messages(caplog)
        assert wrong not in logged and password not in logged

    def test_unknown_username_gets_the_same_answer(self, app, client) -> None:
        password = create_admin(app, "alice")

        unknown = login_with_password(client, "mallory", password)
        wrong = login_with_password(client, "alice", _password())

        assert unknown.status_code == wrong.status_code == 401
        assert unknown.get_data() == wrong.get_data()

    def test_unknown_username_still_costs_one_scrypt(
        self, app, client, monkeypatch
    ) -> None:
        from web.auth import passwords

        derivations: list[int] = []
        real = passwords._derive

        def counting(*args: Any) -> bytes:
            derivations.append(1)
            return real(*args)

        monkeypatch.setattr(passwords, "_derive", counting)

        resp = login_with_password(client, "mallory", _password())

        assert resp.status_code == 401
        assert derivations == [1]

    def test_malformed_username_is_not_logged_verbatim(
        self, client, caplog
    ) -> None:
        # e.g. a password typed into the username field by mistake
        caplog.set_level(logging.DEBUG)
        typed = "Pw!" + _password()

        resp = login_with_password(client, typed, _password())

        assert resp.status_code == 401
        logged = _all_messages(caplog)
        assert typed not in logged and typed.lower() not in logged
        assert any("username=<malformed>" in m for m in _warnings(caplog))

    def test_disabled_account_cannot_log_in(self, app, client, caplog) -> None:
        caplog.set_level(logging.DEBUG)
        password = create_admin(app, "alice")
        _disable(app, "alice")

        resp = login_with_password(client, "alice", password)

        assert resp.status_code == 401
        assert "admin_id" not in _session(client)
        assert any("username=alice" in m and "disabled" in m
                   for m in _warnings(caplog))


# ===================================================================
# Repeated failures lock the client out before any scrypt runs
# ===================================================================

class TestLoginLockout:
    def test_repeated_failures_lock_the_client_out(
        self, app, client, monkeypatch, caplog
    ) -> None:
        from web.auth import passwords

        caplog.set_level(logging.DEBUG)
        app.config["AUTH_MAX_FAILURES"] = 3
        password = create_admin(app, "alice")
        failures = [login_from(client, "192.0.2.10", "alice", _password())
                    for _ in range(3)]
        derivations: list[int] = []
        real = passwords._derive
        monkeypatch.setattr(passwords, "_derive",
                            lambda *args: derivations.append(1) or real(*args))

        locked = login_from(client, "192.0.2.10", "alice", password)

        assert [r.status_code for r in failures] == [401, 401, 401]
        assert locked.status_code == 429
        body = locked.get_data(as_text=True)
        assert _MSG_LOCKED in body and _MSG_BURST not in body
        assert derivations == []  # refused before any password work
        assert "admin_id" not in _session(client)
        assert any("too many" in m and "username=alice" in m
                   for m in _warnings(caplog))
        assert "192.0.2.10" not in _all_messages(caplog)

    def test_every_failure_cause_counts(self, app, client) -> None:
        app.config["AUTH_MAX_FAILURES"] = 3
        password = create_admin(app, "alice")
        _disable(app, "alice")

        causes = [
            login_from(client, "192.0.2.11", "Pw!" + _password(), _password()),
            login_from(client, "192.0.2.11", "mallory", _password()),
            login_from(client, "192.0.2.11", "alice", password),  # disabled
        ]
        locked = login_from(client, "192.0.2.11", "mallory", _password())

        assert [r.status_code for r in causes] == [401, 401, 401]
        assert locked.status_code == 429

    def test_other_clients_are_not_locked_out(self, app, client) -> None:
        app.config["AUTH_MAX_FAILURES"] = 2
        password = create_admin(app, "alice")
        for _ in range(2):
            login_from(client, "192.0.2.12", "alice", _password())

        blocked = login_from(client, "192.0.2.12", "alice", password)
        other = login_from(client, "198.51.100.7", "alice", password)

        assert blocked.status_code == 429
        assert other.status_code == 302
        assert _session(client)["admin_username"] == "alice"

    def test_a_successful_login_does_not_use_up_the_budget(self, app, client) -> None:
        # The success withdraws the place it reserved before the check.
        app.config["AUTH_MAX_FAILURES"] = 2
        password = create_admin(app, "alice")

        statuses = [
            login_from(client, "192.0.2.13", "alice", _password()).status_code,
            login_from(client, "192.0.2.13", "alice", password).status_code,
            login_from(client, "192.0.2.13", "alice", _password()).status_code,
            login_from(client, "192.0.2.13", "alice", password).status_code,
        ]

        assert statuses == [401, 302, 401, 429]
        assert admin_login_failures(app, "192.0.2.13") == 2

    @pytest.mark.parametrize("failed, in_flight, message", [
        (0, 3, _MSG_BURST),
        (2, 1, _MSG_BURST),
        (3, 0, _MSG_LOCKED),
        (3, 2, _MSG_LOCKED),
    ], ids=["in-flight-only", "failures-below-limit", "failures-at-limit",
            "failures-at-limit-and-in-flight"])
    def test_the_refusal_names_its_cause(
        self, app, client, monkeypatch, failed: int, in_flight: int,
        message: str,
    ) -> None:
        from web.auth import passwords

        app.config["AUTH_MAX_FAILURES"] = 3
        password = create_admin(app, "alice")
        for _ in range(failed):
            assert login_from(client, "192.0.2.14", "alice",
                              _password()).status_code == 401
        add_pending_logins(app, "192.0.2.14", in_flight)
        derivations: list[int] = []
        real = passwords._derive
        monkeypatch.setattr(passwords, "_derive",
                            lambda *args: derivations.append(1) or real(*args))

        refused = login_from(client, "192.0.2.14", "alice", password)

        assert refused.status_code == 429
        body = refused.get_data(as_text=True)
        other = _MSG_LOCKED if message == _MSG_BURST else _MSG_BURST
        assert message in body and other not in body
        assert derivations == []
        # The refused attempt withdrew its own reservation.
        assert (admin_login_failures(app, "192.0.2.14"),
                admin_login_pending(app, "192.0.2.14")) == (failed, in_flight)

    def test_a_burst_refusal_leaves_the_address_usable(self, app, client) -> None:
        # Once the attempts in progress end without failing, the address
        # logs in: it was not locked.
        app.config["AUTH_MAX_FAILURES"] = 3
        password = create_admin(app, "alice")
        add_pending_logins(app, "192.0.2.15", 3)

        refused = login_from(client, "192.0.2.15", "alice", password)
        with app.app_context():
            from web.models.db_models import execute_query

            execute_query("DELETE FROM auth_failures WHERE ip_address = ?",
                          ("192.0.2.15",))
        later = login_from(client, "192.0.2.15", "alice", password)

        assert refused.status_code == 429
        assert _MSG_BURST in refused.get_data(as_text=True)
        assert later.status_code == 302


# ===================================================================
# Concurrent logins (Codex round 1, F1)
# ===================================================================

class TestConcurrentLogins:
    """A burst of simultaneous logins cannot buy more password work than a
    sequence could: each attempt reserves its place in the address budget
    before any derivation, and derivations are bounded per process."""

    def test_a_burst_from_one_address_never_exceeds_its_budget(
        self, app, monkeypatch
    ) -> None:
        from web.auth import passwords

        app.config.update(AUTH_MAX_FAILURES=3, ADMIN_LOGIN_MAX_CONCURRENT=16)
        create_admin(app, "alice")
        # The derivations outlast every decision of the burst, so no
        # failure is recorded before the last request is refused.
        slow = SlowDerivations(passwords._derive, delay=1.0)
        monkeypatch.setattr(passwords, "_derive", slow)

        replies = login_burst(app, [("192.0.2.20", "alice", _password())] * 8)

        statuses = [status for status, _ in replies]
        # Requests beyond the address budget never entered scrypt.
        assert slow.calls <= 3, statuses
        assert statuses.count(401) == slow.calls
        assert statuses.count(429) == 8 - slow.calls
        # Refused because of attempts in progress, not because of failures:
        # the message does not claim a lockout.
        for status, body in replies:
            if status == 429:
                assert _MSG_BURST in body and _MSG_LOCKED not in body
        # Refused requests withdrew their reservation; failures keep theirs.
        assert admin_login_failures(app, "192.0.2.20") == slow.calls
        assert admin_login_pending(app, "192.0.2.20") == 0

    def test_concurrent_password_checks_are_bounded_per_process(
        self, app, monkeypatch, caplog
    ) -> None:
        from web.auth import passwords

        caplog.set_level(logging.DEBUG)
        app.config.update(AUTH_MAX_FAILURES=50, ADMIN_LOGIN_MAX_CONCURRENT=2)
        create_admin(app, "alice")
        slow = SlowDerivations(passwords._derive, delay=0.6)
        monkeypatch.setattr(passwords, "_derive", slow)
        ips = [f"192.0.2.{30 + i}" for i in range(6)]

        replies = login_burst(app, [(ip, "alice", _password()) for ip in ips])

        statuses = [status for status, _ in replies]
        assert slow.peak <= 2, statuses
        assert statuses.count(401) == slow.calls
        assert statuses.count(503) == 6 - slow.calls
        assert statuses.count(503) >= 1
        for ip, (status, body) in zip(ips, replies):
            # A request refused for capacity is told the server is busy, did
            # no password work and does not count against its address.
            if status == 503:
                assert _MSG_BUSY in body
                assert _MSG_LOCKED not in body and _MSG_BURST not in body
            assert admin_login_failures(app, ip) == (1 if status == 401 else 0)
            assert admin_login_pending(app, ip) == 0
        assert any("capacity" in m and "username=alice" in m
                   for m in _warnings(caplog))


# ===================================================================
# The shared password is gone
# ===================================================================

class TestSharedPasswordRemoved:
    def test_shared_admin_password_no_longer_logs_in(self, app, client) -> None:
        shared = _password()
        app.config["ADMIN_PASSWORD"] = shared

        answers = [
            post_form(client, LOGIN_URL, {"password": shared}).status_code,
            *(login_with_password(client, name, shared).status_code
              for name in ("", "admin", "administrator")),
        ]

        assert answers == [401, 401, 401, 401]
        assert "admin_id" not in _session(client)
        assert _redirects_to_login(client.get(SHARES_URL))

    def test_configured_admin_password_is_ignored_with_a_warning(
        self, tmp_path, monkeypatch, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        shared = _password()
        monkeypatch.setenv("ADMIN_PASSWORD", shared)

        app = make_release_app(tmp_path, monkeypatch)

        warnings = [r.getMessage() for r in caplog.records
                    if r.levelno == logging.WARNING]
        assert any("ADMIN_PASSWORD" in m and "ignored" in m for m in warnings)
        assert shared not in _all_messages(caplog)
        assert not app.config.get("ADMIN_PASSWORD")

    def test_startup_warns_when_no_account_can_log_in(
        self, tmp_path, monkeypatch, caplog
    ) -> None:
        caplog.set_level(logging.WARNING)

        make_release_app(tmp_path, monkeypatch)

        assert any("No enabled administrator account" in r.getMessage()
                   for r in caplog.records)


# ===================================================================
# Sessions end when the account is disabled or deleted
# ===================================================================

class TestSessionRevocation:
    def _signed_in(self, app: Any, client: Any, username: str = "alice") -> None:
        password = create_admin(app, username)
        assert login_with_password(client, username, password).status_code == 302
        assert client.get(SHARES_URL).status_code == 200

    def test_disabled_account_loses_its_open_session(
        self, app, client, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        seal_id = "S-20260928-E40001"
        self._signed_in(app, client)
        _disable(app, "alice")

        post = post_form(client, ADMIN_URL,
                         {"seal_id": seal_id, "reason": "synthetic"})

        assert _redirects_to_login(post)
        assert audit_rows(app, seal_id) == []
        assert "admin_id" not in _session(client)
        assert _redirects_to_login(client.get(SHARES_URL))
        assert any("username=alice" in m for m in _warnings(caplog))

    def test_deleted_account_loses_its_open_session(self, app, client) -> None:
        self._signed_in(app, client)
        with app.app_context():
            from web.models.db_models import execute_query

            execute_query("DELETE FROM admin_accounts WHERE username = ?",
                          ("alice",))

        assert _redirects_to_login(client.get(SHARES_URL))
        assert _redirects_to_login(client.get(ADMIN_URL))

    def test_session_naming_another_username_is_refused(self, app, client) -> None:
        self._signed_in(app, client)
        with client.session_transaction() as sess:
            sess["admin_username"] = "mallory"

        assert _redirects_to_login(client.get(SHARES_URL))

    @pytest.mark.parametrize("session_values", [
        {"is_admin": True},
        {"admin_id": "1", "admin_username": "alice"},
        {"admin_id": True, "admin_username": "alice"},
        {"admin_id": 1},
    ], ids=["legacy-flag", "id-as-text", "id-as-bool", "no-username"])
    def test_other_session_shapes_are_refused(
        self, app, client, session_values: dict
    ) -> None:
        create_admin(app, "alice")
        with client.session_transaction() as sess:
            sess.update(session_values)

        assert _redirects_to_login(client.get(SHARES_URL))
        assert _redirects_to_login(client.get(ADMIN_URL))


# ===================================================================
# The emergency release names the administrator
# ===================================================================

@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


@pytest.fixture()
def policy_app(tmp_path, monkeypatch, release_pki):
    """An app that verifies seal policies (the admin path needs no TSA/KMS)."""
    return make_release_app(tmp_path, monkeypatch,
                            ca_cert_path=str(release_pki.ca_cert_path))


def _emergency_warnings(caplog: Any) -> list[str]:
    return [m for m in _warnings(caplog) if m.startswith("Emergency recovery")]


def _secret_texts(seal: Any) -> list[str]:
    """Every share and the key, whole and without the index prefix."""
    payloads = [share.split("-", 1)[1] for share in seal.shares]
    return [*seal.shares, *payloads, seal.key_hex, seal.key_hex.upper()]


def _admin_rows(app: Any, seal_id: str) -> list[dict]:
    return [r for r in audit_rows(app, seal_id) if r["path"] == "admin"]


class TestEmergencyAuditIdentity:
    def _ready(self, app: Any, client: Any, master_key: str, signer: Any,
               seal_id: str, *, second: str | None = None) -> Any:
        seal = make_seal_material(seal_id=seal_id, master_key_path=master_key,
                                  signer=signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, second or seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])
        password = create_admin(app, "alice")
        assert login_with_password(client, "alice", password).status_code == 302
        return seal

    def test_release_records_the_operator_and_warns(
        self, policy_app, master_key, signer, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        client = policy_app.test_client()
        seal = self._ready(policy_app, client, master_key, signer,
                           "S-20260928-E40010")
        reason = "court order 2026-E4-01 (synthetic)"

        resp = post_form(client, ADMIN_URL,
                         {"seal_id": seal.seal_id, "reason": reason})

        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert seal.key_hex in body and "alice" in body
        [row] = _admin_rows(policy_app, seal.seal_id)
        assert (row["outcome"], row["policy_status"]) == ("released", "verified")
        assert (row["operator"], row["operator_reason"]) == ("alice", reason)
        [line] = _emergency_warnings(caplog)
        for part in ("Emergency recovery released", "admin=alice",
                     f"seal_id='{seal.seal_id}'", "shares=2+4",
                     "reason=released", reason):
            assert part in line, (part, line)
        logged = _all_messages(caplog)
        for secret in _secret_texts(seal):
            assert secret not in logged

    def test_denied_attempt_names_the_operator(
        self, policy_app, master_key, signer, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        client = policy_app.test_client()
        seal = self._ready(policy_app, client, master_key, signer,
                           "S-20260928-E40011")

        resp = post_form(client, ADMIN_URL, {"seal_id": seal.seal_id, "reason": ""})

        assert resp.status_code == 400
        [row] = _admin_rows(policy_app, seal.seal_id)
        assert (row["outcome"], row["reason"], row["operator"]) == (
            "denied", "reason_required", "alice")
        [line] = _emergency_warnings(caplog)
        for part in ("Emergency recovery denied", "admin=alice", "shares=none",
                     "reason=reason_required"):
            assert part in line, (part, line)

    def test_denial_after_share_selection_names_the_slots(
        self, policy_app, master_key, signer, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        client = policy_app.test_client()
        other = make_seal_material(seal_id="S-20260928-E40099",
                                   master_key_path=master_key, signer=signer)
        seal = self._ready(policy_app, client, master_key, signer,
                           "S-20260928-E40012", second=other.shares[1])

        resp = post_form(client, ADMIN_URL,
                         {"seal_id": seal.seal_id, "reason": "synthetic"})

        assert resp.status_code == 400
        [row] = _admin_rows(policy_app, seal.seal_id)
        assert (row["reason"], row["operator"]) == ("commitment_mismatch", "alice")
        [line] = _emergency_warnings(caplog)
        assert "Emergency recovery denied" in line and "shares=2+4" in line
        logged = _all_messages(caplog)
        for secret in _secret_texts(seal) + _secret_texts(other):
            assert secret not in logged

    def test_gate_error_still_names_the_operator(
        self, policy_app, master_key, signer, monkeypatch
    ) -> None:
        import web.release_gate as gate

        client = policy_app.test_client()
        seal = self._ready(policy_app, client, master_key, signer,
                           "S-20260928-E40013")

        def broken(_seal_id: str) -> Any:
            raise RuntimeError("synthetic policy store failure")

        monkeypatch.setattr(gate, "_resolve_policy", broken)

        resp = post_form(client, ADMIN_URL,
                         {"seal_id": seal.seal_id, "reason": "synthetic"})

        assert resp.status_code == 500
        [row] = _admin_rows(policy_app, seal.seal_id)
        assert (row["reason"], row["operator"]) == ("internal_error", "alice")

    def test_investigator_paths_record_no_operator(
        self, policy_app, master_key, signer
    ) -> None:
        client = policy_app.test_client()
        seal = make_seal_material(seal_id="S-20260928-E40014",
                                  master_key_path=master_key, signer=signer)
        sync_seal(client, policy_app, seal)
        store_share(policy_app, seal.seal_id, 1, seal.shares[0])
        login_admin(client)  # an admin session must not leak into these rows

        standard = recover_standard(client, seal)
        timelock = post_form(client, "/investigator/recover-key-timelock",
                             {"seal_id": seal.seal_id})

        assert standard.status_code == 302
        assert timelock.status_code == 400
        rows = audit_rows(policy_app, seal.seal_id)
        assert [(r["path"], r["operator"]) for r in rows] == [
            ("standard", ""), ("timelock", "")]

    def test_released_timelock_row_records_no_operator(
        self, tmp_path, monkeypatch, release_pki, release_tsa, master_key,
        signer,
    ) -> None:
        # Codex round 1, test adequacy 2: the test above stops before the
        # TSA. Here the time-locked release succeeds (TSA profile set) with
        # an administrator signed in to the same browser.
        app = make_release_app(
            tmp_path, monkeypatch, ca_cert_path=str(release_pki.ca_cert_path),
            master_key_path=master_key, tsa_url=release_tsa,
            **tsa_trust_settings(release_pki),
        )
        client = app.test_client()
        seal = make_seal_material(seal_id="S-20260928-E40015",
                                  master_key_path=master_key, signer=signer)
        sync_seal(client, app, seal)
        assert login_admin(client) == ADMIN_USERNAME

        resp = post_form(client, "/investigator/recover-key-timelock",
                         {"seal_id": seal.seal_id, "share_data": seal.shares[1]})

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        [row] = audit_rows(app, seal.seal_id)
        assert (row["path"], row["outcome"], row["reason"], row["operator"]) == (
            "timelock", "released", "released", "")
        assert row["tsa_token"] and row["tsa_gen_time"]


# ===================================================================
# Seal IDs are quoted on every release-gate log line (Codex round 1, F8)
# ===================================================================

# A newline in a seal ID must not start a forged log line.
_FORGED_ID = "S-20260928-E40040\nRelease released: forged"


def _assert_quoted_lines(caplog: Any, *expected: str) -> None:
    """Each expected line was logged (so the check is not vacuous), and
    every line naming the forged seal ID shows its newline escaped."""
    messages = [r.getMessage() for r in caplog.records
                if "S-20260928-E40040" in r.getMessage()]
    for prefix in expected:
        assert any(m.startswith(prefix) for m in messages), (prefix, messages)
    for message in messages:
        assert "\nRelease released: forged" not in message, message
        assert "\\nRelease released: forged" in message, message


def _raise(*_args: Any, **_kwargs: Any) -> Any:
    raise RuntimeError("synthetic store failure")


def _store_forged_shares(app: Any, master_key: str, *slots: int) -> None:
    """A case under the forged seal ID with legacy shares in ``slots``."""
    shares = make_seal_material(seal_id="S-20260928-E40041",
                                master_key_path=master_key, signer=None).shares
    ensure_case(app, _FORGED_ID)
    for slot in slots:
        store_share(app, _FORGED_ID, slot, shares[slot - 1])


class TestSealIdQuotedInGateLogs:
    @pytest.mark.parametrize("scenario, status, expected", [
        ("no_shares", 400,
         ("Release denied", "Emergency recovery denied")),
        ("legacy_override", 200,
         ("Admin override on an unauthenticated record", "Release released",
          "Emergency recovery released")),
        ("audit_insert_failure", 500,
         ("Admin override on an unauthenticated record",
          "Release audit write failed", "Emergency recovery denied")),
        ("gate_error", 500,
         ("Release gate error", "Release denied", "Emergency recovery denied")),
    ])
    def test_seal_id_is_quoted_in_every_admin_path_log_line(
        self, app, client, master_key, monkeypatch, caplog,
        scenario: str, status: int, expected: tuple[str, ...],
    ) -> None:
        import web.release_gate as gate

        caplog.set_level(logging.DEBUG)
        if scenario != "no_shares":
            _store_forged_shares(app, master_key, 2, 4)
        if scenario == "audit_insert_failure":
            monkeypatch.setattr(gate, "insert_release_audit", _raise)
        if scenario == "gate_error":
            monkeypatch.setattr(gate, "_resolve_policy", _raise)
        login_admin(client)

        resp = post_form(client, ADMIN_URL,
                         {"seal_id": _FORGED_ID, "reason": "synthetic"})

        assert resp.status_code == status
        _assert_quoted_lines(caplog, *expected)

    def test_seal_id_is_quoted_in_the_standard_legacy_line(
        self, app, client, master_key, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        _store_forged_shares(app, master_key, 1)
        presented = make_seal_material(seal_id="S-20260928-E40042",
                                       master_key_path=master_key,
                                       signer=None).shares[1]

        resp = post_form(client, "/investigator/recover-key",
                         {"seal_id": _FORGED_ID, "share_data": presented})

        assert resp.status_code == 403  # no synced record: commitment_missing
        _assert_quoted_lines(caplog, "No synced sealing record for",
                             "Release denied")

    def test_seal_id_is_quoted_in_the_enrollment_failure_line(
        self, app, monkeypatch, caplog
    ) -> None:
        # A signed policy cannot name a seal ID with a control character, so
        # this line is reached directly, with the enrollment write failing.
        # Record selection, with this line, moved to web.release_selection
        # in E2a.
        from types import SimpleNamespace

        import web.release_selection as selection

        caplog.set_level(logging.DEBUG)
        monkeypatch.setattr(selection, "enroll_seal", _raise)
        found = selection.Selection(
            "verified", policy=SimpleNamespace(digest_hex="00" * 32))

        with app.app_context():
            selection._enroll(_FORGED_ID, 1, found)  # logged, never raised

        _assert_quoted_lines(caplog, "Enrollment write failed")


class TestGateRequiresAnOperator:
    def _shares(self, app: Any, master_key: str) -> tuple[Any, dict[int, str]]:
        seal = make_seal_material(seal_id="S-20260928-E40020",
                                  master_key_path=master_key, signer=None)
        ensure_case(app, seal.seal_id)
        return seal, {2: seal.shares[1], 4: seal.shares[3]}

    def test_blank_operator_is_denied_and_audited(self, app, master_key) -> None:
        seal, shares = self._shares(app, master_key)
        with app.app_context():
            from web.release_gate import release_admin

            decision = release_admin(seal.seal_id, "synthetic", shares,
                                     operator="  ")

        assert not decision.allowed
        assert decision.reason == "operator_required"
        assert decision.key_hex is None
        [row] = audit_rows(app, seal.seal_id)
        assert (row["path"], row["outcome"], row["operator"]) == (
            "admin", "denied", "")

    def test_overlong_operator_is_denied_not_truncated(self, app, master_key) -> None:
        seal, shares = self._shares(app, master_key)
        with app.app_context():
            from web.release_gate import release_admin

            decision = release_admin(seal.seal_id, "synthetic", shares,
                                     operator="a" * 65)

        assert (decision.allowed, decision.reason) == (False, "operator_required")
        [row] = audit_rows(app, seal.seal_id)
        assert row["operator"] == ""

    def test_operator_is_a_required_keyword(self, app, master_key) -> None:
        seal, shares = self._shares(app, master_key)
        with app.app_context():
            from web.release_gate import release_admin

            with pytest.raises(TypeError):
                release_admin(seal.seal_id, "synthetic", shares)  # type: ignore[call-arg]

        assert audit_rows(app, seal.seal_id) == []

    def test_operator_message_is_mapped(self) -> None:
        from types import SimpleNamespace

        from web.routes.release_messages import denial_response

        status, message = denial_response(SimpleNamespace(
            reason="operator_required", path="admin", unlock_time_iso=""))

        assert status == 403 and "관리자" in message


# ===================================================================
# Schema: both variants, and the migration of an existing table
# ===================================================================

# release_audit as created by stage D (276af94), before the operator column.
_STAGE_D_RELEASE_AUDIT = """
CREATE TABLE release_audit (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id          TEXT    NOT NULL,
    path             TEXT    NOT NULL CHECK(path IN ('standard','timelock','admin')),
    policy_status    TEXT    NOT NULL,
    policy_digest    TEXT    NOT NULL,
    outcome          TEXT    NOT NULL CHECK(outcome IN ('released','denied')),
    reason           TEXT    NOT NULL,
    detail           TEXT    NOT NULL,
    operator_reason  TEXT    NOT NULL,
    tsa_token_sha256 TEXT    NOT NULL,
    tsa_token        TEXT    NOT NULL,
    tsa_challenge    TEXT    NOT NULL,
    tsa_gen_time     TEXT    NOT NULL,
    created_at       TEXT    NOT NULL
);
CREATE INDEX idx_release_audit_seal ON release_audit (seal_id, id);
INSERT INTO release_audit (seal_id, path, policy_status, policy_digest,
    outcome, reason, detail, operator_reason, tsa_token_sha256, tsa_token,
    tsa_challenge, tsa_gen_time, created_at)
VALUES ('S-20260927-OLD001', 'admin', 'legacy', '', 'released', 'released',
    'shares=2+4', 'pre-E4 row (synthetic)', '', '', '', '',
    '2026-09-27T00:00:00+00:00');
"""

_OPERATOR_DDL = re.compile(
    r"\n\s*operator\s+(TEXT|VARCHAR\(64\))\s+NOT NULL DEFAULT ''\s*\n\s*\)")


class TestOperatorColumn:
    def test_both_schema_variants_declare_the_column_last(self) -> None:
        from web.models import db_models

        for ddl in (db_models._SQLITE_SCHEMA, db_models._MARIADB_SCHEMA):
            block = ddl.split("CREATE TABLE IF NOT EXISTS release_audit", 1)[1]
            block = block.split(";", 1)[0]
            assert _OPERATOR_DDL.search(block), block

    def test_migration_adds_operator_to_an_existing_table(
        self, tmp_path, monkeypatch, master_key
    ) -> None:
        with sqlite3.connect(tmp_path / "release_web.db") as conn:
            conn.executescript(_STAGE_D_RELEASE_AUDIT)

        app = make_release_app(tmp_path, monkeypatch)
        again = make_release_app(tmp_path, monkeypatch)  # idempotent

        with again.app_context():
            from web.models.db_models import get_db

            columns = [row[1] for row in get_db().execute(
                "PRAGMA table_info(release_audit)").fetchall()]
        assert columns[-1] == "operator" and columns.count("operator") == 1
        [old] = audit_rows(app, "S-20260927-OLD001")
        assert (old["operator"], old["operator_reason"]) == (
            "", "pre-E4 row (synthetic)")

        client = again.test_client()
        seal = make_seal_material(seal_id="S-20260928-E40030",
                                  master_key_path=master_key, signer=None)
        ensure_case(again, seal.seal_id)
        store_share(again, seal.seal_id, 2, seal.shares[1])
        store_share(again, seal.seal_id, 4, seal.shares[3])
        login_admin(client)
        resp = post_form(client, ADMIN_URL,
                         {"seal_id": seal.seal_id, "reason": "synthetic"})

        assert resp.status_code == 200
        [row] = _admin_rows(again, seal.seal_id)
        assert row["operator"] == ADMIN_USERNAME
