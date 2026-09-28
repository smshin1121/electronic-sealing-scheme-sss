"""Subject authentication and OTP delivery with a protected identity (E3a).

Basic authentication digests the submitted name, birth date and phone and
compares them with the stored digests (constant time, all three fields);
formatting of the birth date and phone does not matter. The e-mail is
decrypted only to deliver an OTP, only after the basic (and password)
factors of that case pass, and each decryption writes an
``identity_access_audit`` row; if that row cannot be written, the e-mail
is not used. Missing keys answer 503 without counting as a failed
attempt; an unconverted case answers as a wrong credential (Fable gate,
finding 10). Pages reachable without authentication show no decrypted
identity. Synthetic data only.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import sqlite3
from typing import Any

import pytest

from tests.fixtures.privacy_keys import (
    clear_privacy_keys,
    make_privacy_key_files,
    set_privacy_keys,
)
from tests.fixtures.release_web import (
    CSRF_TOKEN,
    login_admin,
    make_release_app,
    post_form,
)

pytestmark = pytest.mark.integration

NAME, EMAIL = "홍길동", "hong.gildong@example.org"
# Not the placeholder the forms show (010-1234-5678), so a page scan can
# only find it if the page leaks it.
BIRTH, PHONE = "1990-01-01", "010-2468-1357"
IDENTITY_TEXTS = (NAME, EMAIL, "hong.gildong", "19900101", BIRTH, "01024681357", PHONE)
# The basic step's answers to a wrong and to an incomplete credential.
MISMATCH = "입력한 정보가 일치하지 않습니다."
INCOMPLETE = "이름, 생년월일, 연락처를 모두 입력해 주세요."


@pytest.fixture()
def app(tmp_path, monkeypatch):
    return make_release_app(tmp_path, monkeypatch)


@pytest.fixture()
def client(app):
    return app.test_client()


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


def _register(client: Any, seal_id: str, **overrides: str) -> None:
    form = {
        "seal_id": seal_id, "case_number": "2026-E3A-AUTH", "investigator": "수사관A",
        "suspect_name": NAME, "suspect_email": EMAIL, "suspect_birth": BIRTH,
        "suspect_phone": PHONE, "auth_level": "basic",
    }
    form.update(overrides)
    resp = post_form(client, "/investigator/register-case", form)
    assert resp.status_code == 302, resp.get_data(as_text=True)


def _auth(client: Any, seal_id: str, name: str = NAME, birth: str = BIRTH,
          phone: str = PHONE, **extra: str) -> Any:
    return post_form(client, f"/suspect/auth/{seal_id}",
                     {"name": name, "birth_date": birth, "phone": phone, **extra})


def _send_otp(client: Any, seal_id: str, name: str = NAME, birth: str = BIRTH,
              phone: str = PHONE, ip: str = "127.0.0.1", **extra: str) -> Any:
    with client.session_transaction() as sess:
        sess["csrf_token"] = CSRF_TOKEN
    return client.post(
        f"/suspect/send-otp/{seal_id}",
        data={"name": name, "birth_date": birth, "phone": phone,
              "csrf_token": CSRF_TOKEN, **extra},
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        environ_base={"REMOTE_ADDR": ip},
    )


def _sql(app: Any, statement: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    try:
        rows = list(conn.execute(statement, params))
        conn.commit()
        return rows
    finally:
        conn.close()


def _access_rows(app: Any, seal_id: str) -> list[dict]:
    with app.app_context():
        from web.models.privacy_models import find_identity_access

        return find_identity_access(seal_id)


def _failures(app: Any, seal_id: str) -> int:
    return _sql(app, "SELECT COUNT(*) FROM auth_failures WHERE seal_id = ?", (seal_id,))[0][0]


def _authenticated(client: Any, seal_id: str) -> bool:
    with client.session_transaction() as sess:
        return bool(sess.get(f"auth_{seal_id}"))


class TestBasicAuthentication:
    @pytest.mark.parametrize("name,birth,phone", [
        (NAME, "19900101", "01024681357"),
        (NAME, "1990-01-01", "010-2468-1357"),
        (f"  {NAME} ", " 1990.01.01 ", "010 2468 1357"),
    ])
    def test_formatting_variants_authenticate(self, app, client, name, birth, phone) -> None:
        _register(client, "S-20260928-AUT001")

        resp = _auth(client, "S-20260928-AUT001", name, birth, phone)

        assert resp.status_code == 302
        assert _authenticated(client, "S-20260928-AUT001")

    @pytest.mark.parametrize("field,wrong", [
        ("name", "홍길순"), ("birth", "1990-01-02"), ("phone", "010-2468-1358"),
    ])
    def test_a_wrong_value_in_any_single_field_fails(self, app, client, field, wrong) -> None:
        _register(client, "S-20260928-AUT002")
        values = {"name": NAME, "birth": BIRTH, "phone": PHONE, field: wrong}

        resp = _auth(client, "S-20260928-AUT002", **values)

        assert resp.status_code == 401
        assert not _authenticated(client, "S-20260928-AUT002")
        assert _failures(app, "S-20260928-AUT002") == 1

    def test_all_three_fields_are_compared_in_constant_time(self, app, client, monkeypatch) -> None:
        _register(client, "S-20260928-AUT003")
        calls: list[bytes] = []
        original = hmac.compare_digest

        def counting(a: Any, b: Any) -> bool:
            # Only digest comparisons (64 hex bytes); the signed session
            # cookie is checked with compare_digest too.
            if isinstance(a, bytes) and re.fullmatch(rb"[0-9a-f]{64}", a):
                calls.append(a)
            return original(a, b)

        monkeypatch.setattr(hmac, "compare_digest", counting)
        resp = _auth(client, "S-20260928-AUT003", name="틀린이름")

        assert resp.status_code == 401
        assert len(calls) == 3  # name, birth date and phone; no early exit

    def test_an_unregistered_phone_never_matches(self, app, client) -> None:
        _register(client, "S-20260928-AUT004", suspect_phone="")

        for phone in ("-", "0", PHONE):
            assert _auth(client, "S-20260928-AUT004", phone=phone).status_code == 401

    def test_an_unregistered_birth_date_never_matches(self, app, client) -> None:
        # v1.0.1 compared normalised birth dates, so a case registered
        # without one accepted any submitted value without digits ("x").
        _register(client, "S-20260928-AUT010", suspect_birth="")

        for birth in ("x", "-", BIRTH):
            assert _auth(client, "S-20260928-AUT010", birth=birth).status_code == 401

    def test_another_pepper_cannot_authenticate(self, app, client, tmp_path, monkeypatch) -> None:
        _register(client, "S-20260928-AUT005")
        pepper, _ = make_privacy_key_files(tmp_path / "other")
        set_privacy_keys(monkeypatch, pepper, app.config["PRIVACY_KMS_MASTER_KEY_PATH"])
        other = make_release_app(tmp_path, monkeypatch)

        resp = _auth(other.test_client(), "S-20260928-AUT005")

        assert resp.status_code == 401

    def test_digests_copied_from_another_case_do_not_match(self, app, client) -> None:
        _register(client, "S-20260928-AUT006")
        _register(client, "S-20260928-AUT007", suspect_name="김철수",
                  suspect_birth="1985-05-05", suspect_phone="010-9876-5432")
        _sql(app, """UPDATE cases SET
                        suspect_name_digest = (SELECT suspect_name_digest FROM cases WHERE seal_id = ?),
                        suspect_birth_digest = (SELECT suspect_birth_digest FROM cases WHERE seal_id = ?),
                        suspect_phone_digest = (SELECT suspect_phone_digest FROM cases WHERE seal_id = ?)
                     WHERE seal_id = ?""",
             ("S-20260928-AUT006",) * 3 + ("S-20260928-AUT007",))

        resp = _auth(client, "S-20260928-AUT007")  # the identity of AUT006

        assert resp.status_code == 401

    @pytest.mark.parametrize("unset", ["pepper", "master_key", "both"])
    def test_missing_keys_refuse_authentication_with_503(self, app, client, unset) -> None:
        # An app does not start without the keys (Fable gate, finding 5);
        # clearing them on a running app stands for a key lost later.
        _register(client, "S-20260928-AUT008")
        clear_privacy_keys(app, unset)

        resp = _auth(client, "S-20260928-AUT008")

        assert resp.status_code == 503
        assert "개인정보 보호 키" in resp.get_data(as_text=True)
        assert _failures(app, "S-20260928-AUT008") == 0


class TestUnconvertedCase:
    """Fable gate, finding 10: a case whose identity was never converted
    answers exactly as a wrong credential (401, the same message, counted
    toward the lockout), so a response does not show which cases are still
    unconverted; the cause is logged at WARNING."""

    @staticmethod
    def _insert_unconverted(app: Any, seal_id: str, auth_level: str = "basic") -> None:
        _sql(app, """INSERT INTO cases (seal_id, case_number, investigator, suspect_name,
                        suspect_birth, suspect_phone, auth_level)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
             (seal_id, "C-OLD", "수사관", NAME, "19900101", PHONE, auth_level))

    @pytest.mark.parametrize("fields, message", [
        ({}, MISMATCH), ({"name": ""}, INCOMPLETE)], ids=["complete", "incomplete"])
    def test_login_answers_as_a_wrong_credential(
        self, app, client, caplog, fields, message
    ) -> None:
        caplog.set_level(logging.WARNING)
        self._insert_unconverted(app, "S-20260928-AUT009")
        _register(client, "S-20260928-AUT011")

        unconverted = _auth(client, "S-20260928-AUT009", **fields)
        wrong = _auth(client, "S-20260928-AUT011", **{"phone": "010-0000-0000", **fields})

        for resp in (unconverted, wrong):
            page = resp.get_data(as_text=True)
            assert resp.status_code == 401
            assert message in page and "이관" not in page
        assert _failures(app, "S-20260928-AUT009") == _failures(app, "S-20260928-AUT011") == 1

    def test_the_cause_is_logged_at_warning_without_the_identity(
        self, app, client, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        self._insert_unconverted(app, "S-20260928-AUT012")

        _auth(client, "S-20260928-AUT012")

        warnings = [r.getMessage() for r in caplog.records
                    if r.levelno == logging.WARNING and "src.web.privacy.migrate" in r.getMessage()]
        assert warnings and all("S-20260928-AUT012" in m for m in warnings)
        logged = "\n".join(r.getMessage() for r in caplog.records)
        assert all(text not in logged for text in IDENTITY_TEXTS)

    def test_failures_count_toward_the_lockout(self, app, client) -> None:
        app.config["AUTH_MAX_FAILURES"] = 2
        self._insert_unconverted(app, "S-20260928-AUT013")

        codes = [_auth(client, "S-20260928-AUT013").status_code for _ in range(3)]

        assert codes == [401, 401, 429]

    def test_otp_delivery_answers_as_a_wrong_credential(self, app, client, sent) -> None:
        self._insert_unconverted(app, "S-20260928-AUT014", auth_level="basic+otp")

        resp = _send_otp(client, "S-20260928-AUT014")

        assert resp.status_code == 401
        assert resp.get_json()["message"] == MISMATCH
        assert sent == [] and _failures(app, "S-20260928-AUT014") == 1
        assert _access_rows(app, "S-20260928-AUT014") == []


class TestOtpDelivery:
    def _register_otp_case(self, client: Any, seal_id: str, **overrides: str) -> None:
        _register(client, seal_id, auth_level="basic+otp", **overrides)

    def test_the_email_is_decrypted_only_after_basic_authentication(self, app, client, sent) -> None:
        self._register_otp_case(client, "S-20260928-OTP001")

        refused = _send_otp(client, "S-20260928-OTP001", phone="010-0000-0000")
        assert refused.status_code == 401
        assert sent == [] and _access_rows(app, "S-20260928-OTP001") == []

        resp = _send_otp(client, "S-20260928-OTP001")

        assert resp.status_code == 200 and resp.get_json()["success"] is True
        assert [email for email, _ in sent] == [EMAIL]
        [row] = _access_rows(app, "S-20260928-OTP001")
        assert (row["field"], row["purpose"], row["actor_role"], row["actor"],
                row["client_address"], row["outcome"]) == (
            "suspect_email", "otp_delivery", "subject", "", "127.0.0.1", "revealed")
        assert EMAIL not in str(row) and "hong" not in str(row)

    def test_the_delivered_code_completes_the_login(self, app, client, sent) -> None:
        self._register_otp_case(client, "S-20260928-OTP002")
        assert _send_otp(client, "S-20260928-OTP002").status_code == 200
        code = sent[-1][1]

        resp = _auth(client, "S-20260928-OTP002", otp=code)

        assert resp.status_code == 302 and _authenticated(client, "S-20260928-OTP002")

    def test_a_request_without_credentials_decrypts_nothing(self, app, client, sent) -> None:
        self._register_otp_case(client, "S-20260928-OTP003")

        resp = _send_otp(client, "S-20260928-OTP003", name="", birth="", phone="")

        assert resp.status_code == 401
        assert sent == [] and _access_rows(app, "S-20260928-OTP003") == []

    def test_failed_requests_count_toward_the_lockout(self, app, client, sent) -> None:
        app.config["AUTH_MAX_FAILURES"] = 2
        self._register_otp_case(client, "S-20260928-OTP004")

        codes = [_send_otp(client, "S-20260928-OTP004", phone="010-0000-0000").status_code
                 for _ in range(2)]
        locked = _send_otp(client, "S-20260928-OTP004")
        elsewhere = _send_otp(client, "S-20260928-OTP004", ip="198.51.100.7")

        assert codes == [401, 401] and locked.status_code == 429
        assert elsewhere.status_code == 200
        assert len(_access_rows(app, "S-20260928-OTP004")) == 1

    def test_a_failing_audit_write_withholds_the_email(self, app, client, sent, monkeypatch) -> None:
        self._register_otp_case(client, "S-20260928-OTP005")

        def broken(entry: Any) -> int:
            raise sqlite3.OperationalError("synthetic audit failure")

        monkeypatch.setattr("web.privacy.case_identity.insert_identity_access", broken)
        resp = _send_otp(client, "S-20260928-OTP005")

        assert resp.status_code == 503
        assert sent == []
        with client.session_transaction() as sess:
            assert "otp_session_S-20260928-OTP005" not in sess

    @pytest.mark.parametrize("unset", ["pepper", "master_key", "both"])
    def test_missing_keys_refuse_delivery_with_503(self, app, client, sent, unset) -> None:
        self._register_otp_case(client, "S-20260928-OTP006")
        clear_privacy_keys(app, unset)

        resp = _send_otp(client, "S-20260928-OTP006")

        assert resp.status_code == 503
        assert sent == [] and _failures(app, "S-20260928-OTP006") == 0

    def test_deliveries_per_seal_are_capped(self, app, client, sent) -> None:
        app.config.update(OTP_MAX_DELIVERIES_PER_SEAL=2, OTP_DELIVERY_WINDOW_SECONDS=600)
        self._register_otp_case(client, "S-20260928-OTP013")

        codes = [_send_otp(client, "S-20260928-OTP013", ip=ip).status_code
                 for ip in ("127.0.0.1", "198.51.100.8", "198.51.100.9")]

        assert codes == [200, 200, 429]
        assert len(sent) == 2
        assert len(_access_rows(app, "S-20260928-OTP013")) == 2  # no third decryption
        assert _failures(app, "S-20260928-OTP013") == 0

    def test_a_case_without_the_otp_factor_gets_no_code(self, app, client, sent) -> None:
        _register(client, "S-20260928-OTP007")

        resp = _send_otp(client, "S-20260928-OTP007")

        assert resp.status_code == 400
        assert sent == [] and _access_rows(app, "S-20260928-OTP007") == []

    def test_the_password_factor_is_checked_before_delivery(self, app, client, sent) -> None:
        password = secrets.token_urlsafe(12)
        _register(client, "S-20260928-OTP008", auth_level="basic+password+otp",
                  password=password)

        wrong = _send_otp(client, "S-20260928-OTP008", password=secrets.token_urlsafe(12))
        right = _send_otp(client, "S-20260928-OTP008", password=password)

        assert (wrong.status_code, right.status_code) == (401, 200)
        assert len(sent) == 1

    def test_otp_log_lines_do_not_contain_the_email(self, app, client, caplog) -> None:
        caplog.set_level(logging.DEBUG)
        self._register_otp_case(client, "S-20260928-OTP009")

        assert _send_otp(client, "S-20260928-OTP009").status_code == 200

        text = "\n".join(r.getMessage() for r in caplog.records)
        for identity in IDENTITY_TEXTS:
            assert identity not in text, identity

    def test_an_email_ciphertext_moved_to_another_case_does_not_decrypt(self, app, client, sent) -> None:
        self._register_otp_case(client, "S-20260928-OTP010")
        self._register_otp_case(client, "S-20260928-OTP011", suspect_email="other@example.org")
        _sql(app, """UPDATE cases SET suspect_email_enc =
                        (SELECT suspect_email_enc FROM cases WHERE seal_id = ?)
                     WHERE seal_id = ?""", ("S-20260928-OTP010", "S-20260928-OTP011"))

        resp = _send_otp(client, "S-20260928-OTP011")

        assert resp.status_code == 500 and sent == []
        [row] = _access_rows(app, "S-20260928-OTP011")
        assert row["outcome"] == "failed"

    def test_a_ciphertext_moved_to_another_column_does_not_decrypt(self, app, client) -> None:
        self._register_otp_case(client, "S-20260928-OTP012")
        _sql(app, "UPDATE cases SET suspect_email_enc = suspect_name_enc WHERE seal_id = ?",
             ("S-20260928-OTP012",))

        with app.test_request_context():
            from web.privacy.case_identity import reveal_case_field
            from web.privacy.field_crypto import FieldCryptoError

            with pytest.raises(FieldCryptoError):
                reveal_case_field("S-20260928-OTP012", "suspect_email",
                                  purpose="otp_delivery", actor_role="subject")
        assert [r["outcome"] for r in _access_rows(app, "S-20260928-OTP012")] == ["failed"]


class TestCasePassword:
    def _insert_legacy(self, app: Any, seal_id: str, password: str) -> None:
        with app.app_context():
            from web.models.db_models import insert_case

            insert_case(seal_id=seal_id, case_number="C-LEGACY", investigator="수사관",
                        suspect_name=NAME, suspect_birth=BIRTH, suspect_phone=PHONE,
                        auth_level="basic+password",
                        password_hash=hashlib.sha256(password.encode("utf-8")).hexdigest())

    def _stored_hash(self, app: Any, seal_id: str) -> str:
        return _sql(app, "SELECT password_hash FROM cases WHERE seal_id = ?", (seal_id,))[0][0]

    def test_a_legacy_hash_logs_in_once_and_is_then_scrypt(self, app, client) -> None:
        password = secrets.token_urlsafe(6)  # shorter than today's policy
        self._insert_legacy(app, "S-20260928-PWD001", password)

        first = _auth(client, "S-20260928-PWD001", password=password)
        upgraded = self._stored_hash(app, "S-20260928-PWD001")
        second = _auth(app.test_client(), "S-20260928-PWD001", password=password)

        from web.auth.passwords import verify_password

        assert (first.status_code, second.status_code) == (302, 302)
        assert upgraded.startswith("scrypt$") and verify_password(password, upgraded)

    def test_a_legacy_check_costs_one_scrypt_derivation_like_a_modern_one(self, monkeypatch) -> None:
        import web.auth.passwords as passwords
        from web.auth.case_passwords import verify_case_password

        password = secrets.token_urlsafe(12)
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        derivations: list[int] = []
        original = passwords._derive

        def counting(*args: Any) -> bytes:
            derivations.append(1)
            return original(*args)

        monkeypatch.setattr(passwords, "_derive", counting)

        assert verify_case_password(password, legacy) is True
        assert verify_case_password(password + "x", legacy) is False
        assert len(derivations) == 2  # timing does not reveal a legacy hash

    def test_an_overlong_legacy_password_logs_in_without_a_traceback(self, app, client, caplog) -> None:
        caplog.set_level(logging.WARNING)
        password = "p" * 1100  # above the scrypt bound, possible under v1.0.1
        self._insert_legacy(app, "S-20260928-PWD005", password)
        before = self._stored_hash(app, "S-20260928-PWD005")

        resp = _auth(client, "S-20260928-PWD005", password=password)

        assert resp.status_code == 302
        assert self._stored_hash(app, "S-20260928-PWD005") == before
        records = [r for r in caplog.records if r.name == "web.routes.suspect"]
        assert any("not upgraded" in r.getMessage() for r in records)
        assert all(r.exc_info is None for r in records)

    def test_a_wrong_password_keeps_the_legacy_hash(self, app, client) -> None:
        password = secrets.token_urlsafe(12)
        self._insert_legacy(app, "S-20260928-PWD002", password)
        before = self._stored_hash(app, "S-20260928-PWD002")

        resp = _auth(client, "S-20260928-PWD002", password=secrets.token_urlsafe(12))

        assert resp.status_code == 401
        assert self._stored_hash(app, "S-20260928-PWD002") == before

    def test_the_legacy_hash_is_compared_in_constant_time(self, app, client, monkeypatch) -> None:
        password = secrets.token_urlsafe(12)
        self._insert_legacy(app, "S-20260928-PWD003", password)
        compared: list[tuple] = []
        original = hmac.compare_digest

        def recording(a: Any, b: Any) -> bool:
            compared.append((a, b))
            return original(a, b)

        monkeypatch.setattr(hmac, "compare_digest", recording)
        _auth(client, "S-20260928-PWD003", password=secrets.token_urlsafe(12))

        stored = self._stored_hash(app, "S-20260928-PWD003").encode("ascii")
        assert any(stored in pair for pair in compared)

    def test_a_new_case_password_logs_in(self, app, client) -> None:
        password = secrets.token_urlsafe(12)
        _register(client, "S-20260928-PWD004", auth_level="basic+password", password=password)

        wrong = _auth(app.test_client(), "S-20260928-PWD004", password=secrets.token_urlsafe(12))
        right = _auth(client, "S-20260928-PWD004", password=password)

        assert (wrong.status_code, right.status_code) == (401, 302)


class TestVisibility:
    PUBLIC_PAGES = (
        "/", "/suspect/auth/", "/suspect/auth/{seal}", "/suspect/records/{seal}",
        "/suspect/upload-share/{seal}", "/suspect/upload-share",
        "/investigator/register-case", "/investigator/upload-share",
        "/investigator/recover-key", "/investigator/recover-key-timelock",
        "/investigator/recovered/{seal}", "/investigator/download-key/{seal}",
        "/admin/login", "/admin/shares", "/admin/emergency-recover",
    )

    def _assert_no_identity(self, body: str, where: str) -> None:
        for identity in IDENTITY_TEXTS:
            assert identity not in body, (where, identity)

    def test_pages_reachable_without_authentication_show_no_identity(self, app, client) -> None:
        seal = "S-20260928-VIS001"
        _register(client, seal, auth_level="basic+otp")

        for page in self.PUBLIC_PAGES:
            resp = client.get(page.format(seal=seal), follow_redirects=True)
            self._assert_no_identity(resp.get_data(as_text=True), page)
        failed = _auth(client, seal, name="김철수")
        otp = _send_otp(client, seal, name="김철수")

        self._assert_no_identity(failed.get_data(as_text=True), "failed auth")
        self._assert_no_identity(otp.get_data(as_text=True), "send-otp")
        assert _access_rows(app, seal) == []

    def test_subject_and_admin_pages_show_no_identity(self, app, client) -> None:
        seal = "S-20260928-VIS002"
        _register(client, seal)
        assert _auth(client, seal).status_code == 302
        login_admin(client)

        for page in ("/suspect/upload-share/{seal}", "/suspect/records/{seal}",
                     "/admin/shares", "/admin/emergency-recover"):
            resp = client.get(page.format(seal=seal))
            assert resp.status_code == 200, page
            self._assert_no_identity(resp.get_data(as_text=True), page)
        assert _access_rows(app, seal) == []
