"""The signed seal record creates its case (stage F, F2).

Fable gate finding 4 (v1.1): case registration was unauthenticated, so
whoever learned a seal ID first could register it with identity values of
their choosing. Since F2 a sync submission whose envelope verifies and
whose record carries a policy ``verified`` for the same seal creates the
missing case from the record, in the transaction that claims the nonce,
stores the record and sets the generation mark:

  - case number and investigator from ``case_info``; the subject's name,
    birth date, phone and e-mail from ``signer_info``, protected exactly as
    the E3a registration protects them; ``SYNC_CASE_AUTH_LEVEL`` (``basic``
    or ``basic+otp``); no password; ``registered_by`` names the sync and
    the certificate that signed the envelope;
  - nothing is created for an unsigned submission (404 as before), an
    envelope that does not verify (401), an invalid policy (422), an
    expired or absent policy (404), a missing or over-long identity value
    (422), or missing privacy keys (503); the nonce stays unused;
  - an existing case is used as it is, and a registration attempted
    without an administrator session leaves the seal free for its record.

Synthetic material only (test CA, temporary keys).
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.case_registration import (
    CASE_NUMBER,
    IDENTITY_TEXTS,
    INVESTIGATOR,
    REGISTER_URL,
    SUBJECT,
    SYNC_URL,
    creatable_record,
    register_as_admin,
    registration_form,
    slow_case_creation,
    without,
)
from tests.fixtures.concurrency import run_concurrently
from tests.fixtures.privacy_keys import clear_privacy_keys, read_pepper
from tests.fixtures.release_pki import (
    load_test_signer,
    make_expired_signer,
    make_seal_material,
)
from tests.fixtures.release_web import (
    ADMIN_USERNAME,
    make_release_app,
    post_form,
    recover_standard,
    recovered_key,
    sync_payload,
)
from tests.fixtures.sync_web import high_water, nonce_rows, signed_payload

pytestmark = pytest.mark.integration


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(tmp_path, monkeypatch, release_pki, master_key):
    return make_release_app(tmp_path, monkeypatch,
                            ca_cert_path=str(release_pki.ca_cert_path),
                            master_key_path=master_key)


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _seal(seal_id: str, master_key: str, signer: Any, **kwargs: Any) -> Any:
    kwargs.setdefault("generation", 1)
    return make_seal_material(seal_id=seal_id, master_key_path=master_key,
                              signer=signer, case_no=CASE_NUMBER, **kwargs)


def _post(app: Any, body: dict) -> Any:
    return app.test_client().post(SYNC_URL, json=body)


def _rows(app: Any, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute(sql, params))
    finally:
        conn.close()


def _case(app: Any, seal_id: str) -> dict[str, Any]:
    [row] = _rows(app, "SELECT * FROM cases WHERE seal_id = ?", (seal_id,))
    return dict(row)


def _nothing_created(app: Any, seal_id: str) -> None:
    for table in ("cases", "seal_records", "seal_data_keys", "wrapped_s3_shares",
                  "policy_enrollment", "policy_high_water"):
        assert _rows(app, f"SELECT * FROM {table} WHERE seal_id = ?", (seal_id,)) == [], table


def _digest(app: Any, field: str, seal_id: str, value: str) -> str:
    from web.privacy.digests import identity_digest

    return identity_digest(read_pepper(app), field, seal_id, value)


def _all_cases(app: Any, seal_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in _rows(app, "SELECT * FROM cases WHERE seal_id = ?",
                                       (seal_id,))]


def _sent_to_login(resp: Any) -> bool:
    return resp.status_code == 302 and resp.headers["Location"].endswith("/admin/login")


def _sync_registrar(signer: Any) -> str:
    from cryptography.hazmat.primitives import hashes

    return "sync:" + signer.cert.fingerprint(hashes.SHA256()).hex()[:16]


# ===================================================================
# A verified signed record creates its case
# ===================================================================

class TestCreation:
    def test_a_signed_sealing_record_creates_its_case(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2C001", master_key, signer)
        body = signed_payload(seal, signer, record=creatable_record(seal))

        resp = _post(app, body)

        assert resp.status_code == 200, resp.get_json()
        case = _case(app, seal.seal_id)
        assert (case["case_number"], case["investigator"]) == (CASE_NUMBER, INVESTIGATOR)
        assert (case["auth_level"], case["password_hash"]) == ("basic", "")
        assert case["registered_by"] == _sync_registrar(signer)
        assert case["identity_scheme"] == "v1"
        assert case["suspect_name_digest"] == _digest(app, "name", seal.seal_id, SUBJECT["name"])
        assert case["suspect_birth_digest"] == _digest(app, "birth_date", seal.seal_id, "19920715")
        assert case["suspect_phone_digest"] == _digest(app, "phone", seal.seal_id, "01058231946")
        for column in ("suspect_name", "suspect_email", "suspect_birth", "suspect_phone"):
            assert case[column] == "", column
        for column, value in case.items():
            for text in IDENTITY_TEXTS:
                assert text not in str(value), (column, text)
        assert len(_rows(app, "SELECT * FROM seal_data_keys WHERE seal_id = ?",
                         (seal.seal_id,))) == 1
        assert len(_rows(app, "SELECT * FROM seal_records WHERE seal_id = ?",
                         (seal.seal_id,))) == 1
        assert _rows(app, "SELECT * FROM identity_access_audit") == []
        assert nonce_rows(app) == [body["sync_auth"]["envelope"]["nonce"]]
        assert high_water(app, seal.seal_id) == (1, seal.policy_digest.hex(), 1)

    def test_the_ciphertexts_decrypt_to_the_record_values(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2C002", master_key, signer)
        assert _post(app, signed_payload(seal, signer,
                                         record=creatable_record(seal))).status_code == 200

        case = _case(app, seal.seal_id)
        with app.app_context():
            from web.privacy.case_identity import load_seal_data_key
            from web.privacy.field_crypto import decrypt_field

            key = load_seal_data_key(seal.seal_id)
        assert decrypt_field(key, "cases", seal.seal_id, "suspect_name_enc",
                             case["suspect_name_enc"]) == SUBJECT["name"]
        assert decrypt_field(key, "cases", seal.seal_id, "suspect_email_enc",
                             case["suspect_email_enc"]) == SUBJECT["email"]

    def test_the_subject_then_authenticates_uploads_share_1_and_a_release_follows(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-F2C003", master_key, signer)
        assert _post(app, signed_payload(seal, signer,
                                         record=creatable_record(seal))).status_code == 200
        subject = app.test_client()

        wrong = post_form(app.test_client(), f"/suspect/auth/{seal.seal_id}",
                          {"name": SUBJECT["name"], "birth_date": SUBJECT["birth_date"],
                           "phone": "010-5823-1947"})
        auth = post_form(subject, f"/suspect/auth/{seal.seal_id}",
                         {"name": SUBJECT["name"], "birth_date": "19920715",
                          "phone": "01058231946"})
        upload = post_form(subject, f"/suspect/upload-share/{seal.seal_id}",
                           {"seal_id": seal.seal_id, "share_data": seal.shares[0]})
        investigator = app.test_client()
        release = recover_standard(investigator, seal)

        assert (wrong.status_code, auth.status_code, upload.status_code) == (401, 302, 302)
        assert release.status_code == 302
        assert recovered_key(investigator, seal.seal_id) == seal.key_hex

    def test_the_email_is_optional_at_the_basic_level(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2C004", master_key, signer)
        record = creatable_record(seal)
        record["signer_info"] = without(record["signer_info"], "email")

        assert _post(app, signed_payload(seal, signer, record=record)).status_code == 200
        case = _case(app, seal.seal_id)
        assert case["suspect_email_enc"] == "" and case["suspect_name_enc"]

    def test_the_configured_otp_level_is_used(self, app, master_key, signer) -> None:
        app.config["SYNC_CASE_AUTH_LEVEL"] = "basic+otp"
        seal = _seal("S-20260928-F2C005", master_key, signer)

        assert _post(app, signed_payload(seal, signer,
                                         record=creatable_record(seal))).status_code == 200
        assert _case(app, seal.seal_id)["auth_level"] == "basic+otp"

    def test_the_otp_level_needs_an_email(self, app, master_key, signer) -> None:
        # A case whose subject has no e-mail could never receive a code.
        app.config["SYNC_CASE_AUTH_LEVEL"] = "basic+otp"
        seal = _seal("S-20260928-F2C006", master_key, signer)
        record = creatable_record(seal, signer_info={"email": ""})
        body = signed_payload(seal, signer, record=record)

        resp = _post(app, body)

        assert resp.status_code == 422
        assert "signer_info.email" in resp.get_json()["message"]
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_a_later_event_may_create_the_case(self, app, master_key, signer) -> None:
        # Unsealing and Resealing records carry case_info and signer_info
        # forward, so the first event the web receives may be a later one.
        seal = _seal("S-20260928-F2C007", master_key, signer, generation=2)
        body = signed_payload(seal, signer, record=creatable_record(seal), event_id=2,
                              event_type="Resealing")

        assert _post(app, body).status_code == 200
        assert _case(app, seal.seal_id)["registered_by"] == _sync_registrar(signer)
        assert high_water(app, seal.seal_id) == (2, seal.policy_digest.hex(), 2)

    def test_an_existing_case_is_used_as_it_is(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2C008", master_key, signer)
        form = registration_form(seal.seal_id)
        assert register_as_admin(app, form).status_code == 302
        before = _case(app, seal.seal_id)

        resp = _post(app, signed_payload(seal, signer, record=creatable_record(seal)))

        assert resp.status_code == 200
        assert _case(app, seal.seal_id) == before
        assert before["registered_by"] == ADMIN_USERNAME
        assert before["suspect_name_digest"] == _digest(app, "name", seal.seal_id,
                                                        form["suspect_name"])
        assert len(_rows(app, "SELECT * FROM seal_data_keys WHERE seal_id = ?",
                         (seal.seal_id,))) == 1

    def test_a_failure_after_the_creation_rolls_the_case_back(
        self, app, master_key, signer
    ) -> None:
        # Creation, nonce, record and mark are one transaction.
        def broken(**_kwargs: Any) -> None:
            raise RuntimeError("synthetic failure after the store")

        seal = _seal("S-20260928-F2C009", master_key, signer)
        body = signed_payload(seal, signer, record=creatable_record(seal))
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("web.routes.sync.raise_high_water", broken)
            assert _post(app, body).status_code == 500

        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []
        assert _post(app, body).status_code == 200

    def test_a_duplicate_event_after_the_creation_keeps_no_case(
        self, app, master_key, signer
    ) -> None:
        # The store's duplicate-event answer (409) would commit what the
        # transaction wrote so far; after a creation it must roll back.
        from web.models.release_models import DuplicateEventError

        def duplicate(**_kwargs: Any) -> None:
            raise DuplicateEventError("synthetic duplicate after the creation")

        seal = _seal("S-20260928-F2C012", master_key, signer)
        body = signed_payload(seal, signer, record=creatable_record(seal))
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("web.routes.sync.store_synced_record", duplicate)
            assert _post(app, body).status_code == 500

        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_no_identity_value_is_logged_or_answered(
        self, app, master_key, signer, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        created = _seal("S-20260928-F2C010", master_key, signer)
        refused = _seal("S-20260928-F2C011", master_key, signer)
        record = creatable_record(refused, signer_info={"phone": "---"})

        answers = [_post(app, signed_payload(created, signer,
                                             record=creatable_record(created))),
                   _post(app, signed_payload(refused, signer, record=record))]

        assert [a.status_code for a in answers] == [200, 422]
        logged = "\n".join(r.getMessage() for r in caplog.records)
        assert "S-20260928-F2C010" in logged and "signer_info.phone" in logged
        for text in IDENTITY_TEXTS:
            assert text not in logged, text
            for answer in answers:
                assert text not in answer.get_data(as_text=True), text


# ===================================================================
# Submissions that create nothing
# ===================================================================

class TestNoCreation:
    def test_an_unsigned_submission_is_refused_with_404(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2N001", master_key, signer)
        body = sync_payload(seal, record=creatable_record(seal))

        resp = _post(app, body)

        assert resp.status_code == 404
        assert "사건" in resp.get_json()["message"]
        _nothing_created(app, seal.seal_id)

    @pytest.mark.parametrize("signed", [False, True])
    def test_a_submission_that_cannot_create_the_case_takes_no_lock(
        self, app, master_key, signer, release_pki, monkeypatch, signed
    ) -> None:
        # Unsigned, or signed over an expired policy: refused before the
        # seal's write lock, so it never holds the gap lock of a missing
        # case row (on MariaDB that lock would delay a real first sync).
        import web.routes.sync as sync_route

        taken: list[str] = []
        real = sync_route.seal_write_transaction

        def counting(seal_id: str) -> Any:
            taken.append(seal_id)
            return real(seal_id)

        monkeypatch.setattr(sync_route, "seal_write_transaction", counting)
        seal = _seal("S-20260928-F2N016", master_key,
                     make_expired_signer(release_pki) if signed else signer)
        record = creatable_record(seal)
        body = (signed_payload(seal, signer, record=record) if signed
                else sync_payload(seal, record=record))

        resp = _post(app, body)
        replay = _post(app, body)

        # No nonce is claimed or checked, so the replay is a 404 as well.
        assert (resp.status_code, replay.status_code) == (404, 404)
        assert taken == []
        assert nonce_rows(app) == []
        _nothing_created(app, seal.seal_id)

    def test_a_refusal_without_a_case_does_not_wait_for_the_write_lock(
        self, app, master_key, signer
    ) -> None:
        # Another writer holds SQLite's write lock: the unsigned submission
        # for a seal without a case is refused at once, not after the busy
        # timeout (5 s) with "database is locked".
        import time

        seal = _seal("S-20260928-F2N017", master_key, signer)
        body = sync_payload(seal, record=creatable_record(seal))
        holder = sqlite3.connect(app.config["SQLITE_PATH"])
        try:
            holder.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            resp = _post(app, body)
            elapsed = time.monotonic() - started
        finally:
            holder.rollback()
            holder.close()

        assert resp.status_code == 404
        assert elapsed < 2.0, elapsed

    def test_a_tampered_envelope_is_refused_with_401(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2N002", master_key, signer)
        body = signed_payload(seal, signer, record=creatable_record(seal))
        body["sync_auth"]["envelope"]["event_id"] = 2

        assert _post(app, body).status_code == 401
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_an_envelope_over_other_bytes_is_refused_with_401(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-F2N003", master_key, signer)
        body = signed_payload(seal, signer, record=creatable_record(seal))
        body["record_json"] = body["record_json"].replace(SUBJECT["phone"], "010-0000-1111")

        assert _post(app, body).status_code == 401
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_an_invalid_policy_is_refused_with_422(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2N004", master_key, signer)
        record = creatable_record(seal)
        record["policy"] = {**record["policy"], "unlock_time_iso": "2020-01-01T00:00:00Z"}

        resp = _post(app, signed_payload(seal, signer, record=record))

        assert resp.status_code == 422
        assert "정책" in resp.get_json()["message"]
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_an_expired_policy_creates_nothing(self, app, master_key, signer, release_pki) -> None:
        seal = _seal("S-20260928-F2N005", master_key, make_expired_signer(release_pki))
        body = signed_payload(seal, signer, record=creatable_record(seal))

        resp = _post(app, body)

        assert resp.status_code == 404
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_a_record_without_a_policy_creates_nothing(self, app, master_key, signer) -> None:
        seal = make_seal_material(seal_id="S-20260928-F2N006", master_key_path=master_key,
                                  signer=None, case_no=CASE_NUMBER)
        body = signed_payload(seal, signer, record=creatable_record(seal),
                              include_wrapped=False)

        resp = _post(app, body)

        assert resp.status_code == 404
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_without_a_pinned_ca_nothing_is_created(
        self, tmp_path, monkeypatch, master_key, signer
    ) -> None:
        app = make_release_app(tmp_path, monkeypatch, master_key_path=master_key)
        seal = _seal("S-20260928-F2N007", master_key, signer)
        record = creatable_record(seal)

        unsigned = _post(app, sync_payload(seal, record=record))
        signed = _post(app, signed_payload(seal, signer, record=record))

        assert (unsigned.status_code, signed.status_code) == (404, 503)
        _nothing_created(app, seal.seal_id)

    @pytest.mark.parametrize("section,field,value", [
        ("case_info", "case_number", None), ("case_info", "case_number", "  "),
        ("case_info", "investigator", None), ("case_info", "investigator", ""),
        ("signer_info", "name", None), ("signer_info", "name", " \t "),
        ("signer_info", "name", 7), ("signer_info", "birth_date", None),
        ("signer_info", "birth_date", "unknown"), ("signer_info", "phone", None),
        ("signer_info", "phone", "--"), ("signer_info", "phone", ["010"]),
    ])
    def test_a_missing_identity_value_is_refused_with_422(
        self, app, master_key, signer, section, field, value
    ) -> None:
        seal = _seal("S-20260928-F2N010", master_key, signer)
        record = creatable_record(seal)
        record[section] = (without(record[section], field) if value is None
                           else {**record[section], field: value})

        resp = _post(app, signed_payload(seal, signer, record=record))

        assert resp.status_code == 422
        assert f"{section}.{field}" in resp.get_json()["message"]
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    @pytest.mark.parametrize("section,field,length", [
        ("case_info", "case_number", 129), ("case_info", "investigator", 129),
        ("signer_info", "name", 129), ("signer_info", "email", 257),
        ("signer_info", "birth_date", 17), ("signer_info", "phone", 33),
    ])
    def test_an_overlong_value_is_refused_not_truncated(
        self, app, master_key, signer, section, field, length
    ) -> None:
        seal = _seal("S-20260928-F2N011", master_key, signer)
        record = creatable_record(seal)
        record[section] = {**record[section], field: "1" * length}

        resp = _post(app, signed_payload(seal, signer, record=record))

        assert resp.status_code == 422
        assert f"{section}.{field}" in resp.get_json()["message"]
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_the_longest_values_are_accepted(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-F2N012", master_key, signer)
        record = creatable_record(
            seal, case_info={"investigator": "수" * 128},
            signer_info={"name": "가" * 128, "email": "e" * 256,
                         "birth_date": "1" * 16, "phone": "2" * 32})

        assert _post(app, signed_payload(seal, signer, record=record)).status_code == 200
        assert _case(app, seal.seal_id)["investigator"] == "수" * 128

    def test_a_record_naming_another_seal_is_refused_with_422(
        self, app, master_key, signer
    ) -> None:
        # Without wrapped_s3: with one, the route refuses the mismatch (400)
        # before any other check.
        seal = _seal("S-20260928-F2N013", master_key, signer)
        record = creatable_record(seal, seal_id="S-20260928-F2N099")

        resp = _post(app, signed_payload(seal, signer, record=record,
                                         include_wrapped=False))

        assert resp.status_code == 422
        _nothing_created(app, seal.seal_id)
        _nothing_created(app, "S-20260928-F2N099")

    def test_a_reserved_seal_id_is_refused_with_422(self, app, master_key, signer) -> None:
        # '@'-keys in auth_failures count admin logins and registrations.
        seal = _seal("@case-registration", master_key, signer)

        resp = _post(app, signed_payload(seal, signer, record=creatable_record(seal)))

        assert resp.status_code == 422
        _nothing_created(app, seal.seal_id)

    @pytest.mark.parametrize("unset", ["pepper", "master_key", "both"])
    def test_missing_privacy_keys_answer_503(self, app, master_key, signer, unset) -> None:
        seal = _seal("S-20260928-F2N014", master_key, signer)
        clear_privacy_keys(app, unset)

        resp = _post(app, signed_payload(seal, signer, record=creatable_record(seal)))

        assert resp.status_code == 503
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []

    def test_a_master_key_unreadable_when_wrapping_answers_503(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        from web.privacy.field_crypto import FieldCryptoError

        def unreadable(*_args: Any) -> bytes:
            raise FieldCryptoError("the data key could not be wrapped")

        monkeypatch.setattr("web.privacy.case_identity.wrap_data_key", unreadable)
        seal = _seal("S-20260928-F2N015", master_key, signer)

        resp = _post(app, signed_payload(seal, signer, record=creatable_record(seal)))

        assert resp.status_code == 503
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []


# ===================================================================
# A registration without a session cannot pre-empt the signed record
# ===================================================================

class TestPreemption:
    def test_the_seal_stays_free_for_its_signed_record(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-F2P001", master_key, signer)
        attempt = registration_form(seal.seal_id)

        squat = post_form(app.test_client(), REGISTER_URL, attempt)
        synced = app.test_client().post(SYNC_URL, json=signed_payload(
            seal, signer, record=creatable_record(seal)))

        assert _sent_to_login(squat)
        assert synced.status_code == 200
        [case] = _all_cases(app, seal.seal_id)
        assert case["registered_by"] == _sync_registrar(signer)
        assert case["case_number"] == CASE_NUMBER
        assert case["suspect_name_digest"] == _digest(app, "name", seal.seal_id,
                                                      SUBJECT["name"])
        squatter = post_form(app.test_client(), f"/suspect/auth/{seal.seal_id}",
                             {"name": attempt["suspect_name"],
                              "birth_date": attempt["suspect_birth"],
                              "phone": attempt["suspect_phone"]})
        subject = post_form(app.test_client(), f"/suspect/auth/{seal.seal_id}",
                            {"name": SUBJECT["name"], "birth_date": SUBJECT["birth_date"],
                             "phone": SUBJECT["phone"]})
        assert (squatter.status_code, subject.status_code) == (401, 302)

    def test_a_case_the_sync_created_is_409_on_the_form(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-F2P002", master_key, signer)
        assert app.test_client().post(SYNC_URL, json=signed_payload(
            seal, signer, record=creatable_record(seal))).status_code == 200

        resp = register_as_admin(app, registration_form(seal.seal_id))

        assert resp.status_code == 409
        assert len(_all_cases(app, seal.seal_id)) == 1


# ===================================================================
# Two first syncs of one seal at the same moment (SQLite)
# ===================================================================

class TestSimultaneousFirstSyncs:
    def test_the_write_lock_serializes_them_into_one_case(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        # SQLite's BEGIN IMMEDIATE makes the second wait; it then finds the
        # case and the record, and completes as an identical resubmission.
        seal = _seal("S-20260928-F2S001", master_key, signer)
        record = creatable_record(seal)
        bodies = [signed_payload(seal, signer, record=record) for _ in range(2)]
        slow_case_creation(monkeypatch, 0.3)

        codes = run_concurrently(lambda body: _post(app, body).status_code, bodies)

        assert codes == [200, 200]
        assert len(_rows(app, "SELECT * FROM cases WHERE seal_id = ?", (seal.seal_id,))) == 1
        assert len(_rows(app, "SELECT * FROM seal_records WHERE seal_id = ?",
                         (seal.seal_id,))) == 1
        assert len(_rows(app, "SELECT * FROM seal_data_keys WHERE seal_id = ?",
                         (seal.seal_id,))) == 1
        assert sorted(nonce_rows(app)) == sorted(
            body["sync_auth"]["envelope"]["nonce"] for body in bodies)


class TestRaceClassification:
    def test_only_a_conflict_on_the_case_insert_is_a_race(self, app) -> None:
        # MariaDB only: a duplicate key, lock wait timeout or deadlock on the
        # case row's insert (503, retry); any other error is a fault (500),
        # for example a duplicate on the data key's insert.
        from flask import g

        from web.models.privacy_models import CaseInsertError
        from web.sync_registration import _lost_to_concurrent_insert

        class DriverError(Exception):
            def __init__(self, errno: int, text: str = "synthetic driver error") -> None:
                super().__init__(text)
                self.errno = errno

        def on_case_insert(cause: Exception) -> CaseInsertError:
            try:
                raise CaseInsertError("the case row was not inserted") from cause
            except CaseInsertError as exc:
                return exc

        with app.test_request_context():
            g.db_type = "mariadb"
            for errno in (1062, 1205, 1213):
                assert _lost_to_concurrent_insert(on_case_insert(DriverError(errno)))
            assert _lost_to_concurrent_insert(on_case_insert(
                RuntimeError("Deadlock found when trying to get lock")))
            assert not _lost_to_concurrent_insert(on_case_insert(DriverError(1452)))
            assert not _lost_to_concurrent_insert(DriverError(1062, "Duplicate entry"))
            g.db_type = "sqlite"
            assert not _lost_to_concurrent_insert(on_case_insert(DriverError(1213)))


# ===================================================================
# SYNC_CASE_AUTH_LEVEL
# ===================================================================

class TestAuthLevelSetting:
    def test_the_default_is_basic(self) -> None:
        import os

        from web.config import BaseConfig
        from web.sync_registration import sync_case_auth_level

        assert sync_case_auth_level({}) == "basic"
        assert BaseConfig.SYNC_CASE_AUTH_LEVEL == os.environ.get(
            "SYNC_CASE_AUTH_LEVEL", "basic")

    @pytest.mark.parametrize("value", ["basic", "basic+otp", " basic+otp "])
    def test_a_passwordless_level_starts(self, tmp_path, monkeypatch, value) -> None:
        from web.config import TestingConfig

        monkeypatch.setattr(TestingConfig, "SYNC_CASE_AUTH_LEVEL", value, raising=False)

        app = make_release_app(tmp_path, monkeypatch)

        assert app.config["SYNC_CASE_AUTH_LEVEL"] == value

    @pytest.mark.parametrize("value", [
        "basic+password", "basic+password+otp", "otp", "BASIC", "", "garbage", None, 1,
    ])
    def test_any_other_value_refuses_start_up(self, tmp_path, monkeypatch, value) -> None:
        from web.config import TestingConfig

        monkeypatch.setattr(TestingConfig, "SYNC_CASE_AUTH_LEVEL", value, raising=False)
        from web.sync_registration import SyncCaseConfigError

        with pytest.raises(SyncCaseConfigError, match="SYNC_CASE_AUTH_LEVEL"):
            make_release_app(tmp_path, monkeypatch)

    def test_a_value_broken_at_run_time_creates_nothing(
        self, app, master_key, signer
    ) -> None:
        app.config["SYNC_CASE_AUTH_LEVEL"] = "basic+password"
        seal = _seal("S-20260928-F2L001", master_key, signer)

        resp = _post(app, signed_payload(seal, signer, record=creatable_record(seal)))

        assert resp.status_code == 503
        _nothing_created(app, seal.seal_id)
        assert nonce_rows(app) == []
