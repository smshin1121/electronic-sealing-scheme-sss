"""Synced seal records are stored encrypted (stage E, E3b).

``POST /sync/upload-record`` stores ``record_json`` and ``record_pdf`` as
AES-256-GCM ciphertexts under the seal's data key, bound to the table, the
seal, the event and the column (``record_scheme = 'v1'``). The model
functions decrypt, so sync admission and the release gate keep their rules.

  - No column of a stored row, and nothing in the SQLite file, holds the
    record text, a signer value or the PDF bytes; decryption returns the
    exact received bytes.
  - A ciphertext moved to another seal, another event or the other column
    reads as unreadable (never as absent): the gate denies and audits.
  - Without the privacy keys the sync route answers 503 and stores nothing;
    a key file unreadable at request time is 503 with an ERROR log that
    holds neither key bytes nor record content. A seal without a case is
    refused with 404 (since stage F, F2, unless its signed record creates
    the case; one that cannot is refused and creates nothing).
  - Rows stored before E3b (``record_scheme = ''``) are never read as
    plaintext: the gate denies, sync answers 503 (run the migration).
  - Identical resubmission, conflicts and displacement behave as before.

Synthetic material only (test CA, temporary keys).
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import (
    SIGNER_INFO,
    copy_column,
    database_file_bytes,
    identity_record,
    insert_plaintext_row,
    leaks,
    needles,
    sql_execute,
    sql_rows,
    stored_row,
    synthetic_pdf,
)
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    login_admin,
    make_release_app,
    post_form,
    recover_standard,
    recovered_key,
    store_share,
    sync_payload,
)
from tests.fixtures.sync_web import nonce_rows, signed_payload

pytestmark = pytest.mark.integration

URL = "/sync/upload-record"


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


def _seal(seal_id: str, master_key: str, signer: Any, **kwargs: Any):
    if signer is not None:
        kwargs.setdefault("generation", 1)
    return make_seal_material(seal_id=seal_id, master_key_path=master_key,
                              signer=signer, **kwargs)


def _post(app: Any, body: dict, *, case: bool = True) -> Any:
    if case:
        ensure_case(app, body["seal_id"])
    return app.test_client().post(URL, json=body)


def _unsigned(seal: Any, record: dict, *, event_id: int = 1,
              event_type: str = "Sealing", pdf: bytes | None = None) -> dict:
    body = sync_payload(seal, record=record, event_id=event_id,
                        event_type=event_type, include_wrapped=False)
    if pdf is not None:
        body["record_pdf"] = base64.b64encode(pdf).decode("ascii")
    return body


def _record_at(app: Any, seal_id: str, event_id: int) -> Any:
    with app.app_context():
        from web.models.release_models import find_record_json_at

        return find_record_json_at(seal_id, event_id)


def _pdf_at(app: Any, seal_id: str, event_id: int) -> Any:
    with app.app_context():
        from web.models.release_models import find_record_pdf_at

        return find_record_pdf_at(seal_id, event_id)


def _is_unreadable(value: Any) -> bool:
    from web.privacy.record_store import UnreadableRecord

    return isinstance(value, UnreadableRecord)


# ===================================================================
# What is stored
# ===================================================================

class TestStoredForm:
    def test_no_column_holds_the_record_its_signer_or_the_pdf(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-E3B001", master_key, signer)
        pdf = synthetic_pdf("signed")
        body = signed_payload(seal, signer, record=identity_record(seal), record_pdf=pdf)

        assert _post(app, body).status_code == 200

        row = stored_row(app, seal.seal_id, 1)
        assert row["record_scheme"] == "v1"
        assert row["record_json"].startswith("r1:")
        assert bytes(row["record_pdf"]).startswith(b"r1:")
        assert leaks(row, needles(body["record_json"], pdf)) == []

    def test_an_unsigned_record_is_protected_the_same_way(self, app, master_key) -> None:
        seal = _seal("S-20260928-E3B002", master_key, None)
        pdf = synthetic_pdf("unsigned")
        body = _unsigned(seal, identity_record(seal), pdf=pdf)

        assert _post(app, body).status_code == 200

        row = stored_row(app, seal.seal_id, 1)
        assert row["record_scheme"] == "v1"
        assert leaks(row, needles(body["record_json"], pdf)) == []

    def test_the_database_file_holds_no_plaintext(self, app, master_key, signer) -> None:
        seal = _seal("S-20260928-E3B003", master_key, signer)
        pdf = synthetic_pdf("file")
        body = signed_payload(seal, signer, record=identity_record(seal), record_pdf=pdf)
        assert _post(app, body).status_code == 200
        other = _seal("S-20260928-E3B004", master_key, None)
        assert _post(app, _unsigned(other, identity_record(other), pdf=pdf)).status_code == 200

        stored = database_file_bytes(app)

        for pattern in needles(body["record_json"], pdf):
            assert pattern not in stored, pattern[:40]

    def test_the_stored_record_decrypts_to_the_exact_received_bytes(
        self, app, master_key
    ) -> None:
        seal = _seal("S-20260928-E3B005", master_key, None)
        record = identity_record(seal)
        # Unusual layout: indentation, key order and a trailing newline.
        text = json.dumps(dict(reversed(list(record.items()))),
                          ensure_ascii=False, indent=3) + "\n"
        pdf = synthetic_pdf("exact") + bytes(range(256))
        body = _unsigned(seal, record, pdf=pdf)
        body["record_json"] = text

        assert _post(app, body).status_code == 200

        assert _record_at(app, seal.seal_id, 1) == text
        assert _pdf_at(app, seal.seal_id, 1) == pdf
        # The column itself decrypts to those bytes under the seal's key.
        row = stored_row(app, seal.seal_id, 1)
        with app.app_context():
            from web.privacy.case_identity import load_seal_data_key
            from web.privacy.record_crypto import open_record_json, open_record_pdf

            key = load_seal_data_key(seal.seal_id)
            assert open_record_json(key, seal.seal_id, 1, row["record_json"]) == text
            assert open_record_pdf(key, seal.seal_id, 1, row["record_pdf"]) == pdf

    def test_a_record_without_a_pdf_keeps_a_null_pdf(self, app, master_key) -> None:
        seal = _seal("S-20260928-E3B006", master_key, None)

        assert _post(app, _unsigned(seal, identity_record(seal))).status_code == 200

        assert stored_row(app, seal.seal_id, 1)["record_pdf"] is None
        assert _pdf_at(app, seal.seal_id, 1) is None

    def test_the_record_uses_the_data_key_of_its_case(self, app, master_key) -> None:
        seal = _seal("S-20260928-E3B007", master_key, None)

        assert _post(app, _unsigned(seal, identity_record(seal))).status_code == 200

        keys = sql_rows(app, "SELECT seal_id FROM seal_data_keys WHERE seal_id = ?",
                        (seal.seal_id,))
        assert len(keys) == 1


# ===================================================================
# Moved ciphertexts fail closed
# ===================================================================

def _two_events(app: Any, seal: Any) -> None:
    for event_id, event_type in ((1, "Sealing"), (2, "Unsealing")):
        record = identity_record(seal, note=f"event {event_id}")
        body = _unsigned(seal, record, event_id=event_id, event_type=event_type,
                         pdf=synthetic_pdf(str(event_id)))
        assert _post(app, body).status_code == 200


class TestMovedCiphertext:
    def test_a_record_copied_to_another_seal_is_unreadable(self, app, master_key) -> None:
        first = _seal("S-20260928-E3B011", master_key, None)
        second = _seal("S-20260928-E3B012", master_key, None)
        for seal in (first, second):
            assert _post(app, _unsigned(seal, identity_record(seal))).status_code == 200

        copy_column(app, (first.seal_id, 1, "record_json"), (second.seal_id, 1, "record_json"))

        assert _is_unreadable(_record_at(app, second.seal_id, 1))
        assert json.loads(_record_at(app, first.seal_id, 1))["seal_id"] == first.seal_id

    def test_a_record_copied_to_another_event_of_the_seal_is_unreadable(
        self, app, master_key
    ) -> None:
        seal = _seal("S-20260928-E3B013", master_key, None)
        _two_events(app, seal)

        copy_column(app, (seal.seal_id, 1, "record_json"), (seal.seal_id, 2, "record_json"))
        copy_column(app, (seal.seal_id, 1, "record_pdf"), (seal.seal_id, 2, "record_pdf"))

        assert _is_unreadable(_record_at(app, seal.seal_id, 2))
        with app.app_context():
            from web.models.release_models import find_record_pdf_at
            from web.privacy.field_crypto import FieldCryptoError

            with pytest.raises(FieldCryptoError):
                find_record_pdf_at(seal.seal_id, 2)
        assert json.loads(_record_at(app, seal.seal_id, 1))["note"] == "event 1"

    @pytest.mark.parametrize("source,target", [
        ("record_pdf", "record_json"), ("record_json", "record_pdf"),
    ])
    def test_a_value_moved_to_the_other_column_is_unreadable(
        self, app, master_key, source, target
    ) -> None:
        seal = _seal("S-20260928-E3B014", master_key, None)
        body = _unsigned(seal, identity_record(seal), pdf=synthetic_pdf("col"))
        assert _post(app, body).status_code == 200

        copy_column(app, (seal.seal_id, 1, source), (seal.seal_id, 1, target))

        with app.app_context():
            from web.models.release_models import find_record_json_at, find_record_pdf_at
            from web.privacy.field_crypto import FieldCryptoError

            if target == "record_json":
                assert _is_unreadable(find_record_json_at(seal.seal_id, 1))
            else:
                with pytest.raises(FieldCryptoError):
                    find_record_pdf_at(seal.seal_id, 1)

    def test_the_gate_denies_an_unreadable_record_and_audits_it(
        self, app, master_key
    ) -> None:
        # Unsigned: no mark and no enrollment, so the record decides alone.
        seal = _seal("S-20260928-E3B015", master_key, None)
        other = _seal("S-20260928-E3B016", master_key, None)
        for material in (seal, other):
            assert _post(app, _unsigned(material, material.record)).status_code == 200
        store_share(app, seal.seal_id, 1, seal.shares[0])
        copy_column(app, (other.seal_id, 1, "record_json"), (seal.seal_id, 1, "record_json"))
        client = app.test_client()

        resp = recover_standard(client, seal)

        assert resp.status_code == 500
        assert recovered_key(client, seal.seal_id) is None
        [row] = audit_rows(app, seal.seal_id)
        assert (row["outcome"], row["reason"], row["policy_status"]) == (
            "denied", "record_unreadable", "record_unreadable")

    def test_unreadable_mark_records_are_denied_not_treated_as_absent(
        self, app, master_key, signer
    ) -> None:
        # Two signed records of one seal (same policy, so the same mark).
        # Swapping their ciphertexts between the events leaves valid
        # plaintext records in plaintext storage; encrypted, neither opens.
        seal = _seal("S-20260928-E3B017", master_key, signer)
        for event_id, event_type in ((1, "Sealing"), (2, "Unsealing")):
            body = signed_payload(seal, signer, event_id=event_id, event_type=event_type,
                                  record=identity_record(seal, note=str(event_id)),
                                  include_wrapped=event_id == 1)
            assert _post(app, body).status_code == 200
        store_share(app, seal.seal_id, 1, seal.shares[0])
        first = stored_row(app, seal.seal_id, 1)["record_json"]
        copy_column(app, (seal.seal_id, 2, "record_json"), (seal.seal_id, 1, "record_json"))
        sql_execute(app, "UPDATE seal_records SET record_json = ? "
                         "WHERE seal_id = ? AND event_id = 2", (first, seal.seal_id))
        client = app.test_client()

        resp = recover_standard(client, seal)

        assert resp.status_code == 403
        assert recovered_key(client, seal.seal_id) is None
        [row] = audit_rows(app, seal.seal_id)
        assert (row["outcome"], row["reason"]) == ("denied", "policy_invalid")
        assert row["policy_status"] not in ("record_missing", "legacy")

    def test_the_admin_path_is_denied_on_an_unreadable_record(
        self, app, master_key
    ) -> None:
        seal = _seal("S-20260928-E3B019", master_key, None)
        other = _seal("S-20260928-E3B020", master_key, None)
        for material in (seal, other):
            assert _post(app, _unsigned(material, material.record)).status_code == 200
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 4, seal.shares[3])
        copy_column(app, (other.seal_id, 1, "record_json"), (seal.seal_id, 1, "record_json"))
        client = app.test_client()
        login_admin(client)

        resp = post_form(client, "/admin/emergency-recover",
                         {"seal_id": seal.seal_id, "reason": "synthetic check"})

        assert resp.status_code == 500
        [row] = audit_rows(app, seal.seal_id)
        assert (row["outcome"], row["reason"]) == ("denied", "record_unreadable")


# ===================================================================
# Fail-closed
# ===================================================================

class TestFailClosed:
    @pytest.mark.parametrize("unset", ["IDENTITY_PEPPER_PATH", "PRIVACY_KMS_MASTER_KEY_PATH"])
    @pytest.mark.parametrize("signed", [False, True])
    def test_without_the_keys_sync_is_refused_and_nothing_stored(
        self, app, master_key, signer, unset, signed
    ) -> None:
        seal = _seal("S-20260928-E3B021", master_key, signer if signed else None)
        ensure_case(app, seal.seal_id)
        body = (signed_payload(seal, signer, record=identity_record(seal),
                               record_pdf=synthetic_pdf())
                if signed else _unsigned(seal, identity_record(seal), pdf=synthetic_pdf()))
        app.config[unset] = ""

        resp = app.test_client().post(URL, json=body)

        assert resp.status_code == 503
        assert "개인정보 보호 키" in resp.get_json()["message"]
        assert sql_rows(app, "SELECT * FROM seal_records") == []
        assert nonce_rows(app) == []
        assert sql_rows(app, "SELECT * FROM policy_high_water") == []

    @pytest.mark.parametrize("problem", ["missing", "wrong_size"])
    def test_an_unreadable_key_file_is_503_with_an_error_log(
        self, app, master_key, signer, tmp_path, caplog, problem
    ) -> None:
        seal = _seal("S-20260928-E3B022", master_key, signer)
        ensure_case(app, seal.seal_id)
        body = signed_payload(seal, signer, record=identity_record(seal),
                              record_pdf=synthetic_pdf())
        broken = tmp_path / "gone.key"
        if problem == "wrong_size":
            broken.write_bytes(b"\x01" * 7)
        app.config["PRIVACY_KMS_MASTER_KEY_PATH"] = str(broken)

        with caplog.at_level(logging.DEBUG):
            resp = app.test_client().post(URL, json=body)

        assert resp.status_code == 503
        assert sql_rows(app, "SELECT * FROM seal_records") == []
        assert nonce_rows(app) == []
        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert errors, "an unreadable key must be logged at ERROR"
        logged = "\n".join(r.getMessage() for r in caplog.records).encode("utf-8")
        for pattern in needles(body["record_json"], synthetic_pdf()):
            assert pattern not in logged
        session_key = Path(_session_master_key()).read_bytes()
        assert session_key.hex().encode() not in logged and session_key not in logged

    def test_without_the_keys_the_gate_denies_a_seal_with_records(
        self, app, master_key, signer
    ) -> None:
        # Records exist but cannot be read: never the v1.0.1 "no record" path.
        seal = _seal("S-20260928-E3B025", master_key, signer)
        assert _post(app, signed_payload(seal, signer)).status_code == 200
        store_share(app, seal.seal_id, 1, seal.shares[0])
        app.config["PRIVACY_KMS_MASTER_KEY_PATH"] = ""
        client = app.test_client()

        resp = recover_standard(client, seal)

        assert resp.status_code == 500
        assert recovered_key(client, seal.seal_id) is None
        [row] = audit_rows(app, seal.seal_id)
        assert row["outcome"] == "denied"
        assert row["policy_status"] not in ("record_missing", "legacy")

    def test_a_seal_without_a_case_is_refused_with_404(self, app, master_key) -> None:
        seal = _seal("S-20260928-E3B023", master_key, None)

        resp = _post(app, _unsigned(seal, identity_record(seal)), case=False)

        assert resp.status_code == 404
        assert "사건" in resp.get_json()["message"]
        assert sql_rows(app, "SELECT * FROM seal_records") == []
        assert sql_rows(app, "SELECT * FROM seal_data_keys WHERE seal_id = ?",
                        (seal.seal_id,)) == []

    def test_a_signed_submission_without_a_case_keeps_its_nonce_unused(
        self, app, master_key, signer
    ) -> None:
        # Stage F, F2: a signed record with a verified policy creates its
        # case, but this synthetic record carries no investigator and no
        # signer_info, so the creation is refused (422) and rolled back.
        seal = _seal("S-20260928-E3B024", master_key, signer)
        body = signed_payload(seal, signer)

        assert _post(app, body, case=False).status_code == 422
        assert nonce_rows(app) == []
        assert sql_rows(app, "SELECT * FROM cases") == []
        assert _post(app, body).status_code == 200

    def test_a_signed_submission_that_cannot_create_a_case_is_404(
        self, app, master_key, signer
    ) -> None:
        # A signed envelope over a record without a policy creates no case
        # (F2): refused with 404 as before, and its nonce stays unused.
        seal = _seal("S-20260928-E3B026", master_key, None)
        body = signed_payload(seal, signer, record=identity_record(seal),
                              include_wrapped=False)

        assert _post(app, body, case=False).status_code == 404
        assert nonce_rows(app) == []
        assert sql_rows(app, "SELECT * FROM cases") == []
        assert _post(app, body).status_code == 200


def _session_master_key() -> str:
    from web.config import TestingConfig

    return TestingConfig.PRIVACY_KMS_MASTER_KEY_PATH


# ===================================================================
# Rows stored before E3b are never read as plaintext
# ===================================================================

class TestUnconvertedRows:
    def test_the_gate_refuses_a_seal_with_an_unconverted_record(
        self, app, master_key
    ) -> None:
        seal = _seal("S-20260928-E3B031", master_key, None)
        ensure_case(app, seal.seal_id)
        insert_plaintext_row(app, seal.seal_id, 1, json.dumps(seal.record))
        store_share(app, seal.seal_id, 1, seal.shares[0])
        client = app.test_client()

        resp = recover_standard(client, seal)

        assert resp.status_code == 500
        assert recovered_key(client, seal.seal_id) is None
        [row] = audit_rows(app, seal.seal_id)
        assert row["outcome"] == "denied"
        assert row["policy_status"] not in ("record_missing", "legacy")

    def test_sync_on_an_unconverted_event_is_503_and_changes_nothing(
        self, app, master_key
    ) -> None:
        seal = _seal("S-20260928-E3B032", master_key, None)
        ensure_case(app, seal.seal_id)
        text = json.dumps(identity_record(seal), ensure_ascii=False)
        insert_plaintext_row(app, seal.seal_id, 1, text)
        before = stored_row(app, seal.seal_id, 1)

        resp = app.test_client().post(URL, json=_unsigned(seal, identity_record(seal)))

        assert resp.status_code == 503
        assert "이관" in resp.get_json()["message"]
        assert stored_row(app, seal.seal_id, 1) == before

    def test_a_signed_record_cannot_bootstrap_its_mark_past_unconverted_rows(
        self, app, master_key, signer
    ) -> None:
        # The mark bootstrap reads every stored record; an unconverted one
        # must stop the decision, not be skipped (E2a's rollback guard).
        seal = _seal("S-20260928-E3B033", master_key, signer)
        ensure_case(app, seal.seal_id)
        insert_plaintext_row(app, seal.seal_id, 1, json.dumps(seal.record))

        resp = app.test_client().post(URL, json=signed_payload(
            seal, signer, event_id=2, event_type="Unsealing", include_wrapped=False))

        assert resp.status_code == 503
        assert sql_rows(app, "SELECT * FROM policy_high_water") == []
        assert nonce_rows(app) == []
        assert [r["event_id"] for r in sql_rows(app, "SELECT event_id FROM seal_records")] == [1]

    def test_a_plaintext_row_marked_protected_is_unreadable(self, app, master_key) -> None:
        seal = _seal("S-20260928-E3B034", master_key, None)
        ensure_case(app, seal.seal_id)
        insert_plaintext_row(app, seal.seal_id, 1, json.dumps(seal.record), scheme="v1")
        store_share(app, seal.seal_id, 1, seal.shares[0])
        client = app.test_client()

        assert _is_unreadable(_record_at(app, seal.seal_id, 1))
        resp = recover_standard(client, seal)

        assert resp.status_code == 500
        [row] = audit_rows(app, seal.seal_id)
        assert (row["reason"], row["policy_status"]) == ("record_unreadable",
                                                          "record_unreadable")


# ===================================================================
# Schema
# ===================================================================

_PRE_E3B_RECORDS = """
CREATE TABLE seal_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id     TEXT    NOT NULL,
    event_id    INTEGER NOT NULL,
    event_type  TEXT    NOT NULL CHECK(event_type IN ('Sealing','Unsealing','Resealing')),
    record_json TEXT    NOT NULL,
    record_pdf  BLOB,
    synced_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(seal_id, event_id)
);
INSERT INTO seal_records (seal_id, event_id, event_type, record_json)
    VALUES ('S-20260928-E3B050', 1, 'Sealing', '{}');
"""


class TestSchema:
    def test_both_schema_variants_declare_the_column(self) -> None:
        from web.models import db_models

        for ddl in (db_models._SQLITE_SCHEMA, db_models._MARIADB_SCHEMA):
            table = ddl.split("CREATE TABLE IF NOT EXISTS seal_records", 1)[1].split(";", 1)[0]
            assert "\n    record_scheme " in table
            assert "NOT NULL DEFAULT ''" in table.split("record_scheme", 1)[1]

    def test_an_existing_table_gains_the_column_at_start_up(
        self, tmp_path, monkeypatch, master_key
    ) -> None:
        import sqlite3

        conn = sqlite3.connect(tmp_path / "release_web.db")
        conn.executescript(_PRE_E3B_RECORDS)
        conn.close()

        for _ in range(2):  # idempotent
            app = make_release_app(tmp_path, monkeypatch, master_key_path=master_key)

        columns = [r["name"] for r in sql_rows(app, "PRAGMA table_info(seal_records)")]
        assert columns[-1] == "record_scheme" and columns.count("record_scheme") == 1
        [row] = sql_rows(app, "SELECT record_json, record_scheme FROM seal_records")
        assert (row["record_json"], row["record_scheme"]) == ("{}", "")


# ===================================================================
# Admission and release unchanged on the protected store
# ===================================================================

class TestAdmissionUnchanged:
    def test_an_identical_resubmission_is_answered_as_before(self, app, master_key) -> None:
        seal = _seal("S-20260928-E3B041", master_key, None)
        record = identity_record(seal)
        assert _post(app, _unsigned(seal, record)).status_code == 200
        first = stored_row(app, seal.seal_id, 1)
        again = _unsigned(seal, record)
        again["record_json"] = json.dumps(dict(reversed(list(record.items()))), indent=2)

        resp = app.test_client().post(URL, json=again)

        assert resp.status_code == 200
        assert resp.get_json()["message"] == "이미 동기화된 기록입니다."
        assert stored_row(app, seal.seal_id, 1) == first

    def test_a_conflicting_resubmission_is_refused(self, app, master_key) -> None:
        seal = _seal("S-20260928-E3B042", master_key, None)
        record = identity_record(seal)
        assert _post(app, _unsigned(seal, record)).status_code == 200
        first = stored_row(app, seal.seal_id, 1)

        resp = app.test_client().post(URL, json=_unsigned(
            seal, {**record, "signer_info": {**SIGNER_INFO, "phone": "010-0000-0001"}}))

        assert resp.status_code == 409
        assert stored_row(app, seal.seal_id, 1) == first

    def test_an_authenticated_record_displaces_an_unauthenticated_one(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-E3B043", master_key, signer)
        stripped = {k: v for k, v in identity_record(seal).items()
                    if k not in ("policy", "policy_signature", "policy_cert")}
        assert _post(app, _unsigned(seal, stripped)).status_code == 200
        squatted = stored_row(app, seal.seal_id, 1)
        body = signed_payload(seal, signer, record=identity_record(seal))

        resp = app.test_client().post(URL, json=body)

        assert resp.status_code == 200
        row = stored_row(app, seal.seal_id, 1)
        assert row["record_json"] != squatted["record_json"]
        assert row["record_scheme"] == "v1"
        assert _record_at(app, seal.seal_id, 1) == body["record_json"]
        assert leaks(row, needles(body["record_json"])) == []

    def test_a_standard_release_decides_on_the_encrypted_record(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-E3B044", master_key, signer)
        assert _post(app, signed_payload(seal, signer, record=identity_record(seal))
                     ).status_code == 200
        store_share(app, seal.seal_id, 1, seal.shares[0])
        client = app.test_client()

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        [row] = audit_rows(app, seal.seal_id)
        assert (row["outcome"], row["policy_status"]) == ("released", "verified")


class TestFirstWriteForAKeylessSeal:
    def test_simultaneous_first_writes_create_one_data_key(
        self, app, master_key, monkeypatch
    ) -> None:
        # A case registered before E3a has no data key; the first record
        # writes create it. Two writes at once must not both create one.
        import time

        from tests.fixtures.concurrency import run_concurrently
        from web.privacy import record_store

        seal = _seal("S-20260928-E3B060", master_key, None)
        sql_execute(app, "INSERT INTO cases (seal_id, case_number, investigator, "
                         "suspect_name) VALUES (?, 'OLD', 'old', 'x')", (seal.seal_id,))
        real = record_store.wrap_data_key

        def slow_wrap(*args: Any) -> bytes:
            time.sleep(0.3)
            return real(*args)

        monkeypatch.setattr(record_store, "wrap_data_key", slow_wrap)

        def write(event_id: int) -> None:
            with app.app_context():
                from web.models.db_models import insert_seal_record

                insert_seal_record(seal.seal_id, event_id, "Unsealing",
                                   json.dumps(identity_record(seal, note=str(event_id))))

        results = run_concurrently(write, (2, 3))

        assert results == [None, None], results
        assert len(sql_rows(app, "SELECT * FROM seal_data_keys WHERE seal_id = ?",
                            (seal.seal_id,))) == 1
        for event_id in (2, 3):
            assert json.loads(_record_at(app, seal.seal_id, event_id))["note"] == str(event_id)


class TestKeyReadsPerRequest:
    def test_a_release_reading_several_records_loads_the_keys_once(
        self, app, master_key, monkeypatch
    ) -> None:
        # No mark: the gate reads every record of the seal (three here).
        from desktop.crypto import local_kms

        seal = _seal("S-20260928-E3B070", master_key, None)
        for event_id, event_type in ((1, "Sealing"), (2, "Unsealing"), (3, "Resealing")):
            assert _post(app, _unsigned(seal, seal.record, event_id=event_id,
                                        event_type=event_type)).status_code == 200
        store_share(app, seal.seal_id, 1, seal.shares[0])
        privacy_key = app.config["PRIVACY_KMS_MASTER_KEY_PATH"]
        loads: list[str] = []
        real = local_kms._load_master_key

        def counting(path: str) -> bytes:
            loads.append(path)
            return real(path)

        monkeypatch.setattr(local_kms, "_load_master_key", counting)
        client = app.test_client()

        first = recover_standard(client, seal)
        second = recover_standard(client, seal)

        assert first.status_code == second.status_code == 302
        # One load per request (application context), not one per record.
        assert loads.count(privacy_key) == 2, loads


class TestAuthenticationBeforeKeyState:
    def test_an_unsigned_request_learns_nothing_about_the_keys(
        self, app, master_key
    ) -> None:
        # With signatures required, an unsigned submission is refused as
        # unauthenticated (401) whether or not the privacy keys are set.
        from tests.fixtures.sync_web import require_signatures

        seal = _seal("S-20260928-E3B080", master_key, None)
        ensure_case(app, seal.seal_id)
        require_signatures(app)
        app.config["PRIVACY_KMS_MASTER_KEY_PATH"] = ""

        resp = app.test_client().post(URL, json=_unsigned(seal, identity_record(seal)))

        assert resp.status_code == 401
        assert sql_rows(app, "SELECT * FROM seal_records") == []


class TestCorruptedStoredRecord:
    def test_an_undecryptable_stored_record_is_never_displaced(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-E3B081", master_key, signer)
        stripped = {k: v for k, v in identity_record(seal).items()
                    if k not in ("policy", "policy_signature", "policy_cert")}
        assert _post(app, _unsigned(seal, stripped)).status_code == 200
        assert _post(app, _unsigned(seal, stripped, event_id=2,
                                    event_type="Unsealing")).status_code == 200
        copy_column(app, (seal.seal_id, 2, "record_json"), (seal.seal_id, 1, "record_json"))
        corrupted = stored_row(app, seal.seal_id, 1)

        resp = app.test_client().post(URL, json=signed_payload(
            seal, signer, record=identity_record(seal)))

        assert resp.status_code == 409
        assert stored_row(app, seal.seal_id, 1) == corrupted


class TestSchemeIsExact:
    @pytest.mark.parametrize("scheme", ["V1", "v1 ", " v1"])
    def test_a_scheme_not_exactly_v1_counts_as_unconverted(
        self, app, master_key, scheme
    ) -> None:
        seal = _seal("S-20260928-E3B090", master_key, None)
        assert _post(app, _unsigned(seal, identity_record(seal))).status_code == 200
        sql_execute(app, "UPDATE seal_records SET record_scheme = ? WHERE seal_id = ?",
                    (scheme, seal.seal_id))

        with app.app_context():
            from web.models.record_models import count_plaintext_record_rows
            from web.models.release_models import find_record_json_at
            from web.privacy.record_store import LegacyRecordError

            assert count_plaintext_record_rows() == 1
            with pytest.raises(LegacyRecordError):
                find_record_json_at(seal.seal_id, 1)
