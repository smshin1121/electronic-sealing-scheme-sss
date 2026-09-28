"""A missing per-seal data key is never silently replaced (Codex round 3, M1).

One data key per seal encrypts its protected case identity (E3a) and its
protected records (E3b); ``seal_data_keys`` holds it wrapped. If that row
goes missing (an incomplete restore, an accidental deletion), creating a new
key would leave the seal with ciphertexts that need two keys while only one
can be stored. So:

  - a seal counts as protected when its case identity is protected
    (``identity_scheme``, or an identity ciphertext column, is set) or when
    any of its records is protected (``record_scheme`` is set);
  - a write that would need a new key for a protected seal is refused: the
    sync route answers 503 with an ERROR log (no key bytes, no content) and
    nothing changes (no key, no record, no nonce, no mark); the conversion
    tool refuses the seal's rows, keeps their plaintext and exits 1;
  - a genuinely unprotected legacy case (neither) still gets a new key.

Synthetic data only.
"""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import (
    IDENTITY_VALUES,
    PDF_MARKER,
    identity_record,
    insert_plaintext_row,
    needles,
    sql_execute,
    sql_rows,
    synthetic_pdf,
)
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import ensure_case, make_release_app, sync_payload
from tests.fixtures.sync_web import high_water, nonce_rows, signed_payload

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


@pytest.fixture()
def cli_app(app, monkeypatch) -> Any:
    from web.cli_support import build_cli_app
    from web.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "SQLITE_PATH", app.config["SQLITE_PATH"])
    return build_cli_app("testing")


def _seal(seal_id: str, master_key: str, signer: Any):
    return make_seal_material(seal_id=seal_id, master_key_path=master_key, signer=signer,
                              generation=1 if signer is not None else None)


def _legacy_case(app: Any, seal_id: str) -> None:
    """A case as v1.0.1 stored it: plaintext identity, no data key."""
    sql_execute(app, "INSERT INTO cases (seal_id, case_number, investigator, suspect_name) "
                     "VALUES (?, 'OLD', 'old', 'x')", (seal_id,))


def _drop_key(app: Any, seal_id: str) -> None:
    sql_execute(app, "DELETE FROM seal_data_keys WHERE seal_id = ?", (seal_id,))


def _keys(app: Any, seal_id: str) -> list[dict]:
    return sql_rows(app, "SELECT wrapped_key FROM seal_data_keys WHERE seal_id = ?", (seal_id,))


def _records(app: Any, seal_id: str) -> list[dict]:
    return sql_rows(app, "SELECT * FROM seal_records WHERE seal_id = ? ORDER BY event_id",
                    (seal_id,))


def _case_row(app: Any, seal_id: str) -> dict:
    [row] = sql_rows(app, "SELECT * FROM cases WHERE seal_id = ?", (seal_id,))
    return row


def _unsigned(seal: Any, record: dict, event_id: int = 1, event_type: str = "Sealing") -> dict:
    return sync_payload(seal, record=record, event_id=event_id, event_type=event_type,
                        include_wrapped=False)


def _logged(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


def _assert_no_secret(text: str, record_text: str) -> None:
    for pattern in needles(record_text):
        assert pattern.decode("utf-8", "replace") not in text


# ===================================================================
# The sync route
# ===================================================================

class TestSyncRefusesAReplacementKey:
    @pytest.mark.parametrize("kind", ["protected_identity", "protected_records"])
    def test_a_new_event_for_a_protected_seal_without_its_key_is_refused(
        self, app, master_key, signer, caplog, kind
    ) -> None:
        seal_id = {"protected_identity": "S-20260928-M1S001",
                   "protected_records": "S-20260928-M1S002"}[kind]
        seal = _seal(seal_id, master_key, signer)
        if kind == "protected_identity":
            ensure_case(app, seal.seal_id)  # E3a: protected identity and a key
        else:
            _legacy_case(app, seal.seal_id)  # the first sync creates the key
        first = signed_payload(seal, signer, record=identity_record(seal))
        assert app.test_client().post(URL, json=first).status_code == 200
        mark, nonces, records = (high_water(app, seal.seal_id), nonce_rows(app),
                                 _records(app, seal.seal_id))
        case_before = _case_row(app, seal.seal_id)
        _drop_key(app, seal.seal_id)
        second = signed_payload(seal, signer, event_id=2, event_type="Unsealing",
                                record=identity_record(seal, note="2"), include_wrapped=False)

        with caplog.at_level(logging.DEBUG):
            resp = app.test_client().post(URL, json=second)

        assert resp.status_code == 503
        assert "데이터 키" in resp.get_json()["message"]
        assert _keys(app, seal.seal_id) == []
        assert nonce_rows(app) == nonces
        assert high_water(app, seal.seal_id) == mark and mark is not None
        assert _records(app, seal.seal_id) == records
        assert _case_row(app, seal.seal_id) == case_before
        assert [r for r in caplog.records if r.levelno >= logging.ERROR]
        logged = _logged(caplog)
        _assert_no_secret(logged, second["record_json"])
        master = Path(app.config["PRIVACY_KMS_MASTER_KEY_PATH"]).read_bytes()
        assert master.hex() not in logged and repr(master) not in logged

    def test_a_protected_identity_without_its_key_refuses_its_first_record(
        self, app, master_key
    ) -> None:
        seal = _seal("S-20260928-M1S100", master_key, None)
        ensure_case(app, seal.seal_id)
        _drop_key(app, seal.seal_id)

        resp = app.test_client().post(URL, json=_unsigned(seal, identity_record(seal)))

        assert resp.status_code == 503
        assert _keys(app, seal.seal_id) == [] and _records(app, seal.seal_id) == []

    def test_a_genuinely_legacy_case_still_gets_its_key(self, app, master_key) -> None:
        seal = _seal("S-20260928-M1S200", master_key, None)
        _legacy_case(app, seal.seal_id)
        body = _unsigned(seal, identity_record(seal))

        resp = app.test_client().post(URL, json=body)

        assert resp.status_code == 200
        assert len(_keys(app, seal.seal_id)) == 1
        with app.app_context():
            from web.models.release_models import find_record_json_at

            assert find_record_json_at(seal.seal_id, 1) == body["record_json"]

    def test_the_compatibility_writer_refuses_too(self, app, master_key) -> None:
        seal = _seal("S-20260928-M1S300", master_key, None)
        ensure_case(app, seal.seal_id)
        _drop_key(app, seal.seal_id)

        with app.app_context():
            from web.models.db_models import insert_seal_record
            from web.privacy.record_store import DataKeyMissing

            with pytest.raises(DataKeyMissing):
                insert_seal_record(seal.seal_id, 1, "Sealing", json.dumps(seal.record))

        assert _keys(app, seal.seal_id) == [] and _records(app, seal.seal_id) == []


# ===================================================================
# The conversion tool
# ===================================================================

def _migrate(cli_app: Any, *argv: str) -> tuple[int, str]:
    from web.privacy.migrate import main

    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), app=cli_app, stdout=out, stderr=err)
    return code, out.getvalue() + err.getvalue()


def _assert_no_content(text: str) -> None:
    for value in IDENTITY_VALUES:
        assert value not in text
    assert PDF_MARKER.decode("ascii") not in text


class TestConversionRefusesAReplacementKey:
    def test_a_mixed_seal_without_its_key_is_refused(self, app, cli_app, master_key) -> None:
        # A v1.0.1 case whose first record was synced (protected, and the
        # key created then) and whose second record predates E3b.
        seal = _seal("S-20260928-M1M001", master_key, None)
        _legacy_case(app, seal.seal_id)
        assert app.test_client().post(
            URL, json=_unsigned(seal, identity_record(seal))).status_code == 200
        old_text = json.dumps(identity_record(seal, note="old"), ensure_ascii=False)
        insert_plaintext_row(app, seal.seal_id, 2, old_text, synthetic_pdf("old"),
                             event_type="Unsealing")
        _drop_key(app, seal.seal_id)
        records, case_before = _records(app, seal.seal_id), _case_row(app, seal.seal_id)

        code, out = _migrate(cli_app, "--apply")

        assert code == 1
        assert "데이터 키 없어 거부 1건" in out
        assert f"데이터 키 없음: {seal.seal_id!r}" in out
        _assert_no_content(out)
        assert _keys(app, seal.seal_id) == []
        assert _records(app, seal.seal_id) == records  # both rows untouched
        assert _case_row(app, seal.seal_id) == case_before  # identity not converted
        assert records[1]["record_scheme"] == "" and records[1]["record_json"] == old_text

    def test_a_protected_identity_without_its_key_refuses_its_old_records(
        self, app, cli_app, master_key
    ) -> None:
        seal = _seal("S-20260928-M1M002", master_key, None)
        ensure_case(app, seal.seal_id)
        insert_plaintext_row(app, seal.seal_id, 1, json.dumps(identity_record(seal)))
        _drop_key(app, seal.seal_id)
        records = _records(app, seal.seal_id)

        code, out = _migrate(cli_app, "--apply")

        assert code == 1
        assert "데이터 키 없어 거부 1건" in out and seal.seal_id in out
        assert _keys(app, seal.seal_id) == []
        assert _records(app, seal.seal_id) == records

    def test_a_genuinely_legacy_seal_still_gets_its_key(self, app, cli_app, master_key) -> None:
        seal = _seal("S-20260928-M1M003", master_key, None)
        _legacy_case(app, seal.seal_id)
        insert_plaintext_row(app, seal.seal_id, 1, json.dumps(identity_record(seal)))

        code, out = _migrate(cli_app, "--apply")

        assert code == 0, out
        assert len(_keys(app, seal.seal_id)) == 1
        assert _records(app, seal.seal_id)[0]["record_scheme"] == "v1"
        assert _case_row(app, seal.seal_id)["identity_scheme"] == "v1"
