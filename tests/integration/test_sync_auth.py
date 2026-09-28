"""Per-event sync authentication on ``/sync/upload-record`` (stage E, E2a).

A submission may carry ``sync_auth`` = {envelope, signature, cert}: the
envelope is signed by the institutional seal-policy key. The server checks
the chain and EKU against ``POLICY_CA_CERT_PATH``, the signature, that
every envelope field equals the request (hashes over the exact received
bytes), that ``sent_at`` is inside ``SYNC_SIGNATURE_WINDOW_SECONDS`` and
that the nonce was never used (claimed in the same transaction as the
store, under the seal's write lock).

  - ``SYNC_REQUIRE_SIGNATURE`` on: unsigned submissions get 401.
  - off (default): unsigned submissions are admitted as in stage D; a
    present but invalid signature is still refused (401), and a signed
    submission the host cannot verify (no pinned CA) gets 503.

Synthetic material only (test CA, temporary master key).
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    ensure_case,
    make_release_app,
    sync_payload,
)
from tests.fixtures.sync_web import (
    nonce_rows,
    require_signatures,
    signed_payload,
)

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
def strict_app(app):
    require_signatures(app)
    return app


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _seal(seal_id: str, master_key: str, signer: Any, **kwargs: Any):
    kwargs.setdefault("generation", 1)
    return make_seal_material(seal_id=seal_id, master_key_path=master_key,
                              signer=signer, **kwargs)


def _post(app, body: dict) -> Any:
    ensure_case(app, body["seal_id"])
    return app.test_client().post(URL, json=body)


def _stored_events(app, seal_id: str) -> list[int]:
    with app.app_context():
        from web.models.db_models import find_seal_records_by_seal_id

        rows = find_seal_records_by_seal_id(seal_id)
    return [row["event_id"] for row in rows]


# ===================================================================
# Switch on: every submission must be signed
# ===================================================================

class TestSwitchOn:
    def test_unsigned_submission_is_refused(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00001", master_key, signer)

        resp = _post(strict_app, sync_payload(seal))

        assert resp.status_code == 401
        assert resp.get_json()["status"] == "error"
        assert _stored_events(strict_app, seal.seal_id) == []

    def test_signed_submission_is_admitted(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00002", master_key, signer)
        body = signed_payload(seal, signer, record_pdf=b"%PDF-1.4 synthetic")

        resp = _post(strict_app, body)

        assert resp.status_code == 200, resp.get_json()
        assert _stored_events(strict_app, seal.seal_id) == [1]
        assert body["sync_auth"]["envelope"]["nonce"] in nonce_rows(strict_app)

    def test_record_tampered_after_signing_is_refused(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00003", master_key, signer)
        body = signed_payload(seal, signer)
        record = json.loads(body["record_json"])
        tampered = {**body, "record_json": json.dumps(
            {**record, "case_info": {"case_number": "2026-TAMPERED"}},
            ensure_ascii=False)}

        resp = _post(strict_app, tampered)

        assert resp.status_code == 401
        assert _stored_events(strict_app, seal.seal_id) == []

    def test_whitespace_change_to_the_record_is_refused(
        self, strict_app, master_key, signer
    ) -> None:
        # The hash is over the exact received bytes, not the parsed JSON.
        seal = _seal("S-20260928-A00004", master_key, signer)
        body = signed_payload(seal, signer)
        reformatted = json.dumps(json.loads(body["record_json"]), indent=1,
                                 ensure_ascii=False)

        resp = _post(strict_app, {**body, "record_json": reformatted})

        assert resp.status_code == 401

    def test_pdf_tampered_after_signing_is_refused(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00005", master_key, signer)
        body = signed_payload(seal, signer, record_pdf=b"%PDF-1.4 original")
        other = base64.b64encode(b"%PDF-1.4 replaced").decode("ascii")

        stripped = _post(strict_app, {**body, "record_pdf": None})
        replaced = _post(strict_app, {**body, "record_pdf": other})

        assert (stripped.status_code, replaced.status_code) == (401, 401)
        assert _stored_events(strict_app, seal.seal_id) == []

    def test_wrapped_s3_swapped_after_signing_is_refused(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00006", master_key, signer)
        body = signed_payload(seal, signer)
        other = base64.b64encode(os.urandom(64)).decode("ascii")

        swapped = _post(strict_app, {**body, "wrapped_s3": other})
        dropped = _post(strict_app, {k: v for k, v in body.items()
                                     if k != "wrapped_s3"})

        assert (swapped.status_code, dropped.status_code) == (401, 401)

    def test_reused_nonce_is_refused(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00007", master_key, signer)
        body = signed_payload(seal, signer)

        first = _post(strict_app, body)
        replay = _post(strict_app, body)

        assert first.status_code == 200
        assert replay.status_code == 409
        assert "nonce" in replay.get_json()["message"]
        assert _stored_events(strict_app, seal.seal_id) == [1]

    @pytest.mark.parametrize("offset", [-301, 301, -3600, 86400])
    def test_sent_at_outside_the_window_is_refused(
        self, strict_app, master_key, signer, offset: int
    ) -> None:
        seal = _seal(f"S-20260928-B{abs(offset):05d}", master_key, signer)
        sent = datetime.now(tz=timezone.utc) + timedelta(seconds=offset)

        resp = _post(strict_app, signed_payload(seal, signer, sent_at=sent))

        assert resp.status_code == 401
        assert _stored_events(strict_app, seal.seal_id) == []

    def test_sent_at_inside_the_window_is_admitted(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00008", master_key, signer)
        sent = datetime.now(tz=timezone.utc) - timedelta(seconds=240)

        resp = _post(strict_app, signed_payload(seal, signer, sent_at=sent))

        assert resp.status_code == 200

    def test_replay_for_another_seal_is_refused(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00009", master_key, signer)
        body = signed_payload(seal, signer)
        # A legacy record does not name a policy, so only the envelope
        # binds it to its seal.
        legacy = make_seal_material(seal_id="S-20260928-A00009",
                                    master_key_path=master_key, signer=None)
        legacy_body = signed_payload(legacy, signer, include_wrapped=False)
        other_id = "S-20260928-A00010"

        resp = _post(strict_app, {**body, "seal_id": other_id})
        legacy_resp = _post(strict_app, {**legacy_body, "seal_id": other_id})

        # The signed record itself names the original seal (400 or 401);
        # the legacy one is refused by the envelope alone.
        assert resp.status_code in (400, 401)
        assert legacy_resp.status_code == 401
        assert _stored_events(strict_app, other_id) == []

    def test_replay_for_another_event_is_refused(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00011", master_key, signer)
        body = signed_payload(seal, signer, event_id=1)

        moved = _post(strict_app, {**body, "event_id": 7})
        relabelled = _post(strict_app, {**body, "event_type": "Resealing"})

        assert (moved.status_code, relabelled.status_code) == (401, 401)
        assert _stored_events(strict_app, seal.seal_id) == []

    def test_generation_claim_must_match_the_record(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00012", master_key, signer, generation=2)

        resp = _post(strict_app, signed_payload(seal, signer,
                                                policy_generation=3))

        assert resp.status_code == 401

    def test_record_json_must_be_a_string_when_signed(
        self, strict_app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-A00013", master_key, signer)
        body = signed_payload(seal, signer)

        resp = _post(strict_app, {**body,
                                  "record_json": json.loads(body["record_json"])})

        assert resp.status_code == 401

    def test_a_refused_submission_consumes_its_nonce(
        self, strict_app, master_key, signer
    ) -> None:
        # An event conflict (409) after the nonce was claimed: the same
        # envelope cannot be presented again later.
        seal = _seal("S-20260928-A00014", master_key, signer)
        other = _seal("S-20260928-A00014", master_key, signer, generation=2)
        assert _post(strict_app, signed_payload(seal, signer)).status_code == 200
        conflict = signed_payload(other, signer, event_id=1)

        first = _post(strict_app, conflict)
        again = _post(strict_app, conflict)

        assert first.status_code == 409
        assert "nonce" not in first.get_json()["message"]
        assert again.status_code == 409
        assert "nonce" in again.get_json()["message"]


# ===================================================================
# Switch off (default): unsigned as before, invalid signatures refused
# ===================================================================

class TestSwitchOff:
    def test_default_is_off(self, app) -> None:
        assert app.config["SYNC_REQUIRE_SIGNATURE"] is False
        assert app.config["SYNC_SIGNATURE_WINDOW_SECONDS"] == 300

    def test_unsigned_submission_is_admitted_as_before(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-C00001", master_key, signer)

        resp = _post(app, sync_payload(seal))

        assert resp.status_code == 200
        assert _stored_events(app, seal.seal_id) == [1]
        assert nonce_rows(app) == []

    def test_legacy_unsigned_submission_is_admitted_as_before(
        self, app, master_key
    ) -> None:
        seal = make_seal_material(seal_id="S-20260928-C00002",
                                  master_key_path=master_key, signer=None)

        resp = _post(app, sync_payload(seal, include_wrapped=False))

        assert resp.status_code == 200

    def test_present_but_invalid_signature_is_refused(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-C00003", master_key, signer)
        body = signed_payload(seal, signer)
        bad = {**body, "sync_auth": {
            **body["sync_auth"],
            "signature": base64.b64encode(os.urandom(384)).decode("ascii")}}

        resp = _post(app, bad)

        assert resp.status_code == 401
        assert _stored_events(app, seal.seal_id) == []

    def test_signature_from_another_ca_is_refused(
        self, app, master_key, signer, release_pki
    ) -> None:
        seal = _seal("S-20260928-C00004", master_key, signer)
        foreign = load_test_signer(release_pki, other_ca=True)

        resp = _post(app, signed_payload(seal, foreign))

        assert resp.status_code == 401

    @pytest.mark.parametrize("auth", [{}, "signed", [], {"envelope": {}}])
    def test_malformed_sync_auth_is_refused(
        self, app, master_key, signer, auth: Any
    ) -> None:
        seal = _seal("S-20260928-C00005", master_key, signer)

        resp = _post(app, {**sync_payload(seal), "sync_auth": auth})

        assert resp.status_code == 401

    def test_signed_submission_is_checked_as_with_the_switch_on(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-C00006", master_key, signer)
        stale = datetime.now(tz=timezone.utc) - timedelta(seconds=900)

        resp = _post(app, signed_payload(seal, signer, sent_at=stale))

        assert resp.status_code == 401

    def test_signed_submission_without_a_pinned_ca_is_refused(
        self, app, master_key, signer
    ) -> None:
        app.config["POLICY_CA_CERT_PATH"] = ""
        seal = _seal("S-20260928-C00007", master_key, signer)

        resp = _post(app, signed_payload(seal, signer))

        assert resp.status_code == 503
        assert _stored_events(app, seal.seal_id) == []


# ===================================================================
# Configuration and the nonce store
# ===================================================================

class TestConfiguration:
    def _create(self, tmp_path, monkeypatch, **settings: Any) -> Any:
        from web.config import TestingConfig

        db_path = str(tmp_path / "config.db")
        monkeypatch.setattr(TestingConfig, "SQLITE_PATH", db_path)
        for name, value in settings.items():
            monkeypatch.setattr(TestingConfig, name, value, raising=False)
        from web.app import create_app

        return create_app("testing")

    def test_switch_without_a_pinned_ca_refuses_start_up(
        self, tmp_path, monkeypatch
    ) -> None:
        from web.sync_auth import SyncConfigError

        with pytest.raises(SyncConfigError):
            self._create(tmp_path, monkeypatch, SYNC_REQUIRE_SIGNATURE=True,
                         POLICY_CA_CERT_PATH="")

    @pytest.mark.parametrize("window", [0, 29, 3601, -5])
    def test_window_out_of_range_refuses_start_up(
        self, tmp_path, monkeypatch, window: int
    ) -> None:
        from web.sync_auth import SyncConfigError

        with pytest.raises(SyncConfigError):
            self._create(tmp_path, monkeypatch,
                         SYNC_SIGNATURE_WINDOW_SECONDS=window)

    def test_switch_with_a_pinned_ca_starts(
        self, tmp_path, monkeypatch, release_pki
    ) -> None:
        app = self._create(tmp_path, monkeypatch, SYNC_REQUIRE_SIGNATURE=True,
                           POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path))
        assert app.config["SYNC_REQUIRE_SIGNATURE"] is True


class TestNonceStore:
    def test_expired_nonces_are_pruned(
        self, app, master_key, signer
    ) -> None:
        with app.app_context():
            from web.models.db_models import execute_query

            execute_query(
                "INSERT INTO sync_nonces (nonce, seal_id, event_id, sent_at, "
                "expires_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                ("0" * 64, "S-20260928-OLD001", 1, "2026-01-01T00:00:00Z",
                 1, "2026-01-01T00:00:00Z"),
            )
        seal = _seal("S-20260928-D00001", master_key, signer)
        body = signed_payload(seal, signer)

        resp = _post(app, body)

        assert resp.status_code == 200
        assert nonce_rows(app) == [body["sync_auth"]["envelope"]["nonce"]]

    def test_nonce_and_record_commit_together(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        from web.routes import sync as sync_route

        seal = _seal("S-20260928-D00002", master_key, signer)
        body = signed_payload(seal, signer)

        def broken(**_kwargs: Any) -> None:
            raise RuntimeError("synthetic store failure")

        monkeypatch.setattr(sync_route, "store_synced_record", broken)
        failed = _post(app, body)
        monkeypatch.undo()

        assert failed.status_code == 500
        assert nonce_rows(app) == []
        # The rolled-back nonce was never consumed: the same submission
        # is admitted once the store works.
        assert _post(app, body).status_code == 200

    def test_event_id_must_be_a_positive_integer(self, app) -> None:
        body = {"seal_id": "S-20260928-D00003", "event_type": "Sealing",
                "record_json": "{}"}
        for value in ("abc", -1, 0, 2 ** 31, True, 1.5):
            resp = _post(app, {**body, "event_id": value})
            assert resp.status_code == 400, value

    def test_a_non_object_body_is_refused(self, app) -> None:
        resp = app.test_client().post(URL, json=["not", "an", "object"])
        assert resp.status_code == 400


# ===================================================================
# Review round: the signature is checked before the payload is decoded
# ===================================================================

class TestCheapChecksFirst:
    def _recording_decoder(self, monkeypatch) -> list[int]:
        from web.routes import sync as sync_route

        calls: list[int] = []
        real = sync_route._decode_record_pdf

        def recording(value: Any):
            calls.append(len(value or ""))
            return real(value)

        monkeypatch.setattr(sync_route, "_decode_record_pdf", recording)
        return calls

    def test_a_bogus_signature_is_refused_before_the_pdf_is_decoded(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        seal = _seal("S-20260928-E00001", master_key, signer)
        calls = self._recording_decoder(monkeypatch)
        big_pdf = base64.b64encode(b"%PDF-1.4 " + os.urandom(1 << 20)).decode()
        body = {**sync_payload(seal), "record_pdf": big_pdf,
                "sync_auth": {"envelope": {}, "signature": "AA==",
                              "cert": "x"}}

        resp = _post(app, body)

        assert resp.status_code == 401
        assert calls == []

    def test_a_stale_envelope_is_refused_before_the_pdf_is_decoded(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        seal = _seal("S-20260928-E00002", master_key, signer)
        stale = datetime.now(tz=timezone.utc) - timedelta(seconds=900)
        body = signed_payload(seal, signer, sent_at=stale,
                              record_pdf=b"%PDF-1.4 synthetic")
        calls = self._recording_decoder(monkeypatch)

        resp = _post(app, body)

        assert resp.status_code == 401
        assert calls == []

    def test_a_valid_submission_still_decodes_and_binds_the_pdf(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        seal = _seal("S-20260928-E00003", master_key, signer)
        body = signed_payload(seal, signer, record_pdf=b"%PDF-1.4 synthetic")
        calls = self._recording_decoder(monkeypatch)

        resp = _post(app, body)

        assert resp.status_code == 200
        assert len(calls) == 1
