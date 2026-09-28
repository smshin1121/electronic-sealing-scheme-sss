"""Standard and admin release paths through the single gate (stage D, D3).

  - Standard (s1+s2): the stored owner share and the investigator share
    presented in the request. The server-UTC unlock gate and commitment
    check are unchanged, but when the synced record carries a verified
    policy its values are used instead of the unauthenticated record
    fields. Legacy records keep the v1.0.1 checks and are audited as
    legacy.
  - Admin (s4 + another share): an override without a time gate; a
    present policy must verify, a reason is required, the commitment is
    checked under a verified policy, and legacy use is flagged in the
    audit trail.
  - Desktop to portal: a record and wrapped s3 produced by the real
    SealProcess are synced and released on the time-locked path.
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.sync_payload import build_sync_payload
from tests.fixtures.release_pki import (
    load_test_signer,
    make_seal_material,
    tsa_trust_settings,
)
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    login_admin,
    make_release_app,
    post_form,
    recover_standard,
    recovered_key,
    store_record_out_of_band,
    store_share,
    sync_payload,
    sync_seal,
)

pytestmark = pytest.mark.integration

TIMELOCK_URL = "/investigator/recover-key-timelock"
ADMIN_URL = "/admin/emergency-recover"


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(tmp_path, monkeypatch, release_pki, release_tsa, master_key):
    return make_release_app(
        tmp_path, monkeypatch,
        ca_cert_path=str(release_pki.ca_cert_path),
        master_key_path=master_key,
        tsa_url=release_tsa,
        tsa_cert_path=str(release_pki.tsa_cert_path),
        **tsa_trust_settings(release_pki),
    )


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _seal(seal_id: str, master_key: str, signer: Any, **kwargs: Any):
    return make_seal_material(
        seal_id=seal_id, master_key_path=master_key, signer=signer, **kwargs
    )


def _last(app, seal_id: str, path: str) -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row"
    return rows[-1]


# ===================================================================
# Standard path
# ===================================================================

class TestStandardPath:
    def _ready(self, app, client, seal, **sync_kw) -> None:
        sync_seal(client, app, seal, **sync_kw)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

    def test_verified_release_is_audited(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-J00001", master_key, signer)
        self._ready(app, client, seal)

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        row = _last(app, seal.seal_id, "standard")
        assert (row["outcome"], row["reason"], row["policy_status"]) == (
            "released", "released", "verified"
        )
        assert row["policy_digest"] == seal.policy_digest.hex()
        assert row["tsa_token"] == ""

    def test_policy_unlock_time_wins_over_the_record_field(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-J00002", master_key, signer,
                     unlock_delta=timedelta(days=2))
        record = {**seal.record, "unlock_time_iso": "2020-01-01T00:00:00Z"}
        self._ready(app, client, seal, record=record)

        resp = recover_standard(client, seal)

        assert resp.status_code == 403
        assert "열람 제한" in resp.get_data(as_text=True)
        assert _last(app, seal.seal_id, "standard")["reason"] == "before_unlock"

    def test_policy_commitment_wins_over_the_record_field(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-J00003", master_key, signer)
        record = {**seal.record, "key_commitment": "0" * 64}
        self._ready(app, client, seal, record=record)

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex

    def test_wrong_share_fails_the_policy_commitment(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-J00004", master_key, signer)
        stranger = _seal("S-20260926-J00005", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, stranger.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 400
        assert "확인값" in resp.get_data(as_text=True)
        assert _last(app, seal.seal_id, "standard")["reason"] == (
            "commitment_mismatch"
        )

    def test_missing_owner_share_is_audited(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-J00006", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 400
        assert "피압수자 키 조각(1)" in resp.get_data(as_text=True)
        assert _last(app, seal.seal_id, "standard")["reason"] == (
            "owner_share_missing"
        )

    def test_unreadable_record_still_maps_to_500(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-J00007", master_key, signer)
        ensure_case(app, seal.seal_id)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])
        with app.app_context():
            from web.models.db_models import insert_seal_record

            insert_seal_record(seal.seal_id, 1, "Sealing", "{not json")

        resp = recover_standard(client, seal)

        assert resp.status_code == 500
        assert "seal_mode" in resp.get_data(as_text=True)
        assert recovered_key(client, seal.seal_id) is None


# ===================================================================
# Admin path
# ===================================================================

class TestAdminPath:
    def _ready(self, app, client, seal, *, second: str | None = None,
               sync: bool = True, **sync_kw) -> None:
        if sync:
            sync_seal(client, app, seal, **sync_kw)
        else:
            ensure_case(app, seal.seal_id)
        store_share(app, seal.seal_id, 2, second or seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])
        login_admin(client)

    def _recover(self, client, seal_id: str, reason: str = "court order"):
        return post_form(client, ADMIN_URL,
                         {"seal_id": seal_id, "reason": reason})

    def test_verified_policy_release_is_audited(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-K00001", master_key, signer)
        self._ready(app, client, seal)

        resp = self._recover(client, seal.seal_id, "subject unreachable")

        assert resp.status_code == 200
        assert seal.key_hex in resp.get_data(as_text=True)
        row = _last(app, seal.seal_id, "admin")
        assert (row["outcome"], row["policy_status"]) == ("released",
                                                         "verified")
        assert row["operator_reason"] == "subject unreachable"

    def test_admin_override_has_no_time_gate(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-K00002", master_key, signer,
                     unlock_delta=timedelta(days=30))
        self._ready(app, client, seal)

        resp = self._recover(client, seal.seal_id)

        assert resp.status_code == 200
        assert _last(app, seal.seal_id, "admin")["outcome"] == "released"

    def test_legacy_record_is_allowed_and_flagged(
        self, app, client, master_key
    ) -> None:
        seal = _seal("S-20260926-K00003", master_key, None)
        self._ready(app, client, seal)

        resp = self._recover(client, seal.seal_id)

        assert resp.status_code == 200
        row = _last(app, seal.seal_id, "admin")
        assert (row["outcome"], row["policy_status"]) == ("released", "legacy")

    def test_missing_record_is_allowed_and_flagged(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-K00004", master_key, signer)
        self._ready(app, client, seal, sync=False)

        resp = self._recover(client, seal.seal_id)

        assert resp.status_code == 200
        assert _last(app, seal.seal_id, "admin")["policy_status"] == (
            "record_missing"
        )

    @pytest.mark.parametrize("drop", ["policy_signature", "tamper"])
    def test_invalid_policy_blocks_the_override(
        self, app, client, master_key, signer, drop: str
    ) -> None:
        seal = _seal("S-20260926-K00005", master_key, signer)
        if drop == "tamper":
            record = {**seal.record, "policy": {**seal.record["policy"],
                                                "seal_mode": "strict"}}
        else:
            record = {k: v for k, v in seal.record.items() if k != drop}
        ensure_case(app, seal.seal_id)
        refused = client.post("/sync/upload-record",
                              json=sync_payload(seal, record=record))
        assert refused.status_code == 422
        store_record_out_of_band(app, seal, record=record)
        self._ready(app, client, seal, sync=False)

        resp = self._recover(client, seal.seal_id)

        assert resp.status_code == 403
        assert seal.key_hex not in resp.get_data(as_text=True)
        row = _last(app, seal.seal_id, "admin")
        assert (row["outcome"], row["reason"]) == ("denied", "policy_invalid")

    def test_commitment_is_checked_under_a_verified_policy(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-K00006", master_key, signer)
        stranger = _seal("S-20260926-K00007", master_key, signer)
        self._ready(app, client, seal, second=stranger.shares[1])

        resp = self._recover(client, seal.seal_id)

        assert resp.status_code == 400
        assert _last(app, seal.seal_id, "admin")["reason"] == (
            "commitment_mismatch"
        )

    def test_reason_is_required_and_audited(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-K00008", master_key, signer)
        self._ready(app, client, seal)

        resp = self._recover(client, seal.seal_id, reason="   ")

        assert resp.status_code == 400
        row = _last(app, seal.seal_id, "admin")
        assert (row["outcome"], row["reason"]) == ("denied", "reason_required")


# ===================================================================
# Desktop sealing -> sync -> portal time-locked release
# ===================================================================

def _desktop_process(tmp_path: Path, signer: Any, key_hex: str) -> Any:
    """A SealProcess at S1 with an elapsed unlock time (unlock_days=-1)."""
    import desktop.seal_process as sp

    enc = tmp_path / "evidence.bin.enc"
    enc.write_bytes(b"x" * 64)
    process = sp.SealProcess(db_path=str(tmp_path / "seal.db"),
                             policy_signer=signer)
    process.set_config(sp.SealConfig(
        source_file=str(tmp_path / "evidence.bin"),
        output_dir=str(tmp_path), chunk_size_bytes=1 << 30,
        case_number="2026-TL-E2E", investigator={"name": "Hong"},
        seizure={"date": "2026-08-02T00:00:00Z", "location": "Seoul",
                 "device_user": "Kim"},
        media={"type": "SSD", "manufacturer": "M", "model": "X",
               "serial": "1"},
        subject={"name": "Kim", "email": "k@example.com",
                 "birth": "1990-01-01", "phone": "010-0000-0000",
                 "participation": "yes", "password": "pw"},
        signature_lines=[(0, 0, 1, 1)],
        unlock_days=-1,
    ))
    process.state["s1"] = {
        "aes_key_hex": key_hex, "enc_filepath": str(enc),
        "encryption_algo": "AES-256-GCM",
        "metadata": {"filename": "evidence.bin", "size": 4096,
                     "md5": "0" * 32, "sha256": "0" * 64,
                     "mtime": "2026-08-02T00:00:00Z",
                     "ctime": "2026-08-02T00:00:00Z",
                     "atime": "2026-08-02T00:00:00Z"},
        "enc_metadata": {"enc_ended_time": "2026-08-02T00:00:00Z",
                         "nonces": ["00"], "tags": ["11"],
                         "chunk_lengths": [4096]},
    }
    return process


class TestDesktopToPortal:
    def test_desktop_seal_is_released_on_the_timelock_path(
        self, app, client, tmp_path: Path, master_key, signer, monkeypatch
    ) -> None:
        from desktop.db import init_db

        monkeypatch.setenv("MASTER_KEY_PATH", master_key)
        key_hex = "5a" * 32
        process = _desktop_process(tmp_path, signer, key_hex)
        process.run_s4()
        s6 = process.run_s6()
        init_db(process._db_path)
        pdf = tmp_path / "record.pdf"
        pdf.write_bytes(b"%PDF-1.4 test")
        # Stand-in for S5 (PDF rendering/PAdES signing is covered elsewhere)
        process.state["s5"] = {"pdf_path": str(pdf), "cert_pem": "",
                               "key_pem": b""}
        result = process.run_s7()

        payload = build_sync_payload(
            seal_id=result.seal_id, event_id=1, event_type="Sealing",
            record_json=result.record_json, record_pdf=pdf.read_bytes(),
            wrapped_s3_b64=result.wrapped_s3_b64,
        )
        ensure_case(app, result.seal_id)
        assert client.post("/sync/upload-record", json=payload).status_code == 200
        store_share(app, result.seal_id, 2, s6["shares"][1])

        resp = post_form(client, TIMELOCK_URL, {"seal_id": result.seal_id,
                                                "share_data": s6["shares"][1]})

        assert resp.status_code == 302
        assert recovered_key(client, result.seal_id) == key_hex
        row = _last(app, result.seal_id, "timelock")
        assert row["outcome"] == "released"
        assert json.loads(result.record_json)["policy"]["case_no"] == (
            "2026-TL-E2E"
        )
        assert base64.b64decode(result.wrapped_s3_b64)
