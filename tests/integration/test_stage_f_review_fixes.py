"""Fixes and added tests from the first external review of stage F (Codex R1).

  - R1-1: a long list of tried stored shares no longer pushes the TSA rule
    (or the selection note) out of the 500-character audit detail: the list
    is bounded and goes last;
  - R1-2: an administrator denial under an authenticated policy keeps the
    record-selection note;
  - coverage the review found missing: an upload right after a generation-2
    record created the case (F1 with F2), and the generation-0 limitation of
    seals without an authenticated policy (a reseal does not open a new
    slot there).

The SQLite rebuild's rollback on failure is tested with the migration
(``test_share_migration.py``). Synthetic data only.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.case_registration import creatable_record
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
    store_record_out_of_band,
    store_share,
    sync_payload,
    sync_seal,
)
from tests.fixtures.share_uploads import (
    share_rows,
    take_flashes,
    upload_owner_share,
)
from tests.fixtures.sync_web import high_water, signed_payload

pytestmark = pytest.mark.integration

TIMELOCK_URL = "/investigator/recover-key-timelock"
EMERGENCY_URL = "/admin/emergency-recover"
MAX_DETAIL = 500


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
def signer(release_pki):
    return load_test_signer(release_pki)


def _last(app: Any, seal_id: str, path: str) -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row"
    return rows[-1]


def _wrong_share(index: int) -> str:
    return f"{index}-" + os.urandom(32).hex()


def test_a_long_candidate_list_keeps_the_tsa_rule(app, master_key, signer) -> None:
    """R1-1: generation 21 of a strict seal, twenty stale owner shares
    (generations 1 to 20) and none for generation 21: the time-locked denial
    still records the TSA rule, and the tried list is shortened."""
    seal = make_seal_material(seal_id="S-20260928-F6R101", master_key_path=master_key,
                              signer=signer, mode="strict", generation=21)
    sync_seal(app.test_client(), app, seal)
    for generation in range(1, 21):
        store_share(app, seal.seal_id, 1, _wrong_share(1), generation=generation)

    resp = post_form(app.test_client(), TIMELOCK_URL,
                     {"seal_id": seal.seal_id, "share_data": seal.shares[1]})

    row = _last(app, seal.seal_id, "timelock")
    assert resp.status_code == 403
    assert (row["outcome"], row["reason"]) == ("denied", "commitment_mismatch")
    assert row["tsa_token"]
    assert len(row["detail"]) <= MAX_DETAIL
    assert "tsa rule genTime - accuracy >= unlock_time" in row["detail"]
    assert "tried: share 1 of generation 20" in row["detail"]
    assert "more)" in row["detail"]
    assert row["detail"].index("tsa rule") < row["detail"].index("tried:")


def test_an_admin_denial_keeps_the_selection_note(app, master_key, signer) -> None:
    """R1-2: the administrator's pairs fail the commitment, and the note on
    the newer unauthenticated record the selection ignored is kept."""
    seal = make_seal_material(seal_id="S-20260928-F6R102", master_key_path=master_key,
                              signer=signer, generation=1)
    sync_seal(app.test_client(), app, seal)
    unauthenticated = {key: value for key, value in seal.record.items()
                       if key not in ("policy", "policy_signature", "policy_cert")}
    store_record_out_of_band(app, seal, record=unauthenticated, event_id=2,
                             event_type="Unsealing")
    store_share(app, seal.seal_id, 2, _wrong_share(2), generation=1)
    store_share(app, seal.seal_id, 4, _wrong_share(4), generation=1)
    client = app.test_client()
    login_admin(client)

    resp = post_form(client, EMERGENCY_URL, {"seal_id": seal.seal_id, "reason": "R1-2"})

    row = _last(app, seal.seal_id, "admin")
    assert resp.status_code != 302
    assert (row["outcome"], row["reason"]) == ("denied", "commitment_mismatch")
    assert "1 newer record(s) without an authenticated policy ignored" in row["detail"]
    assert row["detail"].endswith(
        "tried: share 2 of generation 1 + share 4 of generation 1")


def test_an_upload_right_after_a_generation_2_record_created_the_case(
    app, master_key, signer
) -> None:
    """F1 with F2: the first record the web receives is a signed Resealing
    record of generation 2; it creates the case and the mark, and the
    subject's share 1 uploaded right after is stored for generation 2."""
    seal = make_seal_material(seal_id="S-20260928-F6R103", master_key_path=master_key,
                              signer=signer, generation=2)
    body = signed_payload(seal, signer, record=creatable_record(seal), event_id=2,
                          event_type="Resealing")
    assert app.test_client().post("/sync/upload-record", json=body).status_code == 200

    resp = upload_owner_share(app.test_client(), seal.seal_id, seal.shares[0])

    assert resp.status_code == 302
    assert high_water(app, seal.seal_id) == (2, seal.policy_digest.hex(), 2)
    assert share_rows(app, seal.seal_id) == [(1, 2, seal.shares[0])]


def test_without_an_authenticated_policy_a_reseal_opens_no_new_slot(
    app, master_key
) -> None:
    """The limitation that remains (disclosed): a seal whose records carry no
    authenticated policy stays at generation 0, so after its reseal the new
    share 1 is refused while the first one is stored."""
    first = make_seal_material(seal_id="S-20260928-F6R104", master_key_path=master_key,
                               signer=None)
    resealed = make_seal_material(seal_id=first.seal_id, master_key_path=master_key,
                                  signer=None)
    client = app.test_client()
    ensure_case(app, first.seal_id)
    assert client.post("/sync/upload-record", json=sync_payload(
        first, include_wrapped=False)).status_code == 200
    subject = app.test_client()
    assert upload_owner_share(subject, first.seal_id, first.shares[0]).status_code == 302
    take_flashes(subject)
    assert client.post("/sync/upload-record", json=sync_payload(
        resealed, event_id=2, event_type="Resealing",
        include_wrapped=False)).status_code == 200

    resp = upload_owner_share(subject, first.seal_id, resealed.shares[0])

    assert resp.status_code == 409
    assert "세대 0" in resp.get_data(as_text=True)
    assert share_rows(app, first.seal_id) == [(1, 0, first.shares[0])]
