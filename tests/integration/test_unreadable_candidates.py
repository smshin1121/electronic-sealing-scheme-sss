"""What an unreadable record decides in the release gate (E3b, Codex round 3).

A stored record whose ciphertext does not decrypt is read as unreadable,
never as absent. Whether that denies the release depends on the other
records, exactly as for any record without an authenticated policy:

  - when it is the record the decision would rest on (the only one, or the
    records carrying the seal's marked policy all fail), the release is
    denied and audited (``test_record_protection.py``);
  - when another stored record carrying the marked policy opens, or, for a
    seal without a mark, an older authenticated record, the decision rests
    on that record, and the unreadable one is counted in the audit detail.

Only someone with database write access can make a stored ciphertext
unreadable, and deleting the row has the same effect. Synthetic data only.
"""

from __future__ import annotations

from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import copy_column, identity_record
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    make_release_app,
    recover_standard,
    recovered_key,
    store_record_out_of_band,
    store_share,
    sync_payload,
)
from tests.fixtures.sync_web import signed_payload

pytestmark = pytest.mark.integration

URL = "/sync/upload-record"
IGNORED = "1 newer record(s) without an authenticated policy ignored"


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


def _seal(seal_id: str, master_key: str, signer: Any):
    return make_seal_material(seal_id=seal_id, master_key_path=master_key, signer=signer,
                              generation=1 if signer is not None else None)


def _sync(app: Any, body: dict) -> None:
    ensure_case(app, body["seal_id"])
    assert app.test_client().post(URL, json=body).status_code == 200


def _foreign_record(app: Any, master_key: str) -> str:
    """The seal ID of another seal's synced record (its ciphertext is moved)."""
    other = _seal("S-20260928-E3BU99", master_key, None)
    _sync(app, sync_payload(other, include_wrapped=False))
    return other.seal_id


class TestUnreadableCandidates:
    def test_a_readable_record_with_the_marked_policy_decides(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-E3BU01", master_key, signer)
        for event_id, event_type in ((1, "Sealing"), (2, "Unsealing")):
            _sync(app, signed_payload(seal, signer, event_id=event_id, event_type=event_type,
                                      record=identity_record(seal, note=str(event_id)),
                                      include_wrapped=event_id == 1))
        store_share(app, seal.seal_id, 1, seal.shares[0])
        other = _foreign_record(app, master_key)
        copy_column(app, (other, 1, "record_json"), (seal.seal_id, 2, "record_json"))
        client = app.test_client()

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        [row] = audit_rows(app, seal.seal_id)
        assert (row["outcome"], row["policy_status"]) == ("released", "verified")
        assert IGNORED in row["detail"]

    def test_without_a_mark_an_older_readable_record_decides(
        self, app, master_key, signer
    ) -> None:
        # Records written outside sync admission: no mark, so a full scan.
        seal = _seal("S-20260928-E3BU02", master_key, signer)
        store_record_out_of_band(app, seal, wrapped_s3=seal.wrapped_s3)
        store_record_out_of_band(app, seal, event_id=2, event_type="Unsealing")
        store_share(app, seal.seal_id, 1, seal.shares[0])
        other = _foreign_record(app, master_key)
        copy_column(app, (other, 1, "record_json"), (seal.seal_id, 2, "record_json"))
        client = app.test_client()

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        [row] = audit_rows(app, seal.seal_id)
        assert (row["outcome"], row["policy_status"]) == ("released", "verified")
        assert IGNORED in row["detail"]
