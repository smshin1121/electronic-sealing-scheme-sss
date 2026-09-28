"""A copy of a stored record under another event id is refused (Fable gate, finding 1).

With ``SYNC_REQUIRE_SIGNATURE`` off (the default), anyone holding a
seal's record could post a copy of it under an unused event id: its
policy verifies and its generation and digest equal the mark's. The
desktop's genuine record for that event then met a 409, and its outbox,
which stops at a seal's first failure, kept every later event pending.
Sync admission now compares an authenticated incoming record with the
seal's stored records and refuses an exact copy stored under another
event id (409), before the new-event store and before a displacement.
The refusal rolls the transaction back, so a signed copy's nonce stays
unused. Only exact copies are caught: a copy with a field outside the
signed policy changed is a different record, and only the switch refuses
it (``TestTheSwitchIsWhatClosesSquatting``). The MariaDB variant is
``test_sync_record_copies_mariadb.py``.

Synthetic material only (test CA, temporary master key).
"""

from __future__ import annotations

from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import make_release_app
from tests.fixtures.sync_copies import (
    FOREIGN_WRAPPED_S3,
    event_ids,
    event_record,
    post,
    refused_as_copy,
    signed,
    stored_record,
    stripped,
    unsigned,
)
from tests.fixtures.sync_web import high_water, nonce_rows, require_signatures

pytestmark = pytest.mark.integration

SEALED = ("Sealing",)
UNSEALED = ("Sealing", "Unsealing")


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
    return make_seal_material(seal_id=seal_id, master_key_path=master_key,
                              signer=signer, generation=1)


def _sealed(app, seal) -> dict:
    """Store the genuine sealing record (event 1, with its wrapped s3)."""
    record = event_record(seal, SEALED)
    resp = post(app, unsigned(seal, record, 1, "Sealing", seal.wrapped_s3_b64))
    assert resp.status_code == 200, resp.get_json()
    return record


class TestCopyUnderANewEvent:
    @pytest.mark.parametrize("event_type, wrapped", [
        ("Unsealing", None), ("Sealing", FOREIGN_WRAPPED_S3)])
    def test_a_copy_is_refused_and_the_genuine_event_is_then_admitted(
        self, app, master_key, signer, event_type, wrapped
    ) -> None:
        seal = _seal("S-20260928-CPY001", master_key, signer)
        sealing = _sealed(app, seal)
        mark = high_water(app, seal.seal_id)

        squat = post(app, unsigned(seal, sealing, 2, event_type, wrapped))

        assert refused_as_copy(squat), squat.get_json()
        assert event_ids(app, "seal_records", seal.seal_id) == [1]
        assert event_ids(app, "wrapped_s3_shares", seal.seal_id) == [1]
        assert high_water(app, seal.seal_id) == mark
        genuine = post(app, unsigned(seal, event_record(seal, UNSEALED), 2,
                                     "Unsealing"))
        assert genuine.status_code == 200, genuine.get_json()
        assert event_ids(app, "seal_records", seal.seal_id) == [1, 2]
        assert stored_record(app, seal.seal_id, 2) == event_record(seal, UNSEALED)

    def test_a_signed_copy_is_refused_and_its_nonce_stays_unused(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-CPY002", master_key, signer)
        sealing = _sealed(app, seal)
        copy_body = signed(seal, signer, sealing, 2, "Unsealing")

        first = post(app, copy_body)
        replay = post(app, copy_body)

        assert refused_as_copy(first), first.get_json()
        assert refused_as_copy(replay), replay.get_json()
        assert nonce_rows(app) == []
        genuine = post(app, signed(seal, signer, event_record(seal, UNSEALED),
                                   2, "Unsealing"))
        assert genuine.status_code == 200, genuine.get_json()
        assert len(nonce_rows(app)) == 1

    def test_a_different_record_under_the_same_policy_is_admitted(
        self, app, master_key, signer
    ) -> None:
        # The check is exact equality, not the policy digest: every event
        # of a seal carries the same policy until a reseal.
        seal = _seal("S-20260928-CPY003", master_key, signer)
        _sealed(app, seal)

        resp = post(app, unsigned(seal, event_record(seal, UNSEALED), 2,
                                  "Unsealing"))

        assert resp.status_code == 200, resp.get_json()


class TestCopyOverAnUnauthenticatedOccupant:
    def test_a_copy_does_not_displace_it_and_the_genuine_record_does(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-CPY004", master_key, signer)
        occupant = stripped(event_record(seal, UNSEALED))
        assert post(app, unsigned(seal, occupant, 2, "Unsealing")).status_code == 200
        sealing = _sealed(app, seal)

        squat = post(app, unsigned(seal, sealing, 2, "Unsealing"))

        assert refused_as_copy(squat), squat.get_json()
        assert stored_record(app, seal.seal_id, 2) == occupant
        genuine = post(app, unsigned(seal, event_record(seal, UNSEALED), 2,
                                     "Unsealing"))
        assert genuine.status_code == 200, genuine.get_json()
        assert stored_record(app, seal.seal_id, 2) == event_record(seal, UNSEALED)


class TestTheSwitchIsWhatClosesSquatting:
    """The copy check stops exact copies only. The policy signature covers
    the policy fields, not the rest of the record, so a copy with any other
    field changed still authenticates and is not a copy. With
    ``SYNC_REQUIRE_SIGNATURE`` off it is admitted and the genuine record for
    that event meets a 409 (the limitation README states); with the switch
    on it is refused, since the envelope signs the exact record bytes."""

    def test_with_the_switch_off_a_modified_copy_still_takes_the_event(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-CPY007", master_key, signer)
        sealing = _sealed(app, seal)
        variant = {**sealing, "process_info": {"type": "Unsealing"}}

        squat = post(app, unsigned(seal, variant, 2, "Unsealing"))
        genuine = post(app, unsigned(seal, event_record(seal, UNSEALED), 2,
                                     "Unsealing"))

        assert squat.status_code == 200
        assert genuine.status_code == 409

    def test_with_the_switch_on_it_is_refused_and_the_genuine_record_admitted(
        self, app, master_key, signer
    ) -> None:
        require_signatures(app)
        seal = _seal("S-20260928-CPY008", master_key, signer)
        sealing = event_record(seal, SEALED)
        assert post(app, signed(seal, signer, sealing, 1, "Sealing")).status_code == 200
        variant = {**sealing, "process_info": {"type": "Unsealing"}}

        squat = post(app, unsigned(seal, variant, 2, "Unsealing"))
        genuine = post(app, signed(seal, signer, event_record(seal, UNSEALED),
                                   2, "Unsealing"))

        assert squat.status_code == 401
        assert genuine.status_code == 200, genuine.get_json()


class TestWhatIsNotACopy:
    def test_an_identical_resubmission_of_the_same_event_is_answered_as_before(
        self, app, master_key, signer
    ) -> None:
        seal = _seal("S-20260928-CPY005", master_key, signer)
        sealing = _sealed(app, seal)

        resp = post(app, unsigned(seal, sealing, 1, "Sealing"))

        assert resp.status_code == 200, resp.get_json()
        assert event_ids(app, "seal_records", seal.seal_id) == [1]

    def test_an_unauthenticated_copy_follows_the_stage_d_rules(
        self, app, master_key
    ) -> None:
        # No policy: not authenticated, never enrolls the seal, and a
        # genuine authenticated record displaces it (stage D).
        seal = make_seal_material(seal_id="S-20260928-CPY006",
                                  master_key_path=master_key, signer=None)
        legacy = event_record(seal, SEALED)
        assert post(app, unsigned(seal, legacy, 1, "Sealing")).status_code == 200

        resp = post(app, unsigned(seal, legacy, 2, "Unsealing"))

        assert resp.status_code == 200, resp.get_json()
