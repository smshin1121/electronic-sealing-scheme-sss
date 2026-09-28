"""Policy generations: rollback protection at sync and at release (stage E, E2a).

The server keeps a per-seal high-water mark (``policy_high_water``). Sync
admission refuses a verified policy below the mark, or at the mark with
another digest (409), and raises the mark in the same transaction as the
store, under the seal's write lock. The release gate decides on the
highest verified generation (the newest event among equals) and ignores
records below the mark. The end-to-end run through the desktop processes
is in ``test_sync_end_to_end.py``.

Synthetic material only (test CA, temporary master key).
"""

from __future__ import annotations

from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import (
    load_test_signer,
    make_seal_material,
    write_ca_bundle,
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
)
from tests.fixtures.sync_copies import (
    ROLLBACK_REFUSAL,
    SAME_GENERATION_REFUSAL,
    event_record,
    replayed,
)
from tests.fixtures.sync_web import (
    high_water,
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
def signer(release_pki):
    return load_test_signer(release_pki)


def _seal(seal_id: str, master_key: str, signer: Any, generation: Any = 1,
          **kwargs: Any):
    return make_seal_material(seal_id=seal_id, master_key_path=master_key,
                              signer=signer, generation=generation, **kwargs)


def _post(app, body: dict) -> Any:
    ensure_case(app, body["seal_id"])
    return app.test_client().post(URL, json=body)


def _sync(app, material, event_id: int, event_type: str = "Sealing",
          **kwargs: Any) -> Any:
    return _post(app, sync_payload(material, event_id=event_id,
                                   event_type=event_type, **kwargs))


def _stored_events(app, seal_id: str) -> list[int]:
    with app.app_context():
        from web.models.db_models import find_seal_records_by_seal_id

        return [row["event_id"] for row in find_seal_records_by_seal_id(seal_id)]


def _digest(material) -> str:
    return material.policy_digest.hex()


# ===================================================================
# Sync admission
# ===================================================================

class TestRollbackAtSync:
    def test_the_mark_follows_the_stored_generations(
        self, app, master_key, signer
    ) -> None:
        sealed = _seal("S-20260928-G00001", master_key, signer, 1)
        resealed = _seal("S-20260928-G00001", master_key, signer, 2)

        assert _sync(app, sealed, 1).status_code == 200
        first = high_water(app, sealed.seal_id)
        assert _sync(app, resealed, 3, "Resealing").status_code == 200

        assert first == (1, _digest(sealed), 1)
        assert high_water(app, sealed.seal_id) == (2, _digest(resealed), 3)

    def test_an_older_generation_replayed_under_a_new_event_is_refused(
        self, app, master_key, signer
    ) -> None:
        sealed = _seal("S-20260928-G00002", master_key, signer, 1)
        resealed = _seal("S-20260928-G00002", master_key, signer, 2)
        _sync(app, sealed, 1)
        _sync(app, resealed, 3, "Resealing")

        # An exact copy is refused before the generation rules (Fable gate,
        # finding 1); a replay with another field changed reaches them.
        replay = _sync(app, sealed, 4, record=replayed(sealed, 4))

        assert replay.status_code == 409
        assert ROLLBACK_REFUSAL in replay.get_json()["message"]
        assert _stored_events(app, sealed.seal_id) == [1, 3]
        assert high_water(app, sealed.seal_id) == (2, _digest(resealed), 3)

    def test_the_same_generation_with_another_digest_is_refused(
        self, app, master_key, signer
    ) -> None:
        first = _seal("S-20260928-G00003", master_key, signer, 1)
        rival = _seal("S-20260928-G00003", master_key, signer, 1)
        _sync(app, first, 1)

        resp = _sync(app, rival, 3, "Resealing")

        assert resp.status_code == 409
        assert _stored_events(app, first.seal_id) == [1]

    def test_the_same_policy_under_a_new_event_is_admitted(
        self, app, master_key, signer
    ) -> None:
        # An Unsealing record carries the current policy unchanged (and its
        # own history entry: an exact copy of event 1 would be refused).
        sealed = _seal("S-20260928-G00004", master_key, signer, 1)
        _sync(app, sealed, 1)

        resp = _sync(app, sealed, 2, "Unsealing", include_wrapped=False,
                     record=event_record(sealed, ("Sealing", "Unsealing")))

        assert resp.status_code == 200
        assert high_water(app, sealed.seal_id) == (1, _digest(sealed), 1)

    def test_an_identical_resubmission_below_the_mark_is_still_answered(
        self, app, master_key, signer
    ) -> None:
        sealed = _seal("S-20260928-G00005", master_key, signer, 1)
        resealed = _seal("S-20260928-G00005", master_key, signer, 2)
        _sync(app, sealed, 1)
        _sync(app, resealed, 3, "Resealing")

        retry = _sync(app, sealed, 1)

        assert retry.status_code == 200
        assert high_water(app, sealed.seal_id)[0] == 2

    def test_an_older_generation_cannot_displace_a_squatted_event(
        self, app, master_key, signer
    ) -> None:
        sealed = _seal("S-20260928-G00006", master_key, signer, 1)
        resealed = _seal("S-20260928-G00006", master_key, signer, 2)
        _sync(app, sealed, 1)
        _sync(app, resealed, 3, "Resealing")
        store_record_out_of_band(app, sealed, record={"seal_id": sealed.seal_id},
                                 event_id=5, event_type="Unsealing")

        resp = _sync(app, sealed, 5, "Unsealing", include_wrapped=False,
                     record=replayed(sealed, 5))

        assert resp.status_code == 409
        assert ROLLBACK_REFUSAL in resp.get_json()["message"]
        assert high_water(app, sealed.seal_id)[0] == 2

    def test_version_one_policies_admit_one_digest_per_seal(
        self, app, master_key, signer
    ) -> None:
        v1_first = _seal("S-20260928-G00007", master_key, signer, None)
        v1_other = _seal("S-20260928-G00007", master_key, signer, None)
        v2 = _seal("S-20260928-G00007", master_key, signer, 1)

        assert _sync(app, v1_first, 1).status_code == 200
        assert high_water(app, v1_first.seal_id) == (0, _digest(v1_first), 1)
        assert _sync(app, v1_other, 3, "Resealing").status_code == 409
        assert _sync(app, v2, 4, "Resealing").status_code == 200
        assert high_water(app, v1_first.seal_id)[0] == 1

    def test_signed_rollback_is_refused_too(
        self, app, master_key, signer
    ) -> None:
        require_signatures(app)
        sealed = _seal("S-20260928-G00008", master_key, signer, 1)
        resealed = _seal("S-20260928-G00008", master_key, signer, 2)
        assert _post(app, signed_payload(sealed, signer)).status_code == 200
        assert _post(app, signed_payload(resealed, signer, event_id=3,
                                         event_type="Resealing")).status_code == 200

        resp = _post(app, signed_payload(sealed, signer, event_id=4,
                                         record=replayed(sealed, 4)))

        assert resp.status_code == 409
        assert ROLLBACK_REFUSAL in resp.get_json()["message"]
        assert "nonce" not in resp.get_json()["message"]

    def test_the_mark_and_the_record_commit_together(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        from web.routes import sync as sync_route

        sealed = _seal("S-20260928-G00009", master_key, signer, 1)

        def broken(**_kwargs: Any) -> None:
            raise RuntimeError("synthetic mark failure")

        monkeypatch.setattr(sync_route, "raise_high_water", broken)
        resp = _sync(app, sealed, 1)

        assert resp.status_code == 500
        assert _stored_events(app, sealed.seal_id) == []
        assert high_water(app, sealed.seal_id) is None


# ===================================================================
# Release gate: the highest verified generation decides
# ===================================================================

def _last(app, seal_id: str, path: str = "standard") -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row"
    return rows[-1]


class TestGateSelection:
    def test_a_record_below_the_mark_is_ignored(
        self, app, master_key, signer
    ) -> None:
        sealed = _seal("S-20260928-H00001", master_key, signer, 1)
        resealed = _seal("S-20260928-H00001", master_key, signer, 2)
        _sync(app, sealed, 1)
        _sync(app, resealed, 3, "Resealing")
        # A gen-1 copy that reached the table some other way, newest event.
        store_record_out_of_band(app, sealed, event_id=9,
                                 event_type="Unsealing")
        store_share(app, sealed.seal_id, 1, resealed.shares[0])

        resp = recover_standard(app.test_client(), resealed)

        assert resp.status_code == 302
        row = _last(app, sealed.seal_id)
        assert (row["outcome"], row["policy_digest"]) == (
            "released", _digest(resealed))
        assert "below the high-water mark" in row["detail"]

    def test_without_a_mark_every_record_is_read(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        from web import release_gate

        sealed = _seal("S-20260928-H00002", master_key, signer, 1)
        resealed = _seal("S-20260928-H00002", master_key, signer, 2)
        # Out of band only (no sync, so no mark): the newest event holds
        # the older generation.
        store_record_out_of_band(app, resealed, event_id=1)
        store_record_out_of_band(app, sealed, event_id=5,
                                 event_type="Unsealing")
        store_share(app, sealed.seal_id, 1, resealed.shares[0])
        fetched: list[int] = []
        real = release_gate.find_record_jsons_newest_first

        def counting(seal_id: str):
            for event_id, record_json in real(seal_id):
                fetched.append(event_id)
                yield event_id, record_json

        monkeypatch.setattr(release_gate, "find_record_jsons_newest_first",
                            counting)

        client = app.test_client()
        resp = recover_standard(client, resealed)

        assert resp.status_code == 302
        assert recovered_key(client, resealed.seal_id) == resealed.key_hex
        assert fetched == [5, 1]
        assert _last(app, sealed.seal_id)["policy_digest"] == _digest(resealed)

    def test_only_records_below_the_mark_deny_every_release(
        self, app, master_key, signer, release_pki, tmp_path
    ) -> None:
        # Generation 2 was signed under a CA later removed from the pinned
        # bundle; generation 1 still verifies but lies below the mark.
        bundle = write_ca_bundle(release_pki, tmp_path / "bundle.pem")
        app.config["POLICY_CA_CERT_PATH"] = str(bundle)
        other = load_test_signer(release_pki, other_ca=True)
        sealed = _seal("S-20260928-H00003", master_key, signer, 1)
        resealed = _seal("S-20260928-H00003", master_key, other, 2)
        assert _sync(app, sealed, 1).status_code == 200
        assert _sync(app, resealed, 3, "Resealing").status_code == 200
        app.config["POLICY_CA_CERT_PATH"] = str(release_pki.ca_cert_path)
        store_share(app, sealed.seal_id, 1, sealed.shares[0])
        store_share(app, sealed.seal_id, 4, sealed.shares[3])

        client = app.test_client()
        standard = recover_standard(client, sealed)
        timelock = post_form(client, "/investigator/recover-key-timelock",
                             {"seal_id": sealed.seal_id,
                              "share_data": sealed.shares[1]})
        login_admin(client)
        admin = post_form(client, "/admin/emergency-recover",
                          {"seal_id": sealed.seal_id,
                           "reason": "court order (synthetic)"})

        assert (standard.status_code, timelock.status_code,
                admin.status_code) == (403, 403, 403)
        assert recovered_key(client, sealed.seal_id) is None
        for path in ("standard", "timelock", "admin"):
            row = _last(app, sealed.seal_id, path)
            assert (row["reason"], row["policy_status"]) == (
                "policy_invalid", "invalid"), path
            assert "below the high-water mark" in row["detail"], path


# ===================================================================
# Review round: the mark is bootstrapped from the stored records
# ===================================================================

def _reader_counting(monkeypatch) -> list[int]:
    """Record every event id the gate reads (through release_gate)."""
    from web import release_gate

    fetched: list[int] = []
    real = release_gate.find_record_jsons_newest_first

    def counting(seal_id: str):
        for event_id, record_json in real(seal_id):
            fetched.append(event_id)
            yield event_id, record_json

    monkeypatch.setattr(release_gate, "find_record_jsons_newest_first",
                        counting)
    return fetched


class TestMarkBootstrap:
    def test_a_lower_generation_cannot_seed_the_first_mark(
        self, app, master_key, signer, release_pki
    ) -> None:
        # Security review (HIGH, reproduced): both generations were stored
        # while no CA was pinned, so no mark exists. Once the CA is pinned,
        # a copy of the generation-1 record under a new event must not set
        # the mark to 1 and steer the release to the earlier unlock time.
        app.config["POLICY_CA_CERT_PATH"] = ""
        sealed = _seal("S-20260928-J00001", master_key, signer, 1)
        resealed = _seal("S-20260928-J00001", master_key, signer, 2)
        assert _sync(app, sealed, 1).status_code == 200
        assert _sync(app, resealed, 3, "Resealing").status_code == 200
        assert high_water(app, sealed.seal_id) is None
        app.config["POLICY_CA_CERT_PATH"] = str(release_pki.ca_cert_path)

        replay = _sync(app, sealed, 9, "Unsealing", include_wrapped=False,
                       record=replayed(sealed, 9))
        seeded = high_water(app, sealed.seal_id)
        store_share(app, sealed.seal_id, 1, resealed.shares[0])
        release = recover_standard(app.test_client(), resealed)

        assert replay.status_code == 409
        assert ROLLBACK_REFUSAL in replay.get_json()["message"]
        assert seeded == (2, _digest(resealed), 3)  # set by sync, before the release
        assert _stored_events(app, sealed.seal_id) == [1, 3]
        assert high_water(app, sealed.seal_id) == (2, _digest(resealed), 3)
        assert release.status_code == 302
        assert _last(app, sealed.seal_id)["policy_digest"] == _digest(resealed)

    def test_an_identical_retry_bootstraps_the_mark_to_the_stored_maximum(
        self, app, master_key, signer, release_pki
    ) -> None:
        app.config["POLICY_CA_CERT_PATH"] = ""
        sealed = _seal("S-20260928-J00002", master_key, signer, 1)
        resealed = _seal("S-20260928-J00002", master_key, signer, 2)
        _sync(app, sealed, 1)
        _sync(app, resealed, 3, "Resealing")
        app.config["POLICY_CA_CERT_PATH"] = str(release_pki.ca_cert_path)

        retry = _sync(app, sealed, 1)
        older = _sync(app, sealed, 9, "Unsealing", include_wrapped=False,
                      record=replayed(sealed, 9))

        assert retry.status_code == 200
        assert high_water(app, sealed.seal_id) == (2, _digest(resealed), 3)
        assert older.status_code == 409
        assert ROLLBACK_REFUSAL in older.get_json()["message"]

    def test_a_displacement_is_checked_against_the_bootstrapped_mark(
        self, app, master_key, signer
    ) -> None:
        sealed = _seal("S-20260928-J00003", master_key, signer, 1)
        resealed = _seal("S-20260928-J00003", master_key, signer, 2)
        store_record_out_of_band(app, resealed, event_id=3,
                                 event_type="Resealing")
        store_record_out_of_band(app, sealed, record={"seal_id": sealed.seal_id},
                                 event_id=5, event_type="Unsealing")

        resp = _sync(app, sealed, 5, "Unsealing", include_wrapped=False)

        assert resp.status_code == 409
        assert high_water(app, sealed.seal_id) == (2, _digest(resealed), 3)

    def test_version_one_digests_stored_before_e2a(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        # Stage D stored several version-1 policies per seal. The newest
        # decides (as in stage D), the first release sets the mark to it,
        # and another version-1 digest is refused afterwards.
        first = _seal("S-20260928-J00004", master_key, signer, None)
        newest = _seal("S-20260928-J00004", master_key, signer, None)
        store_record_out_of_band(app, first, event_id=1)
        store_record_out_of_band(app, newest, event_id=3,
                                 event_type="Resealing")
        store_share(app, first.seal_id, 1, newest.shares[0])

        release = recover_standard(app.test_client(), newest)
        mark = high_water(app, first.seal_id)
        other = _sync(app, first, 5, "Unsealing", include_wrapped=False,
                      record=replayed(first, 5))

        assert release.status_code == 302
        assert _last(app, first.seal_id)["policy_digest"] == _digest(newest)
        assert mark == (0, _digest(newest), 3)
        assert other.status_code == 409
        assert SAME_GENERATION_REFUSAL in other.get_json()["message"]


class TestGateMarkBackfill:
    def test_the_first_release_sets_the_mark_and_later_ones_stop_early(
        self, app, master_key, signer, monkeypatch
    ) -> None:
        sealed = _seal("S-20260928-J00005", master_key, signer, 1)
        resealed = _seal("S-20260928-J00005", master_key, signer, 2)
        unsigned = {"seal_id": sealed.seal_id}
        for event_id in (1, 2, 3):
            store_record_out_of_band(app, sealed, record=unsigned,
                                     event_id=event_id, event_type="Unsealing")
        store_record_out_of_band(app, resealed, event_id=4,
                                 event_type="Resealing")
        store_record_out_of_band(app, sealed, event_id=5,
                                 event_type="Unsealing")
        store_share(app, sealed.seal_id, 1, resealed.shares[0])
        fetched = _reader_counting(monkeypatch)
        client = app.test_client()

        first = recover_standard(client, resealed)
        first_reads = list(fetched)
        fetched.clear()
        second = recover_standard(client, resealed)

        assert (first.status_code, second.status_code) == (302, 302)
        assert first_reads == [5, 4, 3, 2, 1]
        assert high_water(app, sealed.seal_id) == (2, _digest(resealed), 4)
        assert fetched == [5, 4]
        row = _last(app, sealed.seal_id)
        assert row["policy_digest"] == _digest(resealed)
        assert "below the high-water mark" in row["detail"]

    def test_the_mark_names_the_policy_not_just_a_floor(
        self, app, master_key, signer
    ) -> None:
        # A record of the mark's generation with another digest, written
        # out of band at a newer event, cannot take the decision.
        sealed = _seal("S-20260928-J00006", master_key, signer, 1)
        rival = _seal("S-20260928-J00006", master_key, signer, 1)
        assert _sync(app, sealed, 1).status_code == 200
        store_record_out_of_band(app, rival, event_id=7,
                                 event_type="Resealing")
        store_share(app, sealed.seal_id, 1, sealed.shares[0])

        resp = recover_standard(app.test_client(), sealed)

        assert resp.status_code == 302
        row = _last(app, sealed.seal_id)
        assert row["policy_digest"] == _digest(sealed)
        assert "another policy" in row["detail"]
