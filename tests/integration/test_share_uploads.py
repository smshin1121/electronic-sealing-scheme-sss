"""Share uploads versioned by policy generation (stage F, F1).

Both upload routes -- the subject's slot 1 (after authentication) and the
investigator's slot 2 (unauthenticated) -- store a share under the
generation of the seal's newest authenticated policy: the high-water
mark's, else the highest authenticated generation among the stored
records, else 0. A slot holds one share per generation: the identical
share again is answered as already stored (no new row), and a different
one is refused with 409, naming the generation. A malformed share is
refused with 400 before anything is stored. Share values reach neither a
response nor a log line.

Synthetic material only (test CA, temporary master key).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import insert_plaintext_row
from tests.fixtures.release_pki import load_test_signer, make_seal_material
from tests.fixtures.release_web import (
    ensure_case,
    make_release_app,
    store_record_out_of_band,
    store_share,
    sync_seal,
)
from tests.fixtures.share_uploads import (
    MSG_IDENTICAL,
    MSG_SYNC_FIRST,
    share_rows,
    take_flashes,
    upload_investigator_share,
    upload_owner_share,
)
from tests.fixtures.sync_web import high_water

pytestmark = pytest.mark.integration

MSG_STORED = "업로드되었습니다"
UPLOADS = {1: upload_owner_share, 2: upload_investigator_share}


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
def client(app):
    return app.test_client()


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _seal(seal_id: str, master_key: str, signer: Any, generation: Any = 1,
          **kwargs: Any):
    return make_seal_material(seal_id=seal_id, master_key_path=master_key,
                              signer=signer, generation=generation, **kwargs)


def _resealed(client, app, seal_id: str, master_key: str, signer: Any):
    """A seal synced at generation 1 (event 1) and resealed at 2 (event 2)."""
    sealed = _seal(seal_id, master_key, signer, 1)
    resealed = _seal(seal_id, master_key, signer, 2)
    sync_seal(client, app, sealed)
    sync_seal(client, app, resealed, event_id=2, event_type="Resealing")
    return sealed, resealed


def _upload(client, slot: int, seal_id: str, share: str) -> Any:
    return UPLOADS[slot](client, seal_id, share)


def _text(resp) -> str:
    return resp.get_data(as_text=True)


# ===================================================================
# The generation a share is stored under
# ===================================================================

class TestGenerationAtUpload:
    @pytest.mark.parametrize("slot", [1, 2])
    def test_the_high_water_mark_gives_the_generation(
        self, app, client, master_key, signer, slot: int
    ) -> None:
        seal_id = f"S-20260929-F1U00{slot}"
        _, resealed = _resealed(client, app, seal_id, master_key, signer)

        resp = _upload(client, slot, seal_id, resealed.shares[slot - 1])

        assert resp.status_code == 302
        assert share_rows(app, seal_id) == [
            (slot, 2, resealed.shares[slot - 1])]

    def test_without_a_mark_the_stored_records_give_it(
        self, app, client, master_key, signer
    ) -> None:
        # Records written outside sync admission leave no mark; the upload
        # reads the generation as sync admission would bootstrap it.
        seal_id = "S-20260929-F1U003"
        sealed = _seal(seal_id, master_key, signer, 1)
        resealed = _seal(seal_id, master_key, signer, 2)
        store_record_out_of_band(app, sealed)
        store_record_out_of_band(app, resealed, event_id=2,
                                 event_type="Resealing")

        resp = upload_owner_share(client, seal_id, resealed.shares[0])

        assert resp.status_code == 302
        assert share_rows(app, seal_id) == [(1, 2, resealed.shares[0])]
        assert high_water(app, seal_id) is None  # the upload seeds no mark

    def test_a_seal_without_an_authenticated_policy_is_generation_0(
        self, app, client, master_key
    ) -> None:
        legacy = _seal("S-20260929-F1U004", master_key, None, None)
        sync_seal(client, app, legacy)
        ensure_case(app, "S-20260929-F1U005")  # no record at all

        first = upload_owner_share(client, legacy.seal_id, legacy.shares[0])
        second = upload_investigator_share(client, "S-20260929-F1U005",
                                           legacy.shares[1])

        assert (first.status_code, second.status_code) == (302, 302)
        assert share_rows(app, legacy.seal_id) == [(1, 0, legacy.shares[0])]
        assert share_rows(app, "S-20260929-F1U005") == [
            (2, 0, legacy.shares[1])]

    def test_a_version_1_policy_is_generation_0(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260929-F1U006", master_key, signer, None)
        sync_seal(client, app, seal)

        resp = upload_owner_share(client, seal.seal_id, seal.shares[0])

        assert resp.status_code == 302
        assert share_rows(app, seal.seal_id) == [(1, 0, seal.shares[0])]


# ===================================================================
# Outcomes: stored, identical, conflict, malformed
# ===================================================================

class TestUploadOutcomes:
    @pytest.mark.parametrize("slot", [1, 2])
    def test_the_identical_share_again_adds_no_row(
        self, app, client, master_key, signer, slot: int
    ) -> None:
        seal = _seal(f"S-20260929-F1U01{slot}", master_key, signer, 1)
        sync_seal(client, app, seal)
        share = seal.shares[slot - 1]

        first = _upload(client, slot, seal.seal_id, share)
        first_flash = take_flashes(client)
        again = _upload(client, slot, seal.seal_id, f"  {share.upper()}\n")
        again_flash = take_flashes(client)

        assert (first.status_code, again.status_code) == (302, 302)
        assert any(MSG_STORED in text for _, text in first_flash)
        assert any(MSG_IDENTICAL in text for _, text in again_flash)
        assert not any(MSG_STORED in text for _, text in again_flash)
        assert share_rows(app, seal.seal_id) == [(slot, 1, share)]

    @pytest.mark.parametrize("slot", [1, 2])
    def test_a_different_share_for_the_generation_is_refused(
        self, app, client, master_key, signer, slot: int
    ) -> None:
        seal_id = f"S-20260929-F1U02{slot}"
        sealed = _seal(seal_id, master_key, signer, 1)
        resealed = _seal(seal_id, master_key, signer, 2)
        sync_seal(client, app, sealed)
        assert _upload(client, slot, seal_id,
                       sealed.shares[slot - 1]).status_code == 302
        take_flashes(client)

        # The resealed share before the resealing record reached the web.
        refused = _upload(client, slot, seal_id, resealed.shares[slot - 1])

        body = _text(refused)
        assert refused.status_code == 409
        assert "세대 1" in body and MSG_SYNC_FIRST in body
        assert MSG_STORED not in body
        assert resealed.shares[slot - 1].split("-")[1] not in body
        assert share_rows(app, seal_id) == [(slot, 1, sealed.shares[slot - 1])]

    def test_after_the_resealing_record_the_new_share_is_stored(
        self, app, client, master_key, signer
    ) -> None:
        seal_id = "S-20260929-F1U030"
        sealed = _seal(seal_id, master_key, signer, 1)
        resealed = _seal(seal_id, master_key, signer, 2)
        sync_seal(client, app, sealed)
        upload_owner_share(client, seal_id, sealed.shares[0])
        assert upload_owner_share(client, seal_id,
                                  resealed.shares[0]).status_code == 409

        sync_seal(client, app, resealed, event_id=2, event_type="Resealing")
        stored = upload_owner_share(client, seal_id, resealed.shares[0])

        assert stored.status_code == 302
        assert share_rows(app, seal_id) == [
            (1, 1, sealed.shares[0]), (1, 2, resealed.shares[0])]

    @pytest.mark.parametrize("slot", [1, 2])
    @pytest.mark.parametrize("shape", [
        "other-slot", "not-hex", "empty-payload", "no-dash",
        "inner-space", "too-long",
    ])
    def test_a_malformed_share_is_refused_with_400(
        self, app, client, master_key, signer, slot: int, shape: str
    ) -> None:
        seal = _seal(f"S-20260929-F1U04{slot}", master_key, signer, 1)
        sync_seal(client, app, seal)
        other = 2 if slot == 1 else 1
        share = {
            "other-slot": f"{other}-" + "ab" * 32,
            "not-hex": f"{slot}-" + "xy" * 32,
            "empty-payload": f"{slot}-",
            "no-dash": "ab" * 32,
            "inner-space": f"{slot}-" + "ab" * 16 + " " + "cd" * 16,
            "too-long": f"{slot}-" + "a" * 4095,   # 4097 characters
        }[shape]

        resp = _upload(client, slot, seal.seal_id, share)

        assert resp.status_code == 400
        assert MSG_STORED not in _text(resp)
        assert share_rows(app, seal.seal_id) == []

    def test_a_share_of_exactly_4096_characters_passes_the_format_check(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260929-F1U050", master_key, signer, 1)
        sync_seal(client, app, seal)
        share = "2-" + "a" * 4094

        resp = upload_investigator_share(client, seal.seal_id, share)

        assert resp.status_code == 302
        assert share_rows(app, seal.seal_id) == [(2, 1, share)]

    def test_an_unknown_seal_is_still_404(self, client) -> None:
        resp = upload_investigator_share(client, "S-20260929-NOCASE",
                                         "2-" + "ab" * 32)

        assert resp.status_code == 404

    def test_the_subject_session_is_checked_before_the_format(
        self, app, client, master_key
    ) -> None:
        seal = _seal("S-20260929-F1U060", master_key, None, None)
        ensure_case(app, seal.seal_id)
        with client.session_transaction() as sess:
            sess["csrf_token"] = "test-csrf-token"  # public-test-fixture

        resp = client.post(f"/suspect/upload-share/{seal.seal_id}", data={
            "seal_id": seal.seal_id, "share_data": "not-a-share",
            "csrf_token": "test-csrf-token"})  # public-test-fixture

        assert resp.status_code == 302
        assert "/suspect/auth" in resp.headers["Location"]

    def test_share_values_reach_no_response_and_no_log(
        self, app, client, master_key, signer, caplog
    ) -> None:
        caplog.set_level(logging.DEBUG)
        seal_id = "S-20260929-F1U070"
        sealed = _seal(seal_id, master_key, signer, 1)
        resealed = _seal(seal_id, master_key, signer, 2)
        sync_seal(client, app, sealed)
        shares = (sealed.shares[0], sealed.shares[0], resealed.shares[0],
                  "1-" + "ab" * 16 + "zz")

        bodies = [_text(upload_owner_share(client, seal_id, share))
                  for share in shares]
        bodies.append(_text(upload_investigator_share(client, seal_id,
                                                      sealed.shares[1])))

        payloads = [share.split("-")[1] for share in (*shares, sealed.shares[1])]
        for payload in payloads:
            assert not any(payload in body for body in bodies)
            assert not any(payload in record.getMessage()
                           for record in caplog.records)


# ===================================================================
# The stored records are read before the seal's write lock
# ===================================================================

class TestGenerationBeforeTheLock:
    """For a seal without a mark the stored records are read (decrypted,
    policies verified) before the seal's write lock is taken, so that work
    never holds the lock (on SQLite the database write lock); under the lock
    the mark is read again and decides when it exists by then (review round,
    security finding 1)."""

    def _unmarked(self, app, master_key, signer, seal_id: str):
        sealed = _seal(seal_id, master_key, signer, 1)
        resealed = _seal(seal_id, master_key, signer, 2)
        store_record_out_of_band(app, sealed)
        store_record_out_of_band(app, resealed, event_id=2,
                                 event_type="Resealing")
        return resealed

    def test_the_records_are_read_outside_the_write_transaction(
        self, app, client, master_key, signer, monkeypatch
    ) -> None:
        import web.share_upload as share_upload

        resealed = self._unmarked(app, master_key, signer, "S-20260929-F1U100")
        real, in_transaction = share_upload.stored_generation, []

        def spy(seal_id: str, read_records: Any, *, ca_path: Any) -> int:
            from flask import g

            in_transaction.append(g.db.in_transaction)
            return real(seal_id, read_records, ca_path=ca_path)

        monkeypatch.setattr(share_upload, "stored_generation", spy)

        resp = upload_owner_share(client, resealed.seal_id, resealed.shares[0])

        assert resp.status_code == 302
        assert in_transaction == [False]
        assert share_rows(app, resealed.seal_id) == [(1, 2, resealed.shares[0])]

    def test_a_mark_created_meanwhile_decides(
        self, app, client, master_key, signer, monkeypatch
    ) -> None:
        # A sync admission between that read and the lock creates the mark;
        # the value read before is then not used.
        import web.share_upload as share_upload

        resealed = self._unmarked(app, master_key, signer, "S-20260929-F1U101")

        def stale(seal_id: str, read_records: Any, *, ca_path: Any) -> int:
            from web.models.sync_models import seed_high_water

            seed_high_water(seal_id=seal_id, generation=2,
                            policy_digest=resealed.policy_digest.hex(),
                            event_id=2, updated_at="2026-09-29T00:00:00+00:00",
                            commit=True)
            return 1

        monkeypatch.setattr(share_upload, "stored_generation", stale)

        resp = upload_owner_share(client, resealed.seal_id, resealed.shares[0])

        assert resp.status_code == 302
        assert share_rows(app, resealed.seal_id) == [(1, 2, resealed.shares[0])]


# ===================================================================
# The generation cannot be read
# ===================================================================

class TestGenerationUnavailable:
    def test_a_seal_whose_records_cannot_be_read_stores_nothing(
        self, app, client, master_key, signer
    ) -> None:
        # A record stored before E3b and not converted: the stored records
        # cannot be read, so the generation is unknown (503, nothing stored).
        seal = _seal("S-20260929-F1U080", master_key, signer, 2)
        ensure_case(app, seal.seal_id)
        insert_plaintext_row(app, seal.seal_id, 1, json.dumps(seal.record))

        resp = upload_investigator_share(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 503
        assert MSG_STORED not in _text(resp)
        assert share_rows(app, seal.seal_id) == []


# ===================================================================
# The model function (v1.x call shape, explicit outcome)
# ===================================================================

class TestInsertKeyShare:
    def test_the_v1_call_shape_stores_generation_0_with_its_outcome(
        self, app, master_key
    ) -> None:
        seal = _seal("S-20260929-F1U090", master_key, None, None)
        other = _seal("S-20260929-F1U091", master_key, None, None)
        ensure_case(app, seal.seal_id)
        with app.app_context():
            from web.models.db_models import insert_key_share

            first = insert_key_share(seal.seal_id, 1, seal.shares[0], "suspect")
            again = insert_key_share(seal.seal_id, 1, seal.shares[0], "suspect")
            clash = insert_key_share(seal.seal_id, 1, other.shares[0], "suspect")
            later = insert_key_share(seal.seal_id, 1, other.shares[0], "suspect",
                                     generation=2)

        assert (first.outcome, first.generation) == ("stored", 0)
        assert first.row_id is not None
        assert (again.outcome, again.row_id) == ("identical", None)
        assert (clash.outcome, clash.generation, clash.row_id) == (
            "conflict", 0, None)
        assert (later.outcome, later.generation) == ("stored", 2)
        assert share_rows(app, seal.seal_id) == [
            (1, 0, seal.shares[0]), (1, 2, other.shares[0])]

    @pytest.mark.parametrize("generation", [-1, True, 2 ** 31, "1"])
    def test_a_generation_outside_the_policy_range_is_refused(
        self, app, master_key, generation: Any
    ) -> None:
        seal = _seal("S-20260929-F1U092", master_key, None, None)
        ensure_case(app, seal.seal_id)

        with pytest.raises(ValueError):
            store_share(app, seal.seal_id, 1, seal.shares[0],
                        generation=generation)
        assert share_rows(app, seal.seal_id) == []
