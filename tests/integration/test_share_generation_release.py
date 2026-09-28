"""Release after a reseal: stored shares chosen by policy generation (stage F, F1).

Stored shares are versioned by policy generation. For the deciding
policy's generation G, the stored owner share s1 (standard path; strict
time-locked path) is taken from generation G first, then from the other
generations, highest first, and the first whose recombination matches the
key commitment is used. The admin path orders s4 and the other stored
share the same way under an authenticated policy, and keeps the v1.1 rule
(generation-0 slots, s4 and the lowest other slot) for an unauthenticated
decision. Released audit rows name the generation of every stored share
used; every attempt is still one audit row.

Before F1 the resealed owner share could not be stored while slot 1 held
the first one, and these releases ended in ``commitment_mismatch``.

Synthetic material only (test CA, local TSA, temporary master key).
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import sql_execute
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
    store_share,
    sync_seal,
)
from tests.fixtures.share_uploads import (
    upload_investigator_share,
    upload_owner_share,
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


def _pair(seal_id: str, master_key: str, signer: Any, **kwargs: Any):
    """The same seal at generation 1 (sealed) and 2 (resealed, a new key)."""
    return tuple(make_seal_material(seal_id=seal_id, master_key_path=master_key,
                                    signer=signer, generation=generation,
                                    **kwargs)
                 for generation in (1, 2))


def _reseal(client, app, resealed) -> None:
    """Sync the resealing record (event 2, with its wrapped s3)."""
    sync_seal(client, app, resealed, event_id=2, event_type="Resealing")


def _last(app, seal_id: str, path: str) -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row"
    return rows[-1]


def _timelock(client, material, share: str | None = None) -> Any:
    presented = material.shares[1] if share is None else share
    return post_form(client, TIMELOCK_URL,
                     {"seal_id": material.seal_id, "share_data": presented})


def _admin(client, seal_id: str) -> Any:
    login_admin(client)
    return post_form(client, ADMIN_URL,
                     {"seal_id": seal_id, "reason": "court order"})


# ===================================================================
# Standard path (stored s1 + presented s2)
# ===================================================================

class TestStandardAfterReseal:
    def test_the_resealed_owner_share_releases_on_generation_2(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R001", master_key, signer)
        sync_seal(client, app, sealed)
        assert upload_owner_share(client, sealed.seal_id,
                                  sealed.shares[0]).status_code == 302
        _reseal(client, app, resealed)
        assert upload_owner_share(client, sealed.seal_id,
                                  resealed.shares[0]).status_code == 302

        resp = recover_standard(client, resealed)

        assert resp.status_code == 302
        assert recovered_key(client, resealed.seal_id) == resealed.key_hex
        row = _last(app, resealed.seal_id, "standard")
        assert (row["outcome"], row["policy_digest"]) == (
            "released", resealed.policy_digest.hex())
        assert row["detail"] == "shares=1+2; share 1 of generation 2"

    def test_an_owner_share_uploaded_before_the_resealing_record_releases(
        self, app, client, master_key, signer
    ) -> None:
        # Tagged with generation 1 (the mark when it arrived); the key
        # commitment of generation 2 still identifies it.
        sealed, resealed = _pair("S-20260929-F1R002", master_key, signer)
        sync_seal(client, app, sealed)
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])
        _reseal(client, app, resealed)

        resp = recover_standard(client, resealed)

        assert resp.status_code == 302
        assert recovered_key(client, resealed.seal_id) == resealed.key_hex
        assert _last(app, resealed.seal_id, "standard")["detail"] == (
            "shares=1+2; share 1 of generation 1")

    def test_the_first_owner_share_does_not_release_the_resealed_key(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R003", master_key, signer)
        sync_seal(client, app, sealed)
        upload_owner_share(client, sealed.seal_id, sealed.shares[0])
        _reseal(client, app, resealed)

        new_s2 = recover_standard(client, resealed)
        old_s2 = recover_standard(client, sealed)

        assert (new_s2.status_code, old_s2.status_code) == (400, 400)
        assert recovered_key(client, sealed.seal_id) is None
        rows = audit_rows(app, sealed.seal_id)
        assert [(r["outcome"], r["reason"]) for r in rows] == [
            ("denied", "commitment_mismatch")] * 2
        assert "generation 1" in rows[-1]["detail"]

    def test_each_attempt_is_one_audit_row_whatever_the_candidates(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R004", master_key, signer)
        stranger = make_seal_material(seal_id="S-20260929-F1R005",
                                      master_key_path=master_key, signer=signer)
        sync_seal(client, app, sealed)
        upload_owner_share(client, sealed.seal_id, sealed.shares[0])
        _reseal(client, app, resealed)
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])

        wrong = recover_standard(client, resealed, stranger.shares[1])
        wrong_text = wrong.get_data(as_text=True)
        right = recover_standard(client, resealed)

        assert (wrong.status_code, right.status_code) == (400, 302)
        assert resealed.key_hex not in wrong_text
        assert sealed.key_hex not in wrong_text
        rows = audit_rows(app, sealed.seal_id)
        assert [(r["outcome"], r["reason"]) for r in rows] == [
            ("denied", "commitment_mismatch"), ("released", "released")]

    def test_without_a_stored_owner_share_the_reason_is_unchanged(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R006", master_key, signer)
        sync_seal(client, app, sealed)
        _reseal(client, app, resealed)

        resp = recover_standard(client, resealed)

        assert resp.status_code == 400
        assert _last(app, sealed.seal_id, "standard")["reason"] == (
            "owner_share_missing")

    def test_a_malformed_stored_row_is_never_combined(
        self, app, client, master_key, signer
    ) -> None:
        # A v1.1 route stored whatever it was given; such a row (here an
        # index-2 share in slot 1, generation 0) is skipped when another
        # candidate exists, and alone it still denies as malformed.
        sealed, resealed = _pair("S-20260929-F1R007", master_key, signer)
        sync_seal(client, app, sealed)
        _reseal(client, app, resealed)
        sql_execute(app, """INSERT INTO key_shares (seal_id, share_index,
                            share_data, uploaded_by, generation)
                            VALUES (?, 1, ?, 'suspect', 0)""",
                    (sealed.seal_id, resealed.shares[1]))

        alone = recover_standard(client, resealed)
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])
        usable = recover_standard(client, resealed)

        assert (alone.status_code, usable.status_code) == (400, 302)
        rows = audit_rows(app, sealed.seal_id)
        assert [r["reason"] for r in rows] == ["owner_share_malformed",
                                               "released"]
        assert rows[-1]["detail"] == "shares=1+2; share 1 of generation 2"

    def test_a_legacy_seal_releases_as_in_v1_1(
        self, app, client, master_key
    ) -> None:
        legacy = make_seal_material(seal_id="S-20260929-F1R008",
                                    master_key_path=master_key, signer=None)
        sync_seal(client, app, legacy)
        upload_owner_share(client, legacy.seal_id, legacy.shares[0])

        resp = recover_standard(client, legacy)

        assert resp.status_code == 302
        assert recovered_key(client, legacy.seal_id) == legacy.key_hex
        row = _last(app, legacy.seal_id, "standard")
        assert (row["policy_status"], row["detail"]) == (
            "legacy", "shares=1+2; share 1 of generation 0")


# ===================================================================
# Strict mode, time-locked path (stored s1 + presented s2 + s3)
# ===================================================================

class TestStrictTimelockAfterReseal:
    def test_the_resealed_owner_share_releases_with_the_new_s3(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R010", master_key, signer,
                                 mode="strict")
        sync_seal(client, app, sealed)
        upload_owner_share(client, sealed.seal_id, sealed.shares[0])
        _reseal(client, app, resealed)
        assert upload_owner_share(client, sealed.seal_id,
                                  resealed.shares[0]).status_code == 302

        resp = _timelock(client, resealed)

        assert resp.status_code == 302
        assert recovered_key(client, resealed.seal_id) == resealed.key_hex
        row = _last(app, resealed.seal_id, "timelock")
        assert row["outcome"] == "released"
        assert row["detail"].startswith(
            "shares=1+2+3; share 1 of generation 2; ")

    def test_an_owner_share_uploaded_before_the_resealing_record_releases(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R011", master_key, signer,
                                 mode="strict")
        sync_seal(client, app, sealed)
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])
        _reseal(client, app, resealed)

        resp = _timelock(client, resealed)

        assert resp.status_code == 302
        assert recovered_key(client, resealed.seal_id) == resealed.key_hex
        assert _last(app, resealed.seal_id, "timelock")["detail"].startswith(
            "shares=1+2+3; share 1 of generation 1; ")


# ===================================================================
# Admin path (s4 + another stored share)
# ===================================================================

class TestAdminAfterReseal:
    def test_the_admin_share_of_generation_g_is_used(
        self, app, client, master_key, signer, caplog
    ) -> None:
        caplog.set_level(logging.WARNING)
        sealed, resealed = _pair("S-20260929-F1R020", master_key, signer)
        sync_seal(client, app, sealed)
        store_share(app, sealed.seal_id, 4, sealed.shares[3], generation=1)
        upload_investigator_share(client, sealed.seal_id, sealed.shares[1])
        _reseal(client, app, resealed)
        store_share(app, sealed.seal_id, 4, resealed.shares[3], generation=2)
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])

        resp = _admin(client, sealed.seal_id)

        assert resp.status_code == 200
        assert resealed.key_hex in resp.get_data(as_text=True)
        row = _last(app, sealed.seal_id, "admin")
        assert (row["outcome"], row["policy_digest"]) == (
            "released", resealed.policy_digest.hex())
        assert row["detail"] == (
            "shares=1+4; share 1 of generation 2, share 4 of generation 2")
        assert any("Emergency recovery released" in r.getMessage()
                   and "shares=1+4" in r.getMessage() for r in caplog.records)

    def test_the_commitment_decides_across_generations(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R021", master_key, signer)
        sync_seal(client, app, sealed)
        store_share(app, sealed.seal_id, 4, sealed.shares[3], generation=1)
        upload_investigator_share(client, sealed.seal_id, sealed.shares[1])
        upload_owner_share(client, sealed.seal_id, resealed.shares[0])
        _reseal(client, app, resealed)
        store_share(app, sealed.seal_id, 4, resealed.shares[3], generation=2)

        resp = _admin(client, sealed.seal_id)

        assert resp.status_code == 200
        assert resealed.key_hex in resp.get_data(as_text=True)
        assert _last(app, sealed.seal_id, "admin")["detail"] == (
            "shares=1+4; share 1 of generation 1, share 4 of generation 2")

    def test_without_a_matching_pair_nothing_is_released(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R022", master_key, signer)
        sync_seal(client, app, sealed)
        store_share(app, sealed.seal_id, 4, sealed.shares[3], generation=1)
        upload_investigator_share(client, sealed.seal_id, sealed.shares[1])
        _reseal(client, app, resealed)

        resp = _admin(client, sealed.seal_id)

        assert resp.status_code == 400
        text = resp.get_data(as_text=True)
        assert resealed.key_hex not in text and sealed.key_hex not in text
        row = _last(app, sealed.seal_id, "admin")
        assert (row["outcome"], row["reason"]) == ("denied",
                                                   "commitment_mismatch")

    def test_an_unauthenticated_decision_uses_generation_0_slots_only(
        self, app, client, master_key
    ) -> None:
        legacy = make_seal_material(seal_id="S-20260929-F1R023",
                                    master_key_path=master_key, signer=None)
        sync_seal(client, app, legacy)
        store_share(app, legacy.seal_id, 2, legacy.shares[1])
        store_share(app, legacy.seal_id, 4, legacy.shares[3], generation=1)

        refused = _admin(client, legacy.seal_id)
        store_share(app, legacy.seal_id, 4, legacy.shares[3])
        released = _admin(client, legacy.seal_id)

        assert (refused.status_code, released.status_code) == (400, 200)
        assert legacy.key_hex in released.get_data(as_text=True)
        rows = audit_rows(app, legacy.seal_id)
        assert [(r["reason"], r["policy_status"]) for r in rows] == [
            ("admin_share_missing", "legacy"), ("released", "legacy")]
        assert rows[-1]["detail"] == (
            "shares=2+4; share 2 of generation 0, share 4 of generation 0")


# ===================================================================
# The administrator's share list
# ===================================================================

class TestAdminShareList:
    def test_the_list_shows_the_generation_and_no_share_value(
        self, app, client, master_key, signer
    ) -> None:
        sealed, resealed = _pair("S-20260929-F1R030", master_key, signer)
        ensure_case(app, sealed.seal_id)
        store_share(app, sealed.seal_id, 4, sealed.shares[3], generation=1)
        store_share(app, sealed.seal_id, 4, resealed.shares[3], generation=2)
        login_admin(client)

        resp = client.get("/admin/shares")

        text = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert "세대" in text
        assert text.count(sealed.seal_id) == 2
        for share in (sealed.shares[3], resealed.shares[3]):
            assert share.split("-")[1] not in text
