"""Stage D fix round: the HIGH findings of the Codex and Fable reviews.

H1  Time-locked path: the requester must present the investigator share
    s2 in the request (possession proof). A share stored in slot 2 plays
    no part (it could be occupied first through the unauthenticated upload
    route), and a request without a well-formed share learns nothing.
H2  Certificate lifetime: a policy whose certificate has since expired
    keeps the standard and admin paths usable with its signed values and
    is refused on the time-locked path; a pinned CA bundle keeps a rotated
    anchor verifiable.
H3  Share selection: the standard path combines exactly s1 and s2, the
    admin path s4 and one other share, each slot holding a share of its
    own index; the audit row names the indices used.
H4  Policy stripping: once a seal has a verified policy, records without
    a verifiable policy are refused at sync and ignored at release;
    records whose policy fails verification are refused at sync; with
    RELEASE_REQUIRE_POLICY on, unauthenticated records release nothing.
R1  Re-review of 6158e2d: the standard path also takes the investigator
    share from the request, so a seal ID and an elapsed unlock time are
    not enough. A reconstruction from a presented share is released only
    against a key commitment; without one (a record that predates it, or
    no record) it is refused, because the stored s1 combined with a
    chosen s2 would reveal s1. A request without a well-formed share is
    refused before any record is read, on both investigator paths.
R2  Codex round 3 on the second round: a presented share longer than any
    share of the scheme is malformed (it would select a larger field in
    the combiner); the commitment check runs one fixed-size hash whatever
    the reconstruction; an identical sync retry fills a missing envelope or
    enrollment and refuses a different envelope; record identity keeps
    JSON value types; displacement only replaces the record it was
    decided on.
R3  The remaining MEDIUM findings (user decision, 2026-09-27): a sync
    submission's admission, conflict decision and writes run in one
    transaction serialized per seal; a release reads records one at a
    time and stops at the newest authenticated one; a release that
    finds an authenticated record enrolls the seal.
R4  Fable re-review of dcb8a33 (user decision, 2026-09-27): a signed
    record replayed under a new event with a malformed envelope, or with
    one wrapped for another policy, no longer blocks the time-locked path
    (the newest envelope that authenticates under the seal and the chosen
    policy is used); the standard path answers a failed recombination and
    a commitment mismatch alike, so the response does not show whether the
    stored owner share has a full-width payload.
R5  Codex round 6 on ca8ec5a (user decision, 2026-09-27): envelopes are
    read one at a time and only after the clock and TSA checks; the master
    key is loaded once per release, and an unusable key is denied as such
    instead of being counted as envelopes that do not authenticate.

Synthetic material only (test CA, local TSA, temporary master key).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from datetime import timedelta
from functools import partial
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.crypto.sss_strict import recover_key_for_mode
from desktop.signature import tsa_client
from tests.fixtures.release_pki import (
    load_test_signer,
    make_expired_signer,
    make_seal_material,
    tsa_trust_settings,
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
    sync_seal,
)
from tests.fixtures.sync_copies import replayed
from tests.fixtures.tsa_proxy import counting_transport

pytestmark = pytest.mark.integration

STANDARD_URL = "/investigator/recover-key"
TIMELOCK_URL = "/investigator/recover-key-timelock"
ADMIN_URL = "/admin/emergency-recover"


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


def _app(tmp_path, monkeypatch, release_pki, release_tsa, master_key, **kw):
    return make_release_app(
        tmp_path, monkeypatch,
        ca_cert_path=kw.pop("ca_cert_path", str(release_pki.ca_cert_path)),
        master_key_path=master_key,
        tsa_url=release_tsa,
        tsa_cert_path=str(release_pki.tsa_cert_path),
        **tsa_trust_settings(release_pki),
        **kw,
    )


@pytest.fixture()
def app(tmp_path, monkeypatch, release_pki, release_tsa, master_key):
    return _app(tmp_path, monkeypatch, release_pki, release_tsa, master_key)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


@pytest.fixture(scope="module")
def expired_signer(release_pki):
    return make_expired_signer(release_pki)


@pytest.fixture()
def tsa_calls(monkeypatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(
        tsa_client, "_send_tsq",
        counting_transport(tsa_client._send_tsq, calls),
    )
    return calls


def _seal(seal_id: str, master_key: str, signer: Any, **kwargs: Any):
    return make_seal_material(
        seal_id=seal_id, master_key_path=master_key, signer=signer, **kwargs
    )


def _rows(app, seal_id: str, path: str) -> list[dict]:
    return [r for r in audit_rows(app, seal_id) if r["path"] == path]


def _last(app, seal_id: str, path: str) -> dict:
    rows = _rows(app, seal_id, path)
    assert rows, f"no {path} audit row for {seal_id}"
    return rows[-1]


def _request_s3(client, seal_id: str, share: str | None) -> Any:
    data = {"seal_id": seal_id}
    if share is not None:
        data["share_data"] = share
    return post_form(client, TIMELOCK_URL, data)


def _admin(client, seal_id: str, reason: str = "court order (synthetic)"):
    login_admin(client)
    return post_form(client, ADMIN_URL, {"seal_id": seal_id, "reason": reason})


def _stripped(material: Any, **fields: Any) -> dict:
    """The record with every policy field removed (and fields overridden)."""
    record = {k: v for k, v in material.record.items()
              if k not in ("policy", "policy_signature", "policy_cert")}
    record.pop("key_commitment", None)
    return {**record, **fields}


# ===================================================================
# H1: the time-locked path requires the presented investigator share
# ===================================================================

class TestPossessionOfTheInvestigatorShare:
    def test_request_without_a_share_is_denied_before_tsa(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        seal = _seal("S-20260927-P00001", master_key, signer)
        sync_seal(client, app, seal)
        # s2 was uploaded earlier, but an anonymous caller does not hold it.
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = _request_s3(client, seal.seal_id, None)

        assert resp.status_code == 400
        assert tsa_calls == []
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "timelock")
        assert (row["outcome"], row["reason"]) == (
            "denied", "investigator_share_missing"
        )

    def test_presented_share_releases_without_a_stored_share(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        seal = _seal("S-20260927-P00002", master_key, signer)
        sync_seal(client, app, seal)

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        assert len(tsa_calls) == 1
        row = _last(app, seal.seal_id, "timelock")
        assert row["outcome"] == "released"
        assert row["detail"].split("; ")[0] == "shares=2+3"

    def test_occupied_slot_2_does_not_block_the_presented_share(
        self, app, client, master_key, signer
    ) -> None:
        # The upload route is unauthenticated: whoever wants recovery
        # blocked could fill slot 2 first. The time-locked path ignores it.
        seal = _seal("S-20260927-P00003", master_key, signer)
        squatter = _seal("S-20260927-P00004", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, squatter.shares[1])

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        assert _last(app, seal.seal_id, "timelock")["outcome"] == "released"

    def test_request_without_a_share_learns_nothing_about_the_seal(
        self, app, client, master_key
    ) -> None:
        legacy = _seal("S-20260927-P00011", master_key, None)
        sync_seal(client, app, legacy)

        resp = _request_s3(client, legacy.seal_id, None)
        unknown = _request_s3(client, "S-20260927-NOSUCH", None)

        assert resp.status_code == unknown.status_code == 400
        assert _last(app, legacy.seal_id, "timelock")["reason"] == (
            "investigator_share_missing"
        )

    def test_another_seals_share_releases_nothing(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-P00005", master_key, signer)
        stranger = _seal("S-20260927-P00006", master_key, signer)
        sync_seal(client, app, seal)

        resp = _request_s3(client, seal.seal_id, stranger.shares[1])

        assert resp.status_code == 403
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "timelock")
        assert (row["outcome"], row["reason"]) == ("denied",
                                                   "commitment_mismatch")

    def test_owner_share_relabelled_as_s2_releases_nothing(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-P00007", master_key, signer)
        sync_seal(client, app, seal)
        relabelled = "2-" + seal.shares[0].split("-", 1)[1]

        resp = _request_s3(client, seal.seal_id, relabelled)

        assert resp.status_code == 403
        assert recovered_key(client, seal.seal_id) is None
        assert _last(app, seal.seal_id, "timelock")["reason"] == (
            "commitment_mismatch"
        )

    def test_owner_share_in_the_form_is_malformed_before_tsa(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        seal = _seal("S-20260927-P00008", master_key, signer)
        sync_seal(client, app, seal)

        resp = _request_s3(client, seal.seal_id, seal.shares[0])

        assert resp.status_code == 400
        assert tsa_calls == []
        assert _last(app, seal.seal_id, "timelock")["reason"] == (
            "investigator_share_malformed"
        )

    @pytest.mark.parametrize("path", ["timelock", "standard"])
    def test_presented_share_is_not_written_to_the_audit_row(
        self, app, client, master_key, signer, caplog, path: str
    ) -> None:
        caplog.set_level(logging.DEBUG)
        seal = _seal("S-20260927-P00009", master_key, signer)
        stranger = _seal("S-20260927-P00010", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        send = (partial(_request_s3, client, seal.seal_id)
                if path == "timelock" else partial(recover_standard, client, seal))

        denied = send(stranger.shares[1])
        released = send(seal.shares[1])

        assert released.status_code == 302
        assert [r["outcome"] for r in _rows(app, seal.seal_id, path)] == [
            "denied", "released"
        ]
        dumped = json.dumps(audit_rows(app, seal.seal_id))
        logged = "\n".join(record.getMessage() for record in caplog.records)
        for share in (seal.shares[1], stranger.shares[1]):
            secret = share.split("-", 1)[1]
            assert secret not in dumped
            assert secret not in logged
            assert secret not in denied.get_data(as_text=True)


# ===================================================================
# H2: certificate expiry and CA rotation
# ===================================================================

class TestCertificateLifetime:
    def test_expired_certificate_keeps_standard_recovery(
        self, app, client, master_key, expired_signer
    ) -> None:
        seal = _seal("S-20260927-Q00001", master_key, expired_signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        row = _last(app, seal.seal_id, "standard")
        assert (row["outcome"], row["policy_status"]) == ("released",
                                                         "expired")
        assert row["policy_digest"] == seal.policy_digest.hex()

    def test_expired_certificate_still_enforces_the_signed_unlock_time(
        self, app, client, master_key, expired_signer
    ) -> None:
        seal = _seal("S-20260927-Q00002", master_key, expired_signer,
                     unlock_delta=timedelta(days=2))
        record = {**seal.record, "unlock_time_iso": "2020-01-01T00:00:00Z"}
        sync_seal(client, app, seal, record=record)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 403
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "standard")
        assert (row["reason"], row["policy_status"]) == ("before_unlock",
                                                        "expired")

    def test_expired_certificate_refuses_the_timelock_path(
        self, app, client, master_key, expired_signer, tsa_calls
    ) -> None:
        seal = _seal("S-20260927-Q00003", master_key, expired_signer)
        sync_seal(client, app, seal)

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 403
        assert tsa_calls == []
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "timelock")
        assert (row["reason"], row["policy_status"]) == ("policy_expired",
                                                        "expired")

    # The unsigned outer key_commitment is made to disagree with the signed
    # one in both directions: it neither blocks the right key nor admits a
    # wrong one.
    def test_expired_certificate_admin_override_ignores_the_outer_commitment(
        self, app, client, master_key, expired_signer
    ) -> None:
        seal = _seal("S-20260927-Q00004", master_key, expired_signer)
        record = {**seal.record, "key_commitment": "0" * 64}
        sync_seal(client, app, seal, record=record)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = _admin(client, seal.seal_id)

        assert resp.status_code == 200
        assert seal.key_hex in resp.get_data(as_text=True)
        assert _last(app, seal.seal_id, "admin")["outcome"] == "released"

    def test_expired_certificate_admin_override_checks_the_signed_commitment(
        self, app, client, master_key, expired_signer
    ) -> None:
        seal = _seal("S-20260927-Q00005", master_key, expired_signer)
        stranger = _seal("S-20260927-Q00009", master_key, expired_signer)
        wrong_key = recover_key_for_mode(
            "standard", [stranger.shares[1], seal.shares[3]]
        )
        record = {**seal.record, "key_commitment": hashlib.sha256(
            bytes.fromhex(wrong_key)).hexdigest()}
        sync_seal(client, app, seal, record=record)
        store_share(app, seal.seal_id, 2, stranger.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = _admin(client, seal.seal_id)

        assert resp.status_code == 400
        assert wrong_key not in resp.get_data(as_text=True)
        assert _last(app, seal.seal_id, "admin")["reason"] == (
            "commitment_mismatch"
        )

    def test_expired_certificate_admin_release_is_audited_as_expired(
        self, app, client, master_key, expired_signer
    ) -> None:
        seal = _seal("S-20260927-Q00006", master_key, expired_signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = _admin(client, seal.seal_id)

        assert resp.status_code == 200
        row = _last(app, seal.seal_id, "admin")
        assert (row["outcome"], row["policy_status"]) == ("released",
                                                         "expired")

    def test_ca_bundle_keeps_a_rotated_anchor(
        self, tmp_path, monkeypatch, release_pki, release_tsa, master_key
    ) -> None:
        bundle = write_ca_bundle(release_pki, tmp_path / "ca_bundle.pem")
        app = _app(tmp_path, monkeypatch, release_pki, release_tsa,
                   master_key, ca_cert_path=str(bundle))
        client = app.test_client()
        old = _seal("S-20260927-Q00007", master_key,
                    load_test_signer(release_pki, other_ca=True))
        new = _seal("S-20260927-Q00008", master_key,
                    load_test_signer(release_pki))
        for seal in (old, new):
            sync_seal(client, app, seal)
            store_share(app, seal.seal_id, 1, seal.shares[0])
            store_share(app, seal.seal_id, 2, seal.shares[1])

            resp = recover_standard(client, seal)

            assert resp.status_code == 302
            assert _last(app, seal.seal_id, "standard")["policy_status"] == (
                "verified"
            )


# ===================================================================
# H3: explicit share selection on the standard and admin paths
# ===================================================================

class TestShareSelection:
    def test_standard_path_refuses_s2_plus_s4(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-R00001", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = recover_standard(client, seal)

        assert resp.status_code == 400
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "standard")
        assert (row["outcome"], row["reason"]) == ("denied",
                                                   "owner_share_missing")

    def test_standard_path_refuses_s2_plus_s4_on_a_legacy_record(
        self, app, client, master_key
    ) -> None:
        seal = _seal("S-20260927-R00002", master_key, None)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = recover_standard(client, seal)

        assert resp.status_code == 400
        assert recovered_key(client, seal.seal_id) is None
        assert _last(app, seal.seal_id, "standard")["reason"] == (
            "owner_share_missing"
        )

    def test_standard_path_refuses_a_mislabelled_owner_slot(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-R00003", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[3])
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 400
        assert recovered_key(client, seal.seal_id) is None
        assert _last(app, seal.seal_id, "standard")["reason"] == (
            "owner_share_malformed"
        )

    def test_standard_release_records_the_share_indices(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-R00004", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        # Stage F (F1): the stored share's generation follows the slots.
        assert _last(app, seal.seal_id, "standard")["detail"] == (
            "shares=1+2; share 1 of generation 0")

    def test_admin_slot_must_hold_an_index_4_share(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-R00005", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[0])

        resp = _admin(client, seal.seal_id)

        assert resp.status_code == 400
        assert seal.key_hex not in resp.get_data(as_text=True)
        assert _last(app, seal.seal_id, "admin")["reason"] == (
            "admin_share_malformed"
        )

    def test_admin_other_slot_must_hold_its_own_index(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-R00006", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = _admin(client, seal.seal_id)

        assert resp.status_code == 400
        assert seal.key_hex not in resp.get_data(as_text=True)
        assert _last(app, seal.seal_id, "admin")["reason"] == (
            "other_share_malformed"
        )

    def test_admin_release_records_the_share_indices(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-R00007", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 2, seal.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = _admin(client, seal.seal_id)

        assert resp.status_code == 200
        # Stage F (F1): the stored shares' generations follow the slots.
        assert _last(app, seal.seal_id, "admin")["detail"] == (
            "shares=2+4; share 2 of generation 0, share 4 of generation 0")


# ===================================================================
# H4: policy stripping through the unauthenticated sync route
# ===================================================================

class TestPolicyStripping:
    def _enrolled(self, app, client, master_key, signer, seal_id: str):
        """A policy-bearing seal whose signed unlock time is tomorrow."""
        seal = _seal(seal_id, master_key, signer,
                     unlock_delta=timedelta(days=1))
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])
        return seal

    def test_stripped_record_is_refused_at_sync_for_an_enrolled_seal(
        self, app, client, master_key, signer
    ) -> None:
        seal = self._enrolled(app, client, master_key, signer,
                              "S-20260927-S00001")
        stripped = _stripped(seal, unlock_time_iso="2020-01-01T00:00:00Z")

        resp = client.post("/sync/upload-record", json=sync_payload(
            seal, event_id=2, event_type="Unsealing", record=stripped,
            include_wrapped=False,
        ))

        assert resp.status_code == 409
        with app.app_context():
            from web.models.db_models import find_seal_records_by_seal_id

            assert len(find_seal_records_by_seal_id(seal.seal_id)) == 1
        std = recover_standard(client, seal)
        assert std.status_code == 403
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "standard")
        assert (row["reason"], row["policy_status"]) == ("before_unlock",
                                                        "verified")

    def test_stripped_record_stored_out_of_band_is_ignored(
        self, app, client, master_key, signer
    ) -> None:
        seal = self._enrolled(app, client, master_key, signer,
                              "S-20260927-S00002")
        store_record_out_of_band(
            app, seal, event_id=9, event_type="Unsealing",
            record=_stripped(seal, unlock_time_iso="2020-01-01T00:00:00Z"),
        )

        std = recover_standard(client, seal)

        assert std.status_code == 403
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "standard")
        assert (row["reason"], row["policy_status"]) == ("before_unlock",
                                                        "verified")
        assert row["policy_digest"] == seal.policy_digest.hex()

    def test_stripped_record_arriving_before_the_signed_one_is_ignored(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-S00003", master_key, signer,
                     unlock_delta=timedelta(days=1))
        ensure_case(app, seal.seal_id)
        early = client.post("/sync/upload-record", json=sync_payload(
            seal, event_id=9, event_type="Unsealing",
            record=_stripped(seal, unlock_time_iso="2020-01-01T00:00:00Z"),
            include_wrapped=False,
        ))
        assert early.status_code == 200  # not yet enrolled: a legacy row
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

        std = recover_standard(client, seal)

        assert std.status_code == 403
        assert _last(app, seal.seal_id, "standard")["reason"] == (
            "before_unlock"
        )

    def test_stripped_record_cannot_open_the_admin_commitment(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-S00004", master_key, signer)
        stranger = _seal("S-20260927-S00005", master_key, signer)
        sync_seal(client, app, seal)
        store_record_out_of_band(app, seal, event_id=9,
                                 event_type="Unsealing",
                                 record=_stripped(seal))
        store_share(app, seal.seal_id, 2, stranger.shares[1])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = _admin(client, seal.seal_id)

        assert resp.status_code == 400
        row = _last(app, seal.seal_id, "admin")
        assert (row["reason"], row["policy_status"]) == (
            "commitment_mismatch", "verified"
        )

    @pytest.mark.parametrize("variant", ["tamper", "unsigned", "other_seal"])
    def test_record_with_a_failing_policy_is_refused_at_sync(
        self, app, client, master_key, signer, variant: str
    ) -> None:
        seal = _seal("S-20260927-S00006", master_key, signer)
        if variant == "tamper":
            record = {**seal.record, "policy": {**seal.record["policy"],
                                                "seal_mode": "strict"}}
        elif variant == "unsigned":
            record = {k: v for k, v in seal.record.items()
                      if k != "policy_signature"}
        else:
            other = _seal("S-20260927-S00007", master_key, signer)
            record = {**seal.record,
                      **{k: other.record[k] for k in
                         ("policy", "policy_signature", "policy_cert")}}
        ensure_case(app, seal.seal_id)

        resp = client.post("/sync/upload-record",
                           json=sync_payload(seal, record=record))

        assert resp.status_code == 422
        with app.app_context():
            from web.models.db_models import find_seal_records_by_seal_id
            from web.models.release_models import find_latest_wrapped_s3

            assert find_seal_records_by_seal_id(seal.seal_id) == []
            assert find_latest_wrapped_s3(seal.seal_id) is None

    def test_legacy_seal_still_syncs_when_the_switch_is_off(
        self, app, client, master_key
    ) -> None:
        seal = _seal("S-20260927-S00008", master_key, None)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert _last(app, seal.seal_id, "standard")["policy_status"] == (
            "legacy"
        )


class TestRequirePolicySwitch:
    @pytest.fixture()
    def strict_app(self, tmp_path, monkeypatch, release_pki, release_tsa,
                   master_key):
        return _app(tmp_path, monkeypatch, release_pki, release_tsa,
                    master_key, require_policy=True)

    def test_legacy_record_releases_nothing(
        self, strict_app, master_key
    ) -> None:
        client = strict_app.test_client()
        seal = _seal("S-20260927-T00001", master_key, None)
        sync_seal(client, strict_app, seal)
        for index in (1, 2, 4):
            store_share(strict_app, seal.seal_id, index, seal.shares[index - 1])

        std = recover_standard(client, seal)
        adm = _admin(client, seal.seal_id)

        assert (std.status_code, adm.status_code) == (403, 403)
        assert recovered_key(client, seal.seal_id) is None
        assert seal.key_hex not in adm.get_data(as_text=True)
        assert _last(strict_app, seal.seal_id, "standard")["reason"] == (
            "policy_required"
        )
        assert _last(strict_app, seal.seal_id, "admin")["reason"] == (
            "policy_required"
        )

    def test_missing_record_releases_nothing(
        self, strict_app, master_key, signer
    ) -> None:
        client = strict_app.test_client()
        seal = _seal("S-20260927-T00002", master_key, signer)
        ensure_case(strict_app, seal.seal_id)
        store_share(strict_app, seal.seal_id, 1, seal.shares[0])
        store_share(strict_app, seal.seal_id, 2, seal.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 403
        row = _last(strict_app, seal.seal_id, "standard")
        assert (row["reason"], row["policy_status"]) == ("policy_required",
                                                        "record_missing")

    def test_verified_and_expired_policies_still_release(
        self, strict_app, master_key, signer, expired_signer
    ) -> None:
        client = strict_app.test_client()
        for seal_id, who in (("S-20260927-T00003", signer),
                             ("S-20260927-T00004", expired_signer)):
            seal = _seal(seal_id, master_key, who)
            sync_seal(client, strict_app, seal)
            store_share(strict_app, seal.seal_id, 1, seal.shares[0])
            store_share(strict_app, seal.seal_id, 2, seal.shares[1])

            resp = recover_standard(client, seal)

            assert resp.status_code == 302
            assert recovered_key(client, seal.seal_id) == seal.key_hex


class TestEventConflicts:
    """The same (seal_id, event_id) submitted again with different content.

    An authenticated record displaces an unauthenticated one squatting its
    event; any other difference is refused (409) instead of being dropped
    silently. An identical record fills a missing envelope or enrollment
    and otherwise changes nothing; a different envelope is refused.
    """

    def _rows(self, app, seal_id: str) -> list:
        with app.app_context():
            from web.models.db_models import find_seal_records_by_seal_id

            return [json.loads(r["record_json"])
                    for r in find_seal_records_by_seal_id(seal_id)]

    @pytest.mark.parametrize("squatted", ["stripped", "empty"])
    def test_authenticated_record_displaces_a_squatted_event(
        self, app, client, master_key, signer, squatted: str
    ) -> None:
        # "empty" is the re-review's literal case: record_json "{}" at event 1.
        seal = _seal("S-20260927-U00001", master_key, signer,
                     unlock_delta=timedelta(days=1))
        ensure_case(app, seal.seal_id)
        squat_record = (
            _stripped(seal, unlock_time_iso="2020-01-01T00:00:00Z")
            if squatted == "stripped" else {}
        )
        squat = client.post("/sync/upload-record", json=sync_payload(
            seal, record=squat_record, include_wrapped=False,
        ))
        assert squat.status_code == 200  # not yet enrolled: stored as legacy

        resp = client.post("/sync/upload-record", json=sync_payload(seal))

        assert resp.status_code == 200
        assert self._rows(app, seal.seal_id) == [seal.record]
        with app.app_context():
            from web.models.release_models import (
                find_latest_wrapped_s3,
                is_policy_enrolled,
            )

            assert find_latest_wrapped_s3(seal.seal_id) == seal.wrapped_s3
            assert is_policy_enrolled(seal.seal_id)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])
        std = recover_standard(client, seal)
        assert std.status_code == 403
        assert _last(app, seal.seal_id, "standard")["reason"] == "before_unlock"

    def test_differing_resubmission_of_an_authenticated_event_is_refused(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-U00002", master_key, signer)
        sync_seal(client, app, seal)
        changed = {**seal.record, "case_info": {"case_number": "OTHER"}}

        resp = client.post("/sync/upload-record",
                           json=sync_payload(seal, record=changed))

        assert resp.status_code == 409
        assert self._rows(app, seal.seal_id) == [seal.record]

    def test_differing_resubmission_of_a_legacy_event_is_refused(
        self, app, client, master_key
    ) -> None:
        seal = _seal("S-20260927-U00003", master_key, None)
        sync_seal(client, app, seal)
        changed = {**seal.record, "unlock_time_iso": "2020-01-01T00:00:00Z"}

        resp = client.post("/sync/upload-record",
                           json=sync_payload(seal, record=changed))

        assert resp.status_code == 409
        assert self._rows(app, seal.seal_id) == [seal.record]

    def test_identical_resubmission_changes_nothing(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-U00004", master_key, signer)
        sync_seal(client, app, seal)

        resp = client.post("/sync/upload-record", json=sync_payload(seal))

        assert resp.status_code == 200
        assert self._rows(app, seal.seal_id) == [seal.record]
        with app.app_context():
            from web.models.release_models import find_latest_wrapped_s3

            assert find_latest_wrapped_s3(seal.seal_id) == seal.wrapped_s3

    def test_identical_record_with_another_envelope_is_refused(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-U00005", master_key, signer)
        other = _seal("S-20260927-U00006", master_key, signer)
        sync_seal(client, app, seal)

        resp = client.post("/sync/upload-record", json=sync_payload(
            seal, wrapped_s3_b64=other.wrapped_s3_b64,
        ))

        assert resp.status_code == 409
        assert self._rows(app, seal.seal_id) == [seal.record]
        with app.app_context():
            from web.models.release_models import find_latest_wrapped_s3

            assert find_latest_wrapped_s3(seal.seal_id) == seal.wrapped_s3


# ===================================================================
# R1: the standard path requires the presented investigator share too
# ===================================================================

class TestStandardPossession:
    def _ready(self, app, client, seal) -> None:
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

    def test_seal_id_alone_releases_nothing(
        self, app, client, master_key, signer
    ) -> None:
        # Both shares stored and the unlock time passed (the re-review case).
        seal = _seal("S-20260927-V00001", master_key, signer)
        self._ready(app, client, seal)

        resp = post_form(client, STANDARD_URL, {"seal_id": seal.seal_id})

        assert resp.status_code == 400
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "standard")
        assert (row["outcome"], row["reason"], row["policy_status"]) == (
            "denied", "investigator_share_missing", "not_evaluated"
        )

    def test_presented_share_releases_with_the_stored_owner_share(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-V00002", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        # Stage F (F1): the stored share's generation follows the slots.
        assert _last(app, seal.seal_id, "standard")["detail"] == (
            "shares=1+2; share 1 of generation 0")

    def test_occupied_slot_2_does_not_block_the_presented_share(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-V00003", master_key, signer)
        squatter = _seal("S-20260927-V00004", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, squatter.shares[1])

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex

    @pytest.mark.parametrize("variant", ["another_seal", "relabelled_owner"])
    def test_wrong_presented_share_fails_the_commitment(
        self, app, client, master_key, signer, variant: str
    ) -> None:
        seal = _seal("S-20260927-V00005", master_key, signer)
        stranger = _seal("S-20260927-V00006", master_key, signer)
        self._ready(app, client, seal)
        share = (stranger.shares[1] if variant == "another_seal"
                 else "2-" + seal.shares[0].split("-", 1)[1])

        resp = recover_standard(client, seal, share)

        assert resp.status_code == 400
        assert recovered_key(client, seal.seal_id) is None
        assert _last(app, seal.seal_id, "standard")["reason"] == (
            "commitment_mismatch"
        )

    def test_owner_share_in_the_form_is_malformed(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-V00007", master_key, signer)
        self._ready(app, client, seal)

        resp = recover_standard(client, seal, seal.shares[0])

        assert resp.status_code == 400
        assert recovered_key(client, seal.seal_id) is None
        assert _last(app, seal.seal_id, "standard")["reason"] == (
            "investigator_share_malformed"
        )

    @pytest.mark.parametrize("stored", ["record_without_commitment", "no_record"])
    def test_unverifiable_reconstruction_is_never_released(
        self, app, client, master_key, stored: str
    ) -> None:
        # Without a commitment a right s2 cannot be told from a chosen one,
        # and the stored s1 combined with a chosen s2 reveals s1. So even
        # the correct share is refused (the admin path remains).
        seal = _seal("S-20260927-V00008", master_key, None)
        if stored == "no_record":
            ensure_case(app, seal.seal_id)
        else:
            record = {k: v for k, v in seal.record.items()
                      if k != "key_commitment"}
            sync_seal(client, app, seal, record=record, include_wrapped=False)
        store_share(app, seal.seal_id, 1, seal.shares[0])

        for share in ("2-" + "1" * 64, seal.shares[1]):
            resp = recover_standard(client, seal, share)

            assert resp.status_code == 403
            assert recovered_key(client, seal.seal_id) is None
            row = _last(app, seal.seal_id, "standard")
            assert (row["outcome"], row["reason"]) == ("denied",
                                                       "commitment_missing")

    def test_admin_still_recovers_a_record_without_commitment(
        self, app, client, master_key
    ) -> None:
        seal = _seal("S-20260927-V00009", master_key, None)
        record = {k: v for k, v in seal.record.items() if k != "key_commitment"}
        sync_seal(client, app, seal, record=record, include_wrapped=False)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        resp = _admin(client, seal.seal_id)

        assert resp.status_code == 200
        assert seal.key_hex in resp.get_data(as_text=True)
        row = _last(app, seal.seal_id, "admin")
        assert (row["outcome"], row["policy_status"]) == ("released", "legacy")

    @pytest.mark.parametrize("url", [STANDARD_URL, TIMELOCK_URL])
    def test_missing_share_is_refused_before_any_record_is_read(
        self, app, client, master_key, signer, monkeypatch, url: str
    ) -> None:
        from web import release_gate

        seal = _seal("S-20260927-V00010", master_key, signer)
        self._ready(app, client, seal)
        reads: list[str] = []
        monkeypatch.setattr(release_gate, "find_record_jsons_newest_first",
                            lambda seal_id: reads.append(seal_id) or [])

        resp = post_form(client, url, {"seal_id": seal.seal_id})
        unknown = post_form(client, url, {"seal_id": "S-20260927-NOSUCH"})

        assert resp.status_code == unknown.status_code == 400
        assert resp.get_data() == unknown.get_data()
        assert reads == []
        path = "standard" if url == STANDARD_URL else "timelock"
        row = _last(app, seal.seal_id, path)
        assert (row["reason"], row["policy_status"]) == (
            "investigator_share_missing", "not_evaluated"
        )


# ===================================================================
# R2: the second round's regressions (Codex round 3)
# ===================================================================

def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _short_s2_seal(prefix: str, master_key: str, signer: Any):
    """A seal whose s2 has fewer than 64 hex digits (about 6% of splits)."""
    for attempt in range(500):
        seal = _seal(f"{prefix}{attempt:03d}", master_key, signer)
        if len(seal.shares[1]) < 2 + 64:
            return seal
    raise AssertionError("no short s2 in 500 splits")


class TestPresentedShareBounds:
    @pytest.mark.parametrize("url", [STANDARD_URL, TIMELOCK_URL])
    def test_oversized_share_is_malformed_before_any_record_read(
        self, app, client, master_key, signer, monkeypatch, url: str
    ) -> None:
        # A value beyond the scheme's field would make the combiner pick a
        # larger prime, whose output width depends on the stored s1.
        from web import release_gate

        seal = _seal("S-20260927-W10001", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        reads: list[str] = []
        monkeypatch.setattr(release_gate, "find_record_jsons_newest_first",
                            lambda seal_id: reads.append(seal_id) or [])

        resp = post_form(client, url, {"seal_id": seal.seal_id,
                                       "share_data": "2-" + "f" * 80})

        assert resp.status_code == 400
        assert reads == []
        path = "standard" if url == STANDARD_URL else "timelock"
        row = _last(app, seal.seal_id, path)
        assert (row["reason"], row["policy_status"]) == (
            "investigator_share_malformed", "not_evaluated"
        )

    @pytest.mark.parametrize("url", [STANDARD_URL, TIMELOCK_URL])
    def test_short_legitimate_share_still_releases(
        self, app, client, master_key, signer, url: str
    ) -> None:
        seal = _short_s2_seal("S-20260927-W2", master_key, signer)
        sync_seal(client, app, seal)
        store_share(app, seal.seal_id, 1, seal.shares[0])

        resp = post_form(client, url, {"seal_id": seal.seal_id,
                                       "share_data": seal.shares[1]})

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex

    def test_commitment_check_hashes_once_whatever_the_reconstruction(
        self, monkeypatch
    ) -> None:
        from web import release_gate

        real = hashlib.sha256
        calls: list[bytes] = []
        monkeypatch.setattr(release_gate.hashlib, "sha256",
                            lambda data=b"": calls.append(data) or real(data))
        key = "ab" * 32
        commitment = real(bytes.fromhex(key)).hexdigest()
        cases = [(key, True), ("1" + "0" * 64, False),
                 ("1" + "0" * 65, False), ("zz", False)]
        for key_hex, expected in cases:
            calls.clear()

            assert release_gate._commitment_matches(key_hex, commitment) is expected
            assert len(calls) == 1, key_hex
        # An out-of-range value never matches, even the placeholder's digest.
        placeholder = real(bytes(32)).hexdigest()
        assert release_gate._commitment_matches("1" + "0" * 64, placeholder) is False
        assert release_gate._commitment_matches("0" * 64, placeholder) is True


class TestIdenticalResubmission:
    def test_identical_retry_adds_a_missing_envelope(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-W30001", master_key, signer)
        ensure_case(app, seal.seal_id)
        first = client.post("/sync/upload-record",
                            json=sync_payload(seal, include_wrapped=False))

        retry = client.post("/sync/upload-record", json=sync_payload(seal))
        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert (first.status_code, retry.status_code) == (200, 200)
        with app.app_context():
            from web.models.release_models import find_latest_wrapped_s3

            assert find_latest_wrapped_s3(seal.seal_id) == seal.wrapped_s3
        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex

    def test_identical_retry_enrolls_once_a_ca_is_pinned(
        self, tmp_path, monkeypatch, release_pki, release_tsa, master_key,
        signer,
    ) -> None:
        app = _app(tmp_path, monkeypatch, release_pki, release_tsa,
                   master_key, ca_cert_path="")
        client = app.test_client()
        seal = _seal("S-20260927-W30002", master_key, signer)
        sync_seal(client, app, seal)
        app.config["POLICY_CA_CERT_PATH"] = str(release_pki.ca_cert_path)

        retry = client.post("/sync/upload-record", json=sync_payload(seal))

        assert retry.status_code == 200
        with app.app_context():
            from web.models.release_models import is_policy_enrolled

            assert is_policy_enrolled(seal.seal_id)


class TestTypePreservingIdentity:
    @pytest.mark.parametrize("version", [True, 1.0])
    def test_type_changed_copy_does_not_block_the_genuine_record(
        self, tmp_path, monkeypatch, release_pki, release_tsa, master_key,
        signer, version: Any,
    ) -> None:
        # With no CA pinned, a copy whose policy says v=true (or 1.0) is
        # stored as unverifiable; once the CA is pinned it is invalid, and
        # the genuine record (v=1) must still be able to replace it.
        app = _app(tmp_path, monkeypatch, release_pki, release_tsa,
                   master_key, ca_cert_path="")
        client = app.test_client()
        seal = _seal("S-20260927-W40001", master_key, signer)
        ensure_case(app, seal.seal_id)
        copy = {**seal.record, "policy": {**seal.record["policy"], "v": version}}
        squat = client.post("/sync/upload-record", json=sync_payload(
            seal, record=copy, include_wrapped=False))
        assert squat.status_code == 200
        app.config["POLICY_CA_CERT_PATH"] = str(release_pki.ca_cert_path)

        resp = client.post("/sync/upload-record", json=sync_payload(seal))
        store_share(app, seal.seal_id, 1, seal.shares[0])
        std = recover_standard(client, seal)

        assert resp.status_code == 200
        with app.app_context():
            from web.models.release_models import (
                find_record_json_at,
                is_policy_enrolled,
            )

            stored = json.loads(find_record_json_at(seal.seal_id, 1))
            assert _canonical(stored) == _canonical(seal.record)
            assert is_policy_enrolled(seal.seal_id)
        assert std.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex

    def test_reordered_and_reformatted_record_is_the_same(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-W40002", master_key, signer)
        sync_seal(client, app, seal)
        body = sync_payload(seal)
        body["record_json"] = json.dumps(
            dict(reversed(list(seal.record.items()))), indent=2
        )

        resp = client.post("/sync/upload-record", json=body)

        assert resp.status_code == 200
        with app.app_context():
            from web.models.release_models import find_record_json_at

            stored = json.loads(find_record_json_at(seal.seal_id, 1))
            assert _canonical(stored) == _canonical(seal.record)

    @pytest.mark.parametrize("changed", [True, 1.0])
    def test_changed_value_type_is_a_different_record(
        self, app, client, master_key, changed: Any
    ) -> None:
        seal = _seal("S-20260927-W40003", master_key, None)
        sync_seal(client, app, seal, record={**seal.record, "file_count": 1})

        resp = client.post("/sync/upload-record", json=sync_payload(
            seal, record={**seal.record, "file_count": changed},
        ))

        assert resp.status_code == 409


class TestConditionalDisplacement:
    def test_displacement_replaces_only_the_record_it_was_decided_on(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-W50001", master_key, signer)
        store_record_out_of_band(app, seal, record=_stripped(seal))
        with app.app_context():
            from web.models.release_models import (
                find_latest_wrapped_s3,
                find_record_json_at,
                is_policy_enrolled,
                replace_synced_record,
                seal_write_transaction,
            )

            before = find_record_json_at(seal.seal_id, 1)
            change = dict(
                seal_id=seal.seal_id, event_id=1, event_type="Sealing",
                record_json=json.dumps(seal.record), record_pdf=None,
                wrapped_s3=seal.wrapped_s3,
                enrolled_digest=seal.policy_digest.hex(),
            )

            with seal_write_transaction(seal.seal_id):
                stale = replace_synced_record(**change,
                                              expected_record_json="{}")

            assert stale is False
            assert find_record_json_at(seal.seal_id, 1) == before
            assert find_latest_wrapped_s3(seal.seal_id) is None
            assert not is_policy_enrolled(seal.seal_id)
            with seal_write_transaction(seal.seal_id):
                assert replace_synced_record(
                    **change, expected_record_json=before) is True
            assert json.loads(find_record_json_at(seal.seal_id, 1)) == seal.record
            assert is_policy_enrolled(seal.seal_id)


# ===================================================================
# R3: the remaining MEDIUM findings
# ===================================================================

def _write_lock_probe(app, outcomes: list[str]) -> None:
    """Try to take the SQLite write lock from a second connection."""
    import sqlite3

    conn = sqlite3.connect(app.config["SQLITE_PATH"], timeout=0.2)
    try:
        conn.execute("BEGIN IMMEDIATE")
        outcomes.append("acquired")
        conn.rollback()
    except sqlite3.OperationalError as exc:
        outcomes.append("locked" if "locked" in str(exc) else str(exc))
    finally:
        conn.close()


def _probe_during(monkeypatch, app, name: str, outcomes: list[str]) -> None:
    """Run the write-lock probe whenever the sync route calls ``name``."""
    from web.routes import sync as sync_route

    real = getattr(sync_route, name)

    def probing(*args: Any, **kwargs: Any) -> Any:
        _write_lock_probe(app, outcomes)
        return real(*args, **kwargs)

    monkeypatch.setattr(sync_route, name, probing)


class TestSerializedSync:
    def test_admission_is_decided_under_the_write_lock(
        self, app, client, master_key, monkeypatch
    ) -> None:
        # An unsigned record is admitted only if the seal is not enrolled;
        # that read must happen while the submission holds the write lock,
        # or an enrolling submission could commit in between.
        seal = _seal("S-20260927-X00001", master_key, None)
        ensure_case(app, seal.seal_id)
        outcomes: list[str] = []
        _probe_during(monkeypatch, app, "is_policy_enrolled", outcomes)

        resp = client.post("/sync/upload-record", json=sync_payload(seal))

        assert resp.status_code == 200
        assert outcomes == ["locked"]

    def test_resubmission_is_decided_under_the_write_lock(
        self, app, client, master_key, monkeypatch
    ) -> None:
        seal = _seal("S-20260927-X00002", master_key, None)
        sync_seal(client, app, seal)
        outcomes: list[str] = []
        _probe_during(monkeypatch, app, "find_record_at", outcomes)

        resp = client.post("/sync/upload-record", json=sync_payload(
            seal, record={**seal.record, "note": "changed"},
        ))

        assert resp.status_code == 409
        assert outcomes == ["locked"]


class TestLazyHistory:
    def test_release_reads_records_until_the_newest_authentic_one(
        self, app, client, master_key, signer, monkeypatch
    ) -> None:
        from web.models import release_models

        seal = _seal("S-20260927-X00003", master_key, signer)
        unsigned = _stripped(seal)
        for event_id in range(1, 11):
            store_record_out_of_band(app, seal, record=unsigned,
                                     event_id=event_id, event_type="Unsealing")
        # Stage E (E2a): the scan stops early only against the seal's
        # high-water mark, which sync admission of the authentic record
        # sets; without a mark every record is read
        # (test_sync_generations.py::TestGateSelection).
        sync_seal(client, app, seal, event_id=11)
        for event_id in range(12, 15):
            store_record_out_of_band(app, seal, record=unsigned,
                                     event_id=event_id, event_type="Unsealing")
        store_share(app, seal.seal_id, 1, seal.shares[0])
        fetched: list[int] = []
        real = release_models.find_record_json_at
        monkeypatch.setattr(
            release_models, "find_record_json_at",
            lambda seal_id, event_id: fetched.append(event_id)
            or real(seal_id, event_id),
        )

        resp = recover_standard(client, seal)

        assert resp.status_code == 302
        assert fetched == [14, 13, 12, 11]


class TestEnrollmentBackfill:
    def test_release_on_an_authenticated_record_enrolls_the_seal(
        self, app, client, master_key, signer
    ) -> None:
        # Stored while no CA was pinned (or before enrollment existed): the
        # first release that authenticates it enrolls the seal, so removing
        # the CA later cannot reopen the unauthenticated fallback.
        seal = _seal("S-20260927-X00004", master_key, signer)
        store_record_out_of_band(app, seal, wrapped_s3=seal.wrapped_s3)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 4, seal.shares[3])

        first = recover_standard(client, seal)
        with app.app_context():
            from web.models.release_models import is_policy_enrolled

            enrolled = is_policy_enrolled(seal.seal_id)
        app.config["POLICY_CA_CERT_PATH"] = ""
        std = recover_standard(client, seal)
        tl = _request_s3(client, seal.seal_id, seal.shares[1])
        adm = _admin(client, seal.seal_id)

        assert first.status_code == 302
        assert enrolled
        assert (std.status_code, tl.status_code, adm.status_code) == (
            403, 403, 403)
        for path in ("standard", "timelock", "admin"):
            row = _last(app, seal.seal_id, path)
            assert (row["reason"], row["policy_status"]) == (
                "policy_unverifiable", "unverifiable"), path


# ===================================================================
# R4: Fable re-review of dcb8a33, findings 2 and 8
# ===================================================================

def _replay(client, seal, event_id: int, wrapped_s3: bytes) -> Any:
    """Post the seal's own signed record under another event, with a field
    outside the signed policy changed.

    An exact copy is refused since the Fable gate fix for finding 1; this
    variant still authenticates, so with ``SYNC_REQUIRE_SIGNATURE`` off
    sync admits it with its envelope.
    """
    body = sync_payload(
        seal, event_id=event_id, record=replayed(seal, event_id),
        wrapped_s3_b64=base64.b64encode(wrapped_s3).decode("ascii"),
    )
    return client.post("/sync/upload-record", json=body)


class TestEnvelopeSelection:
    def test_replayed_record_with_a_malformed_envelope_does_not_block(
        self, app, client, master_key, signer
    ) -> None:
        # Anyone who read the signed record can post a variant of it under a
        # higher event; it authenticates, so sync admits it with its envelope
        # while SYNC_REQUIRE_SIGNATURE is off.
        seal = _seal("S-20260927-Y00001", master_key, signer)
        sync_seal(client, app, seal)
        replay = _replay(client, seal, 99, os.urandom(64))

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert replay.status_code == 200
        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        row = _last(app, seal.seal_id, "timelock")
        assert row["outcome"] == "released"
        assert "1 envelope(s) that do not authenticate skipped" in row["detail"]

    def test_envelope_wrapped_for_another_policy_is_skipped(
        self, app, client, master_key, signer
    ) -> None:
        # A well-formed envelope of the same seal, bound to another policy
        # digest: its GCM tag fails under the chosen policy.
        seal = _seal("S-20260927-Y00002", master_key, signer)
        other = _seal("S-20260927-Y00002", master_key, signer,
                      unlock_delta=timedelta(days=-2))
        sync_seal(client, app, seal)
        replay = _replay(client, seal, 99, other.wrapped_s3)

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert other.policy_digest != seal.policy_digest
        assert replay.status_code == 200
        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex

    def test_no_authenticating_envelope_denies(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-Y00003", master_key, signer)
        sync_seal(client, app, seal,
                  wrapped_s3_b64=base64.b64encode(os.urandom(64)).decode("ascii"))

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 403
        assert recovered_key(client, seal.seal_id) is None
        assert _last(app, seal.seal_id, "timelock")["reason"] == (
            "s3_unwrap_failed"
        )


class TestUniformStandardDenials:
    @staticmethod
    def _strict_claim(app, client, master_key, seal_id: str, digits: int):
        # A never-enrolled seal takes unauthenticated records: here one that
        # claims strict mode and carries a commitment, so the stored standard
        # s1 goes through the strict recombiner, which needs 64 hex digits.
        seal = _seal(seal_id, master_key, None)
        record = {**seal.record, "seal_mode": "strict",
                  "key_commitment": "ab" * 32}
        sync_seal(client, app, seal, record=record, include_wrapped=False)
        store_share(app, seal.seal_id, 1, "1-" + "c" * digits)
        return seal

    def test_owner_share_width_does_not_show_in_the_response(
        self, app, client, master_key
    ) -> None:
        full = self._strict_claim(app, client, master_key,
                                  "S-20260927-Y00011", 64)
        short = self._strict_claim(app, client, master_key,
                                   "S-20260927-Y00012", 63)
        chosen = "2-" + "ab" * 32

        a = recover_standard(client, full, chosen)
        b = recover_standard(client, short, chosen)

        # The audit keeps the two causes apart; the requester sees one answer.
        assert _last(app, full.seal_id, "standard")["reason"] == (
            "commitment_mismatch"
        )
        assert _last(app, short.seal_id, "standard")["reason"] == (
            "recovery_failed"
        )
        assert a.status_code == b.status_code == 400
        assert a.get_data(as_text=True) == b.get_data(as_text=True)
        assert recovered_key(client, full.seal_id) is None
        assert recovered_key(client, short.seal_id) is None


# ===================================================================
# R5: Codex round 6 on ca8ec5a, the two items the R4 fix introduced
# ===================================================================

class TestEnvelopeWork:
    def test_envelopes_are_not_read_before_the_unlock_check(
        self, app, client, master_key, signer, monkeypatch, tsa_calls
    ) -> None:
        # Only the existence of an envelope is checked before the clock and
        # TSA checks; the envelopes themselves are read after them.
        from web import release_gate

        seal = _seal("S-20260927-Z00001", master_key, signer,
                     unlock_delta=timedelta(days=1))
        sync_seal(client, app, seal)
        reads: list[str] = []
        real = release_gate.find_wrapped_s3_newest_first

        def counting(seal_id: str):
            reads.append(seal_id)
            return real(seal_id)

        monkeypatch.setattr(release_gate, "find_wrapped_s3_newest_first", counting)

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 403
        assert _last(app, seal.seal_id, "timelock")["reason"] == "before_unlock"
        assert tsa_calls == []
        assert reads == []

    def test_master_key_is_loaded_once_per_release(
        self, app, client, master_key, signer, monkeypatch
    ) -> None:
        from desktop.crypto import local_kms

        seal = _seal("S-20260927-Z00002", master_key, signer)
        sync_seal(client, app, seal)
        for event_id in (97, 98, 99):
            assert _replay(client, seal, event_id, os.urandom(64)).status_code == 200
        loads: list[str] = []
        real = local_kms._load_master_key

        def counting(path: str) -> bytes:
            loads.append(path)
            return real(path)

        monkeypatch.setattr(local_kms, "_load_master_key", counting)

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        # Stage E, E3b: reading the encrypted records also loads the privacy
        # master key (another file, once per request); the release master
        # key is still loaded exactly once.
        privacy_key = app.config["PRIVACY_KMS_MASTER_KEY_PATH"]
        assert loads.count(master_key) == 1 and loads.count(privacy_key) == 1
        assert len(loads) == 2
        assert "3 envelope(s) that do not authenticate skipped" in (
            _last(app, seal.seal_id, "timelock")["detail"]
        )

    def test_unusable_master_key_is_not_counted_as_envelopes(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260927-Z00003", master_key, signer)
        sync_seal(client, app, seal)
        with open(master_key, "wb") as handle:  # present, but not a usable key
            handle.write(b"short")

        resp = _request_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 503
        assert recovered_key(client, seal.seal_id) is None
        row = _last(app, seal.seal_id, "timelock")
        assert row["reason"] == "kms_unavailable"
        assert "envelope" not in row["detail"]
