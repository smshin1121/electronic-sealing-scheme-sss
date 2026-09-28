"""Time-locked s3 release through the single release gate (stage D).

End to end over the Flask routes with synthetic material only: a local
RFC 3161 TSA, a test CA with a seal-policy certificate, and a temporary
local-KMS master key. The investigator's s2, entered in the request (a
share stored on the server is not a credential), plus the unwrapped s3
must reproduce the committed key, and only when:

  - the synced record carries a policy signed under the pinned CA for
    this seal_id,
  - a fresh TSA token over SHA-256("ESS-S3-RELEASE-v1" || SHA-256(policy)
    || challenge) verifies (nonce echo, imprint, CMS signature) and its
    genTime is not before the policy's unlock time,
  - the wrapped s3 unwraps under the (seal_id, policy digest) context.

Every other outcome denies, and every attempt leaves an audit row.
Records whose policy fails verification are refused by the sync route
(422); the tests that exercise the gate's own policy checks store them out
of band, as rows the sync route never vetted.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from asn1crypto import cms, tsp

from desktop.crypto.local_kms import init_master_key
from desktop.signature import tsa_client
from desktop.signature.seal_policy import release_imprint
from desktop.signature.tsa_client import (
    request_timestamp_verified_token,
    verify_timestamp,
)
from tests.fixtures.release_pki import (
    load_test_signer,
    make_seal_material,
    tsa_trust_settings,
)
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    make_release_app,
    post_form,
    recover_standard,
    recovered_key,
    store_record_out_of_band,
    store_share,
    sync_payload,
    sync_seal,
)
from tests.fixtures.tsa_proxy import (
    STALE_NONCE,
    counting_transport,
    forwarding_proxy,
    replaying_transport,
)

pytestmark = pytest.mark.integration

TIMELOCK_URL = "/investigator/recover-key-timelock"


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


def _ready(app, client, material, *, owner: bool = False, **sync_kw):
    """Sync the seal and store s2 (and s1 when ``owner``)."""
    sync_seal(client, app, material, **sync_kw)
    store_share(app, material.seal_id, 2, material.shares[1])
    if owner:
        store_share(app, material.seal_id, 1, material.shares[0])


def _post_s3(client, seal_id: str, share: str | None) -> Any:
    """POST the time-locked request; ``share`` is the s2 the requester enters."""
    data = {"seal_id": seal_id}
    if share is not None:
        data["share_data"] = share
    return post_form(client, TIMELOCK_URL, data)


def _refused_then_stored(app, client, material, record, *,
                         wrapped_s3: bytes | None = None) -> None:
    """The sync route refuses the record (422); store it out of band so the
    gate's own policy check is exercised."""
    ensure_case(app, material.seal_id)
    body = sync_payload(material, record=record)
    if wrapped_s3 is not None:
        body["wrapped_s3"] = base64.b64encode(wrapped_s3).decode("ascii")
    refused = client.post("/sync/upload-record", json=body)
    assert refused.status_code == 422, refused.get_json()
    store_record_out_of_band(app, material, record=record,
                             wrapped_s3=wrapped_s3 or material.wrapped_s3)


def _last_audit(app, seal_id: str, path: str = "timelock") -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row for {seal_id}"
    return rows[-1]


def _assert_denied(app, client, seal_id: str, reason: str) -> dict:
    assert recovered_key(client, seal_id) is None
    row = _last_audit(app, seal_id)
    assert row["outcome"] == "denied"
    assert row["reason"] == reason, row
    return row


# ===================================================================
# Happy path (standard and strict)
# ===================================================================

class TestTimelockRelease:
    def test_standard_mode_releases_after_unlock(
        self, app, client, master_key, signer, release_pki, tsa_calls
    ) -> None:
        seal = _seal("S-20260926-A00001", master_key, signer)
        _ready(app, client, seal)

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 302
        assert f"/investigator/recovered/{seal.seal_id}" in resp.headers[
            "Location"
        ]
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        assert len(tsa_calls) == 1

        row = _last_audit(app, seal.seal_id)
        assert row["outcome"] == "released"
        assert row["reason"] == "released"
        assert row["policy_status"] == "verified"
        assert row["policy_digest"] == seal.policy_digest.hex()
        token = base64.b64decode(row["tsa_token"])
        assert row["tsa_token_sha256"] == hashlib.sha256(token).hexdigest()
        gen_time = verify_timestamp(token, str(release_pki.tsa_cert_path))
        assert gen_time == datetime.fromisoformat(row["tsa_gen_time"])

    def test_audited_token_is_independently_checkable(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-A00002", master_key, signer)
        _ready(app, client, seal)
        _post_s3(client, seal.seal_id, seal.shares[1])

        row = _last_audit(app, seal.seal_id)
        content = cms.ContentInfo.load(base64.b64decode(row["tsa_token"]))
        info = tsp.TSTInfo.load(
            content["content"]["encap_content_info"]["content"].parsed.dump()
        )
        expected = release_imprint(
            seal.policy_digest, bytes.fromhex(row["tsa_challenge"])
        )
        assert info["message_imprint"]["hashed_message"].native == expected

    def test_strict_mode_releases_with_owner_share(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-A00003", master_key, signer, mode="strict")
        _ready(app, client, seal, owner=True)

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        assert _last_audit(app, seal.seal_id)["outcome"] == "released"

    def test_strict_mode_without_owner_share_is_denied_before_tsa(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        seal = _seal("S-20260926-A00004", master_key, signer, mode="strict")
        _ready(app, client, seal)

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 400
        assert tsa_calls == []
        _assert_denied(app, client, seal.seal_id, "owner_share_missing")

    def test_missing_investigator_share_is_denied(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        seal = _seal("S-20260926-A00005", master_key, signer)
        sync_seal(client, app, seal)

        resp = _post_s3(client, seal.seal_id, None)

        assert resp.status_code == 400
        assert tsa_calls == []
        _assert_denied(app, client, seal.seal_id, "investigator_share_missing")

    def test_investigator_slot_must_hold_an_index_2_share(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        # The owner's s1 entered as the investigator share would still
        # recombine with s3 (any two SSS shares do), so the path would not
        # be the audited "s2 + s3" release. It is refused up front.
        seal = _seal("S-20260926-A00006", master_key, signer)
        sync_seal(client, app, seal)

        resp = _post_s3(client, seal.seal_id, seal.shares[0])

        assert resp.status_code == 400
        assert tsa_calls == []
        _assert_denied(app, client, seal.seal_id, "investigator_share_malformed")

    def test_get_renders_the_form(self, client) -> None:
        resp = client.get(TIMELOCK_URL)
        assert resp.status_code == 200
        assert 'name="seal_id"' in resp.get_data(as_text=True)


# ===================================================================
# Time conditions
# ===================================================================

class TestTimeCondition:
    def test_local_clock_before_unlock_denies_without_tsa(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        seal = _seal("S-20260926-B00001", master_key, signer,
                     unlock_delta=timedelta(days=1))
        _ready(app, client, seal)

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 403
        assert tsa_calls == []
        _assert_denied(app, client, seal.seal_id, "before_unlock")

    def test_tsa_time_before_unlock_denies(
        self, app, client, master_key, signer, monkeypatch
    ) -> None:
        import web.release_gate as gate

        seal = _seal("S-20260926-B00002", master_key, signer,
                     unlock_delta=timedelta(hours=1))
        _ready(app, client, seal)
        # The server clock is wrong (ahead); only the TSA is trusted.
        monkeypatch.setattr(
            gate, "_utc_now",
            lambda: datetime.now(tz=timezone.utc) + timedelta(hours=2),
        )

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 403
        row = _assert_denied(
            app, client, seal.seal_id, "tsa_time_before_unlock"
        )
        assert row["tsa_token_sha256"]
        assert row["tsa_gen_time"]


# ===================================================================
# Replay and token substitution
# ===================================================================

class TestReplay:
    def test_replayed_earlier_response_is_denied(
        self, app, client, master_key, signer, release_pki, release_tsa,
        monkeypatch,
    ) -> None:
        seal = _seal("S-20260926-C00001", master_key, signer)
        _ready(app, client, seal)
        earlier = request_timestamp_verified_token(
            hashlib.sha256(b"earlier exchange").digest(), release_tsa,
            str(release_pki.tsa_cert_path),
        )
        monkeypatch.setattr(
            tsa_client, "_send_tsq", replaying_transport(earlier.token)
        )

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 503
        _assert_denied(app, client, seal.seal_id, "tsa_failed")

    def test_stale_nonce_is_denied(
        self, app, client, master_key, signer, monkeypatch
    ) -> None:
        seal = _seal("S-20260926-C00002", master_key, signer)
        _ready(app, client, seal)
        monkeypatch.setattr(
            tsa_client, "_send_tsq",
            forwarding_proxy(tsa_client._send_tsq, nonce=STALE_NONCE),
        )

        _post_s3(client, seal.seal_id, seal.shares[1])

        row = _assert_denied(app, client, seal.seal_id, "tsa_failed")
        assert "nonce" in row["detail"]

    def test_token_over_another_imprint_is_denied(
        self, app, client, master_key, signer, monkeypatch
    ) -> None:
        seal = _seal("S-20260926-C00003", master_key, signer)
        _ready(app, client, seal)
        monkeypatch.setattr(
            tsa_client, "_send_tsq",
            forwarding_proxy(
                tsa_client._send_tsq,
                hashed_message=hashlib.sha256(b"other policy").digest(),
            ),
        )

        _post_s3(client, seal.seal_id, seal.shares[1])

        row = _assert_denied(app, client, seal.seal_id, "tsa_failed")
        assert "messageImprint" in row["detail"]


# ===================================================================
# Availability: s3 fails closed, standard recovery is unaffected
# ===================================================================

class TestAvailability:
    @pytest.mark.parametrize(
        "scenario", ["tsa_unconfigured", "tsa_unreachable", "tsa_bad_cert"]
    )
    def test_s3_denied_while_standard_recovery_works(
        self, app, client, master_key, signer, release_pki, monkeypatch,
        scenario: str,
    ) -> None:
        seal = _seal("S-20260926-D00001", master_key, signer)
        _ready(app, client, seal, owner=True)
        if scenario == "tsa_unconfigured":
            app.config["RELEASE_TSA_URL"] = ""
        elif scenario == "tsa_unreachable":
            app.config["RELEASE_TSA_URL"] = "http://127.0.0.1:1/tsa"
            monkeypatch.setattr(tsa_client.time, "sleep", lambda _s: None)
        else:
            app.config["RELEASE_TSA_CERT_PATH"] = str(
                release_pki.other_policy_cert_path
            )

        denied = _post_s3(client, seal.seal_id, seal.shares[1])
        assert denied.status_code == 503
        row = _last_audit(app, seal.seal_id)
        assert row["outcome"] == "denied"
        assert row["reason"] in {"config_missing", "tsa_failed"}
        assert recovered_key(client, seal.seal_id) is None

        standard = recover_standard(client, seal)
        assert standard.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        std_row = _last_audit(app, seal.seal_id, path="standard")
        assert std_row["outcome"] == "released"
        assert std_row["policy_status"] == "verified"

    def test_kms_unconfigured_denies_before_tsa(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        seal = _seal("S-20260926-D00010", master_key, signer)
        _ready(app, client, seal)
        app.config["RELEASE_KMS_MASTER_KEY_PATH"] = ""

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 503
        assert tsa_calls == []
        _assert_denied(app, client, seal.seal_id, "config_missing")

    def test_trust_anchor_unconfigured_denies_an_enrolled_seal(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        # Enrolled while the CA was pinned: removing the anchor must not
        # reopen the v1.0.1 fallback on the unauthenticated record fields.
        seal = _seal("S-20260926-D00011", master_key, signer)
        _ready(app, client, seal, owner=True)
        app.config["POLICY_CA_CERT_PATH"] = ""

        denied = _post_s3(client, seal.seal_id, seal.shares[1])
        assert denied.status_code == 403
        assert tsa_calls == []
        _assert_denied(app, client, seal.seal_id, "policy_unverifiable")

        standard = recover_standard(client, seal)
        assert standard.status_code == 403
        assert recovered_key(client, seal.seal_id) is None
        row = _last_audit(app, seal.seal_id, "standard")
        assert (row["reason"], row["policy_status"]) == (
            "policy_unverifiable", "unverifiable"
        )

    def test_trust_anchor_unconfigured_disables_s3_only_for_unenrolled_seals(
        self, tmp_path, monkeypatch, master_key, signer, tsa_calls
    ) -> None:
        # A host that never pinned a CA stores policy-bearing records as
        # unverifiable (never enrolled): s3 is denied, standard is v1.0.1.
        app = make_release_app(tmp_path, monkeypatch, master_key_path=master_key)
        client = app.test_client()
        seal = _seal("S-20260926-D00012", master_key, signer)
        _ready(app, client, seal, owner=True)

        denied = _post_s3(client, seal.seal_id, seal.shares[1])
        assert denied.status_code == 403
        assert tsa_calls == []
        _assert_denied(app, client, seal.seal_id, "policy_unverifiable")

        standard = recover_standard(client, seal)
        assert standard.status_code == 302
        assert _last_audit(app, seal.seal_id, "standard")["policy_status"] == (
            "unverifiable"
        )


# ===================================================================
# Legacy records
# ===================================================================

class TestLegacyRecords:
    def test_legacy_record_denies_s3_and_keeps_standard(
        self, app, client, master_key, tsa_calls
    ) -> None:
        seal = _seal("S-20260926-E00001", master_key, None)
        _ready(app, client, seal, owner=True)

        denied = _post_s3(client, seal.seal_id, seal.shares[1])
        assert denied.status_code == 403
        assert tsa_calls == []
        row = _assert_denied(app, client, seal.seal_id, "policy_legacy")
        assert row["policy_status"] == "legacy"

        standard = recover_standard(client, seal)
        assert standard.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        std_row = _last_audit(app, seal.seal_id, "standard")
        assert std_row["policy_status"] == "legacy"
        assert std_row["outcome"] == "released"

    def test_no_synced_record_denies_s3(
        self, app, client, master_key, signer
    ) -> None:
        from tests.fixtures.release_web import ensure_case

        seal = _seal("S-20260926-E00002", master_key, signer)
        ensure_case(app, seal.seal_id)
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 403
        _assert_denied(app, client, seal.seal_id, "record_missing")


# ===================================================================
# Policy integrity
# ===================================================================

class TestPolicyIntegrity:
    @pytest.mark.parametrize(
        "field_name, value",
        [
            ("seal_mode", "strict"),
            ("unlock_time_iso", "2020-01-01T00:00:00Z"),
            ("key_commitment", "0" * 64),
        ],
    )
    def test_tampered_policy_is_denied_on_s3_and_standard(
        self, app, client, master_key, signer, field_name: str, value: str
    ) -> None:
        seal = _seal("S-20260926-F00001", master_key, signer)
        record = {**seal.record,
                  "policy": {**seal.record["policy"], field_name: value}}
        _refused_then_stored(app, client, seal, record)
        store_share(app, seal.seal_id, 1, seal.shares[0])
        store_share(app, seal.seal_id, 2, seal.shares[1])

        resp = _post_s3(client, seal.seal_id, seal.shares[1])
        assert resp.status_code == 403
        _assert_denied(app, client, seal.seal_id, "policy_invalid")

        standard = recover_standard(client, seal)
        assert standard.status_code == 403
        assert recovered_key(client, seal.seal_id) is None

    def test_policy_signed_under_another_ca_is_denied(
        self, app, client, master_key, release_pki
    ) -> None:
        foreign = load_test_signer(release_pki, other_ca=True)
        seal = _seal("S-20260926-F00010", master_key, foreign)
        _refused_then_stored(app, client, seal, seal.record)

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 403
        _assert_denied(app, client, seal.seal_id, "policy_invalid")

    def test_missing_signature_is_denied(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-F00011", master_key, signer)
        record = {k: v for k, v in seal.record.items()
                  if k != "policy_signature"}
        _refused_then_stored(app, client, seal, record)

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 403
        row = _assert_denied(app, client, seal.seal_id, "policy_invalid")
        assert row["policy_status"] == "invalid"


# ===================================================================
# Substitution of another seal's policy or wrapped s3
# ===================================================================

class TestSubstitution:
    def test_another_seals_policy_is_denied(
        self, app, client, master_key, signer
    ) -> None:
        target = _seal("S-20260926-G00001", master_key, signer)
        other = _seal("S-20260926-G00002", master_key, signer)
        record = {**target.record,
                  **{k: other.record[k] for k in
                     ("policy", "policy_signature", "policy_cert")}}
        _refused_then_stored(app, client, target, record,
                             wrapped_s3=other.wrapped_s3)
        store_share(app, target.seal_id, 1, target.shares[0])
        store_share(app, target.seal_id, 2, target.shares[1])

        resp = _post_s3(client, target.seal_id, target.shares[1])
        assert resp.status_code == 403
        row = _assert_denied(app, client, target.seal_id, "policy_invalid")
        assert "seal_id" in row["detail"]

        standard = recover_standard(client, target)
        assert standard.status_code == 403

    def test_another_seals_wrapped_s3_is_denied(
        self, app, client, master_key, signer
    ) -> None:
        target = _seal("S-20260926-G00003", master_key, signer)
        other = _seal("S-20260926-G00004", master_key, signer)
        _ready(app, client, target, wrapped_s3_b64=other.wrapped_s3_b64)

        resp = _post_s3(client, target.seal_id, target.shares[1])

        assert resp.status_code == 403
        _assert_denied(app, client, target.seal_id, "s3_unwrap_failed")

    def test_stale_wrapped_s3_after_reseal_is_denied(
        self, app, client, master_key, signer
    ) -> None:
        seal_id = "S-20260926-G00005"
        # Stage E (E2a): a reseal signs the next policy generation; two
        # different policies of one generation are refused at sync.
        sealed = _seal(seal_id, master_key, signer, generation=1)
        resealed = _seal(seal_id, master_key, signer, generation=2)
        sync_seal(client, app, sealed)
        # The resealing record reaches the portal, its wrapped s3 does not.
        sync_seal(client, app, resealed, event_id=3, event_type="Resealing",
                  include_wrapped=False)
        store_share(app, seal_id, 2, resealed.shares[1])

        resp = _post_s3(client, seal_id, resealed.shares[1])

        assert resp.status_code == 403
        _assert_denied(app, client, seal_id, "s3_unwrap_failed")


# ===================================================================
# Audit trail
# ===================================================================

class TestAuditTrail:
    def test_every_attempt_leaves_a_row(
        self, app, client, master_key, signer
    ) -> None:
        seal = _seal("S-20260926-H00001", master_key, signer)
        sync_seal(client, app, seal)

        _post_s3(client, seal.seal_id, None)
        _post_s3(client, seal.seal_id, seal.shares[1])

        rows = audit_rows(app, seal.seal_id)
        assert [r["outcome"] for r in rows] == ["denied", "released"]
        # The share is checked before any record is read: the first attempt
        # carries no policy evaluation.
        assert [(r["policy_status"], r["policy_digest"]) for r in rows] == [
            ("not_evaluated", ""), ("verified", seal.policy_digest.hex())
        ]
        for row in rows:
            assert row["path"] == "timelock"
            assert datetime.fromisoformat(row["created_at"]).tzinfo

    def test_audit_failure_blocks_the_release(
        self, app, client, master_key, signer, monkeypatch
    ) -> None:
        import web.release_gate as gate

        seal = _seal("S-20260926-H00002", master_key, signer)
        _ready(app, client, seal)

        def _broken(*_args: Any, **_kwargs: Any) -> int:
            raise RuntimeError("audit store unavailable")

        monkeypatch.setattr(gate, "insert_release_audit", _broken)

        resp = _post_s3(client, seal.seal_id, seal.shares[1])

        assert resp.status_code == 500
        assert recovered_key(client, seal.seal_id) is None
