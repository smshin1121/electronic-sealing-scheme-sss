"""The per-event sync envelope (stage E, E2a).

For every submission the desktop signs a canonical envelope

    {v, context: "ESS-SYNC-EVENT-v1", seal_id, event_id, event_type,
     record_sha256, pdf_sha256, wrapped_s3_sha256, policy_generation,
     sent_at, nonce}

with RSA-PSS/SHA-256 and the institutional seal-policy key (the same key
as the seal policy; the context and disjoint exact key sets separate the
two kinds of signature). The release host verifies the schema, the
signer certificate against its pinned CA bundle (direct issuance, end
entity, digitalSignature, seal-policy EKU, currently valid) and the
signature.

Synthetic material only (test CA from ``release_pki``).
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from desktop.signature.seal_policy import (
    PolicyVerificationError,
    build_policy,
    canonicalize_policy,
    load_ca_certificates,
    verify_policy,
)
from desktop.signature.sync_envelope import (
    SYNC_ENVELOPE_VERSION,
    SYNC_EVENT_CONTEXT,
    SyncEnvelopeError,
    SyncEnvelopeVerificationError,
    build_sync_envelope,
    canonicalize_sync_envelope,
    format_sent_at,
    sha256_hex,
    sign_sync_envelope,
    verify_sync_envelope,
)
from tests.fixtures.release_pki import load_test_signer, make_expired_signer

SEAL_ID = "S-20260928-E2A002"
RECORD_JSON = json.dumps({"seal_id": SEAL_ID, "name": "합성"}, ensure_ascii=False)
PDF = b"%PDF-1.4 synthetic"
WRAPPED = b"\x01" * 60


def _envelope(**overrides: Any) -> dict:
    kwargs: dict[str, Any] = {
        "seal_id": SEAL_ID, "event_id": 1, "event_type": "Sealing",
        "record_json": RECORD_JSON, "record_pdf": PDF, "wrapped_s3": WRAPPED,
        "policy_generation": 1,
    }
    kwargs.update(overrides)
    return build_sync_envelope(**kwargs)


def _anchors(release_pki) -> list:
    return load_ca_certificates(release_pki.ca_cert_path)


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


class TestCanonicalEnvelope:
    def test_fields_and_hashes_over_the_exact_bytes(self) -> None:
        env = _envelope()
        assert set(env) == {
            "v", "context", "seal_id", "event_id", "event_type",
            "record_sha256", "pdf_sha256", "wrapped_s3_sha256",
            "policy_generation", "sent_at", "nonce",
        }
        assert env["v"] == SYNC_ENVELOPE_VERSION == 1
        assert env["context"] == SYNC_EVENT_CONTEXT == "ESS-SYNC-EVENT-v1"
        assert env["record_sha256"] == hashlib.sha256(
            RECORD_JSON.encode("utf-8")).hexdigest()
        assert env["pdf_sha256"] == hashlib.sha256(PDF).hexdigest()
        assert env["wrapped_s3_sha256"] == hashlib.sha256(WRAPPED).hexdigest()
        assert len(env["nonce"]) == 64 and int(env["nonce"], 16) >= 0
        assert env["sent_at"].endswith("Z")

    def test_absent_pdf_and_envelope_hash_to_the_empty_string(self) -> None:
        env = _envelope(record_pdf=None, wrapped_s3=None)
        assert env["pdf_sha256"] == env["wrapped_s3_sha256"] == ""
        assert sha256_hex(None) == ""

    def test_canonical_bytes_are_sorted_and_compact(self) -> None:
        env = _envelope()
        expected = json.dumps(env, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        assert canonicalize_sync_envelope(env) == expected
        assert canonicalize_sync_envelope(env).startswith(
            b'{"context":"ESS-SYNC-EVENT-v1"')

    def test_fresh_nonce_and_time_per_envelope(self) -> None:
        first, second = _envelope(), _envelope()
        assert first["nonce"] != second["nonce"]

    def test_sent_at_format(self) -> None:
        moment = datetime(2026, 9, 28, 1, 2, 3, tzinfo=timezone.utc)
        assert format_sent_at(moment) == "2026-09-28T01:02:03Z"
        assert _envelope(sent_at=moment)["sent_at"] == "2026-09-28T01:02:03Z"

    @pytest.mark.parametrize(
        "mutation",
        [
            {"v": True}, {"v": 2}, {"context": "ESS-SYNC-EVENT-v2"},
            {"extra": 1}, {"event_id": 0}, {"event_id": True},
            {"event_id": 1.0}, {"event_id": 2 ** 31},
            {"event_type": "Opening"}, {"seal_id": ""},
            {"seal_id": "S\n1"}, {"record_sha256": "AB" * 32},
            {"pdf_sha256": "ab" * 16}, {"wrapped_s3_sha256": 7},
            {"policy_generation": -1}, {"policy_generation": True},
            {"sent_at": "2026-09-28 01:02:03"}, {"nonce": "ab" * 8},
            {"nonce": "XY" * 16},
        ],
    )
    def test_schema_violations_are_refused(self, mutation: dict) -> None:
        with pytest.raises(SyncEnvelopeError):
            canonicalize_sync_envelope({**_envelope(), **mutation})

    def test_missing_field_is_refused(self) -> None:
        env = _envelope()
        del env["nonce"]
        with pytest.raises(SyncEnvelopeError):
            canonicalize_sync_envelope(env)


class TestSignAndVerify:
    def test_round_trip(self, release_pki) -> None:
        signed = sign_sync_envelope(_envelope(), load_test_signer(release_pki))
        auth = signed.payload_field()

        verified = verify_sync_envelope(auth, ca_certs=_anchors(release_pki),
                                        at=_now())

        assert set(auth) == {"envelope", "signature", "cert"}
        assert verified.seal_id == SEAL_ID
        assert verified.event_id == 1
        assert verified.event_type == "Sealing"
        assert verified.nonce == auth["envelope"]["nonce"]
        assert verified.policy_generation == 1
        assert verified.sent_at.tzinfo is not None

    def test_a_changed_field_breaks_the_signature(self, release_pki) -> None:
        auth = sign_sync_envelope(
            _envelope(), load_test_signer(release_pki)).payload_field()
        forged = {**auth, "envelope": {**auth["envelope"], "event_id": 2}}
        with pytest.raises(SyncEnvelopeVerificationError):
            verify_sync_envelope(forged, ca_certs=_anchors(release_pki),
                                 at=_now())

    def test_a_certificate_from_another_ca_is_refused(self, release_pki) -> None:
        other = load_test_signer(release_pki, other_ca=True)
        auth = sign_sync_envelope(_envelope(), other).payload_field()
        with pytest.raises(SyncEnvelopeVerificationError):
            verify_sync_envelope(auth, ca_certs=_anchors(release_pki),
                                 at=_now())

    def test_an_expired_certificate_is_refused(self, release_pki) -> None:
        auth = sign_sync_envelope(
            _envelope(), make_expired_signer(release_pki)).payload_field()
        with pytest.raises(SyncEnvelopeVerificationError):
            verify_sync_envelope(auth, ca_certs=_anchors(release_pki),
                                 at=_now())

    def test_a_certificate_without_the_policy_eku_is_refused(
        self, release_pki
    ) -> None:
        # The TSA key and certificate chain to the same CA, but the
        # certificate carries only the timeStamping EKU: a correct
        # signature under it must still be refused.
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from desktop.signature.seal_policy import PolicySigner
        from tests.fixtures.release_pki import TSA_KEY_PASSWORD

        tsa_pem = release_pki.tsa_cert_path.read_text(encoding="ascii")
        tsa_signer = PolicySigner(
            cert=x509.load_pem_x509_certificate(tsa_pem.encode("ascii")),
            cert_pem=tsa_pem,
            private_key=serialization.load_pem_private_key(
                release_pki.tsa_key_path.read_bytes(),
                password=TSA_KEY_PASSWORD.encode("utf-8")),
            release_window=None,
        )
        auth = sign_sync_envelope(_envelope(), tsa_signer).payload_field()
        with pytest.raises(SyncEnvelopeVerificationError, match="EKU"):
            verify_sync_envelope(auth, ca_certs=_anchors(release_pki),
                                 at=_now())

    @pytest.mark.parametrize(
        "auth",
        [None, [], {"envelope": {}}, {"envelope": {}, "signature": "", "cert": ""},
         {"envelope": "x", "signature": "AA==", "cert": "x", "extra": 1}],
    )
    def test_malformed_auth_objects_are_refused(self, release_pki, auth) -> None:
        with pytest.raises(SyncEnvelopeVerificationError):
            verify_sync_envelope(auth, ca_certs=_anchors(release_pki),
                                 at=_now())

    def test_garbage_signature_is_refused(self, release_pki) -> None:
        auth = sign_sync_envelope(
            _envelope(), load_test_signer(release_pki)).payload_field()
        bad = {**auth, "signature": base64.b64encode(b"\0" * 384).decode()}
        with pytest.raises(SyncEnvelopeVerificationError):
            verify_sync_envelope(bad, ca_certs=_anchors(release_pki),
                                 at=_now())

    def test_an_unexpected_certificate_failure_is_a_refusal(
        self, release_pki, monkeypatch
    ) -> None:
        import desktop.signature.sync_envelope as module

        auth = sign_sync_envelope(
            _envelope(), load_test_signer(release_pki)).payload_field()

        def broken(*_args: Any) -> None:
            raise RuntimeError("synthetic library failure")

        monkeypatch.setattr(module, "_issuing_anchors", broken)
        with pytest.raises(SyncEnvelopeVerificationError, match="RuntimeError"):
            verify_sync_envelope(auth, ca_certs=_anchors(release_pki),
                                 at=_now())

    def test_verification_time_outside_the_certificate_is_refused(
        self, release_pki
    ) -> None:
        auth = sign_sync_envelope(
            _envelope(), load_test_signer(release_pki)).payload_field()
        long_ago = datetime(2000, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(SyncEnvelopeVerificationError):
            verify_sync_envelope(auth, ca_certs=_anchors(release_pki),
                                 at=long_ago)


class TestDomainSeparation:
    """The same key signs policies and envelopes; neither passes as the other."""

    def test_a_policy_signature_is_not_an_envelope_signature(
        self, release_pki
    ) -> None:
        signer = load_test_signer(release_pki)
        policy = build_policy(seal_id=SEAL_ID, case_no="2026-TL-001",
                              seal_mode="standard",
                              unlock_time_iso="2026-10-06T00:00:00Z",
                              key_commitment="ab" * 32, generation=1)
        signed_policy = signer.sign(policy)
        auth = {"envelope": dict(policy),
                "signature": signed_policy.signature_b64,
                "cert": signed_policy.cert_pem}
        with pytest.raises(SyncEnvelopeVerificationError):
            verify_sync_envelope(auth, ca_certs=_anchors(release_pki),
                                 at=_now())

    def test_an_envelope_signature_is_not_a_policy_signature(
        self, release_pki
    ) -> None:
        signed = sign_sync_envelope(_envelope(), load_test_signer(release_pki))
        with pytest.raises(PolicyVerificationError):
            verify_policy(signed.envelope, signed.signature_b64,
                          signed.cert_pem, ca_cert=release_pki.ca_cert,
                          expected_seal_id=SEAL_ID)

    def test_the_canonical_forms_cannot_coincide(self) -> None:
        env_bytes = canonicalize_sync_envelope(_envelope())
        policy = build_policy(seal_id=SEAL_ID, case_no="c",
                              seal_mode="standard",
                              unlock_time_iso="2026-10-06T00:00:00Z",
                              key_commitment="ab" * 32, generation=1)
        assert env_bytes.startswith(b'{"context":')
        assert canonicalize_policy(policy).startswith(b'{"case_no":')
        with pytest.raises(Exception):
            canonicalize_policy(json.loads(env_bytes))


def test_sent_at_in_the_future_is_well_formed() -> None:
    later = _now() + timedelta(seconds=30)
    assert _envelope(sent_at=later)["sent_at"] == format_sent_at(later)
