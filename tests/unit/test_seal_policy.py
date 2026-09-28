"""Authenticated canonical seal policy (stage D, D1).

Pins the shared canonicalize / sign / verify contract used by both the
desktop sealing process and the web release gate:

  - canonical bytes are sort-keyed, compact, UTF-8 JSON of exactly
    ``{v, seal_id, case_no, seal_mode, unlock_time_iso, key_commitment}``
  - a policy verifies only with a certificate issued by the pinned CA
    that carries the dedicated seal-policy EKU, within its validity
  - any tampering, a foreign CA, a wrong EKU, a missing signature or a
    seal_id mismatch is rejected
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from desktop.signature.seal_policy import (
    POLICY_CERT_PATH_ENV,
    POLICY_INVALID,
    POLICY_KEY_PASSWORD_ENV,
    POLICY_KEY_PATH_ENV,
    POLICY_LEGACY,
    POLICY_UNVERIFIABLE,
    POLICY_VERIFIED,
    S3_RELEASE_CONTEXT,
    S3_WRAP_CONTEXT,
    SEAL_POLICY_EKU_OID,
    PolicyError,
    PolicyVerificationError,
    assess_record_policy,
    attach_policy,
    attach_policy_if_configured,
    build_policy,
    canonicalize_policy,
    load_ca_certificate,
    load_policy_signer,
    load_policy_signer_from_env,
    policy_digest,
    policy_from_record,
    release_imprint,
    s3_wrap_aad,
    verify_policy,
)
from tests.fixtures.release_pki import (
    POLICY_KEY_PASSWORD,
    TSA_KEY_PASSWORD,
    load_test_signer,
)

SEAL_ID = "S-20260926-ABC123"
COMMIT = "ab" * 32


def _policy(**overrides: object) -> dict:
    fields = {
        "seal_id": SEAL_ID,
        "case_no": "2026-형제-001",
        "seal_mode": "standard",
        "unlock_time_iso": "2026-10-06T00:00:00Z",
        "key_commitment": COMMIT,
    }
    fields.update(overrides)
    return build_policy(**fields)


def _record(**overrides: object) -> dict:
    record = {
        "seal_id": SEAL_ID,
        "seal_mode": "standard",
        "unlock_time_iso": "2026-10-06T00:00:00Z",
        "key_commitment": COMMIT,
        "case_info": {"case_number": "2026-형제-001"},
    }
    record.update(overrides)
    return record


# ===================================================================
# Canonical form
# ===================================================================

class TestCanonicalForm:
    def test_exact_canonical_bytes(self) -> None:
        policy = _policy()
        expected = json.dumps(
            {
                "v": 1, "seal_id": SEAL_ID, "case_no": "2026-형제-001",
                "seal_mode": "standard",
                "unlock_time_iso": "2026-10-06T00:00:00Z",
                "key_commitment": COMMIT,
            },
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

        assert canonicalize_policy(policy) == expected
        assert canonicalize_policy(policy).startswith(b'{"case_no":"2026-')
        assert "형제".encode("utf-8") in canonicalize_policy(policy)

    def test_insertion_order_does_not_matter(self) -> None:
        policy = _policy()
        reordered = dict(reversed(list(policy.items())))
        assert canonicalize_policy(reordered) == canonicalize_policy(policy)

    def test_digest_is_sha256_of_canonical_bytes(self) -> None:
        policy = _policy()
        assert policy_digest(policy) == hashlib.sha256(
            canonicalize_policy(policy)
        ).digest()

    def test_policy_from_record_extracts_the_signed_fields(self) -> None:
        assert policy_from_record(_record()) == _policy()

    def test_policy_from_record_without_commitment_raises(self) -> None:
        record = _record()
        del record["key_commitment"]
        with pytest.raises(PolicyError):
            policy_from_record(record)

    @pytest.mark.parametrize(
        "mutation",
        [
            {"v": True},
            {"v": 2},
            {"extra": "x"},
            {"seal_mode": "lenient"},
            {"key_commitment": "AB" * 32},
            {"key_commitment": "ab" * 16},
            {"unlock_time_iso": "2026-10-06 00:00:00"},
            {"unlock_time_iso": "2026-13-45T00:00:00Z"},
            {"seal_id": ""},
            {"case_no": ""},
        ],
    )
    def test_schema_violations_are_rejected(self, mutation: dict) -> None:
        bad = {**_policy(), **mutation}
        with pytest.raises(PolicyError):
            canonicalize_policy(bad)


# ===================================================================
# Signing and verification
# ===================================================================

class TestSignAndVerify:
    def test_valid_signature_verifies(self, release_pki) -> None:
        signed = load_test_signer(release_pki).sign(_policy())

        verified = verify_policy(
            signed.policy, signed.signature_b64, signed.cert_pem,
            ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
        )

        assert verified.seal_id == SEAL_ID
        assert verified.seal_mode == "standard"
        assert verified.key_commitment == COMMIT
        assert verified.unlock_time == datetime(
            2026, 10, 6, tzinfo=timezone.utc
        )
        assert verified.canonical == canonicalize_policy(_policy())
        assert verified.digest == hashlib.sha256(verified.canonical).digest()
        assert verified.recheck_digest() is True

    def test_verified_policy_is_immutable(self, release_pki) -> None:
        signed = load_test_signer(release_pki).sign(_policy())
        verified = verify_policy(
            signed.policy, signed.signature_b64, signed.cert_pem,
            ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            verified.seal_mode = "strict"  # type: ignore[misc]

    @pytest.mark.parametrize(
        "field_name, value",
        [
            ("seal_mode", "strict"),
            ("unlock_time_iso", "2020-01-01T00:00:00Z"),
            ("key_commitment", "cd" * 32),
            ("case_no", "2026-other"),
        ],
    )
    def test_tampered_field_is_rejected(
        self, release_pki, field_name: str, value: str
    ) -> None:
        signed = load_test_signer(release_pki).sign(_policy())
        tampered = {**signed.policy, field_name: value}

        with pytest.raises(PolicyVerificationError):
            verify_policy(
                tampered, signed.signature_b64, signed.cert_pem,
                ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
            )

    def test_certificate_from_another_ca_is_rejected(self, release_pki) -> None:
        signed = load_test_signer(release_pki, other_ca=True).sign(_policy())

        with pytest.raises(PolicyVerificationError):
            verify_policy(
                signed.policy, signed.signature_b64, signed.cert_pem,
                ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
            )

    def test_certificate_without_policy_eku_is_rejected(
        self, release_pki
    ) -> None:
        # The TSA certificate is issued by the trusted CA but carries the
        # timeStamping EKU only; a signature made with its key must not be
        # accepted as a seal policy.
        tsa_key = serialization.load_pem_private_key(
            release_pki.tsa_key_path.read_bytes(),
            password=TSA_KEY_PASSWORD.encode("utf-8"),
        )
        canonical = canonicalize_policy(_policy())
        signature = tsa_key.sign(
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        with pytest.raises(PolicyVerificationError, match="EKU"):
            verify_policy(
                _policy(), base64.b64encode(signature).decode("ascii"),
                release_pki.tsa_cert_path.read_text(encoding="utf-8"),
                ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
            )

    def test_seal_id_mismatch_is_rejected(self, release_pki) -> None:
        signed = load_test_signer(release_pki).sign(_policy())
        with pytest.raises(PolicyVerificationError, match="seal_id"):
            verify_policy(
                signed.policy, signed.signature_b64, signed.cert_pem,
                ca_cert=release_pki.ca_cert,
                expected_seal_id="S-20260926-FFFFFF",
            )

    @pytest.mark.parametrize("bad_sig", ["", "not base64!!", "AAAA"])
    def test_malformed_signature_is_rejected(
        self, release_pki, bad_sig: str
    ) -> None:
        signed = load_test_signer(release_pki).sign(_policy())
        with pytest.raises(PolicyVerificationError):
            verify_policy(
                signed.policy, bad_sig, signed.cert_pem,
                ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
            )

    def test_certificate_outside_validity_is_rejected(
        self, release_pki
    ) -> None:
        signed = load_test_signer(release_pki).sign(_policy())
        far_future = datetime.now(tz=timezone.utc) + timedelta(days=365 * 30)
        with pytest.raises(PolicyVerificationError, match="valid"):
            verify_policy(
                signed.policy, signed.signature_b64, signed.cert_pem,
                ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
                at=far_future,
            )

    def test_non_ca_trust_anchor_is_refused(self, release_pki) -> None:
        with pytest.raises(PolicyError):
            load_ca_certificate(release_pki.policy_cert_path)

    def test_trust_anchor_loads(self, release_pki) -> None:
        ca = load_ca_certificate(release_pki.ca_cert_path)
        assert ca.subject == release_pki.ca_cert.subject


# ===================================================================
# Issuing and loading the institutional policy key
# ===================================================================

class TestPolicyCertificate:
    def test_issued_cert_is_dedicated_to_policy_signing(
        self, release_pki
    ) -> None:
        cert = x509.load_pem_x509_certificate(
            release_pki.policy_cert_path.read_bytes()
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert eku.critical is True
        assert list(eku.value) == [SEAL_POLICY_EKU_OID]
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic.value.ca is False
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert usage.value.digital_signature is True
        assert usage.value.key_cert_sign is False
        assert cert.issuer == release_pki.ca_cert.subject
        cert.verify_directly_issued_by(release_pki.ca_cert)
        assert (
            cert.not_valid_after_utc
            <= release_pki.ca_cert.not_valid_after_utc
        )

    def test_signer_refuses_certificate_without_policy_eku(
        self, release_pki
    ) -> None:
        with pytest.raises(PolicyError, match="EKU"):
            load_policy_signer(
                release_pki.tsa_key_path, release_pki.tsa_cert_path,
                TSA_KEY_PASSWORD,
            )

    def test_signer_refuses_key_certificate_mismatch(
        self, release_pki
    ) -> None:
        with pytest.raises(PolicyError):
            load_policy_signer(
                release_pki.policy_key_path,
                release_pki.other_policy_cert_path,
                POLICY_KEY_PASSWORD,
            )

    def test_wrong_password_does_not_leak(self, release_pki) -> None:
        with pytest.raises(PolicyError) as exc_info:
            load_policy_signer(
                release_pki.policy_key_path, release_pki.policy_cert_path,
                "wrong-test-password",
            )
        assert "wrong-test-password" not in str(exc_info.value)


class TestSignerFromEnvironment:
    def test_unset_environment_means_no_signer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in (POLICY_KEY_PATH_ENV, POLICY_CERT_PATH_ENV,
                     POLICY_KEY_PASSWORD_ENV):
            monkeypatch.delenv(name, raising=False)
        assert load_policy_signer_from_env() is None

    def test_partial_configuration_fails_closed(
        self, release_pki, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(POLICY_KEY_PATH_ENV, str(release_pki.policy_key_path))
        monkeypatch.delenv(POLICY_CERT_PATH_ENV, raising=False)
        monkeypatch.setenv(POLICY_KEY_PASSWORD_ENV, POLICY_KEY_PASSWORD)
        with pytest.raises(PolicyError):
            load_policy_signer_from_env()

    def test_missing_password_fails_closed(
        self, release_pki, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(POLICY_KEY_PATH_ENV, str(release_pki.policy_key_path))
        monkeypatch.setenv(
            POLICY_CERT_PATH_ENV, str(release_pki.policy_cert_path)
        )
        monkeypatch.delenv(POLICY_KEY_PASSWORD_ENV, raising=False)
        with pytest.raises(PolicyError):
            load_policy_signer_from_env()

    def test_full_configuration_loads_a_working_signer(
        self, release_pki, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(POLICY_KEY_PATH_ENV, str(release_pki.policy_key_path))
        monkeypatch.setenv(
            POLICY_CERT_PATH_ENV, str(release_pki.policy_cert_path)
        )
        monkeypatch.setenv(POLICY_KEY_PASSWORD_ENV, POLICY_KEY_PASSWORD)
        signer = load_policy_signer_from_env()
        assert signer is not None
        signed = signer.sign(_policy())
        verify_policy(
            signed.policy, signed.signature_b64, signed.cert_pem,
            ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
        )


# ===================================================================
# Attaching the policy to a record
# ===================================================================

class TestAttachPolicy:
    def test_attach_returns_a_new_record(self, release_pki) -> None:
        original = _record()
        snapshot = json.dumps(original, sort_keys=True)

        new_record, signed = attach_policy(
            original, load_test_signer(release_pki)
        )

        assert json.dumps(original, sort_keys=True) == snapshot
        assert new_record is not original
        assert new_record["policy"] == policy_from_record(original)
        assert new_record["policy_signature"] == signed.signature_b64
        assert new_record["policy_cert"] == signed.cert_pem
        assert signed.digest == policy_digest(new_record["policy"])

    def test_without_signer_the_record_stays_legacy(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        for name in (POLICY_KEY_PATH_ENV, POLICY_CERT_PATH_ENV,
                     POLICY_KEY_PASSWORD_ENV):
            monkeypatch.delenv(name, raising=False)
        with caplog.at_level(logging.WARNING):
            record, digest = attach_policy_if_configured(_record())
        assert digest is None
        assert "policy" not in record
        assert any("policy" in r.getMessage() for r in caplog.records)


# ===================================================================
# Classifying a synced record
# ===================================================================

class TestAssessRecordPolicy:
    def _signed_record(self, release_pki) -> dict:
        record, _ = attach_policy(_record(), load_test_signer(release_pki))
        return record

    def test_no_policy_fields_is_legacy(self, release_pki) -> None:
        result = assess_record_policy(
            _record(), ca_cert_path=str(release_pki.ca_cert_path),
            expected_seal_id=SEAL_ID,
        )
        assert result.status == POLICY_LEGACY
        assert result.policy is None

    def test_policy_without_trust_anchor_is_unverifiable(
        self, release_pki
    ) -> None:
        result = assess_record_policy(
            self._signed_record(release_pki), ca_cert_path=None,
            expected_seal_id=SEAL_ID,
        )
        assert result.status == POLICY_UNVERIFIABLE
        assert result.policy is None

    @pytest.mark.parametrize("with_ca", [True, False])
    def test_missing_signature_is_invalid(
        self, release_pki, with_ca: bool
    ) -> None:
        record = self._signed_record(release_pki)
        del record["policy_signature"]
        result = assess_record_policy(
            record,
            ca_cert_path=str(release_pki.ca_cert_path) if with_ca else None,
            expected_seal_id=SEAL_ID,
        )
        assert result.status == POLICY_INVALID

    def test_valid_policy_is_verified(self, release_pki) -> None:
        result = assess_record_policy(
            self._signed_record(release_pki),
            ca_cert_path=str(release_pki.ca_cert_path),
            expected_seal_id=SEAL_ID,
        )
        assert result.status == POLICY_VERIFIED
        assert result.policy is not None
        assert result.policy.seal_id == SEAL_ID

    def test_tampered_policy_is_invalid(self, release_pki) -> None:
        record = self._signed_record(release_pki)
        record["policy"] = {**record["policy"], "seal_mode": "strict"}
        result = assess_record_policy(
            record, ca_cert_path=str(release_pki.ca_cert_path),
            expected_seal_id=SEAL_ID,
        )
        assert result.status == POLICY_INVALID
        assert result.detail

    def test_non_object_policy_is_invalid(self, release_pki) -> None:
        record = self._signed_record(release_pki)
        record["policy"] = "not-an-object"
        result = assess_record_policy(
            record, ca_cert_path=str(release_pki.ca_cert_path),
            expected_seal_id=SEAL_ID,
        )
        assert result.status == POLICY_INVALID

    def test_unreadable_trust_anchor_fails_closed(
        self, release_pki, tmp_path
    ) -> None:
        result = assess_record_policy(
            self._signed_record(release_pki),
            ca_cert_path=str(tmp_path / "missing-ca.pem"),
            expected_seal_id=SEAL_ID,
        )
        assert result.status == POLICY_INVALID


# ===================================================================
# Release bindings (wrap AAD and TSA imprint)
# ===================================================================

class TestReleaseBindings:
    def test_release_imprint_formula(self) -> None:
        digest = hashlib.sha256(b"policy").digest()
        challenge = bytes(range(32))
        assert release_imprint(digest, challenge) == hashlib.sha256(
            S3_RELEASE_CONTEXT + digest + challenge
        ).digest()
        assert S3_RELEASE_CONTEXT == b"ESS-S3-RELEASE-v1"

    def test_release_imprint_depends_on_challenge(self) -> None:
        digest = hashlib.sha256(b"policy").digest()
        assert release_imprint(digest, b"\x00" * 32) != release_imprint(
            digest, b"\x01" * 32
        )

    @pytest.mark.parametrize("digest_len, challenge_len", [(31, 32), (32, 31)])
    def test_release_imprint_requires_32_byte_inputs(
        self, digest_len: int, challenge_len: int
    ) -> None:
        with pytest.raises(PolicyError):
            release_imprint(b"\x00" * digest_len, b"\x00" * challenge_len)

    def test_wrap_aad_binds_seal_and_policy(self) -> None:
        digest = hashlib.sha256(b"policy").digest()
        aad = s3_wrap_aad(SEAL_ID, digest)
        assert aad.startswith(S3_WRAP_CONTEXT)
        assert aad.endswith(digest)
        assert aad != s3_wrap_aad("S-20260926-FFFFFF", digest)
        assert aad != s3_wrap_aad(SEAL_ID, hashlib.sha256(b"other").digest())

    def test_wrap_aad_requires_32_byte_digest(self) -> None:
        with pytest.raises(PolicyError):
            s3_wrap_aad(SEAL_ID, b"short")
