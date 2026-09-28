"""Seal-policy certificate lifecycle (stage D fix round, finding H2).

- A policy whose certificate chain and signature verify, but whose
  certificate (or pinned CA) has since expired, is classified ``expired``
  and keeps its signed values. A certificate not yet valid, a bad
  signature or another seal's policy stays ``invalid``.
- The pinned trust anchor may be a bundle of CA certificates, so a rotated
  CA keeps older policies verifiable; every bundle member must be a CA.
- Sealing refuses a policy whose unlock time does not leave the release
  window inside the signing certificate's validity, so a time lock cannot
  outlive the certificate that authenticates it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from desktop.signature.ca_setup import issue_policy_cert
from desktop.signature.seal_policy import (
    DEFAULT_RELEASE_WINDOW,
    POLICY_EXPIRED,
    POLICY_INVALID,
    POLICY_VERIFIED,
    PolicyCertificateExpired,
    PolicyError,
    PolicySigner,
    PolicyVerificationError,
    assess_record_policy,
    attach_policy,
    build_policy,
    load_ca_certificates,
    verify_policy,
)
from tests.fixtures.release_pki import (
    iso_z,
    load_test_signer,
    make_expired_signer,
    write_ca_bundle,
)

SEAL_ID = "S-20260927-11FE01"
COMMIT = "cd" * 32


def _unlock(days: float) -> str:
    return iso_z(datetime.now(tz=timezone.utc) + timedelta(days=days))


def _policy(**overrides: object) -> dict:
    fields = {
        "seal_id": SEAL_ID,
        "case_no": "2026-TL-LIFE",
        "seal_mode": "standard",
        "unlock_time_iso": _unlock(-1),
        "key_commitment": COMMIT,
    }
    fields.update(overrides)
    return build_policy(**fields)


def _record(**overrides: object) -> dict:
    record = {
        "seal_id": SEAL_ID,
        "seal_mode": "standard",
        "unlock_time_iso": _unlock(-1),
        "key_commitment": COMMIT,
        "case_info": {"case_number": "2026-TL-LIFE"},
    }
    record.update(overrides)
    return record


def _assess(record: dict, ca_path, **kwargs):
    return assess_record_policy(
        record, ca_cert_path=str(ca_path),
        expected_seal_id=kwargs.pop("expected_seal_id", SEAL_ID), **kwargs,
    )


def _signer(pki, *, validity_days: int, **kwargs) -> PolicySigner:
    key, cert = issue_policy_cert(pki.ca_key, pki.ca_cert,
                                  validity_days=validity_days)
    return PolicySigner(
        cert=cert,
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private_key=key,
        **kwargs,
    )


# ===================================================================
# Expired certificates
# ===================================================================

class TestExpiredCertificate:
    def test_expired_certificate_is_classified_expired(self, release_pki) -> None:
        record, signed = attach_policy(_record(), make_expired_signer(release_pki))

        assessment = _assess(record, release_pki.ca_cert_path)

        assert assessment.status == POLICY_EXPIRED
        assert assessment.policy is not None
        assert assessment.policy.digest == signed.digest
        assert assessment.policy.key_commitment == COMMIT
        assert "expired" in assessment.detail

    def test_verify_policy_reports_expiry_with_the_policy(self, release_pki) -> None:
        signed = make_expired_signer(release_pki).sign(_policy())

        with pytest.raises(PolicyCertificateExpired) as info:
            verify_policy(
                signed.policy, signed.signature_b64, signed.cert_pem,
                ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
            )

        assert isinstance(info.value, PolicyVerificationError)
        assert info.value.policy.digest == signed.digest

    def test_expired_certificate_with_a_bad_signature_is_invalid(
        self, release_pki
    ) -> None:
        record, _ = attach_policy(_record(), make_expired_signer(release_pki))
        record = {**record,
                  "policy": {**record["policy"], "seal_mode": "strict"}}

        assert _assess(record, release_pki.ca_cert_path).status == POLICY_INVALID

    def test_expired_certificate_for_another_seal_is_invalid(
        self, release_pki
    ) -> None:
        record, _ = attach_policy(_record(), make_expired_signer(release_pki))

        assessment = _assess(record, release_pki.ca_cert_path,
                             expected_seal_id="S-20260927-0THER1")

        assert assessment.status == POLICY_INVALID
        assert "seal_id" in assessment.detail

    def test_certificate_not_yet_valid_is_invalid(self, release_pki) -> None:
        record, _ = attach_policy(_record(), load_test_signer(release_pki))
        before_issue = datetime.now(tz=timezone.utc) - timedelta(days=30)

        assessment = _assess(record, release_pki.ca_cert_path, at=before_issue)

        assert assessment.status == POLICY_INVALID

    def test_expired_anchor_and_certificate_are_classified_expired(
        self, release_pki
    ) -> None:
        record, _ = attach_policy(_record(), load_test_signer(release_pki))
        far_future = datetime.now(tz=timezone.utc) + timedelta(days=365 * 30)

        assessment = _assess(record, release_pki.ca_cert_path, at=far_future)

        assert assessment.status == POLICY_EXPIRED


# ===================================================================
# Pinned CA bundles (rotation)
# ===================================================================

class TestCaBundle:
    def test_bundle_loads_every_anchor(self, release_pki, tmp_path) -> None:
        bundle = write_ca_bundle(release_pki, tmp_path / "bundle.pem")

        anchors = load_ca_certificates(bundle)

        assert len(anchors) == 2
        assert release_pki.ca_cert.subject in {a.subject for a in anchors}

    def test_bundle_member_that_is_not_a_ca_is_refused(
        self, release_pki, tmp_path
    ) -> None:
        bundle = tmp_path / "mixed.pem"
        bundle.write_bytes(release_pki.ca_cert_path.read_bytes()
                           + release_pki.policy_cert_path.read_bytes())

        with pytest.raises(PolicyError, match="not a CA"):
            load_ca_certificates(bundle)

    def test_empty_bundle_is_refused(self, tmp_path) -> None:
        empty = tmp_path / "empty.pem"
        empty.write_text("", encoding="ascii")

        with pytest.raises(PolicyError):
            load_ca_certificates(empty)

    def test_policies_under_either_anchor_verify(
        self, release_pki, tmp_path
    ) -> None:
        bundle = write_ca_bundle(release_pki, tmp_path / "bundle.pem")
        for signer in (load_test_signer(release_pki),
                       load_test_signer(release_pki, other_ca=True)):
            record, _ = attach_policy(_record(), signer)

            assert _assess(record, bundle).status == POLICY_VERIFIED

    def test_policy_under_an_unlisted_ca_is_invalid(self, release_pki) -> None:
        record, _ = attach_policy(
            _record(), load_test_signer(release_pki, other_ca=True)
        )

        assessment = _assess(record, release_pki.ca_cert_path)

        assert assessment.status == POLICY_INVALID
        assert "pinned CA" in assessment.detail


# ===================================================================
# Sealing-time release window
# ===================================================================

class TestSealingReleaseWindow:
    def test_default_window_is_one_year(self) -> None:
        assert DEFAULT_RELEASE_WINDOW == timedelta(days=365)

    def test_time_lock_outliving_the_certificate_is_refused(
        self, release_pki
    ) -> None:
        signer = _signer(release_pki, validity_days=200)

        with pytest.raises(PolicyError, match="release window"):
            signer.sign(_policy(unlock_time_iso=_unlock(10)))

    def test_time_lock_inside_the_window_is_signed(self, release_pki) -> None:
        signer = _signer(release_pki, validity_days=800)

        signed = signer.sign(_policy(unlock_time_iso=_unlock(10)))

        assert signed.signature_b64

    def test_window_is_configurable(self, release_pki) -> None:
        signer = _signer(release_pki, validity_days=200,
                         release_window=timedelta(days=30))

        assert signer.sign(_policy(unlock_time_iso=_unlock(10))).signature_b64

    def test_loaded_signer_uses_the_default_window(self, release_pki) -> None:
        assert load_test_signer(release_pki).release_window == (
            DEFAULT_RELEASE_WINDOW
        )


# ===================================================================
# Same-key CA renewals in a bundle (order must not matter)
# ===================================================================

def _renewed_ca(pki, *, starts: timedelta, ends: timedelta) -> x509.Certificate:
    """The pinned CA re-issued with the same subject and key, other validity."""
    now = datetime.now(tz=timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(pki.ca_cert.subject)
        .issuer_name(pki.ca_cert.subject)
        .public_key(pki.ca_cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + starts)
        .not_valid_after(now + ends)
    )
    for extension in pki.ca_cert.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    return builder.sign(pki.ca_key, hashes.SHA256())


def _bundle(tmp_path, *certs: x509.Certificate):
    path = tmp_path / "renewal_bundle.pem"
    path.write_bytes(b"".join(
        c.public_bytes(serialization.Encoding.PEM) for c in certs))
    return path


class TestSameKeyRenewal:
    @pytest.mark.parametrize("order", ["expired_first", "current_first",
                                       "future_first"])
    def test_a_current_anchor_wins_whatever_the_order(
        self, release_pki, tmp_path, order: str
    ) -> None:
        expired = _renewed_ca(release_pki, starts=timedelta(days=-20),
                              ends=timedelta(days=-10))
        future = _renewed_ca(release_pki, starts=timedelta(days=10),
                             ends=timedelta(days=20))
        current = release_pki.ca_cert
        certs = {"expired_first": (expired, current),
                 "current_first": (current, expired),
                 "future_first": (future, current)}[order]
        record, _ = attach_policy(_record(), load_test_signer(release_pki))

        assessment = _assess(record, _bundle(tmp_path, *certs))

        assert assessment.status == POLICY_VERIFIED, assessment.detail

    def test_only_an_expired_anchor_is_classified_expired(
        self, release_pki, tmp_path
    ) -> None:
        expired = _renewed_ca(release_pki, starts=timedelta(days=-20),
                              ends=timedelta(days=-10))
        record, _ = attach_policy(_record(), load_test_signer(release_pki))

        assert _assess(record, _bundle(tmp_path, expired)).status == (
            POLICY_EXPIRED)

    def test_only_a_future_anchor_is_invalid(self, release_pki, tmp_path) -> None:
        future = _renewed_ca(release_pki, starts=timedelta(days=10),
                             ends=timedelta(days=20))
        record, _ = attach_policy(_record(), load_test_signer(release_pki))

        assessment = _assess(record, _bundle(tmp_path, future))

        assert assessment.status == POLICY_INVALID
        assert "not yet valid" in assessment.detail
