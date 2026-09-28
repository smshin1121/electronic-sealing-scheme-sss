"""Pinned TSA trust profile for the time-locked release path (stage E, E2b).

A token is accepted only when, besides the stage D checks (nonce echo,
SHA-256 imprint equality, RSA signature), its signer certificate is found
by the SignerInfo sid, is issued directly by a pinned TSA CA, carries a
critical timeStamping-only EKU, is named by an ESS signing-certificate
attribute, and the TSTInfo carries the pinned policy OID and an accuracy.

Each rejection test changes one thing in a token that an independent
validator (pyHanko) accepts, and asserts the stable failure code.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from asn1crypto import cms, core, x509 as asn1_x509

from desktop.signature import tsa_client
from desktop.signature.ca_setup import issue_tsa_cert
from desktop.signature.exceptions import TSAError
from desktop.signature.tsa_profile import (
    TsaTrustProfile,
    check_tsa_certificate,
    check_tsa_leaf_key,
    load_trust_profile,
    load_tsa_ca_certificates,
    verify_trusted_token,
)
from desktop.signature.tsa_client import request_timestamp_trusted
from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID
from tests.fixtures.release_pki import running_tsa, running_unauthorized_endpoint
from tests.fixtures.tsa_forge import (
    CLIENT_AUTH,
    ONE_SECOND,
    TIME_STAMPING,
    TokenSpec,
    der,
    forge_token,
    make_ca,
    make_tsa_cert,
    new_ec_key,
    new_key,
    pem,
)

NONCE = 0x5EED_1234_ABCD


@dataclasses.dataclass(frozen=True)
class Pki:
    """Pinned CA, a production-issued TSA certificate, and an other CA."""

    root: Path
    ca_key: Any
    ca_cert: Any
    ca_path: Path
    tsa_key: Any
    tsa_cert: Any
    other_key: Any
    other_cert: Any
    spare_key: Any

    def profile(self, **changes: Any) -> TsaTrustProfile:
        base = TsaTrustProfile(
            ca_cert_path=str(self.ca_path), policy_oid=DEFAULT_TSA_POLICY_OID
        )
        return dataclasses.replace(base, **changes)

    def spec(self, **changes: Any) -> TokenSpec:
        base = TokenSpec(
            key=self.tsa_key, cert=self.tsa_cert,
            gen_time=datetime.now(timezone.utc).replace(microsecond=0),
            accuracy=ONE_SECOND,
        )
        return dataclasses.replace(base, **changes)

    def leaf(self, **options: Any) -> tuple[Any, Any]:
        """A TSA certificate under the pinned CA (shared spare key)."""
        return make_tsa_cert(self.ca_key, self.ca_cert, key=self.spare_key,
                             **options)

    def write(self, name: str, cert: Any) -> str:
        path = self.root / name
        path.write_bytes(pem(cert))
        return str(path)


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    root = tmp_path_factory.mktemp("tsa_trust_profile")
    # Valid long before any genTime the validity tests use.
    ca_key, ca_cert = make_ca(
        "E2b Pinned TSA CA",
        not_before=datetime.now(timezone.utc) - timedelta(days=365),
    )
    tsa_key, tsa_cert = issue_tsa_cert(ca_key, ca_cert)  # production issuer
    other_key, other_cert = make_ca("E2b Unpinned CA")
    ca_path = root / "tsa_ca.pem"
    ca_path.write_bytes(pem(ca_cert))
    return Pki(root, ca_key, ca_cert, ca_path, tsa_key, tsa_cert,
               other_key, other_cert, new_key())


def _hash() -> bytes:
    return hashlib.sha256(b"E2b release imprint").digest()


def _verify(
    pki: Pki,
    spec: TokenSpec,
    *,
    profile: TsaTrustProfile | None = None,
    at: datetime | None = None,
    **forge: Any,
):
    token = forge_token(spec, data_hash=forge.pop("data_hash", _hash()),
                        nonce=forge.pop("nonce", NONCE), **forge)
    return verify_trusted_token(token, _hash(), NONCE, profile or pki.profile(),
                                at=at)


def _raw_gen_time(text: str) -> core.GeneralizedTime:
    """A GeneralizedTime with exactly this encoding (not normalised)."""
    return core.GeneralizedTime.load(
        bytes([0x18, len(text)]) + text.encode("ascii")
    )


def _rejected(code: str, pki: Pki, spec: TokenSpec, **kwargs: Any) -> TSAError:
    with pytest.raises(TSAError) as info:
        _verify(pki, spec, **kwargs)
    assert info.value.code == code, (info.value.code, str(info.value))
    return info.value


# ===================================================================
# Acceptance
# ===================================================================

class TestAccepted:
    def test_baseline_forged_token_is_valid_for_pyhanko(self, pki: Pki) -> None:
        # The negative cases below each change one thing in this token.
        from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
        from pyhanko_certvalidator import ValidationContext

        token = forge_token(pki.spec(), data_hash=_hash(), nonce=NONCE)
        signed_data = cms.ContentInfo.load(token)["content"]
        context = ValidationContext(
            trust_roots=[asn1_x509.Certificate.load(der(pki.ca_cert))]
        )
        status = asyncio.run(
            validate_tst_signed_data(signed_data, context, lambda _a: _hash())
        )
        assert (status["intact"], status["valid"]) == (True, True)
        assert status["trust_problem_indic"] is None

    def test_valid_token_is_accepted_with_its_accuracy(self, pki: Pki) -> None:
        spec = pki.spec(accuracy={"seconds": 1, "millis": 250, "micros": 5})

        stamp = _verify(pki, spec)

        assert stamp.accuracy == timedelta(seconds=1, milliseconds=250,
                                           microseconds=5)
        assert stamp.gen_time == spec.gen_time
        assert stamp.earliest_gen_time == spec.gen_time - stamp.accuracy
        assert stamp.nonce == NONCE
        assert stamp.policy_oid == DEFAULT_TSA_POLICY_OID
        assert stamp.signer_cert_sha256 == hashlib.sha256(
            der(pki.tsa_cert)
        ).hexdigest()

    def test_ess_v1_signing_certificate_is_accepted(self, pki: Pki) -> None:
        # RFC 3161 compatibility: signingCertificate (SHA-1 ESSCertID).
        assert _verify(pki, pki.spec(ess="v1")).accuracy == timedelta(seconds=1)

    def test_both_ess_attributes_are_accepted_when_both_match(
        self, pki: Pki
    ) -> None:
        assert _verify(pki, pki.spec(ess="both")).accuracy == timedelta(seconds=1)

    @pytest.mark.parametrize("ess_hash", ["sha384", "sha512"])
    def test_stronger_ess_v2_hash_is_accepted(
        self, pki: Pki, ess_hash: str
    ) -> None:
        assert _verify(pki, pki.spec(ess_hash=ess_hash)).gen_time

    def test_sid_by_subject_key_identifier_is_accepted(self, pki: Pki) -> None:
        key, cert = pki.leaf(with_ski=True)
        assert _verify(pki, pki.spec(key=key, cert=cert, sid="ski")).gen_time

    def test_empty_accuracy_is_zero(self, pki: Pki) -> None:
        # All three fields absent: each counts as zero (RFC 3161 2.4.2).
        stamp = _verify(pki, pki.spec(accuracy=b"\x30\x00"))
        assert stamp.accuracy == timedelta(0)

    def test_matching_leaf_pin_is_accepted(self, pki: Pki) -> None:
        pinned = pki.profile(
            leaf_cert_path=pki.write("pin_ok.pem", pki.tsa_cert)
        )
        assert _verify(pki, pki.spec(), profile=pinned).gen_time

    def test_ca_bundle_with_an_extra_anchor_is_accepted(self, pki: Pki) -> None:
        bundle = pki.root / "bundle.pem"
        bundle.write_bytes(pem(pki.other_cert) + pem(pki.ca_cert))
        profile = pki.profile(ca_cert_path=str(bundle))
        assert _verify(pki, pki.spec(), profile=profile).gen_time

    @pytest.mark.parametrize("digest, signature", [
        ("sha256", "rsassa_pkcs1v15"),   # plain rsaEncryption (common form)
        ("sha384", "sha384_rsa"),
        ("sha512", "sha512_rsa"),
        ("sha512", "rsassa_pkcs1v15"),
    ])
    def test_signer_digest_and_signature_algorithms(
        self, pki: Pki, digest: str, signature: str
    ) -> None:
        spec = pki.spec(digest_algorithm=digest, signature_algorithm=signature)
        assert _verify(pki, spec).gen_time

    def test_a_loaded_profile_is_accepted(self, pki: Pki) -> None:
        token = forge_token(pki.spec(), data_hash=_hash(), nonce=NONCE)
        loaded = load_trust_profile(pki.profile())
        assert verify_trusted_token(token, _hash(), NONCE, loaded).gen_time


# ===================================================================
# Chain: sid lookup and direct issuance by a pinned CA
# ===================================================================

class TestChain:
    def test_leaf_issued_by_an_unpinned_ca(self, pki: Pki) -> None:
        key, cert = issue_tsa_cert(pki.other_key, pki.other_cert)
        _rejected("tsa_chain", pki, pki.spec(key=key, cert=cert))

    def test_sid_naming_no_certificate_in_the_token(self, pki: Pki) -> None:
        exc = _rejected("tsa_chain", pki, pki.spec(sid_serial=424242))
        assert "sid" in str(exc)

    def test_token_without_certificates(self, pki: Pki) -> None:
        _rejected("tsa_chain", pki, pki.spec(certificates=()))

    def test_sid_matching_two_certificates(self, pki: Pki) -> None:
        # "certificates" is not signed: an added copy makes the sid ambiguous.
        spec = pki.spec(certificates=(pki.tsa_cert, pki.tsa_cert))
        _rejected("tsa_chain", pki, spec)

    def test_leaf_that_is_a_ca(self, pki: Pki) -> None:
        key, cert = pki.leaf(is_ca=True)
        _rejected("tsa_chain", pki, pki.spec(key=key, cert=cert))

    def test_token_signed_by_the_pinned_ca_itself(self, pki: Pki) -> None:
        # The self-signed anchor "issues itself"; it must not act as a TSA.
        exc = _rejected("tsa_chain", pki,
                        pki.spec(key=pki.ca_key, cert=pki.ca_cert))
        assert "CA certificate" in str(exc)

    def test_self_signed_tsa_certificate(self, pki: Pki) -> None:
        key, cert = make_ca("E2b Self-signed TSA", key=pki.spare_key,
                            is_ca=False)
        _rejected("tsa_chain", pki, pki.spec(key=key, cert=cert))

    def test_leaf_pin_mismatch(self, pki: Pki) -> None:
        _key, other_leaf = pki.leaf()
        pinned = pki.profile(leaf_cert_path=pki.write("pin_x.pem", other_leaf))
        exc = _rejected("tsa_chain", pki, pki.spec(), profile=pinned)
        assert "pinned TSA certificate" in str(exc)


# ===================================================================
# Validity at genTime and at verification time
# ===================================================================

class TestValidity:
    def test_leaf_expired_at_gen_time(self, pki: Pki) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        key, cert = pki.leaf(not_before=now - timedelta(days=10),
                             not_after=now + timedelta(hours=1))
        # The TSA claims a genTime after the certificate's notAfter while
        # the verification time is still inside the validity period.
        spec = pki.spec(key=key, cert=cert, gen_time=now + timedelta(hours=2))
        exc = _rejected("tsa_chain", pki, spec, at=now)
        assert "genTime" in str(exc)

    def test_leaf_expired_at_verification_time(self, pki: Pki) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        key, cert = pki.leaf(not_before=now - timedelta(days=10),
                             not_after=now - timedelta(days=1))
        spec = pki.spec(key=key, cert=cert, gen_time=now - timedelta(days=2))
        exc = _rejected("tsa_chain", pki, spec, at=now)
        assert "verification time" in str(exc)

    def test_leaf_not_yet_valid_at_gen_time(self, pki: Pki) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        key, cert = pki.leaf(not_before=now - timedelta(hours=1))
        spec = pki.spec(key=key, cert=cert, gen_time=now - timedelta(hours=2))
        exc = _rejected("tsa_chain", pki, spec, at=now)
        assert "genTime" in str(exc)

    def test_pinned_ca_expired(self, pki: Pki, tmp_path: Path) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        ca_key, ca_cert = make_ca("E2b Expired CA", key=pki.spare_key,
                                  not_before=now - timedelta(days=30),
                                  not_after=now - timedelta(days=1))
        key, cert = make_tsa_cert(ca_key, ca_cert, key=pki.tsa_key,
                                  not_before=now - timedelta(days=20),
                                  not_after=now + timedelta(days=20))
        ca_path = tmp_path / "expired_ca.pem"
        ca_path.write_bytes(pem(ca_cert))
        profile = pki.profile(ca_cert_path=str(ca_path))
        _rejected("tsa_chain", pki, pki.spec(key=key, cert=cert),
                  profile=profile)


# ===================================================================
# Extended key usage (RFC 3161 section 2.3)
# ===================================================================

class TestExtendedKeyUsage:
    def test_leaf_without_eku(self, pki: Pki) -> None:
        key, cert = pki.leaf(eku=())
        _rejected("tsa_eku", pki, pki.spec(key=key, cert=cert))

    def test_eku_not_critical(self, pki: Pki) -> None:
        key, cert = pki.leaf(eku_critical=False)
        _rejected("tsa_eku", pki, pki.spec(key=key, cert=cert))

    def test_eku_with_an_extra_purpose(self, pki: Pki) -> None:
        key, cert = pki.leaf(eku=(TIME_STAMPING, CLIENT_AUTH))
        _rejected("tsa_eku", pki, pki.spec(key=key, cert=cert))

    def test_eku_without_time_stamping(self, pki: Pki) -> None:
        key, cert = pki.leaf(eku=(CLIENT_AUTH,))
        _rejected("tsa_eku", pki, pki.spec(key=key, cert=cert))

    def test_key_usage_without_signing(self, pki: Pki) -> None:
        key, cert = pki.leaf(signing=False)
        _rejected("tsa_eku", pki, pki.spec(key=key, cert=cert))

    def test_key_usage_with_an_extra_bit(self, pki: Pki) -> None:
        # RFC 5280 4.2.1.12: only digitalSignature and/or nonRepudiation are
        # consistent with id-kp-timeStamping (OpenSSL enforces the same).
        key, cert = pki.leaf(encipherment=True)
        _rejected("tsa_eku", pki, pki.spec(key=key, cert=cert))


# ===================================================================
# ESS signed attributes (RFC 2634 / RFC 5035 / RFC 5816)
# ===================================================================

class TestEssAttributes:
    def test_signed_attributes_absent(self, pki: Pki) -> None:
        _rejected("tsa_ess", pki, pki.spec(ess="no_signed_attrs"))

    def test_signing_certificate_attribute_missing(self, pki: Pki) -> None:
        _rejected("tsa_ess", pki, pki.spec(ess="none"))

    def test_ess_hash_of_another_certificate(self, pki: Pki) -> None:
        _key, other_leaf = pki.leaf()
        _rejected("tsa_ess", pki, pki.spec(ess_cert=other_leaf))

    def test_ess_v1_hash_of_another_certificate(self, pki: Pki) -> None:
        _key, other_leaf = pki.leaf()
        _rejected("tsa_ess", pki, pki.spec(ess="v1", ess_cert=other_leaf))

    def test_ess_issuer_serial_of_another_certificate(self, pki: Pki) -> None:
        _key, other_leaf = pki.leaf()
        _rejected("tsa_ess", pki, pki.spec(ess_issuer_serial_of=other_leaf))

    def test_ess_v2_with_sha1(self, pki: Pki) -> None:
        _rejected("tsa_ess", pki, pki.spec(ess_hash="sha1"))

    def test_content_type_attribute_is_not_tst_info(self, pki: Pki) -> None:
        _rejected("tsa_ess", pki, pki.spec(content_type="data"))

    def test_message_digest_mismatch(self, pki: Pki) -> None:
        _rejected("tsa_ess", pki, pki.spec(message_digest=bytes(32)))

    def test_ess_lists_another_certificate_first(self, pki: Pki) -> None:
        # Only the first ESSCertID names the signer (RFC 2634 5.4).
        _key, other_leaf = pki.leaf()
        _rejected("tsa_ess", pki, pki.spec(ess_leading_cert=other_leaf))

    def test_ess_issuer_name_of_another_issuer(self, pki: Pki) -> None:
        # Right hash and serial, but issuerSerial names another issuer.
        _rejected("tsa_ess", pki, pki.spec(ess_issuer_name_of=pki.other_cert))

    @pytest.mark.parametrize("attribute", [
        "content_type", "message_digest", "signing_certificate_v2",
    ])
    def test_duplicate_signed_attribute_instance(
        self, pki: Pki, attribute: str
    ) -> None:
        exc = _rejected("tsa_ess", pki,
                        pki.spec(duplicate_attribute=attribute))
        assert "exactly once" in str(exc)

    @pytest.mark.parametrize("attribute, ess", [
        ("content_type", "v2"), ("message_digest", "v2"),
        ("signing_certificate_v2", "v2"), ("signing_certificate", "v1"),
    ])
    def test_empty_duplicate_instance(
        self, pki: Pki, attribute: str, ess: str
    ) -> None:
        # Codex round 1, F6: one valid instance plus an empty one of the
        # same type left exactly one value when values were pooled.
        exc = _rejected("tsa_ess", pki, pki.spec(
            ess=ess, empty_duplicate_attribute=attribute))
        assert "exactly once" in str(exc)

    @pytest.mark.parametrize("attribute, ess", [
        ("content_type", "v2"), ("message_digest", "v2"),
        ("signing_certificate_v2", "v2"), ("signing_certificate", "v1"),
    ])
    def test_two_values_in_one_instance(
        self, pki: Pki, attribute: str, ess: str
    ) -> None:
        exc = _rejected("tsa_ess", pki, pki.spec(
            ess=ess, multi_value_attribute=attribute))
        assert "exactly one value" in str(exc)

    def test_baseline_token_has_one_value_per_attribute(self, pki: Pki) -> None:
        # The knobs above change only the named attribute.
        token = forge_token(pki.spec(ess="both"), data_hash=_hash(), nonce=NONCE)
        signer = cms.ContentInfo.load(token)["content"]["signer_infos"][0]
        shape = sorted((a["type"].native, len(a["values"]))
                       for a in signer["signed_attrs"])
        assert shape == [("content_type", 1), ("message_digest", 1),
                         ("signing_certificate", 1),
                         ("signing_certificate_v2", 1)]


# ===================================================================
# Signature, policy, accuracy, structure, binding
# ===================================================================

class TestTokenContent:
    def test_signature_by_another_key(self, pki: Pki) -> None:
        _rejected("tsa_signature", pki, pki.spec(key=pki.spare_key))

    def test_tsa_key_below_2048_bits(self, pki: Pki) -> None:
        key, cert = make_tsa_cert(pki.ca_key, pki.ca_cert, key=new_key(1024))
        _rejected("tsa_signature", pki, pki.spec(key=key, cert=cert))

    def test_tsa_certificate_with_an_ec_key(self, pki: Pki) -> None:
        # The token is signed with an RSA key; the key check comes first.
        _key, cert = make_tsa_cert(pki.ca_key, pki.ca_cert, key=new_ec_key())
        exc = _rejected("tsa_signature", pki,
                        pki.spec(key=pki.spare_key, cert=cert))
        assert "RSA" in str(exc)

    def test_signature_algorithm_not_matching_the_digest(self, pki: Pki) -> None:
        _rejected("tsa_signature", pki,
                  pki.spec(signature_algorithm="sha512_rsa"))

    def test_sha1_digest_algorithm(self, pki: Pki) -> None:
        _rejected("tsa_signature", pki, pki.spec(
            digest_algorithm="sha1", signature_algorithm="rsassa_pkcs1v15"))

    @pytest.mark.parametrize("suffix", ["", "+0900"])
    def test_gen_time_not_in_utc(self, pki: Pki, suffix: str) -> None:
        # RFC 3161 2.4.2: genTime is YYYYMMDDhhmmss[.s...]Z.
        text = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + suffix
        _rejected("tsa_format", pki, pki.spec(gen_time=_raw_gen_time(text)))

    @pytest.mark.parametrize("encoding", [
        "{s}+0000",      # zero offset instead of Z (Codex round 1, F5)
        "{s}-0000",
        "{s}.50Z",       # fraction with a trailing zero
        "{s}.0Z",        # zero fraction written out
        "{s},5Z",        # comma as the decimal sign
        "{m}Z",          # no seconds
        "{h}Z",          # no minutes and seconds
    ])
    def test_gen_time_encodings_rfc_3161_forbids(
        self, pki: Pki, encoding: str
    ) -> None:
        # asn1crypto parses each of these as a UTC time; the verifier checks
        # the encoding itself: YYYYMMDDhhmmss, optional ".fraction" without
        # trailing zeros, then "Z".
        now = datetime.now(timezone.utc)
        text = encoding.format(s=now.strftime("%Y%m%d%H%M%S"),
                               m=now.strftime("%Y%m%d%H%M"),
                               h=now.strftime("%Y%m%d%H"))
        exc = _rejected("tsa_format", pki,
                        pki.spec(gen_time=_raw_gen_time(text)))
        assert "genTime" in str(exc)

    def test_gen_time_with_a_fraction_is_accepted(self, pki: Pki) -> None:
        base = datetime.now(timezone.utc).replace(microsecond=0)
        text = base.strftime("%Y%m%d%H%M%S") + ".5Z"
        stamp = _verify(pki, pki.spec(gen_time=_raw_gen_time(text)))
        assert stamp.gen_time == base + timedelta(milliseconds=500)

    def test_gen_time_beyond_microseconds_is_truncated(self, pki: Pki) -> None:
        # Never rounded up: a later genTime would release earlier.
        base = datetime.now(timezone.utc).replace(microsecond=0)
        text = base.strftime("%Y%m%d%H%M%S") + ".1234567Z"
        stamp = _verify(pki, pki.spec(gen_time=_raw_gen_time(text)))
        assert stamp.gen_time == base + timedelta(microseconds=123456)

    def test_policy_oid_mismatch(self, pki: Pki) -> None:
        exc = _rejected("tsa_policy", pki,
                        pki.spec(policy_oid="1.2.3.4.5.6.7.8.10"))
        assert "1.2.3.4.5.6.7.8.10" in str(exc)

    def test_accuracy_missing(self, pki: Pki) -> None:
        _rejected("tsa_accuracy_missing", pki, pki.spec(accuracy=None))

    @pytest.mark.parametrize("accuracy", [
        {"millis": 0}, {"millis": 1000}, {"micros": 1000}, {"seconds": -1},
    ])
    def test_accuracy_out_of_range(self, pki: Pki, accuracy: dict) -> None:
        _rejected("tsa_accuracy_invalid", pki, pki.spec(accuracy=accuracy))

    def test_two_signer_infos(self, pki: Pki) -> None:
        _rejected("tsa_format", pki, pki.spec(signer_count=2))

    def test_not_a_token(self, pki: Pki) -> None:
        with pytest.raises(TSAError) as info:
            verify_trusted_token(b"\x30\x03\x02\x01\x00", _hash(), NONCE,
                                 pki.profile())
        assert info.value.code == "tsa_format"

    def test_imprint_over_another_hash(self, pki: Pki) -> None:
        exc = _rejected("tsa_imprint", pki, pki.spec(),
                        data_hash=hashlib.sha256(b"other").digest())
        assert "messageImprint" in str(exc)

    def test_imprint_algorithm_not_sha256(self, pki: Pki) -> None:
        _rejected("tsa_imprint", pki, pki.spec(), imprint_alg="sha512")

    def test_stale_nonce(self, pki: Pki) -> None:
        exc = _rejected("tsa_nonce", pki, pki.spec(), nonce=1)
        assert "nonce" in str(exc)


# ===================================================================
# Profile configuration
# ===================================================================

class TestProfileConfiguration:
    def test_missing_ca_file(self, pki: Pki, tmp_path: Path) -> None:
        profile = pki.profile(ca_cert_path=str(tmp_path / "absent.pem"))
        _rejected("tsa_config", pki, pki.spec(), profile=profile)

    def test_ca_file_holding_a_leaf(self, pki: Pki) -> None:
        profile = pki.profile(ca_cert_path=pki.write("leaf_as_ca.pem",
                                                     pki.tsa_cert))
        _rejected("tsa_config", pki, pki.spec(), profile=profile)

    @pytest.mark.parametrize("oid", ["", "1.2.x", "3.1", "1.40.2", "01.2"])
    def test_malformed_policy_oid(self, pki: Pki, oid: str) -> None:
        _rejected("tsa_config", pki, pki.spec(), profile=pki.profile(
            policy_oid=oid))

    def test_unreadable_leaf_pin(self, pki: Pki, tmp_path: Path) -> None:
        profile = pki.profile(leaf_cert_path=str(tmp_path / "absent.pem"))
        _rejected("tsa_config", pki, pki.spec(), profile=profile)

    def test_pinned_ca_with_a_short_rsa_key(self, pki: Pki) -> None:
        _key, short_ca = make_ca("E2b Short-key CA", key=new_key(1024))
        profile = pki.profile(ca_cert_path=pki.write("short_ca.pem", short_ca))
        _rejected("tsa_config", pki, pki.spec(), profile=profile)

    @pytest.mark.parametrize("key_kind", ["ec_p256", "rsa_1024"])
    def test_static_leaf_check_refuses_an_unusable_key(
        self, pki: Pki, key_kind: str
    ) -> None:
        # Codex round 1, F4: start-up (check_tsa_certificate) and run time
        # (the signature check) share one key rule.
        key = new_ec_key() if key_kind == "ec_p256" else new_key(1024)
        _key, cert = make_tsa_cert(pki.ca_key, pki.ca_cert, key=key)
        for check in (lambda: check_tsa_leaf_key(cert),
                      lambda: check_tsa_certificate(cert, [pki.ca_cert])):
            with pytest.raises(TSAError) as info:
                check()
            assert info.value.code == "tsa_signature"

    def test_static_leaf_check_accepts_the_issued_tsa_certificate(
        self, pki: Pki
    ) -> None:
        check_tsa_leaf_key(pki.tsa_cert)
        check_tsa_certificate(pki.tsa_cert, [pki.ca_cert])

    def test_ca_loader_accepts_a_bundle_of_cas(self, pki: Pki) -> None:
        bundle = pki.root / "loader_bundle.pem"
        bundle.write_bytes(pem(pki.ca_cert) + pem(pki.other_cert))
        assert len(load_tsa_ca_certificates(str(bundle))) == 2


# ===================================================================
# End to end against the local TSA server
# ===================================================================

class TestAgainstTheLocalTsa:
    def _profile(self, release_pki: Any, **changes: Any) -> TsaTrustProfile:
        base = TsaTrustProfile(
            ca_cert_path=str(release_pki.ca_cert_path),
            policy_oid=DEFAULT_TSA_POLICY_OID,
        )
        return dataclasses.replace(base, **changes)

    def test_local_tsa_token_is_accepted(self, release_pki, release_tsa) -> None:
        digest = hashlib.sha256(os.urandom(16)).digest()

        stamp = request_timestamp_trusted(
            digest, release_tsa, self._profile(release_pki)
        )

        assert stamp.accuracy == timedelta(seconds=1)
        assert stamp.policy_oid == DEFAULT_TSA_POLICY_OID
        assert abs(stamp.gen_time - datetime.now(timezone.utc)) < timedelta(
            seconds=30
        )

    @pytest.mark.parametrize("micros", [120000, 1, 999999])
    def test_local_tsa_fractional_gen_time_is_accepted(
        self, release_pki, release_tsa, monkeypatch, micros: int
    ) -> None:
        # The server's encoder (asn1crypto) drops trailing zeros, which the
        # strict genTime form requires.
        from desktop.signature import tsa_server

        pinned = datetime.now(timezone.utc).replace(microsecond=micros)
        monkeypatch.setattr(tsa_server, "_utc_now", lambda: pinned)

        stamp = request_timestamp_trusted(
            hashlib.sha256(b"frac").digest(), release_tsa,
            self._profile(release_pki),
        )

        assert stamp.gen_time == pinned

    def test_local_tsa_with_another_policy(self, release_pki) -> None:
        with running_tsa(release_pki.tsa_key_path, release_pki.tsa_cert_path,
                         policy_oid="1.2.3.4.5.6.7.8.10") as url:
            with pytest.raises(TSAError) as info:
                request_timestamp_trusted(
                    hashlib.sha256(b"p").digest(), url,
                    self._profile(release_pki),
                )
        assert info.value.code == "tsa_policy"

    def test_unreachable_tsa(self, release_pki, monkeypatch) -> None:
        monkeypatch.setattr(tsa_client.time, "sleep", lambda _s: None)
        with pytest.raises(TSAError) as info:
            request_timestamp_trusted(
                hashlib.sha256(b"u").digest(), "http://127.0.0.1:1/tsa",
                self._profile(release_pki),
            )
        assert info.value.code == "tsa_transport"

    def test_url_credentials_never_reach_the_error_or_the_log(
        self, release_pki, monkeypatch, caplog
    ) -> None:
        # requests renders the URL, userinfo included, into HTTPError text.
        monkeypatch.setattr(tsa_client.time, "sleep", lambda _s: None)
        with running_unauthorized_endpoint() as port, caplog.at_level("DEBUG"):
            with pytest.raises(TSAError) as info:
                request_timestamp_trusted(
                    hashlib.sha256(b"cred").digest(),
                    f"http://tsa-user:Secr3t-Pass@127.0.0.1:{port}/tsa",
                    self._profile(release_pki),
                )
        assert info.value.code == "tsa_transport"
        assert "HTTP 401" in str(info.value)
        for text in (str(info.value), caplog.text):
            assert "Secr3t-Pass" not in text
            assert "tsa-user" not in text

    def test_profile_is_checked_before_contacting_the_tsa(
        self, release_pki, tmp_path: Path, monkeypatch
    ) -> None:
        calls: list[str] = []
        monkeypatch.setattr(tsa_client, "_send_tsq",
                            lambda _q, url: calls.append(url) or b"")
        with pytest.raises(TSAError) as info:
            request_timestamp_trusted(
                hashlib.sha256(b"c").digest(), "http://127.0.0.1:9/tsa",
                self._profile(release_pki,
                              ca_cert_path=str(tmp_path / "none.pem")),
            )
        assert info.value.code == "tsa_config"
        assert calls == []

    def test_legacy_functions_keep_their_signatures(self) -> None:
        import inspect

        assert list(inspect.signature(
            tsa_client.request_timestamp_verified_token
        ).parameters) == ["data_hash", "tsa_url", "tsa_cert_path"]
        assert list(inspect.signature(
            tsa_client.request_timestamp_verified
        ).parameters) == ["data_hash", "tsa_url", "tsa_cert_path"]
        assert list(inspect.signature(
            tsa_client.verify_timestamp
        ).parameters) == ["tst_token", "tsa_cert_path"]
