"""Authenticated canonical seal policy, shared by desktop and web code.

At sealing (and resealing) the recovery policy of a seal is fixed as

    {"v": 2, "seal_id", "case_no", "seal_mode", "unlock_time_iso",
     "key_commitment", "generation"}

serialized canonically (sorted keys, ``(",", ":")`` separators, UTF-8,
``ensure_ascii=False``) and signed with RSA-PSS/SHA-256 by an
institutional seal-policy key whose certificate is issued by the internal
CA with the dedicated :data:`SEAL_POLICY_EKU_OID`. The record JSON then
carries ``policy`` (the object), ``policy_signature`` (base64) and
``policy_cert`` (PEM).

``generation`` (stage E, E2a) orders the policies of one seal: sealing
signs generation 1 and each reseal the previous generation + 1, so a
release host can refuse an older, validly signed policy replayed later
(rollback). The stage D form without it (``"v": 1``) still verifies and
counts as generation 0. The schema and canonical form live in
:mod:`desktop.signature.policy_schema` and are re-exported here.

A release host pins one or more CA certificates (a bundle, so a rotated CA
keeps older policies verifiable) and uses the policy only after
:func:`verify_policy` (chain, EKU, validity, signature, schema, seal_id)
succeeds. A policy whose chain and signature verify but whose certificate
or anchor has since expired is reported separately
(:class:`PolicyCertificateExpired`, status ``expired``): its values are
authentic, but no trusted signing time shows the signature predates the
expiry, so release paths decide whether to accept it. Sealing refuses a
policy whose unlock time leaves less than :data:`DEFAULT_RELEASE_WINDOW`
before the signing certificate expires. The module also defines the two
release bindings:

  - :func:`s3_wrap_aad` -- associated data binding the wrapped s3 to its
    seal and policy digest;
  - :func:`release_imprint` -- the TSA message imprint
    ``SHA-256(b"ESS-S3-RELEASE-v1" || SHA-256(policy) || challenge)``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Type, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .policy_schema import (  # noqa: F401 (re-exported)
    FIRST_POLICY_GENERATION,
    LEGACY_POLICY_VERSION,
    MAX_POLICY_GENERATION,
    SEAL_POLICY_VERSION,
    PolicyError,
    build_policy,
    canonicalize_policy,
    parse_unlock_time,
    policy_digest,
    policy_from_record,
    policy_generation,
)

logger = logging.getLogger(__name__)

# Dedicated extended key usage of the institutional seal-policy key. The
# OID sits under a UUID-derived arc (ITU-T X.667: 2.25.<uuid-integer>), so
# it is globally unique without a registered enterprise number.
SEAL_POLICY_EKU_OID = x509.ObjectIdentifier(
    "2.25.255006611877951703000563735246775686018.1"
)
S3_RELEASE_CONTEXT = b"ESS-S3-RELEASE-v1"
S3_WRAP_CONTEXT = b"ESS-S3-WRAP-v1"
POLICY_FIELDS = ("policy", "policy_signature", "policy_cert")

POLICY_KEY_PATH_ENV = "ENC_ENVELOPE_POLICY_KEY_PATH"  # public-config-key
POLICY_CERT_PATH_ENV = "ENC_ENVELOPE_POLICY_CERT_PATH"  # public-config-key
POLICY_KEY_PASSWORD_ENV = "ENC_ENVELOPE_POLICY_KEY_PASSWORD"  # public-config-key

# Classification of the policy carried by a synced record.
POLICY_LEGACY = "legacy"            # no policy fields at all
POLICY_UNVERIFIABLE = "unverifiable"  # complete, but no pinned CA configured
POLICY_INVALID = "invalid"          # present but incomplete or failing checks
POLICY_VERIFIED = "verified"        # verified against the pinned CA
POLICY_EXPIRED = "expired"          # verified, but the certificate has expired

# Sealing refuses a policy whose unlock time is later than the signing
# certificate's notAfter minus this window, so the time-locked release
# stays verifiable for at least this long after the unlock time.
DEFAULT_RELEASE_WINDOW = timedelta(days=365)

_DIGEST_LEN = 32
_MIN_RSA_BITS = 2048
_MAX_SIGNATURE_B64_LEN = 4096
_MAX_CERT_PEM_LEN = 16384


class PolicyVerificationError(PolicyError):
    """A presented seal policy failed verification (fail-closed)."""


class PolicyCertificateExpired(PolicyVerificationError):
    """Chain, profile, signature and seal_id verify; the validity has lapsed.

    ``policy`` is the otherwise verified policy. Callers that do not handle
    expiry explicitly see an ordinary verification failure.
    """

    def __init__(self, message: str, policy: "VerifiedPolicy") -> None:
        super().__init__(message)
        self.policy = policy


# ---------------------------------------------------------------------------
# Signing (desktop)
# ---------------------------------------------------------------------------

def _pss() -> padding.PSS:
    """RSA-PSS parameters used for seal policies (SHA-256, MGF1-SHA-256)."""
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH,
    )


@dataclass(frozen=True)
class SignedPolicy:
    """A signed policy ready to be attached to a record."""

    policy: dict[str, Any]
    canonical: bytes
    digest: bytes
    signature_b64: str
    cert_pem: str

    def record_fields(self) -> dict[str, Any]:
        """The three record fields, as a new dict."""
        return {
            "policy": dict(self.policy),
            "policy_signature": self.signature_b64,
            "policy_cert": self.cert_pem,
        }


@dataclass(frozen=True)
class PolicySigner:
    """The institutional seal-policy key and its CA-issued certificate.

    ``release_window`` is how long after the unlock time the certificate
    must remain valid; ``None`` disables the check (historical material).
    """

    cert: x509.Certificate
    cert_pem: str
    private_key: rsa.RSAPrivateKey = field(repr=False)
    release_window: Optional[timedelta] = DEFAULT_RELEASE_WINDOW

    def sign(self, policy: Mapping[str, Any]) -> SignedPolicy:
        """Sign the canonical form of ``policy`` (RSA-PSS, SHA-256).

        Raises:
            PolicyError: If the schema is violated, or the unlock time does
                not leave the release window inside the certificate's
                validity (renew the seal-policy certificate first).
        """
        canonical = canonicalize_policy(policy)
        self._check_release_window(json.loads(canonical)["unlock_time_iso"])
        signature = self.private_key.sign(canonical, _pss(), hashes.SHA256())
        return SignedPolicy(
            policy=json.loads(canonical),
            canonical=canonical,
            digest=hashlib.sha256(canonical).digest(),
            signature_b64=base64.b64encode(signature).decode("ascii"),
            cert_pem=self.cert_pem,
        )

    def _check_release_window(self, unlock_time_iso: str) -> None:
        """Refuse a time lock that would outlive the signing certificate."""
        if self.release_window is None:
            return
        not_after = self.cert.not_valid_after_utc
        if parse_unlock_time(unlock_time_iso) + self.release_window > not_after:
            raise PolicyError(
                f"the seal-policy certificate expires at {not_after.isoformat()}"
                f", less than the release window ({self.release_window.days} "
                f"days) after the unlock time {unlock_time_iso}; renew the "
                "seal-policy certificate before sealing"
            )


def load_policy_signer(
    key_path: str | Path, cert_path: str | Path, password: str
) -> PolicySigner:
    """Load the password-protected policy key and its certificate.

    Raises:
        PolicyError: If a file is unreadable, the password is wrong, the
            key is not RSA >= 2048 bits, the certificate lacks the
            seal-policy EKU, or key and certificate do not match.
    """
    if not password:
        raise PolicyError("policy signing key password is required")
    try:
        key_bytes = Path(key_path).read_bytes()
        cert_bytes = Path(cert_path).read_bytes()
    except OSError as exc:
        raise PolicyError("policy signing credentials are unreadable") from exc
    try:
        key = serialization.load_pem_private_key(
            key_bytes, password=password.encode("utf-8")
        )
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise PolicyError(
            "policy signing key or certificate could not be loaded "
            "(wrong password or malformed PEM)"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < _MIN_RSA_BITS:
        raise PolicyError("policy signing key must be RSA of at least 2048 bits")
    _require_policy_eku(cert, PolicyError)
    cert_key = cert.public_key()
    if not isinstance(cert_key, rsa.RSAPublicKey) or (
        cert_key.public_numbers() != key.public_key().public_numbers()
    ):
        raise PolicyError("policy signing key does not match its certificate")
    return PolicySigner(
        cert=cert,
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private_key=key,
    )


def load_policy_signer_from_env() -> Optional[PolicySigner]:
    """Load the signer configured through the environment, if any.

    Returns:
        ``None`` when neither the key nor the certificate path is set
        (legacy sealing without an authenticated policy).

    Raises:
        PolicyError: On a partial or broken configuration (fail-closed:
            a configured key never silently degrades to legacy).
    """
    key_path = os.environ.get(POLICY_KEY_PATH_ENV, "").strip()
    cert_path = os.environ.get(POLICY_CERT_PATH_ENV, "").strip()
    if not key_path and not cert_path:
        return None
    if not key_path or not cert_path:
        raise PolicyError(
            f"both {POLICY_KEY_PATH_ENV} and {POLICY_CERT_PATH_ENV} must be "
            "set to sign seal policies"
        )
    password = os.environ.get(POLICY_KEY_PASSWORD_ENV, "")
    if not password:
        raise PolicyError(f"{POLICY_KEY_PASSWORD_ENV} is required")
    return load_policy_signer(key_path, cert_path, password)


def attach_policy(
    record: Mapping[str, Any], signer: PolicySigner, *,
    generation: Optional[int] = None,
) -> tuple[dict[str, Any], SignedPolicy]:
    """Return a new record carrying the signed policy of ``record``.

    ``generation`` makes it a version-2 policy; the processes always pass
    one (sealing 1, resealing the previous + 1).
    """
    signed = signer.sign(policy_from_record(record, generation=generation))
    return {**record, **signed.record_fields()}, signed


def attach_policy_if_configured(
    record: Mapping[str, Any], signer: Optional[PolicySigner] = None, *,
    generation: Optional[int] = None,
) -> tuple[dict[str, Any], Optional[bytes]]:
    """Attach a signed policy when a signer is given or configured.

    Returns:
        ``(new_record, policy_digest)``; the digest is ``None`` when no
        policy key is configured (legacy record, warning logged).

    Raises:
        PolicyError: On a broken signer configuration or a record whose
            policy fields are malformed.
    """
    resolved = signer if signer is not None else load_policy_signer_from_env()
    if resolved is None:
        logger.warning(
            "No seal-policy signing key configured (%s / %s): the record "
            "carries no authenticated policy and the time-locked s3 path "
            "will refuse it (legacy record)",
            POLICY_KEY_PATH_ENV, POLICY_CERT_PATH_ENV,
        )
        return dict(record), None
    new_record, signed = attach_policy(record, resolved, generation=generation)
    logger.info(
        "Seal policy signed: seal_id=%s generation=%s policy_digest=%s",
        new_record.get("seal_id"), signed.policy.get("generation", 0),
        signed.digest.hex(),
    )
    return new_record, signed.digest


# ---------------------------------------------------------------------------
# Verification (release host)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VerifiedPolicy:
    """A policy that passed :func:`verify_policy`; immutable by design."""

    seal_id: str
    case_no: str
    seal_mode: str
    unlock_time_iso: str
    unlock_time: datetime
    key_commitment: str
    canonical: bytes
    digest: bytes
    cert_fingerprint: str
    generation: int = 0  # 0 for a version-1 policy

    @property
    def digest_hex(self) -> str:
        """Hex form of the policy digest (audit reference)."""
        return self.digest.hex()

    def recheck_digest(self) -> bool:
        """Recompute SHA-256 over the canonical bytes (constant time)."""
        return hmac.compare_digest(
            hashlib.sha256(self.canonical).digest(), self.digest
        )


@dataclass(frozen=True)
class PolicyAssessment:
    """Classification of the policy carried by a synced record."""

    status: str
    policy: Optional[VerifiedPolicy] = None
    detail: str = ""


def load_ca_certificates(path: str | Path) -> list[x509.Certificate]:
    """Load the pinned policy CA bundle (one or more PEM certificates).

    A bundle lets a release host keep a retired CA pinned next to its
    successor, so policies signed before a rotation stay verifiable.

    Raises:
        PolicyError: If unreadable, empty, or any member is not a
            certificate-signing CA.
    """
    try:
        certs = x509.load_pem_x509_certificates(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise PolicyError("pinned policy CA bundle is unreadable") from exc
    if not certs:
        raise PolicyError("pinned policy CA bundle holds no certificate")
    for cert in certs:
        _require_ca(cert)
    return certs


def load_ca_certificate(path: str | Path) -> x509.Certificate:
    """Load a single pinned policy CA certificate (the first of a bundle).

    Raises:
        PolicyError: As :func:`load_ca_certificates`.
    """
    return load_ca_certificates(path)[0]


def _require_ca(cert: x509.Certificate) -> None:
    """A trust anchor must be a CA allowed to sign certificates."""
    basic = _extension(cert, x509.BasicConstraints)
    usage = _extension(cert, x509.KeyUsage)
    if basic is None or not basic.ca:
        raise PolicyError("pinned policy CA certificate is not a CA")
    if usage is None or not usage.key_cert_sign:
        raise PolicyError("pinned policy CA certificate cannot sign certificates")


def verify_policy(
    policy: Mapping[str, Any],
    signature_b64: str,
    cert_pem: str,
    *,
    ca_cert: Union[x509.Certificate, Sequence[x509.Certificate]],
    expected_seal_id: str,
    at: Optional[datetime] = None,
) -> VerifiedPolicy:
    """Verify a presented policy against the pinned CA(s) (fail-closed).

    Checks, in order: schema and canonical form; the signer certificate is
    issued directly by one of ``ca_cert`` (a certificate or a bundle), is
    an end entity with digitalSignature and the seal-policy EKU; the
    RSA-PSS signature over the canonical bytes; the policy names
    ``expected_seal_id``; finally the certificate and its anchor are
    valid at ``at`` (default: now).

    Raises:
        PolicyCertificateExpired: Every check passed except that the
            certificate or its anchor has expired (carries the policy).
        PolicyVerificationError: On any other failed check, including a
            certificate that is not yet valid.
    """
    moment = at or datetime.now(tz=timezone.utc)
    try:
        canonical = canonicalize_policy(policy)
    except PolicyError as exc:
        raise PolicyVerificationError(f"policy schema: {exc}") from exc
    cert = _load_signer_certificate(cert_pem)
    anchors = [ca_cert] if isinstance(ca_cert, x509.Certificate) else list(ca_cert)
    issuers = _issuing_anchors(cert, anchors)
    _check_certificate_profile(cert)
    _check_signature(cert, _decode_signature(signature_b64), canonical)
    fields = json.loads(canonical)
    if not isinstance(expected_seal_id, str) or fields["seal_id"] != (
        expected_seal_id
    ):
        raise PolicyVerificationError(
            "policy seal_id does not match the requested seal_id"
        )
    verified = VerifiedPolicy(
        seal_id=fields["seal_id"],
        case_no=fields["case_no"],
        seal_mode=fields["seal_mode"],
        unlock_time_iso=fields["unlock_time_iso"],
        unlock_time=parse_unlock_time(fields["unlock_time_iso"]),
        key_commitment=fields["key_commitment"],
        canonical=canonical,
        digest=hashlib.sha256(canonical).digest(),
        cert_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        generation=fields.get("generation", 0),
    )
    _check_validity(cert, issuers, moment, verified)
    return verified


def assess_record_policy(
    record: Mapping[str, Any],
    *,
    ca_cert_path: Optional[str],
    expected_seal_id: str,
    at: Optional[datetime] = None,
) -> PolicyAssessment:
    """Classify the policy of a synced record.

    ``legacy`` when none of the three policy fields is present;
    ``invalid`` when only some are present or verification fails
    (including an unreadable pinned CA bundle); ``unverifiable`` when
    complete but no pinned CA is configured; ``expired`` when everything
    verifies except that the certificate or its anchor has expired (the
    policy is returned); ``verified`` otherwise.
    """
    present = [name for name in POLICY_FIELDS if name in record]
    if not present:
        return PolicyAssessment(POLICY_LEGACY)
    if len(present) != len(POLICY_FIELDS):
        missing = sorted(set(POLICY_FIELDS) - set(present))
        return PolicyAssessment(
            POLICY_INVALID, detail=f"incomplete policy: missing {missing}"
        )
    if not ca_cert_path:
        return PolicyAssessment(
            POLICY_UNVERIFIABLE, detail="no pinned policy CA configured"
        )
    try:
        verified = verify_policy(
            record["policy"], record["policy_signature"],
            record["policy_cert"],
            ca_cert=load_ca_certificates(ca_cert_path),
            expected_seal_id=expected_seal_id, at=at,
        )
    except PolicyCertificateExpired as exc:
        return PolicyAssessment(POLICY_EXPIRED, policy=exc.policy,
                                detail=str(exc))
    except PolicyError as exc:
        return PolicyAssessment(POLICY_INVALID, detail=str(exc))
    return PolicyAssessment(POLICY_VERIFIED, policy=verified)


def _load_signer_certificate(cert_pem: Any) -> x509.Certificate:
    """Parse the signer certificate carried by the record."""
    if not isinstance(cert_pem, str) or not cert_pem or (
        len(cert_pem) > _MAX_CERT_PEM_LEN
    ):
        raise PolicyVerificationError("policy certificate is missing")
    try:
        return x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise PolicyVerificationError(
            "policy certificate is not a PEM certificate"
        ) from exc


def _issuing_anchors(
    cert: x509.Certificate, anchors: Sequence[x509.Certificate]
) -> list[x509.Certificate]:
    """Every pinned CA that directly issued ``cert`` (signature checked).

    A CA renewed with the same subject and key matches more than once;
    :func:`_check_validity` then prefers a currently valid one.
    """
    issuers = []
    for anchor in anchors:
        if cert.issuer != anchor.subject:
            continue
        try:
            cert.verify_directly_issued_by(anchor)
        except (ValueError, TypeError, InvalidSignature):
            continue
        issuers.append(anchor)
    if not issuers:
        raise PolicyVerificationError(
            "policy certificate is not issued by a pinned CA"
        )
    return issuers


def _check_validity(
    cert: x509.Certificate,
    issuers: Sequence[x509.Certificate],
    moment: datetime,
    verified: VerifiedPolicy,
) -> None:
    """Not yet valid is a failure; lapsed validity is reported as expiry.

    Among the matching anchors a currently valid one is used, whatever the
    bundle order; an expired one only when none is current; anchors that
    are all not yet valid fail.
    """
    if moment < cert.not_valid_before_utc:
        raise PolicyVerificationError(
            f"policy certificate is not yet valid at {moment.isoformat()}"
        )
    current = [a for a in issuers
               if a.not_valid_before_utc <= moment <= a.not_valid_after_utc]
    lapsed = [a for a in issuers if moment > a.not_valid_after_utc]
    if not current and not lapsed:
        raise PolicyVerificationError(
            f"pinned CA is not yet valid at {moment.isoformat()}"
        )
    if moment > cert.not_valid_after_utc:
        raise PolicyCertificateExpired(
            f"policy certificate is not valid at {moment.isoformat()} "
            f"(expired {cert.not_valid_after_utc.isoformat()})",
            verified,
        )
    if not current:
        raise PolicyCertificateExpired(
            f"pinned CA is not valid at {moment.isoformat()} (expired "
            f"{lapsed[0].not_valid_after_utc.isoformat()})",
            verified,
        )


def _check_certificate_profile(cert: x509.Certificate) -> None:
    """Basic constraints, key usage and EKU of the signer certificate."""
    basic = _extension(cert, x509.BasicConstraints)
    if basic is None or basic.ca:
        raise PolicyVerificationError(
            "policy certificate must be an end-entity certificate"
        )
    usage = _extension(cert, x509.KeyUsage)
    if usage is None or not usage.digital_signature:
        raise PolicyVerificationError(
            "policy certificate lacks the digitalSignature key usage"
        )
    _require_policy_eku(cert, PolicyVerificationError)


def _decode_signature(signature_b64: Any) -> bytes:
    """Decode the base64 policy signature (bounded, strict alphabet)."""
    if not isinstance(signature_b64, str) or not signature_b64 or (
        len(signature_b64) > _MAX_SIGNATURE_B64_LEN
    ):
        raise PolicyVerificationError("policy signature is missing")
    try:
        return base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PolicyVerificationError(
            "policy signature is not valid base64"
        ) from exc


def _check_signature(
    cert: x509.Certificate, signature: bytes, canonical: bytes
) -> None:
    """Verify RSA-PSS/SHA-256 over the canonical policy bytes."""
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey) or (
        public_key.key_size < _MIN_RSA_BITS
    ):
        raise PolicyVerificationError("policy key must be RSA >= 2048 bits")
    try:
        public_key.verify(signature, canonical, _pss(), hashes.SHA256())
    except (InvalidSignature, ValueError) as exc:
        raise PolicyVerificationError(
            "policy signature does not verify"
        ) from exc


def _require_policy_eku(
    cert: x509.Certificate, error: Type[PolicyError]
) -> None:
    """Require the dedicated seal-policy extended key usage."""
    eku = _extension(cert, x509.ExtendedKeyUsage)
    if eku is None or SEAL_POLICY_EKU_OID not in eku:
        raise error("certificate EKU does not include the seal-policy purpose")


def _extension(cert: x509.Certificate, ext_type: type) -> Any:
    """Return the value of an extension, or ``None`` when absent."""
    try:
        return cert.extensions.get_extension_for_class(ext_type).value
    except x509.ExtensionNotFound:
        return None


# ---------------------------------------------------------------------------
# Release bindings
# ---------------------------------------------------------------------------

def s3_wrap_aad(seal_id: str, digest: bytes) -> bytes:
    """Associated data binding a wrapped s3 to its seal and policy.

    ``CONTEXT || 0x00 || seal_id (UTF-8) || 0x00 || SHA-256(policy)``; the
    trailing digest has a fixed length, so the encoding is unambiguous.
    """
    if not isinstance(seal_id, str) or not seal_id:
        raise PolicyError("seal_id is required for the s3 wrap binding")
    if not isinstance(digest, (bytes, bytearray)) or len(digest) != _DIGEST_LEN:
        raise PolicyError("policy digest must be 32 bytes")
    return (
        S3_WRAP_CONTEXT + b"\x00" + seal_id.encode("utf-8") + b"\x00"
        + bytes(digest)
    )


def release_imprint(digest: bytes, challenge: bytes) -> bytes:
    """TSA imprint for an s3 release: SHA-256(context || digest || challenge)."""
    if not isinstance(digest, (bytes, bytearray)) or len(digest) != _DIGEST_LEN:
        raise PolicyError("policy digest must be 32 bytes")
    if not isinstance(challenge, (bytes, bytearray)) or (
        len(challenge) != _DIGEST_LEN
    ):
        raise PolicyError("release challenge must be 32 bytes")
    return hashlib.sha256(
        S3_RELEASE_CONTEXT + bytes(digest) + bytes(challenge)
    ).digest()
