"""Pinned TSA trust profile for RFC 3161 time-stamp tokens (stage E, E2b).

The time-locked release path accepts a TSA token only under this
profile. :func:`verify_trusted_token` runs the checks below in order;
each failure raises :class:`~desktop.signature.exceptions.TSAError` whose
``code`` is the stable failure code in brackets:

1. structure: CMS SignedData encapsulating a TSTInfo, exactly one
   SignerInfo [tsa_format];
2. binding: SHA-256 messageImprint equal to the request hash
   [tsa_imprint]; the fresh request nonce echoed [tsa_nonce];
3. chain: the certificate named by the SignerInfo sid (issuer and serial
   number, or subject key identifier) occurs exactly once in the token's
   ``certificates``; it is issued directly by a pinned TSA CA (issuer
   name equals the CA subject and the CA key verifies its signature); it
   is not a CA; it equals the optional leaf pin [tsa_chain];
4. purpose: ExtendedKeyUsage present, critical and id-kp-timeStamping
   only (RFC 3161 section 2.3); a KeyUsage, if present, asserts only
   digitalSignature and/or nonRepudiation (RFC 5280 4.2.1.12) [tsa_eku];
5. ESS: signed attributes present with content-type id-ct-TSTInfo, a
   message-digest of the TSTInfo, and signing-certificate-v2 (RFC 5816,
   SHA-256/384/512) or signing-certificate (RFC 2634, SHA-1) whose first
   ESSCertID hashes the signer certificate DER and whose issuerSerial, if
   present, names it; every such attribute present must match [tsa_ess];
6. signature: RSA (at least 2048 bits) PKCS#1 v1.5 with SHA-256/384/512
   over the DER SET OF the signed attributes [tsa_signature];
7. validity: genTime encoded exactly as ``YYYYMMDDhhmmss[.fraction]Z``
   (no offset, seconds present, no trailing zeros; RFC 3161 2.4.2) and a
   valid time, a fraction beyond microseconds truncated [tsa_format]; the
   signer certificate and an issuing pinned CA are valid at genTime and at
   the verification time [tsa_chain];
8. policy: TSTInfo.policy equals the pinned policy OID [tsa_policy];
9. accuracy: present [tsa_accuracy_missing]; seconds non-negative, millis
   and micros within 1..999 [tsa_accuracy_invalid]. Absent components
   count as zero (RFC 3161 section 2.4.2).

Configuration problems are ``tsa_config``; a TSA that cannot be reached
or answers without a usable response is ``tsa_transport`` (set by
:func:`desktop.signature.tsa_client.request_timestamp_trusted`).

Scope (not implemented): intermediate CAs (the TSA certificate must be
issued directly by a pinned CA), non-RSA keys and RSA-PSS, revocation
checking (CRL/OCSP), certificate policy and name-constraint processing,
rejection of unknown critical extensions, comparison of the TSTInfo
``tsa`` name, and the CMS algorithm-protection attribute.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from asn1crypto import cms, core, tsp, x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from .exceptions import TSAError
from .types import VerifiedTimestamp

TSA_CONFIG = "tsa_config"
TSA_TRANSPORT = "tsa_transport"
TSA_FORMAT = "tsa_format"
TSA_IMPRINT = "tsa_imprint"
TSA_NONCE = "tsa_nonce"
TSA_CHAIN = "tsa_chain"
TSA_EKU = "tsa_eku"
TSA_ESS = "tsa_ess"
TSA_SIGNATURE = "tsa_signature"
TSA_POLICY = "tsa_policy"
TSA_ACCURACY_MISSING = "tsa_accuracy_missing"
TSA_ACCURACY_INVALID = "tsa_accuracy_invalid"

# Dotted decimal, at least two arcs, no leading zeros.
_OID_RE = re.compile(r"(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))+")
_MAX_OID_LEN = 256
# RFC 3161 2.4.2: YYYYMMDDhhmmss[.s...]Z, seconds present, no trailing
# zeros in the fraction, "." as the decimal sign, "Z" (UTC).
_GEN_TIME_RE = re.compile(rb"([0-9]{14})(?:\.([0-9]*[1-9]))?Z")
_DIGESTS = {
    "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512,
}
# SignerInfo signature algorithms accepted, with the digest each implies
# (None: rsaEncryption, the digest comes from digestAlgorithm).
_RSA_PKCS1 = {
    "rsassa_pkcs1v15": None, "sha256_rsa": "sha256",
    "sha384_rsa": "sha384", "sha512_rsa": "sha512",
}
_ESS_V2_HASHES = frozenset(_DIGESTS)
_MIN_RSA_BITS = 2048


class TimeStampResponse(core.Sequence):
    """TimeStampResp as RFC 3161 2.4.2 defines it, the token OPTIONAL.

    asn1crypto 1.5.1 declares ``time_stamp_token`` mandatory, so its
    ``tsp.TimeStampResp`` can neither encode nor decode a rejection (which
    carries no token). The bundled TSA encodes rejections and the client
    decodes every reply with this type.
    """

    _fields = [
        ("status", tsp.PKIStatusInfo),
        ("time_stamp_token", cms.ContentInfo, {"optional": True}),
    ]


def is_dotted_oid(text: object) -> bool:
    """True when ``text`` is a syntactically valid dotted OID.

    Beyond the digits-and-dots form, the arc rules of X.690 must hold
    (first arc 0, 1 or 2; second arc below 40 under 0 and 1). They are
    checked by a DER round trip: an OID that breaks them re-encodes to a
    different dotted form (``3.1`` would become ``2.41``).
    """
    if not isinstance(text, str) or len(text) > _MAX_OID_LEN:
        return False
    if not _OID_RE.fullmatch(text):
        return False
    try:
        encoded = core.ObjectIdentifier(text).dump()
        return core.ObjectIdentifier.load(encoded).dotted == text
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class TsaTrustProfile:
    """What the time-locked release path accepts from a TSA.

    ``ca_cert_path``: PEM file holding the CA (or a bundle of CAs) allowed
    to issue the TSA certificate directly. Pinning the CA, not the TSA
    certificate, lets the TSA rotate its key without reconfiguration, but
    then every timeStamping certificate that CA issues is trusted: the CA
    must be dedicated to the TSA(s) the release host trusts.
    ``policy_oid``: the TSA policy every token must assert.
    ``leaf_cert_path``: optional extra pin; when set, the signer
    certificate must be exactly this certificate (key rotation then needs
    a configuration change).
    """

    ca_cert_path: str
    policy_oid: str
    leaf_cert_path: str = ""


@dataclass(frozen=True)
class LoadedTsaProfile:
    """A :class:`TsaTrustProfile` whose files and policy OID were checked."""

    anchors: tuple[x509.Certificate, ...]
    policy_oid: str
    leaf_pin_der: Optional[bytes] = None


def _fail(code: str, message: str) -> TSAError:
    return TSAError(message, code=code)


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

def load_tsa_ca_certificates(path: str | Path) -> list[x509.Certificate]:
    """Load the pinned TSA CA file (one PEM certificate or a bundle).

    Raises:
        TSAError: ``tsa_config`` when the path is empty or the file is
            unreadable, holds no certificate, or holds a certificate that
            is not a certificate-signing CA.
    """
    if not path:
        raise _fail(TSA_CONFIG, "no pinned TSA CA configured")
    try:
        certs = x509.load_pem_x509_certificates(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise _fail(TSA_CONFIG, f"pinned TSA CA file is unusable: {exc}") from exc
    if not certs:
        raise _fail(TSA_CONFIG, "pinned TSA CA file holds no certificate")
    for cert in certs:
        _require_ca(cert)
    return certs


def load_trust_profile(profile: TsaTrustProfile) -> LoadedTsaProfile:
    """Read and check the profile's CA file, leaf pin and policy OID.

    Raises:
        TSAError: ``tsa_config`` on any unusable value.
    """
    if not is_dotted_oid(profile.policy_oid):
        raise _fail(TSA_CONFIG, "pinned TSA policy OID is not a dotted OID: "
                                f"{profile.policy_oid!r}")
    anchors = tuple(load_tsa_ca_certificates(profile.ca_cert_path))
    return LoadedTsaProfile(anchors, profile.policy_oid,
                            _load_leaf_pin(profile.leaf_cert_path))


def check_tsa_certificate(
    cert: x509.Certificate, anchors: Sequence[x509.Certificate]
) -> None:
    """Static profile of a TSA certificate (validity is not checked).

    Direct issuance by one of ``anchors``, not a CA, a critical
    timeStamping-only EKU, and a key the signature check accepts
    (:func:`check_tsa_leaf_key`). Used at start-up for the optional leaf
    pin, so a pin that no token could satisfy is refused there.

    Raises:
        TSAError: ``tsa_chain``, ``tsa_eku`` or ``tsa_signature``.
    """
    der = cert.public_bytes(serialization.Encoding.DER)
    _check_chain(cert, der, LoadedTsaProfile(tuple(anchors), ""))
    _check_purpose(cert)
    check_tsa_leaf_key(cert)


def check_tsa_leaf_key(cert: x509.Certificate) -> rsa.RSAPublicKey:
    """The TSA certificate's key must be RSA of at least 2048 bits.

    The one key rule, shared by start-up validation of a leaf pin and by
    the signature check at run time.

    Raises:
        TSAError: ``tsa_signature`` for any other key type or size.
    """
    try:
        key = cert.public_key()
    except (ValueError, TypeError) as exc:  # e.g. an unsupported key type
        raise _fail(TSA_SIGNATURE, f"TSA key cannot be loaded: {exc}") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < _MIN_RSA_BITS:
        raise _fail(TSA_SIGNATURE, "TSA key must be RSA of at least 2048 bits")
    return key


def release_rule_note(stamp: VerifiedTimestamp, unlock_time: datetime) -> str:
    """Audit text of the release rule ``genTime - accuracy >= unlock_time``.

    Names the accuracy (seconds, six decimals), genTime - accuracy and the
    unlock time. Contains no ``"; "`` (the audit detail separator).

    Raises:
        TSAError: ``tsa_accuracy_missing`` if the token has no accuracy.
    """
    earliest = stamp.earliest_gen_time
    micros = (stamp.gen_time - earliest) // timedelta(microseconds=1)
    return (f"tsa rule genTime - accuracy >= unlock_time: accuracy="
            f"{micros // 1_000_000}.{micros % 1_000_000:06d}s, genTime - "
            f"accuracy={earliest.isoformat()}, "
            f"unlock_time={unlock_time.isoformat()}")


def _load_leaf_pin(path: str) -> Optional[bytes]:
    if not path:
        return None
    try:
        cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise _fail(TSA_CONFIG,
                    f"pinned TSA certificate is unusable: {exc}") from exc
    return cert.public_bytes(serialization.Encoding.DER)


def _require_ca(cert: x509.Certificate) -> None:
    basic = _extension(cert, x509.BasicConstraints, TSA_CONFIG)
    usage = _extension(cert, x509.KeyUsage, TSA_CONFIG)
    if basic is None or not basic.value.ca:
        raise _fail(TSA_CONFIG, "pinned TSA CA certificate is not a CA")
    if usage is None or not usage.value.key_cert_sign:
        raise _fail(TSA_CONFIG,
                    "pinned TSA CA certificate cannot sign certificates")
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < _MIN_RSA_BITS:
        raise _fail(TSA_CONFIG, "pinned TSA CA key is RSA below 2048 bits")


def _extension(
    cert: x509.Certificate, ext_type: type, code: str
) -> Optional[x509.Extension]:
    """The extension of ``ext_type``, None when absent (fail if unparsable)."""
    try:
        return cert.extensions.get_extension_for_class(ext_type)
    except x509.ExtensionNotFound:
        return None
    except (ValueError, x509.DuplicateExtension) as exc:
        raise _fail(code, f"certificate extensions cannot be parsed: {exc}") from exc


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------

def verify_trusted_token(
    token: bytes,
    data_hash: bytes,
    nonce: int,
    profile: TsaTrustProfile | LoadedTsaProfile,
    *,
    at: Optional[datetime] = None,
) -> VerifiedTimestamp:
    """Accept ``token`` only under the pinned TSA trust profile (fail-closed).

    Args:
        token: DER TimeStampToken (CMS ContentInfo).
        data_hash: The SHA-256 hash the request asked the TSA to stamp.
        nonce: The fresh nonce the request carried.
        profile: Pinned TSA CA(s), policy OID and optional leaf pin, as
            configured or already loaded by :func:`load_trust_profile`.
        at: Verification time (default: now, UTC).

    Returns:
        The verified token with its genTime, accuracy and policy OID.

    Raises:
        TSAError: With the ``code`` of the first failed check (see the
            module docstring).
    """
    loaded = (profile if isinstance(profile, LoadedTsaProfile)
              else load_trust_profile(profile))
    moment = at or datetime.now(timezone.utc)
    try:
        return _verify(token, data_hash, nonce, loaded, moment)
    except TSAError:
        raise
    except Exception as exc:  # malformed ASN.1 surfaces lazily; never accept
        raise _fail(TSA_FORMAT, f"TST token cannot be processed: {exc}") from exc


def _verify(
    token: bytes,
    data_hash: bytes,
    nonce: int,
    loaded: LoadedTsaProfile,
    moment: datetime,
) -> VerifiedTimestamp:
    signed_data, tst_der, tst_info = _parse_token(token)
    _check_binding(tst_info, data_hash, nonce)
    signer_info = _single_signer(signed_data)
    payload = _signed_attrs_payload(signer_info)
    leaf_asn1 = _signer_certificate(signed_data, signer_info)
    leaf = _load_certificate(leaf_asn1)
    issuers = _check_chain(leaf, leaf_asn1.dump(), loaded)
    _check_purpose(leaf)
    _check_ess(signer_info, tst_der, leaf_asn1)
    _check_signature(signer_info, payload, leaf)
    gen_time = _gen_time(tst_info)
    _check_validity(leaf, issuers, gen_time, moment)
    _check_policy(tst_info, loaded.policy_oid)
    accuracy = _accuracy(tst_info, gen_time)
    return VerifiedTimestamp(
        gen_time=gen_time, token=token, nonce=nonce,
        serial_number=int(tst_info["serial_number"].native),
        accuracy=accuracy, policy_oid=loaded.policy_oid,
        signer_cert_sha256=hashlib.sha256(leaf_asn1.dump()).hexdigest(),
    )


def _parse_token(token: bytes) -> tuple[cms.SignedData, bytes, tsp.TSTInfo]:
    content_info = cms.ContentInfo.load(token)
    if content_info["content_type"].native != "signed_data":
        raise _fail(TSA_FORMAT, "TST token is not CMS signed_data")
    signed_data = content_info["content"]
    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise _fail(TSA_FORMAT, "TST token does not encapsulate tst_info")
    if isinstance(encap["content"], core.Void):
        raise _fail(TSA_FORMAT, "TST token carries no TSTInfo")
    tst_der = encap["content"].parsed.dump()
    return signed_data, tst_der, tsp.TSTInfo.load(tst_der)


def _check_binding(tst_info: tsp.TSTInfo, data_hash: bytes, nonce: int) -> None:
    imprint = tst_info["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != "sha256":
        raise _fail(TSA_IMPRINT, "TST messageImprint hash algorithm is not SHA-256")
    hashed = imprint["hashed_message"].native
    if not isinstance(hashed, bytes) or not hmac.compare_digest(hashed, data_hash):
        raise _fail(TSA_IMPRINT,
                    "TST messageImprint does not match the request hash")
    echoed = tst_info["nonce"].native
    if echoed != nonce:
        raise _fail(TSA_NONCE, "TST nonce mismatch: expected the fresh request "
                               f"nonce, got {echoed!r} (possible replay)")


def _single_signer(signed_data: cms.SignedData) -> cms.SignerInfo:
    infos = signed_data["signer_infos"]
    if len(infos) != 1:
        raise _fail(TSA_FORMAT, "TST token must carry exactly one SignerInfo, "
                                f"found {len(infos)}")
    return infos[0]


def _signed_attrs_payload(signer_info: cms.SignerInfo) -> Optional[bytes]:
    """DER of the signed attributes as signed (RFC 5652 5.4), or None.

    The attributes are encoded with the [0] IMPLICIT tag in the SignerInfo
    but signed as a universal SET OF (tag 0x31).
    """
    attrs = signer_info["signed_attrs"]
    if isinstance(attrs, core.Void) or len(attrs) == 0:
        return None
    return b"\x31" + attrs.dump()[1:]


def _signer_certificate(
    signed_data: cms.SignedData, signer_info: cms.SignerInfo
) -> asn1_x509.Certificate:
    """The one certificate in the token that the SignerInfo sid names."""
    certs = signed_data["certificates"]
    candidates = [] if isinstance(certs, core.Void) else [
        choice.chosen for choice in certs if choice.name == "certificate"
    ]
    matches = [c for c in candidates if _sid_names(signer_info["sid"], c)]
    if len(matches) != 1:
        raise _fail(TSA_CHAIN, f"SignerInfo sid matches {len(matches)} "
                               "certificate(s) in the token; exactly one is "
                               "required")
    return matches[0]


def _sid_names(sid: cms.SignerIdentifier, cert: asn1_x509.Certificate) -> bool:
    if sid.name == "issuer_and_serial_number":
        chosen = sid.chosen
        return (cert.issuer == chosen["issuer"]
                and cert.serial_number == chosen["serial_number"].native)
    if sid.name == "subject_key_identifier":
        return cert.key_identifier is not None and (
            cert.key_identifier == sid.chosen.native
        )
    return False


def _load_certificate(cert_asn1: asn1_x509.Certificate) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(cert_asn1.dump())
    except ValueError as exc:
        raise _fail(TSA_CHAIN, f"TSA certificate cannot be parsed: {exc}") from exc


def _check_chain(
    leaf: x509.Certificate, leaf_der: bytes, loaded: LoadedTsaProfile
) -> list[x509.Certificate]:
    """The pinned CAs that directly issued ``leaf``; leaf not a CA; pin."""
    issuers = [ca for ca in loaded.anchors if _directly_issued(leaf, ca)]
    if not issuers:
        raise _fail(TSA_CHAIN,
                    "TSA certificate is not issued directly by a pinned TSA CA")
    basic = _extension(leaf, x509.BasicConstraints, TSA_CHAIN)
    if basic is not None and basic.value.ca:
        raise _fail(TSA_CHAIN, "TSA certificate is a CA certificate")
    if loaded.leaf_pin_der is not None and leaf_der != loaded.leaf_pin_der:
        raise _fail(TSA_CHAIN, "TSA certificate is not the pinned TSA certificate")
    return issuers


def _directly_issued(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    if cert.issuer != ca.subject:
        return False
    try:
        cert.verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _check_purpose(leaf: x509.Certificate) -> None:
    """RFC 3161 2.3: one critical EKU, id-kp-timeStamping only."""
    eku = _extension(leaf, x509.ExtendedKeyUsage, TSA_EKU)
    if eku is None:
        raise _fail(TSA_EKU, "TSA certificate has no extended key usage")
    if not eku.critical:
        raise _fail(TSA_EKU, "TSA certificate extended key usage is not critical")
    if list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise _fail(TSA_EKU, "TSA certificate extended key usage must be "
                             "id-kp-timeStamping only")
    usage = _extension(leaf, x509.KeyUsage, TSA_EKU)
    if usage is not None and not _signing_key_usage(usage.value):
        raise _fail(TSA_EKU, "TSA certificate key usage must be "
                             "digitalSignature and/or nonRepudiation only")


def _signing_key_usage(usage: x509.KeyUsage) -> bool:
    """RFC 5280 4.2.1.12: the only key usage bits consistent with
    id-kp-timeStamping (OpenSSL's timestamp-signing purpose agrees).

    encipherOnly/decipherOnly are only defined with keyAgreement, which
    is refused, so they are not read.
    """
    other = (usage.key_encipherment, usage.data_encipherment,
             usage.key_agreement, usage.key_cert_sign, usage.crl_sign)
    return (usage.digital_signature or usage.content_commitment) and not any(
        other
    )


def _check_ess(
    signer_info: cms.SignerInfo, tst_der: bytes, leaf: asn1_x509.Certificate
) -> None:
    """content-type, message-digest and the ESS signing-certificate(s)."""
    attrs = signer_info["signed_attrs"]
    if isinstance(attrs, core.Void) or len(attrs) == 0:
        raise _fail(TSA_ESS, "SignerInfo carries no signed attributes")
    # Instances are kept apart: pooling their values would let one valid
    # instance plus an empty one of the same type pass as "exactly one".
    instances: dict[str, list[Any]] = {}
    for attr in attrs:
        instances.setdefault(attr["type"].native, []).append(attr["values"])
    if _single(instances, "content_type").native != "tst_info":
        raise _fail(TSA_ESS, "content-type attribute is not id-ct-TSTInfo")
    digest = hashlib.new(_digest_name(signer_info), tst_der).digest()
    found = _single(instances, "message_digest").native
    if not isinstance(found, bytes) or not hmac.compare_digest(found, digest):
        raise _fail(TSA_ESS, "message-digest attribute does not match the TSTInfo")
    _check_signing_certificate(instances, leaf)


def _check_signing_certificate(
    instances: dict[str, list[Any]], leaf: asn1_x509.Certificate
) -> None:
    has_v2 = "signing_certificate_v2" in instances
    has_v1 = "signing_certificate" in instances
    if not has_v2 and not has_v1:
        raise _fail(TSA_ESS, "no ESS signing-certificate attribute")
    leaf_der = leaf.dump()
    if has_v2:
        cert_id = _first_cert_id(_single(instances, "signing_certificate_v2"))
        algorithm = cert_id["hash_algorithm"]["algorithm"].native
        if algorithm not in _ESS_V2_HASHES:
            raise _fail(TSA_ESS, f"ESSCertIDv2 hash algorithm {algorithm} is "
                                 "not SHA-256 or stronger")
        _check_cert_id(cert_id, hashlib.new(algorithm, leaf_der).digest(), leaf)
    if has_v1:
        cert_id = _first_cert_id(_single(instances, "signing_certificate"))
        _check_cert_id(cert_id, hashlib.sha1(leaf_der).digest(), leaf)


def _single(instances: dict[str, list[Any]], name: str) -> Any:
    """The value of the one instance of ``name``, which has one value
    (RFC 5652 11.1/11.2, RFC 5035 5.4: a single instance, single value)."""
    found = instances.get(name, [])
    if len(found) != 1 or len(found[0]) != 1:
        raise _fail(TSA_ESS, f"signed attribute {name} must occur exactly once "
                             "with exactly one value (found "
                             f"{[len(values) for values in found]} value(s) "
                             "per instance)")
    return found[0][0]


def _first_cert_id(value: Any) -> Any:
    certs = value["certs"]
    if len(certs) == 0:
        raise _fail(TSA_ESS, "ESS signing-certificate attribute names no certificate")
    return certs[0]


def _check_cert_id(
    cert_id: Any, expected_hash: bytes, leaf: asn1_x509.Certificate
) -> None:
    """The first ESSCertID(v2) must hash the signer certificate DER."""
    cert_hash = cert_id["cert_hash"].native
    if not isinstance(cert_hash, bytes) or not hmac.compare_digest(
        cert_hash, expected_hash
    ):
        raise _fail(TSA_ESS,
                    "ESS certificate hash does not match the signer certificate")
    issuer_serial = cert_id["issuer_serial"]
    if isinstance(issuer_serial, core.Void):
        return
    names = [name.chosen for name in issuer_serial["issuer"]
             if name.name == "directory_name"]
    if (issuer_serial["serial_number"].native != leaf.serial_number
            or leaf.issuer not in names):
        raise _fail(TSA_ESS, "ESS issuerSerial does not name the signer certificate")


def _digest_name(signer_info: cms.SignerInfo) -> str:
    name = signer_info["digest_algorithm"]["algorithm"].native
    if name not in _DIGESTS:
        raise _fail(TSA_SIGNATURE, f"unsupported TST digest algorithm: {name}")
    return name


def _check_signature(
    signer_info: cms.SignerInfo, payload: Optional[bytes], leaf: x509.Certificate
) -> None:
    digest_name = _digest_name(signer_info)
    algorithm = signer_info["signature_algorithm"]["algorithm"].native
    if algorithm not in _RSA_PKCS1 or _RSA_PKCS1[algorithm] not in (
        None, digest_name
    ):
        raise _fail(TSA_SIGNATURE,
                    f"unsupported TST signature algorithm: {algorithm}")
    key = check_tsa_leaf_key(leaf)
    if payload is None:
        raise _fail(TSA_ESS, "SignerInfo carries no signed attributes")
    try:
        key.verify(signer_info["signature"].native, payload,
                   padding.PKCS1v15(), _DIGESTS[digest_name]())
    except InvalidSignature as exc:
        raise _fail(TSA_SIGNATURE,
                    "TST signature does not verify with the TSA certificate") from exc


def _gen_time(tst_info: tsp.TSTInfo) -> datetime:
    """genTime in the one form RFC 3161 2.4.2 allows (UTC, ``...Z``).

    The encoding itself is checked, since asn1crypto also parses offsets
    (``+0000``), missing seconds and comma fractions as UTC times. The
    time is then built from the checked digits; a fraction beyond
    microseconds is truncated, never rounded up (a later genTime would
    open the time lock earlier).
    """
    match = _GEN_TIME_RE.fullmatch(tst_info["gen_time"].contents or b"")
    if match is None:
        raise _fail(TSA_FORMAT, "TST genTime is not YYYYMMDDhhmmss[.fraction]Z "
                                "without trailing zeros (RFC 3161 2.4.2)")
    digits, fraction = match.group(1).decode("ascii"), match.group(2) or b""
    fields = [int(digits[i:i + 2]) for i in range(4, 14, 2)]
    micros = int(fraction.decode("ascii")[:6].ljust(6, "0"))
    try:
        return datetime(int(digits[:4]), *fields, micros, tzinfo=timezone.utc)
    except ValueError as exc:  # e.g. month 13, hour 24, second 60
        raise _fail(TSA_FORMAT, f"TST genTime is not a valid time: {exc}") from exc


def _check_validity(
    leaf: x509.Certificate,
    issuers: Sequence[x509.Certificate],
    gen_time: datetime,
    moment: datetime,
) -> None:
    """Signer certificate and an issuing CA valid at genTime and now."""
    for label, when in (("genTime", gen_time), ("verification time", moment)):
        if not _valid_at(leaf, when):
            raise _fail(TSA_CHAIN, f"TSA certificate is not valid at {label} "
                                   f"{when.isoformat()}")
    if not any(_valid_at(ca, gen_time) and _valid_at(ca, moment)
               for ca in issuers):
        raise _fail(TSA_CHAIN, "no issuing pinned TSA CA is valid at genTime "
                               "and at verification time")


def _valid_at(cert: x509.Certificate, when: datetime) -> bool:
    return cert.not_valid_before_utc <= when <= cert.not_valid_after_utc


def _check_policy(tst_info: tsp.TSTInfo, policy_oid: str) -> None:
    asserted = tst_info["policy"].dotted
    if asserted != policy_oid:
        raise _fail(TSA_POLICY, f"TST policy {asserted} is not the pinned TSA "
                                f"policy {policy_oid}")


def _accuracy(tst_info: tsp.TSTInfo, gen_time: datetime) -> timedelta:
    """The asserted accuracy (required on this path)."""
    field = tst_info["accuracy"]
    if isinstance(field, core.Void):
        raise _fail(TSA_ACCURACY_MISSING, "TSTInfo carries no accuracy; it is "
                                          "required on the time-locked path")
    seconds, millis, micros = (
        field[name].native for name in ("seconds", "millis", "micros")
    )
    in_range = (seconds is None or seconds >= 0) and all(
        part is None or 1 <= part <= 999 for part in (millis, micros)
    )
    if not in_range:
        raise _fail(TSA_ACCURACY_INVALID, "TSTInfo accuracy out of range: "
                    f"seconds={seconds}, millis={millis}, micros={micros}")
    try:
        accuracy = timedelta(seconds=seconds or 0, milliseconds=millis or 0,
                             microseconds=micros or 0)
        gen_time - accuracy  # noqa: B018 - the lower bound must exist
    except OverflowError as exc:
        raise _fail(TSA_ACCURACY_INVALID, "TSTInfo accuracy is too large") from exc
    return accuracy
