"""Test-only RFC 3161 token forge and certificate builders (synthetic).

Builds TSA certificates with chosen defects and time-stamp tokens with
chosen signed attributes, policy, accuracy, signer identifier and
certificate set, signed with a real key, so that each check of the
pinned TSA trust profile can be exercised on its own. Nothing here is
used by production code, and no key or certificate is written to the
repository.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Sequence

from asn1crypto import algos, cms, core, tsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID

TIME_STAMPING = ExtendedKeyUsageOID.TIME_STAMPING
CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
ONE_SECOND = {"seconds": 1}
_HASHES = {
    "sha1": hashes.SHA1, "sha256": hashes.SHA256,
    "sha384": hashes.SHA384, "sha512": hashes.SHA512,
}


def new_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    """A fresh RSA key (test only)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def new_ec_key() -> ec.EllipticCurvePrivateKey:
    """A fresh P-256 key (test only; the TSA profile accepts RSA only)."""
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "E2b test (synthetic)"),
    ])


def _key_usage(
    *, signing: bool, cert_sign: bool, encipherment: bool = False
) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=signing, content_commitment=False,
        key_encipherment=encipherment or not signing, data_encipherment=False,
        key_agreement=False, key_cert_sign=cert_sign, crl_sign=cert_sign,
        encipher_only=False, decipher_only=False,
    )


def _window(
    not_before: Optional[datetime], not_after: Optional[datetime]
) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    return (not_before or now - timedelta(days=1),
            not_after or now + timedelta(days=365))


def make_ca(
    common_name: str,
    *,
    key: Optional[rsa.RSAPrivateKey] = None,
    is_ca: bool = True,
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """A self-signed CA (or, with ``is_ca=False``, a self-signed leaf)."""
    key = key or new_key()
    start, end = _window(not_before, not_after)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
            critical=True,
        )
        .add_extension(_key_usage(signing=True, cert_sign=is_ca), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_tsa_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    key: Optional[rsa.RSAPrivateKey] = None,
    common_name: str = "E2b Test TSA",
    eku: Sequence[x509.ObjectIdentifier] = (TIME_STAMPING,),
    eku_critical: bool = True,
    is_ca: bool = False,
    signing: bool = True,
    encipherment: bool = False,
    with_ski: bool = False,
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """A TSA certificate issued by ``ca_cert``; ``eku=()`` omits the EKU.

    ``signing=False`` gives keyEncipherment only; ``encipherment=True``
    adds keyEncipherment to digitalSignature.
    """
    key = key or new_key()
    start, end = _window(not_before, not_after)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True,
        )
        .add_extension(
            _key_usage(signing=signing, cert_sign=is_ca,
                       encipherment=encipherment),
            critical=True,
        )
    )
    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(list(eku)), critical=eku_critical,
        )
    if with_ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    return key, builder.sign(ca_key, hashes.SHA256())


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _asn1(cert: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(der(cert))


@dataclass(frozen=True)
class TokenSpec:
    """How to forge one token (``dataclasses.replace`` makes variants).

    ``gen_time``: a datetime, or a raw ``core.GeneralizedTime``.
    ``accuracy``: a dict for tsp.Accuracy, raw DER bytes, or None (omit).
    ``ess``: "v2", "v1", "both", "none" (no signing-certificate
    attribute) or "no_signed_attrs" (signature over the TSTInfo).
    ``ess_leading_cert``: an ESSCertID for this certificate is listed
    before the one naming the signer. ``ess_issuer_name_of``: the
    issuerSerial takes its issuer name (not its serial) from this one.
    ``duplicate_attribute``: a second instance of that signed attribute.
    ``empty_duplicate_attribute``: a second, empty instance (no values).
    ``multi_value_attribute``: that attribute's one instance carries its
    value twice.
    ``certificates``: the token's certificate set; None means
    ``(cert,)`` and an empty tuple omits the field.
    """

    key: Any
    cert: x509.Certificate
    gen_time: Any
    policy_oid: str = DEFAULT_TSA_POLICY_OID
    accuracy: Any = None
    ess: str = "v2"
    ess_cert: Optional[x509.Certificate] = None
    ess_hash: str = "sha256"
    ess_issuer_serial_of: Optional[x509.Certificate] = None
    ess_issuer_name_of: Optional[x509.Certificate] = None
    ess_leading_cert: Optional[x509.Certificate] = None
    duplicate_attribute: Optional[str] = None
    empty_duplicate_attribute: Optional[str] = None
    multi_value_attribute: Optional[str] = None
    certificates: Optional[tuple[x509.Certificate, ...]] = None
    sid: str = "issuer_serial"
    sid_serial: Optional[int] = None
    content_type: str = "tst_info"
    message_digest: Optional[bytes] = None
    digest_algorithm: str = "sha256"
    signature_algorithm: str = "sha256_rsa"
    signer_count: int = 1


def _attr(name: str, value: Any) -> cms.CMSAttribute:
    return cms.CMSAttribute({"type": cms.CMSAttributeType(name), "values": [value]})


def _issuer_serial(
    cert: x509.Certificate, name_of: Optional[x509.Certificate] = None
) -> tsp.IssuerSerial:
    issuer = _asn1(name_of or cert).issuer
    return tsp.IssuerSerial({
        "issuer": [asn1_x509.GeneralName({"directory_name": issuer})],
        "serial_number": _asn1(cert).serial_number,
    })


def _cert_ids(spec: TokenSpec, hash_name: str) -> list[tuple[bytes, Any]]:
    """(hash, issuerSerial) pairs: an optional leading one, then the signer's."""
    named = spec.ess_cert or spec.cert
    serial_of = spec.ess_issuer_serial_of or named
    ids = [(hashlib.new(hash_name, der(named)).digest(),
            _issuer_serial(serial_of, spec.ess_issuer_name_of))]
    if spec.ess_leading_cert is not None:
        lead = spec.ess_leading_cert
        ids.insert(0, (hashlib.new(hash_name, der(lead)).digest(),
                       _issuer_serial(lead)))
    return ids


def _ess_attributes(spec: TokenSpec) -> list[cms.CMSAttribute]:
    attrs = []
    if spec.ess in ("v2", "both"):
        algorithm = algos.DigestAlgorithm({"algorithm": spec.ess_hash})
        attrs.append(_attr("signing_certificate_v2", tsp.SigningCertificateV2({
            "certs": [tsp.ESSCertIDv2({"hash_algorithm": algorithm,
                                       "cert_hash": cert_hash,
                                       "issuer_serial": serial})
                      for cert_hash, serial in _cert_ids(spec, spec.ess_hash)],
        })))
    if spec.ess in ("v1", "both"):
        attrs.append(_attr("signing_certificate", tsp.SigningCertificate({
            "certs": [tsp.ESSCertID({"cert_hash": cert_hash,
                                     "issuer_serial": serial})
                      for cert_hash, serial in _cert_ids(spec, "sha1")],
        })))
    return attrs


def _signed_attributes(spec: TokenSpec, tst_der: bytes) -> cms.CMSAttributes:
    digest = spec.message_digest or hashlib.new(
        spec.digest_algorithm, tst_der
    ).digest()
    attrs = [
        _attr("content_type", cms.ContentType(spec.content_type)),
        _attr("message_digest", digest),
        *_ess_attributes(spec),
    ]
    if spec.duplicate_attribute:
        attrs += [attr for attr in attrs
                  if attr["type"].native == spec.duplicate_attribute]
    return cms.CMSAttributes(_malformed_instances(spec, attrs))


def _malformed_instances(
    spec: TokenSpec, attrs: list[cms.CMSAttribute]
) -> list[cms.CMSAttribute]:
    """Apply ``empty_duplicate_attribute`` and ``multi_value_attribute``."""
    result = []
    for attr in attrs:
        name = attr["type"].native
        if name == spec.multi_value_attribute:
            value = attr["values"][0]
            attr = cms.CMSAttribute({"type": attr["type"],
                                     "values": [value, value.copy()]})
        result.append(attr)
    if spec.empty_duplicate_attribute:
        result.append(cms.CMSAttribute({
            "type": cms.CMSAttributeType(spec.empty_duplicate_attribute),
            "values": [],
        }))
    return result


def _sid(spec: TokenSpec) -> cms.SignerIdentifier:
    cert_asn1 = _asn1(spec.cert)
    if spec.sid == "ski":
        return cms.SignerIdentifier(
            {"subject_key_identifier": cert_asn1.key_identifier}
        )
    serial = cert_asn1.serial_number if spec.sid_serial is None else spec.sid_serial
    return cms.SignerIdentifier({"issuer_and_serial_number": {
        "issuer": cert_asn1.issuer, "serial_number": serial,
    }})


def _signer_info(spec: TokenSpec, tst_der: bytes) -> cms.SignerInfo:
    fields: dict[str, Any] = {
        "version": "v3" if spec.sid == "ski" else "v1",
        "sid": _sid(spec),
        "digest_algorithm": {"algorithm": spec.digest_algorithm},
        "signature_algorithm": {"algorithm": spec.signature_algorithm},
    }
    if spec.ess == "no_signed_attrs":
        payload = tst_der
    else:
        attrs = _signed_attributes(spec, tst_der)
        fields["signed_attrs"] = attrs
        payload = attrs.dump()
    fields["signature"] = spec.key.sign(
        payload, padding.PKCS1v15(), _HASHES[spec.digest_algorithm]()
    )
    return cms.SignerInfo(fields)


def _tst_info(
    spec: TokenSpec, data_hash: bytes, nonce: Optional[int], imprint_alg: str
) -> tsp.TSTInfo:
    fields: dict[str, Any] = {
        "version": "v1",
        "policy": spec.policy_oid,
        "message_imprint": {
            "hash_algorithm": {"algorithm": imprint_alg},
            "hashed_message": data_hash,
        },
        "serial_number": 7,
        "gen_time": spec.gen_time,
    }
    if isinstance(spec.accuracy, bytes):
        fields["accuracy"] = tsp.Accuracy.load(spec.accuracy)
    elif spec.accuracy is not None:
        fields["accuracy"] = tsp.Accuracy(spec.accuracy)
    if nonce is not None:
        fields["nonce"] = nonce
    return tsp.TSTInfo(fields)


def forge_token(
    spec: TokenSpec,
    *,
    data_hash: bytes,
    nonce: Optional[int],
    imprint_alg: str = "sha256",
) -> bytes:
    """A DER TimeStampToken (CMS ContentInfo) built from ``spec``.

    The outer ContentInfo is written directly around the SignedData DER:
    wrapping a SignedData object makes asn1crypto re-encode it from parsed
    values, which is lossy for a raw genTime it cannot represent (e.g. a
    7-digit fraction) and produced a length mismatch. The result is
    checked, so a malformed token never reaches a test.
    """
    tst_der = _tst_info(spec, data_hash, nonce, imprint_alg).dump()
    signed_der = cms.SignedData(_signed_data_fields(spec, tst_der)).dump()
    token = _tlv(0x30, _SIGNED_DATA_OID + _tlv(0xA0, signed_der))
    return _checked(token, tst_der)


_SIGNED_DATA_OID = core.ObjectIdentifier("1.2.840.113549.1.7.2").dump()


def _signed_data_fields(spec: TokenSpec, tst_der: bytes) -> dict[str, Any]:
    signer_info = _signer_info(spec, tst_der)
    certs = (spec.cert,) if spec.certificates is None else spec.certificates
    signed: dict[str, Any] = {
        "version": "v3",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {
            "content_type": "tst_info",
            "content": core.ParsableOctetString(tst_der),
        },
        "signer_infos": [signer_info] * spec.signer_count,
    }
    if certs:
        signed["certificates"] = [
            cms.CertificateChoices({"certificate": _asn1(cert)}) for cert in certs
        ]
    return signed


def _tlv(tag: int, content: bytes) -> bytes:
    """A DER tag-length-value with a definite (short or long form) length."""
    size = len(content)
    if size < 0x80:
        return bytes([tag, size]) + content
    octets = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(octets)]) + octets + content


def _checked(token: bytes, tst_der: bytes) -> bytes:
    """Strict DER load; the embedded TSTInfo must be exactly what was signed."""
    info = cms.ContentInfo.load(token, strict=True)
    embedded = info["content"]["encap_content_info"]["content"].contents
    if embedded != tst_der:
        raise AssertionError("forged token does not carry the signed TSTInfo")
    return token


def forging_transport(spec: TokenSpec) -> Callable[[bytes, str], bytes]:
    """A ``tsa_client._send_tsq`` stand-in answering every request with a
    token forged from ``spec`` over the request's own imprint and nonce."""

    def _send(tsq_bytes: bytes, _tsa_url: str) -> bytes:
        tsq = tsp.TimeStampReq.load(tsq_bytes)
        return forge_token(
            spec,
            data_hash=tsq["message_imprint"]["hashed_message"].native,
            nonce=tsq["nonce"].native,
        )

    return _send
