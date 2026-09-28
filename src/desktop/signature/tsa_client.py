"""RFC 3161 TSA client for requesting and verifying timestamps.

Sends TimeStampReq (TSQ) to a TSA server and receives TimeStampResp (TSR).
Supports retry with exponential backoff and TST token verification.

Two verified requests exist. :func:`request_timestamp_verified` and
:func:`request_timestamp_verified_token` check a token against one pinned
TSA certificate (stage D; kept for the desktop component and backward
compatibility). :func:`request_timestamp_trusted` accepts a token only
under the pinned TSA trust profile of :mod:`.tsa_profile` (TSA CA chain,
EKU, ESS, policy OID, accuracy; stage E, E2b) and is the one the
time-locked release path uses.
"""

from __future__ import annotations

import hmac
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests
from asn1crypto import algos, cms, core, tsp

from .exceptions import TSAError
from .tsa_profile import (
    TSA_CONFIG,
    TSA_IMPRINT,
    TSA_TRANSPORT,
    TimeStampResponse,
    TsaTrustProfile,
    load_trust_profile,
    verify_trusted_token,
)
from .types import VerifiedTimestamp

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 1.0  # seconds

# A TSA on the loopback interface either answers immediately or is
# down — long timeouts and extra retries only delay the fallback.
_LOCAL_TIMEOUT_SECONDS = 2
_LOCAL_MAX_RETRIES = 2
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# A TimeStampResp is a few kilobytes: the token and the TSA certificate,
# perhaps its chain. A larger reply is refused, not read, with the same
# 64 KiB bound as the desktop sync transport's answers
# (desktop.sync.transport.MAX_ANSWER_BYTES).
MAX_TSA_REPLY_BYTES = 64 * 1024


def _is_local_tsa(tsa_url: str) -> bool:
    """Return True if the TSA URL points at the loopback interface."""
    from urllib.parse import urlparse

    try:
        host = urlparse(tsa_url).hostname or ""
    except ValueError:
        return False
    return host.lower() in _LOCAL_HOSTS


def _build_tsq(data_hash: bytes, nonce: int | None = None) -> bytes:
    """Build an RFC 3161 TimeStampReq (TSQ) for a SHA-256 hash.

    Args:
        data_hash: SHA-256 hash of the data to timestamp (32 bytes).
        nonce: Optional RFC 3161 request nonce; the TSA must echo it
            inside the signed TSTInfo (replay defense).

    Returns:
        DER-encoded TSQ bytes.

    Raises:
        TSAError: If the hash length is invalid.
    """
    if len(data_hash) != 32:
        raise TSAError(
            f"Expected 32-byte SHA-256 hash, got {len(data_hash)} bytes"
        )

    message_imprint = tsp.MessageImprint({
        "hash_algorithm": algos.DigestAlgorithm({
            "algorithm": "sha256",
        }),
        "hashed_message": data_hash,
    })

    fields: dict = {
        "version": "v1",
        "message_imprint": message_imprint,
        "cert_req": True,
    }
    if nonce is not None:
        fields["nonce"] = nonce

    tsq = tsp.TimeStampReq(fields)

    return tsq.dump()


def _parse_tsr(tsr_bytes: bytes) -> bytes:
    """Parse a TimeStampResp and extract the TST token.

    Args:
        tsr_bytes: DER-encoded TSR bytes.

    Returns:
        DER-encoded TimeStampToken (ContentInfo) bytes.

    Raises:
        TSAError: If the TSR indicates failure or cannot be parsed.
    """
    try:  # the RFC 3161 structure: a rejection carries no token
        tsr = TimeStampResponse.load(tsr_bytes)
        status_info = tsr["status"]
        status = status_info["status"].native
        fail_info = status_info["fail_info"].native
        status_string = status_info["status_string"].native
        tst_token = tsr["time_stamp_token"]
    except Exception as exc:
        raise TSAError(f"Failed to parse TSR: {exc}") from exc

    if status != "granted" and status != "granted_with_mods":
        raise TSAError(
            f"TSA request rejected: status={status}, "
            f"fail_info={fail_info}, status_string={status_string}"
        )

    if isinstance(tst_token, core.Void):
        raise TSAError("TSR contains no TimeStampToken")

    return tst_token.dump()


def request_timestamp(data_hash: bytes, tsa_url: str) -> bytes:
    """Send an RFC 3161 TSQ to a TSA and return the TST token.

    Retries with exponential backoff on network errors. Loopback TSA
    URLs use a shorter timeout (2s) and fewer retries (2) since a
    local server either responds immediately or is not running.

    Args:
        data_hash: SHA-256 hash (32 bytes) of the data to timestamp.
        tsa_url: URL of the TSA server endpoint.

    Returns:
        DER-encoded TST token bytes.

    Raises:
        TSAError: If the request fails after all retries.
    """
    if not tsa_url:
        raise TSAError("TSA URL is required")

    tsq_bytes = _build_tsq(data_hash)
    return _send_tsq(tsq_bytes, tsa_url)


def _redact_url(url: str) -> str:
    """``url`` without userinfo, so credentials never reach logs or audit."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparsable TSA URL>"
    return urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))


def _failure_text(exc: Exception, tsa_url: str) -> str:
    """Log and error text of a failed TSA request, without URL credentials.

    requests renders the full URL, userinfo included, into ``HTTPError``
    text; that case is rebuilt from the status code, and any other text
    has the userinfo removed.
    """
    response = getattr(exc, "response", None)
    if isinstance(exc, requests.HTTPError) and response is not None:
        return f"HTTP {response.status_code} from {_redact_url(tsa_url)}"
    text = str(exc).replace(tsa_url, _redact_url(tsa_url))
    userinfo = tsa_url.partition("://")[2].partition("/")[0].rpartition("@")[0]
    return text.replace(userinfo + "@", "") if userinfo else text


def _send_tsq(tsq_bytes: bytes, tsa_url: str) -> bytes:
    """POST a DER-encoded TSQ and return the extracted TST token.

    A redirect is not followed, a content-coded reply is not accepted, and
    the reply is read up to :data:`MAX_TSA_REPLY_BYTES`: each of these is
    refused at once as ``tsa_transport``, without a retry (Fable gate,
    finding 7). Network errors and HTTP 4xx/5xx answers are retried. Logs
    and errors name the URL without its userinfo (credentials).
    """
    if _is_local_tsa(tsa_url):
        timeout_seconds = _LOCAL_TIMEOUT_SECONDS
        max_retries = _LOCAL_MAX_RETRIES
    else:
        timeout_seconds = _TIMEOUT_SECONDS
        max_retries = _MAX_RETRIES

    last_error = ""

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(
                "TSA request attempt %d/%d to %s",
                attempt, max_retries, _redact_url(tsa_url),
            )
            tst_token = _parse_tsr(_post_tsq(tsq_bytes, tsa_url, timeout_seconds))
            logger.info("TST token received successfully (attempt %d)", attempt)
            return tst_token

        except TSAError:
            raise
        except Exception as exc:
            last_error = _failure_text(exc, tsa_url)
            if attempt < max_retries:
                wait_time = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning(
                    "TSA request attempt %d failed: %s. Retrying in %.1fs...",
                    attempt, last_error, wait_time,
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    "TSA request failed after %d attempts", max_retries
                )

    raise TSAError(
        f"TSA request failed after {max_retries} attempts: {last_error}"
    )


def _post_tsq(tsq_bytes: bytes, tsa_url: str, timeout: float) -> bytes:
    """One POST of the TSQ; the reply body under the rules of :func:`_send_tsq`.

    Raises:
        TSAError: ``tsa_transport`` for a redirect, a content-coded or an
            oversized reply.
        requests.RequestException: Network errors and HTTP 4xx/5xx answers
            (retried by the caller).
    """
    with requests.post(
        tsa_url,
        data=tsq_bytes,
        headers={"Content-Type": "application/timestamp-query",
                 "Accept-Encoding": "identity"},
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    ) as response:
        if 300 <= response.status_code < 400:
            raise _transport_refusal(
                tsa_url, f"answered with a redirect (HTTP "
                         f"{response.status_code}); redirects are not followed")
        response.raise_for_status()
        encoding = response.headers.get("Content-Encoding", "").strip().lower()
        if encoding not in ("", "identity"):
            raise _transport_refusal(
                tsa_url, f"sent a {encoding}-coded reply; only identity is "
                         "accepted")
        content_type = response.headers.get("Content-Type", "")
        if "application/timestamp-reply" not in content_type:
            logger.warning("Unexpected Content-Type from TSA: %s", content_type)
        return _bounded_body(response, tsa_url)


def _bounded_body(response: requests.Response, tsa_url: str) -> bytes:
    """The reply body; refused, not read on, beyond MAX_TSA_REPLY_BYTES."""
    declared = response.headers.get("Content-Length", "").strip()
    if declared.isascii() and declared.isdigit() and (
        int(declared) > MAX_TSA_REPLY_BYTES
    ):
        raise _oversized(tsa_url)
    body = bytearray()
    for chunk in response.iter_content(chunk_size=16 * 1024):
        body += chunk
        if len(body) > MAX_TSA_REPLY_BYTES:
            raise _oversized(tsa_url)
    return bytes(body)


def _oversized(tsa_url: str) -> TSAError:
    return _transport_refusal(
        tsa_url, f"reply exceeds {MAX_TSA_REPLY_BYTES} bytes; not read further")


def _transport_refusal(tsa_url: str, what: str) -> TSAError:
    """A ``tsa_transport`` error naming the TSA without URL credentials."""
    return TSAError(f"TSA {_redact_url(tsa_url)} {what}", code=TSA_TRANSPORT)


def verify_timestamp(tst_token: bytes, tsa_cert_path: str) -> datetime:
    """Verify a TST token and return the genTime.

    Performs basic structural verification of the TST token and extracts
    the generation time. For full cryptographic verification, the TSA
    certificate chain should be validated separately.

    Args:
        tst_token: DER-encoded TST token (ContentInfo) bytes.
        tsa_cert_path: Path to the TSA certificate PEM file (for future
            full chain validation).

    Returns:
        The genTime from the TST token as a timezone-aware datetime.

    Raises:
        TSAError: If verification fails.
    """
    try:
        content_info = cms.ContentInfo.load(tst_token)
        if content_info["content_type"].native != "signed_data":
            raise TSAError(
                f"Expected signed_data, got {content_info['content_type'].native}"
            )

        signed_data = content_info["content"]
        encap_content = signed_data["encap_content_info"]

        if encap_content["content_type"].native != "tst_info":
            raise TSAError(
                f"Expected tst_info content, got {encap_content['content_type'].native}"
            )

        tst_info = tsp.TSTInfo.load(encap_content["content"].parsed.dump())
        gen_time = tst_info["gen_time"].native

        if gen_time is None:
            raise TSAError("TST token contains no genTime")

        # Ensure timezone-aware
        if gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=timezone.utc)

        serial = tst_info["serial_number"].native

        # Cryptographic signature verification against the TSA cert
        # (CR-01: previously a TODO — now mandatory).
        _verify_tst_signature(content_info, tsa_cert_path)

        logger.info(
            "TST verified (signature checked): genTime=%s, serial=%s",
            gen_time.isoformat(), serial,
        )

        return gen_time

    except TSAError:
        raise
    except Exception as exc:
        raise TSAError(f"Failed to verify TST token: {exc}") from exc


def _verify_tst_signature(
    content_info: "cms.ContentInfo", tsa_cert_path: str
) -> None:
    """Verify the CMS signature of a TST against the TSA certificate.

    Handles both SignerInfo forms: without signed attributes the
    signature covers the DER-encoded TSTInfo directly; with signed
    attributes it covers the SET-OF-retagged attributes, whose
    message-digest attribute must in turn match the TSTInfo digest.

    Raises:
        TSAError: On any mismatch or verification failure (fail-closed).
    """
    import hashlib as _hashlib

    from cryptography import x509 as c_x509
    from cryptography.hazmat.primitives import hashes as c_hashes
    from cryptography.hazmat.primitives.asymmetric import padding as c_padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    with open(tsa_cert_path, "rb") as f:
        cert = c_x509.load_pem_x509_certificate(f.read())
    public_key = cert.public_key()
    if not isinstance(public_key, RSAPublicKey):
        raise TSAError("Unsupported TSA key type (RSA required)")

    signed_data = content_info["content"]
    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) < 1:
        raise TSAError("TST token contains no SignerInfo")
    signer_info = signer_infos[0]

    digest_alg = signer_info["digest_algorithm"]["algorithm"].native
    if digest_alg not in ("sha256", "sha384", "sha512"):
        raise TSAError(f"Unsupported TST digest algorithm: {digest_alg}")
    hash_cls = {
        "sha256": c_hashes.SHA256,
        "sha384": c_hashes.SHA384,
        "sha512": c_hashes.SHA512,
    }[digest_alg]

    tst_info_der = signed_data["encap_content_info"]["content"].parsed.dump()
    signature = signer_info["signature"].native

    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None:
        # No signed attributes: signature covers the TSTInfo directly.
        signed_payload = tst_info_der
    else:
        # Signed attributes present: message-digest attribute must match
        # the TSTInfo digest, and the signature covers the attributes
        # re-tagged as a universal SET OF (RFC 5652 5.4).
        md_values = [
            attr["values"][0].native
            for attr in signed_attrs
            if attr["type"].native == "message_digest"
        ]
        if not md_values:
            raise TSAError("Signed attributes lack message_digest")
        expected_md = _hashlib.new(digest_alg, tst_info_der).digest()
        if md_values[0] != expected_md:
            raise TSAError("message_digest attribute mismatch")
        attrs_der = signed_attrs.dump()
        signed_payload = b"\x31" + attrs_der[1:]

    try:
        public_key.verify(
            signature,
            signed_payload,
            c_padding.PKCS1v15(),
            hash_cls(),
        )
    except Exception as exc:
        raise TSAError(f"TST signature verification failed: {exc}") from exc


def request_timestamp_verified(
    data_hash: bytes,
    tsa_url: str,
    tsa_cert_path: str,
) -> datetime:
    """Request a timestamp and fully verify the response (fail-closed).

    Sends an RFC 3161 TSQ carrying a fresh random nonce, then verifies on
    the response: TSA status, message-imprint equality with the request
    hash, nonce echo inside the signed TSTInfo, and the CMS signature
    against the TSA certificate. Any failure raises.

    Args:
        data_hash: SHA-256 hash (32 bytes) the TSA must bind.
        tsa_url: TSA endpoint URL.
        tsa_cert_path: PEM path of the TSA certificate to verify against.

    Returns:
        The verified genTime as a timezone-aware datetime.

    Raises:
        TSAError: On any transport, parse, or verification failure.
    """
    _require_tsa_config(tsa_url, tsa_cert_path)
    nonce = _fresh_nonce()
    tst_token = _send_tsq(_build_tsq(data_hash, nonce=nonce), tsa_url)
    _content_info, tst_info = _check_verified_tst(
        tst_token, data_hash, nonce, tsa_cert_path
    )
    return _gen_time_of(tst_info)


def request_timestamp_verified_token(
    data_hash: bytes,
    tsa_url: str,
    tsa_cert_path: str,
) -> VerifiedTimestamp:
    """Like :func:`request_timestamp_verified`, also returning the token.

    Performs the same fail-closed checks (fresh nonce echoed in the signed
    TSTInfo, message-imprint equality, CMS signature against the pinned
    TSA certificate) and additionally requires the imprint algorithm to
    be SHA-256. The verified DER token is returned so a release decision
    can be audited and the evidence re-verified later.

    Args:
        data_hash: SHA-256 hash (32 bytes) the TSA must bind.
        tsa_url: TSA endpoint URL.
        tsa_cert_path: PEM path of the TSA certificate to verify against.

    Returns:
        The verified genTime, token bytes, nonce and TSA serial number.

    Raises:
        TSAError: On any transport, parse, or verification failure.
    """
    _require_tsa_config(tsa_url, tsa_cert_path)
    nonce = _fresh_nonce()
    tst_token = _send_tsq(_build_tsq(data_hash, nonce=nonce), tsa_url)
    _content_info, tst_info = _check_verified_tst(
        tst_token, data_hash, nonce, tsa_cert_path
    )
    algorithm = tst_info["message_imprint"]["hash_algorithm"]["algorithm"]
    if algorithm.native != "sha256":
        raise TSAError("TST messageImprint hash algorithm is not SHA-256")
    return VerifiedTimestamp(
        gen_time=_gen_time_of(tst_info),
        token=tst_token,
        nonce=nonce,
        serial_number=int(tst_info["serial_number"].native),
    )


def request_timestamp_trusted(
    data_hash: bytes,
    tsa_url: str,
    profile: TsaTrustProfile,
    *,
    at: Optional[datetime] = None,
) -> VerifiedTimestamp:
    """Request a fresh token and accept it only under a pinned TSA profile.

    The TSA call of the time-locked release path (stage E, E2b). The
    profile's files and policy OID are checked before the TSA is
    contacted; the request carries a fresh 64-bit nonce; the response is
    accepted only by
    :func:`~desktop.signature.tsa_profile.verify_trusted_token` (binding,
    chain to a pinned TSA CA, EKU, ESS, signature, validity, policy OID,
    accuracy).

    Args:
        data_hash: SHA-256 hash (32 bytes) the TSA must bind.
        tsa_url: TSA endpoint URL.
        profile: Pinned TSA CA(s), policy OID and optional leaf pin.
        at: Verification time for certificate validity (default: now).

    Returns:
        The verified token with its genTime, accuracy and policy OID.

    Raises:
        TSAError: Always with a stable ``code``: ``tsa_config``,
            ``tsa_transport`` (no usable response), or the code of the
            failed token check.
    """
    if not tsa_url:
        raise TSAError("TSA URL is required", code=TSA_CONFIG)
    if not isinstance(data_hash, bytes) or len(data_hash) != 32:
        raise TSAError("the data hash must be a 32-byte SHA-256 value",
                       code=TSA_IMPRINT)
    loaded = load_trust_profile(profile)  # refuse before any network traffic
    nonce = _fresh_nonce()
    tsq = _build_tsq(data_hash, nonce=nonce)
    try:
        tst_token = _send_tsq(tsq, tsa_url)
    except TSAError as exc:
        raise TSAError(str(exc), code=exc.code or TSA_TRANSPORT) from exc
    return verify_trusted_token(tst_token, data_hash, nonce, loaded, at=at)


def _require_tsa_config(tsa_url: str, tsa_cert_path: str) -> None:
    """Refuse to contact a TSA without an URL and a pinned certificate."""
    if not tsa_url:
        raise TSAError("TSA URL is required")
    if not tsa_cert_path:
        raise TSAError("TSA certificate path is required")


def _fresh_nonce() -> int:
    """Draw a fresh 64-bit RFC 3161 request nonce."""
    import secrets

    return secrets.randbits(64)


def _check_verified_tst(
    tst_token: bytes,
    data_hash: bytes,
    nonce: int,
    tsa_cert_path: str,
) -> tuple["cms.ContentInfo", "tsp.TSTInfo"]:
    """Structure, imprint, nonce-echo and signature checks (in order).

    Raises:
        TSAError: On the first failed check (fail-closed).
    """
    content_info = cms.ContentInfo.load(tst_token)
    if content_info["content_type"].native != "signed_data":
        raise TSAError("TST token is not CMS signed_data")
    signed_data = content_info["content"]
    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise TSAError("TST token does not encapsulate tst_info")
    tst_info = tsp.TSTInfo.load(encap["content"].parsed.dump())

    imprint = tst_info["message_imprint"]["hashed_message"].native
    if not isinstance(imprint, bytes) or not hmac.compare_digest(
        imprint, data_hash
    ):
        raise TSAError("TST messageImprint does not match the request hash")

    echoed = tst_info["nonce"].native
    if echoed != nonce:
        raise TSAError(
            "TST nonce mismatch: expected fresh request nonce, "
            f"got {echoed!r} (possible replay)"
        )

    _verify_tst_signature(content_info, tsa_cert_path)
    return content_info, tst_info


def _gen_time_of(tst_info: "tsp.TSTInfo") -> datetime:
    """Return the TSTInfo genTime as an aware datetime (UTC if naive)."""
    gen_time = tst_info["gen_time"].native
    if gen_time is None:
        raise TSAError("TST token contains no genTime")
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)
    return gen_time
