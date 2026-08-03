"""RFC 3161 TSA client for requesting and verifying timestamps.

Sends TimeStampReq (TSQ) to a TSA server and receives TimeStampResp (TSR).
Supports retry with exponential backoff and TST token verification.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import requests
from asn1crypto import algos, cms, core, tsp

from .exceptions import TSAError

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 1.0  # seconds

# A TSA on the loopback interface either answers immediately or is
# down — long timeouts and extra retries only delay the fallback.
_LOCAL_TIMEOUT_SECONDS = 2
_LOCAL_MAX_RETRIES = 2
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


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
    try:
        tsr = tsp.TimeStampResp.load(tsr_bytes)
    except Exception as exc:
        raise TSAError(f"Failed to parse TSR: {exc}") from exc

    status = tsr["status"]["status"].native
    if status != "granted" and status != "granted_with_mods":
        fail_info = tsr["status"].get("fail_info")
        status_string = tsr["status"].get("status_string")
        raise TSAError(
            f"TSA request rejected: status={status}, "
            f"fail_info={fail_info}, status_string={status_string}"
        )

    tst_token = tsr["time_stamp_token"]
    if tst_token.native is None:
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


def _send_tsq(tsq_bytes: bytes, tsa_url: str) -> bytes:
    """POST a DER-encoded TSQ and return the extracted TST token."""
    if _is_local_tsa(tsa_url):
        timeout_seconds = _LOCAL_TIMEOUT_SECONDS
        max_retries = _LOCAL_MAX_RETRIES
    else:
        timeout_seconds = _TIMEOUT_SECONDS
        max_retries = _MAX_RETRIES

    last_error: Exception | None = None

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(
                "TSA request attempt %d/%d to %s",
                attempt, max_retries, tsa_url,
            )
            response = requests.post(
                tsa_url,
                data=tsq_bytes,
                headers={"Content-Type": "application/timestamp-query"},
                timeout=timeout_seconds,
            )
            response.raise_for_status()

            content_type = response.headers.get("Content-Type", "")
            if "application/timestamp-reply" not in content_type:
                logger.warning(
                    "Unexpected Content-Type from TSA: %s", content_type
                )

            tst_token = _parse_tsr(response.content)
            logger.info("TST token received successfully (attempt %d)", attempt)
            return tst_token

        except TSAError:
            raise
        except Exception as exc:
            last_error = exc
            if attempt < max_retries:
                wait_time = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning(
                    "TSA request attempt %d failed: %s. Retrying in %.1fs...",
                    attempt, exc, wait_time,
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    "TSA request failed after %d attempts", max_retries
                )

    raise TSAError(
        f"TSA request failed after {max_retries} attempts: {last_error}"
    )


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
    import secrets

    if not tsa_url:
        raise TSAError("TSA URL is required")
    if not tsa_cert_path:
        raise TSAError("TSA certificate path is required")

    nonce = secrets.randbits(64)
    tsq_bytes = _build_tsq(data_hash, nonce=nonce)
    tst_token = _send_tsq(tsq_bytes, tsa_url)

    content_info = cms.ContentInfo.load(tst_token)
    if content_info["content_type"].native != "signed_data":
        raise TSAError("TST token is not CMS signed_data")
    signed_data = content_info["content"]
    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise TSAError("TST token does not encapsulate tst_info")
    tst_info = tsp.TSTInfo.load(encap["content"].parsed.dump())

    imprint = tst_info["message_imprint"]["hashed_message"].native
    if imprint != data_hash:
        raise TSAError("TST messageImprint does not match the request hash")

    echoed = tst_info["nonce"].native
    if echoed != nonce:
        raise TSAError(
            "TST nonce mismatch: expected fresh request nonce, "
            f"got {echoed!r} (possible replay)"
        )

    _verify_tst_signature(content_info, tsa_cert_path)

    gen_time = tst_info["gen_time"].native
    if gen_time is None:
        raise TSAError("TST token contains no genTime")
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)
    return gen_time
