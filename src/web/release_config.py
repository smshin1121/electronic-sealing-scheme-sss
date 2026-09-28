"""Start-up validation of the release-gate configuration.

A configured but unusable pinned CA, KMS master key, TSA certificate,
TSA CA or TSA policy OID refuses to start the web app. Otherwise a wrong
path after a deploy would turn every policy-bearing seal into a runtime
denial on the standard and admin paths, which the design reserves for
tampering. Unset values keep their documented runtime meaning (the
time-locked path denies; without a pinned CA no policy is authenticated).
``RELEASE_REQUIRE_POLICY`` needs a pinned CA, since it denies every record
that is not authenticated.

The TSA trust profile of the time-locked path (stage E, E2b):
``RELEASE_TSA_CA_CERT_PATH`` must hold only certificate-signing CAs,
``RELEASE_TSA_POLICY_OID`` must be a dotted OID, and a TSA certificate pin
(``RELEASE_TSA_CERT_PATH``) must carry a key the verifier accepts (RSA of
at least 2048 bits) and, configured together with the TSA CA, be one the
profile can accept (issued directly by a pinned TSA CA, not a CA,
critical timeStamping-only EKU). Warnings only, since the standard path
must still start: a TSA URL without the CA or the policy OID; a TSA CA
pinned without a TSA certificate pin (every timeStamping certificate the
CA issues is then trusted, so the CA must be dedicated to the TSA); a pin
or CA file with no certificate currently within its validity period.

After this check a runtime read failure is a genuine anomaly, and the
release gate treats it fail-closed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography import x509

from desktop.crypto.local_kms import validate_master_key
from desktop.signature.seal_policy import load_ca_certificates
from desktop.signature.tsa_profile import (
    check_tsa_certificate,
    check_tsa_leaf_key,
    is_dotted_oid,
    load_tsa_ca_certificates,
)

logger = logging.getLogger(__name__)


class ReleaseConfigError(RuntimeError):
    """The release-gate configuration is unusable; the app must not start."""


def validate_release_config(config: Mapping[str, Any]) -> None:
    """Validate the release keys of a Flask config (fail at start-up).

    Raises:
        ReleaseConfigError: Naming the offending key and the reason.
    """
    ca_path = _text(config, "POLICY_CA_CERT_PATH")
    master_path = _text(config, "RELEASE_KMS_MASTER_KEY_PATH")
    if ca_path:
        _check("POLICY_CA_CERT_PATH", lambda: load_ca_certificates(ca_path))
    if master_path:
        _check("RELEASE_KMS_MASTER_KEY_PATH",
               lambda: validate_master_key(master_path))
    _validate_tsa_profile(config)
    if bool(config.get("RELEASE_REQUIRE_POLICY")) and not ca_path:
        raise ReleaseConfigError(
            "RELEASE_REQUIRE_POLICY is set but POLICY_CA_CERT_PATH is not: "
            "no policy could be authenticated, so every release would be denied"
        )


def _validate_tsa_profile(config: Mapping[str, Any]) -> None:
    """TSA CA, policy OID and optional leaf pin of the time-locked path."""
    tsa_cert_path = _text(config, "RELEASE_TSA_CERT_PATH")
    tsa_ca_path = _text(config, "RELEASE_TSA_CA_CERT_PATH")
    policy_oid = _text(config, "RELEASE_TSA_POLICY_OID")
    anchors = None
    if tsa_ca_path:
        anchors = _check("RELEASE_TSA_CA_CERT_PATH",
                         lambda: load_tsa_ca_certificates(tsa_ca_path))
    if policy_oid and not is_dotted_oid(policy_oid):
        raise ReleaseConfigError(
            f"RELEASE_TSA_POLICY_OID is not a dotted OID: {policy_oid!r}"
        )
    if tsa_cert_path:
        pin = _check("RELEASE_TSA_CERT_PATH",
                     lambda: x509.load_pem_x509_certificate(
                         Path(tsa_cert_path).read_bytes()))
        _check("RELEASE_TSA_CERT_PATH", lambda: check_tsa_leaf_key(pin))
        if anchors:
            _check("RELEASE_TSA_CERT_PATH",
                   lambda: check_tsa_certificate(pin, anchors))
        _warn_if_outside_validity("RELEASE_TSA_CERT_PATH", [pin])
    elif anchors:
        logger.warning(
            "RELEASE_TSA_CA_CERT_PATH is set without RELEASE_TSA_CERT_PATH: "
            "every timeStamping certificate this CA issues is trusted, so "
            "the CA must be dedicated to the TSA (or pin the TSA certificate)"
        )
    if anchors:
        _warn_if_outside_validity("RELEASE_TSA_CA_CERT_PATH", anchors)
    if _text(config, "RELEASE_TSA_URL") and not (tsa_ca_path and policy_oid):
        logger.warning(
            "RELEASE_TSA_URL is set but RELEASE_TSA_CA_CERT_PATH and "
            "RELEASE_TSA_POLICY_OID are not both set: the time-locked path "
            "will deny every release (config_missing)"
        )


def _warn_if_outside_validity(key: str, certs: list[x509.Certificate]) -> None:
    """Validity changes with time, so it only warns: the app must start."""
    now = datetime.now(timezone.utc)
    if not any(c.not_valid_before_utc <= now <= c.not_valid_after_utc
               for c in certs):
        logger.warning(
            "%s holds no certificate within its validity period now: the "
            "time-locked path will deny every release until it is replaced", key
        )


def _text(config: Mapping[str, Any], key: str) -> str:
    return str(config.get(key) or "").strip()


def _check(key: str, load: Callable[[], Any]) -> Any:
    try:
        return load()
    except Exception as exc:  # any read/parse failure refuses start-up
        raise ReleaseConfigError(f"{key} is configured but unusable: {exc}") from exc
