"""OpenSSL ``ts -verify`` as an independent check of the TSA profile.

Skipped when ``openssl`` is not on PATH. OpenSSL's time-stamp verifier
requires an ESS signing-certificate attribute and a TSA certificate whose
purpose is time stamping (critical EKU, id-kp-timeStamping only, key usage
limited to signing). These tests pair each OpenSSL verdict with a control
that differs in one element, so a failure is attributable to that element,
and check that the pinned-profile verifier agrees.

``scripts/tsa_openssl_crosscheck.py`` runs the same check by hand against
any source tree (including the pre-ESS server of commit 999af1c); its
recorded output is ``docs/R2-stage-E-E2b-openssl-crosscheck.txt``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import requests
from cryptography import x509

from desktop.signature.exceptions import TSAError
from desktop.signature.tsa_client import _build_tsq
from desktop.signature.tsa_profile import TsaTrustProfile, verify_trusted_token
from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID
from tests.fixtures.release_pki import load_tsa_key
from tests.fixtures.tsa_forge import (
    CLIENT_AUTH,
    ONE_SECOND,
    TIME_STAMPING,
    TokenSpec,
    forge_token,
    make_tsa_cert,
)

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl not on PATH")

NONCE = 0x0FED_CBA9_8765_4321
DATA_HASH = hashlib.sha256(b"E2b OpenSSL interop").digest()


def _openssl_verify(work: Path, ca_path: Path, token_or_reply: bytes,
                    *, token: bool) -> str:
    """Run ``openssl ts -verify`` on a query with DATA_HASH and NONCE."""
    (work / "query.tsq").write_bytes(_build_tsq(DATA_HASH, nonce=NONCE))
    (work / "input.der").write_bytes(token_or_reply)
    args = [OPENSSL, "ts", "-verify", "-queryfile", "query.tsq",
            "-in", "input.der", "-CAfile", str(ca_path)]
    run = subprocess.run(args + (["-token_in"] if token else []), cwd=work,
                         capture_output=True, text=True, check=False)
    return run.stdout + run.stderr


def _spec(release_pki: Any, **changes: Any) -> TokenSpec:
    cert = x509.load_pem_x509_certificate(release_pki.tsa_cert_path.read_bytes())
    base = TokenSpec(
        key=load_tsa_key(release_pki), cert=cert,
        gen_time=datetime.now(timezone.utc).replace(microsecond=0),
        accuracy=ONE_SECOND,
    )
    return dataclasses.replace(base, **changes)


def _profile(release_pki: Any) -> TsaTrustProfile:
    return TsaTrustProfile(str(release_pki.ca_cert_path), DEFAULT_TSA_POLICY_OID)


def test_local_tsa_reply_verifies_with_openssl(
    release_pki, release_tsa, tmp_path: Path
) -> None:
    response = requests.post(
        release_tsa, data=_build_tsq(DATA_HASH, nonce=NONCE), timeout=10,
        headers={"Content-Type": "application/timestamp-query"},
    )
    response.raise_for_status()

    output = _openssl_verify(tmp_path, release_pki.ca_cert_path,
                             response.content, token=False)

    assert "Verification: OK" in output, output


@pytest.mark.parametrize("ess, expected", [
    ("v2", "Verification: OK"),                    # the local TSA's format now
    ("no_signed_attrs", "Verification: FAILED"),   # its format before 0a07159
])
def test_openssl_requires_the_ess_attribute(
    release_pki, tmp_path: Path, ess: str, expected: str
) -> None:
    token = forge_token(_spec(release_pki, ess=ess), data_hash=DATA_HASH,
                        nonce=NONCE)

    output = _openssl_verify(tmp_path, release_pki.ca_cert_path, token,
                             token=True)

    assert expected in output, output


@pytest.mark.parametrize("options", [
    {"eku_critical": False},
    {"eku": (TIME_STAMPING, CLIENT_AUTH)},
    {"eku": ()},
    {"encipherment": True},
], ids=["eku_not_critical", "eku_extra_purpose", "no_eku", "key_usage_extra_bit"])
def test_openssl_and_the_profile_reject_the_same_certificates(
    release_pki, tmp_path: Path, options: dict
) -> None:
    key, cert = make_tsa_cert(release_pki.ca_key, release_pki.ca_cert, **options)
    token = forge_token(_spec(release_pki, key=key, cert=cert),
                        data_hash=DATA_HASH, nonce=NONCE)

    output = _openssl_verify(tmp_path, release_pki.ca_cert_path, token,
                             token=True)

    assert "Verification: FAILED" in output, output
    with pytest.raises(TSAError) as info:
        verify_trusted_token(token, DATA_HASH, NONCE, _profile(release_pki))
    assert info.value.code == "tsa_eku"
