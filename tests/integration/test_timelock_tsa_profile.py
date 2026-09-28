"""Time-locked release under the pinned TSA trust profile (stage E, E2b).

The gate accepts a TSA token only under the profile configured by
RELEASE_TSA_CA_CERT_PATH (the pinned TSA CA), RELEASE_TSA_POLICY_OID and
the optional RELEASE_TSA_CERT_PATH leaf pin, and releases only when
genTime - accuracy >= unlock_time (RFC 3161 section 2.4.2). A TSA failure
is audited as ``tsa_failed`` with the failure code at the start of the
detail; after a verified token the detail names the accuracy and the rule.

Synthetic material only: the session PKI and local TSA, TSA servers on
ephemeral ports, and tokens forged with test keys.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography import x509

from desktop.crypto.local_kms import init_master_key
from desktop.signature import tsa_client, tsa_server
from desktop.signature.ca_setup import issue_tsa_cert
from tests.fixtures.release_pki import (
    load_test_signer,
    load_tsa_key,
    make_seal_material,
    running_tsa,
    running_unauthorized_endpoint,
    tsa_trust_settings,
    write_tsa_credentials,
)
from tests.fixtures.release_web import (
    audit_rows,
    make_release_app,
    post_form,
    recovered_key,
    store_share,
    sync_seal,
)
from tests.fixtures.tsa_forge import (
    ONE_SECOND,
    TokenSpec,
    forging_transport,
    make_ca,
)
from tests.fixtures.tsa_proxy import counting_transport

pytestmark = pytest.mark.integration

TIMELOCK_URL = "/investigator/recover-key-timelock"
RULE = "genTime - accuracy >= unlock_time"


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(tmp_path, monkeypatch, release_pki, release_tsa, master_key):
    # Trust by the pinned CA only: no leaf pin (RELEASE_TSA_CERT_PATH unset).
    return make_release_app(
        tmp_path, monkeypatch,
        ca_cert_path=str(release_pki.ca_cert_path),
        master_key_path=master_key,
        tsa_url=release_tsa,
        **tsa_trust_settings(release_pki),
    )


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


@pytest.fixture()
def tsa_calls(monkeypatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(tsa_client, "_send_tsq",
                        counting_transport(tsa_client._send_tsq, calls))
    return calls


def _ready_seal(app, client, seal_id: str, master_key: str, signer: Any,
                **kwargs: Any):
    seal = make_seal_material(seal_id=seal_id, master_key_path=master_key,
                              signer=signer, **kwargs)
    sync_seal(client, app, seal)
    store_share(app, seal.seal_id, 2, seal.shares[1])
    return seal


def _post(client, seal) -> Any:
    return post_form(client, TIMELOCK_URL,
                     {"seal_id": seal.seal_id, "share_data": seal.shares[1]})


def _last(app, seal_id: str) -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == "timelock"]
    assert rows, f"no timelock audit row for {seal_id}"
    return rows[-1]


def _denied(app, client, seal, reason: str) -> dict:
    assert recovered_key(client, seal.seal_id) is None
    row = _last(app, seal.seal_id)
    assert (row["outcome"], row["reason"]) == ("denied", reason), row
    return row


def _iso_us(moment: datetime) -> str:
    """Policy unlock time with six fractional digits (``...ss.ffffffZ``)."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ===================================================================
# Configuration of the profile
# ===================================================================

class TestProfileConfiguration:
    def test_releases_with_the_ca_pinned_and_no_leaf_pin(
        self, app, client, master_key, signer, tsa_calls
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00001", master_key, signer)

        resp = _post(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex
        assert len(tsa_calls) == 1
        row = _last(app, seal.seal_id)
        assert (row["outcome"], row["reason"]) == ("released", "released")
        assert row["detail"].startswith("shares=2+3; ")
        assert f"tsa rule {RULE}: accuracy=1.000000s, " in row["detail"]
        assert row["tsa_token"] and row["tsa_gen_time"]

    @pytest.mark.parametrize("key", [
        "RELEASE_TSA_URL", "RELEASE_TSA_CA_CERT_PATH", "RELEASE_TSA_POLICY_OID",
    ])
    def test_each_required_key_missing_is_config_missing(
        self, app, client, master_key, signer, tsa_calls, key: str
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00002", master_key, signer)
        app.config[key] = ""

        resp = _post(client, seal)

        assert resp.status_code == 503
        assert tsa_calls == []
        assert key in _denied(app, client, seal, "config_missing")["detail"]

    @pytest.mark.parametrize("key, value", [
        ("RELEASE_TSA_CA_CERT_PATH", "absent-tsa-ca.pem"),
        ("RELEASE_TSA_POLICY_OID", "1.2.x"),
        ("RELEASE_TSA_CERT_PATH", "absent-tsa-leaf.pem"),
    ])
    def test_unusable_runtime_value_is_config_missing(
        self, app, client, master_key, signer, tsa_calls, tmp_path,
        key: str, value: str,
    ) -> None:
        # Start-up validation refuses these; a value changed afterwards
        # still fails closed.
        seal = _ready_seal(app, client, "S-20260928-T00003", master_key, signer)
        app.config[key] = str(tmp_path / value) if value.endswith(".pem") else value

        resp = _post(client, seal)

        assert resp.status_code == 503
        assert tsa_calls == []
        assert key in _denied(app, client, seal, "config_missing")["detail"]


# ===================================================================
# Trust decisions reach the audit trail with their code
# ===================================================================

class TestTrustDecisions:
    def test_tsa_with_another_policy_oid(
        self, app, client, master_key, signer, release_pki
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00010", master_key, signer)
        with running_tsa(release_pki.tsa_key_path, release_pki.tsa_cert_path,
                         policy_oid="1.2.3.4.5.6.7.8.10") as url:
            app.config["RELEASE_TSA_URL"] = url
            resp = _post(client, seal)

        assert resp.status_code == 503
        row = _denied(app, client, seal, "tsa_failed")
        assert row["detail"].startswith("tsa_policy: ")
        assert row["tsa_token"] == ""

    def test_tsa_certificate_from_an_unpinned_ca(
        self, app, client, master_key, signer, tmp_path
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00011", master_key, signer)
        other_key, other_cert = make_ca("E2b Unpinned CA (gate)")
        key_path, cert_path = write_tsa_credentials(
            tmp_path / "rogue", *issue_tsa_cert(other_key, other_cert)
        )
        with running_tsa(key_path, cert_path) as url:
            app.config["RELEASE_TSA_URL"] = url
            resp = _post(client, seal)

        assert resp.status_code == 503
        row = _denied(app, client, seal, "tsa_failed")
        assert row["detail"].startswith("tsa_chain: ")

    def test_rotated_tsa_key_under_the_pinned_ca_is_accepted(
        self, app, client, master_key, signer, release_pki, tmp_path
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00012", master_key, signer)
        key_path, cert_path = write_tsa_credentials(
            tmp_path / "rotated",
            *issue_tsa_cert(release_pki.ca_key, release_pki.ca_cert),
        )
        with running_tsa(key_path, cert_path) as url:
            app.config["RELEASE_TSA_URL"] = url
            resp = _post(client, seal)

        assert resp.status_code == 302
        assert recovered_key(client, seal.seal_id) == seal.key_hex

    def test_leaf_pin_refuses_a_rotated_key(
        self, app, client, master_key, signer, release_pki, tmp_path
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00013", master_key, signer)
        app.config["RELEASE_TSA_CERT_PATH"] = str(release_pki.tsa_cert_path)
        key_path, cert_path = write_tsa_credentials(
            tmp_path / "rotated",
            *issue_tsa_cert(release_pki.ca_key, release_pki.ca_cert),
        )
        with running_tsa(key_path, cert_path) as url:
            app.config["RELEASE_TSA_URL"] = url
            resp = _post(client, seal)

        assert resp.status_code == 503
        row = _denied(app, client, seal, "tsa_failed")
        assert row["detail"].startswith("tsa_chain: ")
        assert "pinned TSA certificate" in row["detail"]

    def test_redirecting_tsa_is_refused_as_transport(
        self, app, client, master_key, signer, release_tsa, monkeypatch
    ) -> None:
        # Fable gate, finding 7: the redirect leads to a working proxy for
        # the real TSA; following it would release the key.
        from tests.fixtures.tsa_http import forward_to, redirect_to, running_endpoint

        seal = _ready_seal(app, client, "S-20260928-T00016", master_key, signer)
        monkeypatch.setattr(tsa_client.time, "sleep", lambda _s: None)
        with running_endpoint(forward_to(release_tsa)) as (target, target_log):
            with running_endpoint(redirect_to(target, 307)) as (url, _log):
                app.config["RELEASE_TSA_URL"] = url
                resp = _post(client, seal)

        assert resp.status_code == 503
        row = _denied(app, client, seal, "tsa_failed")
        assert row["detail"].startswith("tsa_transport: ")
        assert "redirect (HTTP 307)" in row["detail"]
        assert target_log.requests == []

    def test_tsa_url_credentials_do_not_reach_the_audit_row(
        self, app, client, master_key, signer, monkeypatch, caplog
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00015", master_key, signer)
        monkeypatch.setattr(tsa_client.time, "sleep", lambda _s: None)
        with running_unauthorized_endpoint() as port, caplog.at_level("DEBUG"):
            app.config["RELEASE_TSA_URL"] = (
                f"http://tsa-user:Secr3t-Pass@127.0.0.1:{port}/tsa"
            )
            resp = _post(client, seal)

        assert resp.status_code == 503
        row = _denied(app, client, seal, "tsa_failed")
        assert row["detail"].startswith("tsa_transport: ")
        for text in (row["detail"], caplog.text):
            assert "Secr3t-Pass" not in text

    @pytest.mark.parametrize("defect, code", [
        ({"accuracy": None}, "tsa_accuracy_missing"),
        ({"ess": "none"}, "tsa_ess"),
        ({"ess": "no_signed_attrs"}, "tsa_ess"),
    ])
    def test_forged_token_defects_are_audited_with_their_code(
        self, app, client, master_key, signer, release_pki, monkeypatch,
        defect: dict, code: str,
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00014", master_key, signer)
        spec = dataclasses.replace(TokenSpec(
            key=load_tsa_key(release_pki),
            cert=x509.load_pem_x509_certificate(
                release_pki.tsa_cert_path.read_bytes()
            ),
            gen_time=datetime.now(timezone.utc).replace(microsecond=0),
            accuracy=ONE_SECOND,
        ), **defect)
        monkeypatch.setattr(tsa_client, "_send_tsq", forging_transport(spec))

        resp = _post(client, seal)

        assert resp.status_code == 503
        assert _denied(app, client, seal, "tsa_failed")["detail"].startswith(
            f"{code}: "
        )


# ===================================================================
# The accuracy rule: genTime - accuracy >= unlock_time
# ===================================================================

class TestAccuracyRule:
    @pytest.fixture()
    def pinned_clocks(self, monkeypatch) -> datetime:
        """TSA genTime and the release host clock, both pinned to T."""
        import web.release_gate as gate

        moment = (datetime.now(timezone.utc) + timedelta(seconds=5)).replace(
            microsecond=0
        )
        monkeypatch.setattr(tsa_server, "_utc_now", lambda: moment)
        monkeypatch.setattr(gate, "_utc_now", lambda: moment)
        return moment

    @pytest.mark.parametrize("unlock_before_t, released", [
        (timedelta(seconds=1), True),                     # equality releases
        (timedelta(seconds=1, microseconds=-1), False),   # 1 us too early
        (timedelta(0), False),                            # 1 s too early
    ])
    def test_boundary_with_one_second_accuracy(
        self, app, client, master_key, signer, pinned_clocks,
        unlock_before_t: timedelta, released: bool,
    ) -> None:
        unlock = pinned_clocks - unlock_before_t
        seal = _ready_seal(app, client, "S-20260928-T00020", master_key, signer,
                           unlock_time_iso=_iso_us(unlock))

        resp = _post(client, seal)

        row = _last(app, seal.seal_id)
        expected_note = (
            f"tsa rule {RULE}: accuracy=1.000000s, genTime - accuracy="
            f"{(pinned_clocks - timedelta(seconds=1)).isoformat()}, "
            f"unlock_time={unlock.isoformat()}"
        )
        assert expected_note in row["detail"]
        assert row["tsa_gen_time"] == pinned_clocks.isoformat()
        if released:
            assert resp.status_code == 302
            assert recovered_key(client, seal.seal_id) == seal.key_hex
            assert row["reason"] == "released"
        else:
            assert resp.status_code == 403
            _denied(app, client, seal, "tsa_time_before_unlock")

    @pytest.mark.parametrize("unlock_before_t, released", [
        (timedelta(milliseconds=250), True),
        (timedelta(milliseconds=249), False),
    ])
    def test_boundary_with_a_millisecond_accuracy(
        self, app, client, master_key, signer, release_pki, pinned_clocks,
        unlock_before_t: timedelta, released: bool,
    ) -> None:
        seal = _ready_seal(app, client, "S-20260928-T00021", master_key, signer,
                           unlock_time_iso=_iso_us(pinned_clocks - unlock_before_t))
        with running_tsa(release_pki.tsa_key_path, release_pki.tsa_cert_path,
                         accuracy=timedelta(milliseconds=250)) as url:
            app.config["RELEASE_TSA_URL"] = url
            resp = _post(client, seal)

        assert "accuracy=0.250000s" in _last(app, seal.seal_id)["detail"]
        if released:
            assert resp.status_code == 302
            assert recovered_key(client, seal.seal_id) == seal.key_hex
        else:
            assert resp.status_code == 403
            _denied(app, client, seal, "tsa_time_before_unlock")


# ===================================================================
# Evidence after a verified token (Codex round 1, F7)
# ===================================================================

def _raise_injected(*_args: Any, **_kwargs: Any) -> Any:
    raise RuntimeError("injected failure after the TSA check")


class TestEvidenceAfterVerification:
    """An unexpected error after a successful TSA check is denied as
    ``internal_error``, and its one audit row keeps the verified token,
    challenge, genTime and the rule, as every other exit after it does."""

    @pytest.mark.parametrize("target", [
        "find_wrapped_s3_newest_first",   # envelope read (store failure)
        "load_master_key",                # KMS load, an error that is not KMSError
        "s3_wrap_aad",                    # binding of the unwrap
        "_recover_or_none",               # recombination
    ])
    def test_unexpected_error_keeps_the_verified_evidence(
        self, app, client, master_key, signer, release_pki, monkeypatch,
        target: str,
    ) -> None:
        import web.release_gate as gate

        seal = _ready_seal(app, client, "S-20260928-T00030", master_key, signer)
        monkeypatch.setattr(gate, target, _raise_injected)

        resp = _post(client, seal)

        assert resp.status_code == 500
        assert recovered_key(client, seal.seal_id) is None
        [row] = [r for r in audit_rows(app, seal.seal_id)
                 if r["path"] == "timelock"]
        assert (row["outcome"], row["reason"]) == ("denied", "internal_error")
        token = base64.b64decode(row["tsa_token"])
        assert token and row["tsa_token_sha256"] == hashlib.sha256(token).hexdigest()
        assert f"tsa rule {RULE}: accuracy=1.000000s, " in row["detail"]
        stamp = _reverify(token, seal, row["tsa_challenge"], release_pki)
        assert stamp.gen_time == datetime.fromisoformat(row["tsa_gen_time"])


def _reverify(token: bytes, seal: Any, challenge_hex: str, release_pki: Any):
    """The audited token binds this seal's policy and the audited challenge,
    and passes the pinned profile again (nonce read from the token)."""
    from asn1crypto import cms, tsp

    from desktop.signature.seal_policy import release_imprint
    from desktop.signature.tsa_profile import TsaTrustProfile, verify_trusted_token
    from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID

    content = cms.ContentInfo.load(token)["content"]["encap_content_info"]
    nonce = tsp.TSTInfo.load(content["content"].parsed.dump())["nonce"].native
    imprint = release_imprint(seal.policy_digest, bytes.fromhex(challenge_hex))
    profile = TsaTrustProfile(str(release_pki.ca_cert_path),
                              DEFAULT_TSA_POLICY_OID)
    return verify_trusted_token(token, imprint, nonce, profile)
