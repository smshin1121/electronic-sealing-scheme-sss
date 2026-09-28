"""Strict mode end to end, through a reseal (stage F, F4).

One chained run of the pieces that v1.1 tested separately (strict sealing,
signed sync, web strict release) and of what v1.2 adds (the case created
by the signed record, F2; share slots per policy generation, F1):

  1. the sealing process (its steps S4, S6 and S7; see below) seals in
     strict mode and pushes its signed
     record to the reference web application served over HTTP, with
     ``SYNC_REQUIRE_SIGNATURE`` and ``RELEASE_REQUIRE_POLICY`` on and no
     case registered beforehand: the record creates the case;
  2. the subject authenticates with the identity the record carries and
     uploads share 1 through the subject route;
  3. the investigator's time-locked release (presented s2, the TSA-verified
     unwrap of s3, and in strict mode the stored s1) returns the key;
  4. the resealing process (its steps R6, R7 and R8) reseals (strict
     carried over, policy generation 2, new shares and wrapped s3) and
     pushes its record;
  5. before the subject uploads the resealed share 1, the time-locked and
     the standard release with the resealed s2 are denied: the stored share
     1 of generation 1 does not match the new key's commitment;
  6. the subject uploads the resealed share 1 (stored for generation 2),
     and both the time-locked and the standard releases return the new key.

What runs for real and what is supplied (``tests/fixtures/sync_processes.py``):
S4 (policy signing), S6 (strict split and s3 wrap) and S7 (save, outbox
and signed push) of the sealing process, and R6 (reseal record and policy
of the next generation), R7 (split) and R8 (save and push) of the
resealing process, run as in production. The file encryption and its
result (S1), the signed record PDF (S5), and the loaded record, file
classification and re-encryption state of R1, R2 and R5 are supplied by
the fixture, and the reseal PDF renderer is stubbed; so this run does not
exercise encryption, decryption, PAdES signing or R1's lineage checks,
which have their own tests.

The desktop processes run with their clock an hour back, so that the
unlock time they sign (``unlock_days=0``) is already past for the TSA's
genTime minus its one-second accuracy; the web application and the TSA use
the real clock. The GUI is not part of this run (it has its own tests).

Synthetic material only: test CA, local RFC 3161 TSA, temporary master
keys, loopback server.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.signature import tsa_client
from tests.fixtures.release_pki import load_test_signer, tsa_trust_settings
from tests.fixtures.release_web import (
    audit_rows,
    make_release_app,
    post_form,
    recovered_key,
)
from tests.fixtures.share_uploads import share_rows
from tests.fixtures.sync_web import high_water, live_server, require_signatures
from tests.fixtures.tsa_proxy import counting_transport

pytestmark = pytest.mark.integration

TIMELOCK_URL = "/investigator/recover-key-timelock"
STANDARD_URL = "/investigator/recover-key"
# The subject values of the sealing fixture (tests/fixtures/sync_processes.py).
IDENTITY = {"name": "Kim", "birth_date": "1990-01-01", "phone": "010-0000-0000"}


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(tmp_path, monkeypatch, release_pki, release_tsa, master_key):
    app = make_release_app(
        tmp_path, monkeypatch,
        ca_cert_path=str(release_pki.ca_cert_path),
        master_key_path=master_key,
        tsa_url=release_tsa,
        tsa_cert_path=str(release_pki.tsa_cert_path),
        **tsa_trust_settings(release_pki),
    )
    app.config["RELEASE_REQUIRE_POLICY"] = True
    require_signatures(app)
    return app


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


@pytest.fixture()
def tsa_calls(monkeypatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(tsa_client, "_send_tsq",
                        counting_transport(tsa_client._send_tsq, calls))
    return calls


class _HourEarlier(datetime):
    """``datetime`` of the desktop processes, an hour behind the real clock."""

    @classmethod
    def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
        return datetime.now(tz) - timedelta(hours=1)


def _desktop_clock_an_hour_back(monkeypatch: pytest.MonkeyPatch) -> None:
    import desktop.reseal_process as rp
    import desktop.seal_process as sp

    monkeypatch.setattr(sp, "datetime", _HourEarlier)
    monkeypatch.setattr(rp, "datetime", _HourEarlier)


def _release(app: Any, url: str, seal_id: str, s2: str) -> tuple[int, Any]:
    """One investigator's release request; ``(status, recovered key)``."""
    client = app.test_client()
    resp = post_form(client, url, {"seal_id": seal_id, "share_data": s2})
    return resp.status_code, recovered_key(client, seal_id)


def _last(app: Any, seal_id: str, path: str) -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row"
    return rows[-1]


def _case(app: Any, seal_id: str) -> dict:
    with app.app_context():
        from web.models.db_models import find_case_by_seal_id

        row = find_case_by_seal_id(seal_id)
    return {k: row[k] for k in row.keys()} if row is not None else {}


def test_strict_seal_sync_release_reseal_sync_release(
    app, tmp_path, monkeypatch, signer, master_key
) -> None:
    from desktop.signature.seal_policy import policy_digest
    from tests.fixtures.sync_processes import (
        E2E_SEAL_ID,
        RESEAL_KEY_HEX,
        SEAL_KEY_HEX,
        reseal_through_process,
        seal_through_process,
    )

    _desktop_clock_an_hour_back(monkeypatch)
    monkeypatch.setenv("MASTER_KEY_PATH", master_key)
    monkeypatch.delenv("ENC_ENVELOPE_SYNC_PORTAL_URL", raising=False)
    db_path = str(tmp_path / "desktop.db")
    subject = app.test_client()
    with live_server(app) as (url, _counter):
        monkeypatch.setenv("ENC_ENVELOPE_SYNC_WEB_URL", url)

        # 1-3: strict sealing, the case from the signed record, share 1, release
        sealed = seal_through_process(tmp_path, signer, db_path, seal_mode="strict")
        created = _case(app, E2E_SEAL_ID)
        auth = post_form(subject, f"/suspect/auth/{E2E_SEAL_ID}", IDENTITY)
        first_upload = post_form(subject, f"/suspect/upload-share/{E2E_SEAL_ID}",
                                 {"seal_id": E2E_SEAL_ID,
                                  "share_data": sealed.key_shares[0]})
        first = _release(app, TIMELOCK_URL, E2E_SEAL_ID, sealed.key_shares[1])
        first_row = _last(app, E2E_SEAL_ID, "timelock")

        # 4: strict reseal, pushed
        resealed = reseal_through_process(
            tmp_path, signer, db_path, json.loads(sealed.record_json), monkeypatch)
    sealed_record = json.loads(sealed.record_json)
    resealed_record = json.loads(resealed.record_json)

    # 5: the stored share 1 of generation 1 does not open generation 2
    stale = _release(app, TIMELOCK_URL, E2E_SEAL_ID, resealed.key_shares[1])
    stale_row = _last(app, E2E_SEAL_ID, "timelock")
    stale_standard = _release(app, STANDARD_URL, E2E_SEAL_ID, resealed.key_shares[1])
    stale_standard_row = _last(app, E2E_SEAL_ID, "standard")

    # 6: the resealed share 1, then both release paths
    second_upload = post_form(subject, f"/suspect/upload-share/{E2E_SEAL_ID}",
                              {"seal_id": E2E_SEAL_ID,
                               "share_data": resealed.key_shares[0]})
    timelock = _release(app, TIMELOCK_URL, E2E_SEAL_ID, resealed.key_shares[1])
    timelock_row = _last(app, E2E_SEAL_ID, "timelock")
    standard = _release(app, STANDARD_URL, E2E_SEAL_ID, resealed.key_shares[1])
    standard_row = _last(app, E2E_SEAL_ID, "standard")

    # The seal is strict before and after the reseal, under generations 1 and 2.
    assert (sealed_record["seal_mode"], resealed_record["seal_mode"]) == (
        "strict", "strict")
    assert (sealed_record["policy"]["generation"],
            resealed_record["policy"]["generation"]) == (1, 2)
    assert high_water(app, E2E_SEAL_ID) == (
        2, policy_digest(resealed_record["policy"]).hex(), 2)
    # The case came from the signed record; nothing was registered by hand.
    assert created["registered_by"].startswith("sync:")
    assert (auth.status_code, first_upload.status_code) == (302, 302)
    # Generation 1: s2 + s3 (TSA-verified) + the stored s1.
    assert first == (302, SEAL_KEY_HEX)
    assert first_row["outcome"] == "released"
    assert first_row["detail"].startswith("shares=1+2+3; share 1 of generation 1")
    assert first_row["tsa_token"]
    # Without the resealed share 1 the new key is not released.
    assert stale == (403, None)
    assert (stale_row["outcome"], stale_row["reason"]) == (
        "denied", "commitment_mismatch")
    assert "share 1 of generation 1" in stale_row["detail"]
    assert stale_standard == (400, None)
    assert (stale_standard_row["outcome"], stale_standard_row["reason"]) == (
        "denied", "commitment_mismatch")
    # Generation 2, both paths.
    assert second_upload.status_code == 302
    assert share_rows(app, E2E_SEAL_ID) == [
        (1, 1, sealed.key_shares[0]), (1, 2, resealed.key_shares[0])]
    assert timelock == (302, RESEAL_KEY_HEX)
    assert timelock_row["detail"].startswith("shares=1+2+3; share 1 of generation 2")
    assert standard == (302, RESEAL_KEY_HEX)
    assert standard_row["detail"] == "shares=1+2; share 1 of generation 2"


def test_strict_release_needs_the_owner_share(
    app, tmp_path, monkeypatch, signer, master_key, tsa_calls
) -> None:
    """Institutional shares alone (the presented s2 and the system's s3) do
    not open a strict seal: with no share 1 stored, the time-locked path is
    denied before the TSA is asked, and the standard path is denied too."""
    from tests.fixtures.sync_processes import E2E_SEAL_ID, seal_through_process

    _desktop_clock_an_hour_back(monkeypatch)
    monkeypatch.setenv("MASTER_KEY_PATH", master_key)
    monkeypatch.delenv("ENC_ENVELOPE_SYNC_PORTAL_URL", raising=False)
    db_path = str(tmp_path / "desktop.db")
    with live_server(app) as (url, _counter):
        monkeypatch.setenv("ENC_ENVELOPE_SYNC_WEB_URL", url)
        sealed = seal_through_process(tmp_path, signer, db_path, seal_mode="strict")

    timelock = _release(app, TIMELOCK_URL, E2E_SEAL_ID, sealed.key_shares[1])
    timelock_row = _last(app, E2E_SEAL_ID, "timelock")
    standard = _release(app, STANDARD_URL, E2E_SEAL_ID, sealed.key_shares[1])
    standard_row = _last(app, E2E_SEAL_ID, "standard")

    assert timelock[1] is None and standard[1] is None
    assert (timelock_row["outcome"], timelock_row["reason"]) == (
        "denied", "owner_share_missing")
    assert timelock_row["tsa_token"] == "" and tsa_calls == []
    assert (standard_row["outcome"], standard_row["reason"]) == (
        "denied", "owner_share_missing")
