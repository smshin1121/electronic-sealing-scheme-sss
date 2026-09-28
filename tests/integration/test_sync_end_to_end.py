"""Generations end to end (stage E, E2a).

The real sealing and resealing processes save their records, and their
sync hook queues each one and pushes it, signed, to the reference web
application served over HTTP with ``SYNC_REQUIRE_SIGNATURE`` on. Sealing
gives policy generation 1, resealing generation 2, the server's
high-water mark follows, and the release gate decides on generation 2.

Synthetic material only (test CA, temporary master keys, loopback server).
"""

from __future__ import annotations

import json

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.release_web import (
    audit_rows,
    ensure_case,
    make_release_app,
    recover_standard,
    recovered_key,
    store_share,
)
from tests.fixtures.sync_web import high_water, live_server, require_signatures

pytestmark = pytest.mark.integration

URL = "/sync/upload-record"


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(tmp_path, monkeypatch, release_pki, master_key):
    return make_release_app(tmp_path, monkeypatch,
                            ca_cert_path=str(release_pki.ca_cert_path),
                            master_key_path=master_key)


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _last(app, seal_id: str, path: str = "standard") -> dict:
    rows = [r for r in audit_rows(app, seal_id) if r["path"] == path]
    assert rows, f"no {path} audit row"
    return rows[-1]


class _Presented:
    """The two attributes ``recover_standard`` reads from a seal."""

    def __init__(self, seal_id: str, s2: str) -> None:
        self.seal_id = seal_id
        self.shares = ("", s2, "", "")


def test_seal_sync_reseal_sync_releases_on_generation_two(
    app, tmp_path, monkeypatch, signer, master_key, release_pki
) -> None:
    from desktop.signature.seal_policy import (
        load_ca_certificates,
        policy_digest,
        verify_policy,
    )
    from desktop.sync import SyncClient
    from tests.fixtures.sync_processes import (
        E2E_SEAL_ID,
        RESEAL_KEY_HEX,
        reseal_through_process,
        seal_through_process,
    )

    require_signatures(app)
    ensure_case(app, E2E_SEAL_ID)
    monkeypatch.setenv("MASTER_KEY_PATH", master_key)
    monkeypatch.delenv("ENC_ENVELOPE_SYNC_PORTAL_URL", raising=False)
    db_path = str(tmp_path / "desktop.db")
    with live_server(app) as (url, counter):
        monkeypatch.setenv("ENC_ENVELOPE_SYNC_WEB_URL", url)
        sealed = seal_through_process(tmp_path, signer, db_path)
        first_mark = high_water(app, E2E_SEAL_ID)
        resealed = reseal_through_process(
            tmp_path, signer, db_path, json.loads(sealed.record_json),
            monkeypatch)
    outbox = SyncClient(db_path, backends=[]).entries()
    posts = [path for path in counter.calls if path == URL]

    sealed_policy = json.loads(sealed.record_json)["policy"]
    record = json.loads(resealed.record_json)
    verified = verify_policy(
        record["policy"], record["policy_signature"], record["policy_cert"],
        ca_cert=load_ca_certificates(release_pki.ca_cert_path),
        expected_seal_id=E2E_SEAL_ID)
    assert first_mark == (1, policy_digest(sealed_policy).hex(), 1)
    assert verified.generation == 2
    assert high_water(app, E2E_SEAL_ID) == (2, verified.digest_hex, 2)
    assert posts == [URL, URL]
    assert [(e.event_id, e.event_type, e.backend, e.status) for e in outbox] == [
        (1, "Sealing", "web", "sent"), (2, "Resealing", "web", "sent")]

    store_share(app, E2E_SEAL_ID, 1, resealed.key_shares[0])
    client = app.test_client()
    resp = recover_standard(client, _Presented(E2E_SEAL_ID,
                                               resealed.key_shares[1]))

    assert resp.status_code == 302
    assert recovered_key(client, E2E_SEAL_ID) == RESEAL_KEY_HEX
    row = _last(app, E2E_SEAL_ID)
    assert (row["outcome"], row["policy_digest"]) == (
        "released", verified.digest_hex)
