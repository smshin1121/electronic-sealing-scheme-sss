"""Generations end to end (stage E, E2a; stage F, F1); the case from the record (stage F, F2).

The real sealing and resealing processes save their records, and their
sync hook queues each one and pushes it, signed, to the reference web
application served over HTTP with ``SYNC_REQUIRE_SIGNATURE`` on. Sealing
gives policy generation 1, resealing generation 2, the server's
high-water mark follows, and the release gate decides on generation 2.
Since F1 the subject's share 1 may be uploaded after sealing and again
after resealing: each is stored under the generation of its time.

Stage F, F2: with no case registered on the web beforehand, the signed
sealing record creates the case (identity from its ``signer_info``); the
subject authenticates with those values and uploads share 1, and a
standard release succeeds.

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
from tests.fixtures.share_uploads import share_rows, upload_owner_share
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


def test_slot_1_filled_before_the_reseal_releases_on_generation_two(
    app, tmp_path, monkeypatch, signer, master_key
) -> None:
    """The subject uploads share 1 after sealing and the resealed share 1
    after resealing (the upload route, with the session flag of a subject
    authentication); the standard release of generation 2 then combines the
    resealed share 1 with the presented resealed s2. Before F1 the second
    upload was answered as stored but ignored, and this ended in
    ``commitment_mismatch``."""
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
    client = app.test_client()
    with live_server(app) as (url, counter):
        monkeypatch.setenv("ENC_ENVELOPE_SYNC_WEB_URL", url)
        sealed = seal_through_process(tmp_path, signer, db_path)
        first = upload_owner_share(client, E2E_SEAL_ID, sealed.key_shares[0])
        resealed = reseal_through_process(
            tmp_path, signer, db_path, json.loads(sealed.record_json),
            monkeypatch)
        second = upload_owner_share(client, E2E_SEAL_ID, resealed.key_shares[0])
    posts = [path for path in counter.calls if path == URL]

    resp = recover_standard(client, _Presented(E2E_SEAL_ID,
                                               resealed.key_shares[1]))

    assert posts == [URL, URL]
    assert (first.status_code, second.status_code) == (302, 302)
    assert resp.status_code == 302
    assert recovered_key(client, E2E_SEAL_ID) == RESEAL_KEY_HEX
    row = _last(app, E2E_SEAL_ID)
    assert (row["outcome"], row["detail"]) == (
        "released", "shares=1+2; share 1 of generation 2")
    assert share_rows(app, E2E_SEAL_ID) == [
        (1, 1, sealed.key_shares[0]), (1, 2, resealed.key_shares[0])]


def _case_row(app, seal_id: str) -> dict:
    import sqlite3

    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    conn.row_factory = sqlite3.Row
    try:
        [row] = list(conn.execute("SELECT * FROM cases WHERE seal_id = ?",
                                  (seal_id,)))
        return dict(row)
    finally:
        conn.close()


def test_the_signed_record_registers_its_case_and_a_standard_release_follows(
    app, tmp_path, monkeypatch, signer, master_key
) -> None:
    """Stage F, F2: no case is registered on the web beforehand.

    The real sealing process pushes its signed record (switch on); the
    record creates the case with the subject's identity from its
    ``signer_info``, the subject authenticates with those values and
    uploads share 1, and the investigator's standard release succeeds.
    """
    from cryptography.hazmat.primitives import hashes

    from desktop.sync import SyncClient
    from tests.fixtures.privacy_keys import read_pepper
    from tests.fixtures.release_web import post_form
    from tests.fixtures.sync_processes import (
        E2E_SEAL_ID,
        SEAL_KEY_HEX,
        seal_through_process,
    )
    from web.privacy.digests import identity_digest

    require_signatures(app)
    monkeypatch.setenv("MASTER_KEY_PATH", master_key)
    monkeypatch.delenv("ENC_ENVELOPE_SYNC_PORTAL_URL", raising=False)
    db_path = str(tmp_path / "desktop.db")
    with live_server(app) as (url, counter):
        monkeypatch.setenv("ENC_ENVELOPE_SYNC_WEB_URL", url)
        sealed = seal_through_process(tmp_path, signer, db_path)
    outbox = SyncClient(db_path, backends=[]).entries()

    assert [(e.event_id, e.event_type, e.status) for e in outbox] == [
        (1, "Sealing", "sent")]
    assert [path for path in counter.calls if path == URL] == [URL]
    case = _case_row(app, E2E_SEAL_ID)
    fingerprint = signer.cert.fingerprint(hashes.SHA256()).hex()
    assert case["registered_by"] == "sync:" + fingerprint[:16]
    assert (case["case_number"], case["investigator"]) == ("2026-형제-E2A", "Hong")
    pepper = read_pepper(app)
    assert case["suspect_phone_digest"] == identity_digest(
        pepper, "phone", E2E_SEAL_ID, "01000000000")
    assert case["suspect_name"] == "" and case["suspect_email_enc"]

    subject = app.test_client()
    auth = post_form(subject, f"/suspect/auth/{E2E_SEAL_ID}",
                     {"name": "Kim", "birth_date": "1990-01-01",
                      "phone": "010-0000-0000"})
    upload = post_form(subject, f"/suspect/upload-share/{E2E_SEAL_ID}",
                       {"seal_id": E2E_SEAL_ID,
                        "share_data": sealed.key_shares[0]})
    investigator = app.test_client()
    resp = recover_standard(investigator, _Presented(E2E_SEAL_ID,
                                                     sealed.key_shares[1]))

    assert (auth.status_code, upload.status_code, resp.status_code) == (
        302, 302, 302)
    assert recovered_key(investigator, E2E_SEAL_ID) == SEAL_KEY_HEX
    row = _last(app, E2E_SEAL_ID)
    assert row["outcome"] == "released"
