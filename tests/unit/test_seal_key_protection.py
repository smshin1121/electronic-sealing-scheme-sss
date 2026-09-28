"""S7 never stores the signing key without the master-key envelope (stage E, E2f; Fable finding 9).

Before: when the envelope wrap of the subject's signing-key PEM failed at
S7 (the master key unavailable), S7 stored the PEM as it was, protected by
the subject's password only, and said nothing. Now S7 refuses with
``SealKeyProtectionError`` and saves nothing: no record, shares,
certificate or sync intent.

S6 already needs the master key (it wraps shares 3 and 4), so the refusal
concerns a key that became unavailable or unusable between S6 and S7.
Synthetic data only.
"""

from __future__ import annotations

import sqlite3

import pytest

from desktop.crypto.local_kms import decrypt_envelope, init_master_key
from desktop.db import get_key_share, get_seal_record
from desktop.seal_process import SealKeyProtectionError, SealRecordError
from desktop.sync.backends import PORTAL_URL_ENV, WEB_URL_ENV
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.sync_processes import E2E_SEAL_ID, sealing_before_s7
from tests.fixtures.sync_web import StubHttpServer

ACK = (200, {"status": "ok", "message": "동기화 완료"})
CERT_PEM = "synthetic certificate text"
KEY_PEM = b"synthetic signing key, protected by the subject's password"


@pytest.fixture()
def master(tmp_path, monkeypatch) -> str:
    path = str(tmp_path / "master.key")
    init_master_key(path)
    monkeypatch.setenv("MASTER_KEY_PATH", path)
    for name in (WEB_URL_ENV, PORTAL_URL_ENV, "SYNC_SHARED_SECRET"):
        monkeypatch.delenv(name, raising=False)
    return path


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _with_signing_key(process) -> None:
    """S5 produced a certificate and the subject's protected key."""
    process.state["s5"] = {**process.state["s5"], "cert_pem": CERT_PEM,
                           "key_pem": KEY_PEM}


def _certificate_key(db: str) -> bytes | None:
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT key_pem_encrypted FROM certificates WHERE seal_id = ?",
            (E2E_SEAL_ID,)).fetchone()
    return None if row is None else bytes(row[0])


def _outbox_rows(db: str) -> list[tuple]:
    with sqlite3.connect(db) as conn:
        try:
            return conn.execute("SELECT * FROM sync_outbox").fetchall()
        except sqlite3.OperationalError:  # no table: nothing was queued
            return []


def test_s7_refuses_when_the_key_cannot_be_wrapped(
    tmp_path, master, signer, monkeypatch
) -> None:
    db = str(tmp_path / "desktop.db")
    with StubHttpServer([ACK]) as stub:
        monkeypatch.setenv(WEB_URL_ENV, stub.url)
        process = sealing_before_s7(tmp_path, signer, db)  # S6 used the key
        _with_signing_key(process)
        monkeypatch.setenv("MASTER_KEY_PATH", str(tmp_path / "gone.key"))

        with pytest.raises(SealKeyProtectionError, match="마스터 키") as info:
            process.run_s7()

    assert isinstance(info.value, SealRecordError)
    assert "synthetic signing key" not in str(info.value)
    assert get_seal_record(db, E2E_SEAL_ID) is None
    assert get_key_share(db, E2E_SEAL_ID, 3) is None
    assert _certificate_key(db) is None
    assert _outbox_rows(db) == [] and stub.requests == []
    assert "s7" not in process.state


def test_s7_stores_the_key_under_the_master_key(tmp_path, master, signer) -> None:
    """Control: with the key available the stored PEM is the envelope."""
    db = str(tmp_path / "desktop.db")
    process = sealing_before_s7(tmp_path, signer, db)
    _with_signing_key(process)

    process.run_s7()

    stored = _certificate_key(db)
    assert stored is not None and stored != KEY_PEM
    assert decrypt_envelope(stored, master) == KEY_PEM
