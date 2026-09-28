"""Flask helpers for the release-gate tests (synthetic data only)."""

from __future__ import annotations

import functools
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Optional

import pytest

CSRF_TOKEN = "test-csrf-token"  # public-test-fixture
STANDARD_URL = "/investigator/recover-key"


def make_release_app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ca_cert_path: Optional[str] = None,
    master_key_path: Optional[str] = None,
    tsa_url: Optional[str] = None,
    tsa_cert_path: Optional[str] = None,
    require_policy: bool = False,
    tsa_ca_cert_path: Optional[str] = None,
    tsa_policy_oid: Optional[str] = None,
) -> Any:
    """Create a testing app on a fresh SQLite DB with release config.

    ``tsa_cert_path`` is the optional TSA leaf pin; ``tsa_ca_cert_path``
    and ``tsa_policy_oid`` form the pinned TSA trust profile (stage E).
    """
    db_path = str(tmp_path / "release_web.db")
    monkeypatch.setenv("USE_SQLITE", "true")
    monkeypatch.setenv("SQLITE_PATH", db_path)

    from web.config import TestingConfig

    monkeypatch.setattr(TestingConfig, "SQLITE_PATH", db_path)
    from web.app import create_app

    app = create_app("testing")
    app.config.update(
        POLICY_CA_CERT_PATH=ca_cert_path or "",
        RELEASE_KMS_MASTER_KEY_PATH=master_key_path or "",
        RELEASE_TSA_URL=tsa_url or "",
        RELEASE_TSA_CERT_PATH=tsa_cert_path or "",
        RELEASE_REQUIRE_POLICY=require_policy,
        RELEASE_TSA_CA_CERT_PATH=tsa_ca_cert_path or "",
        RELEASE_TSA_POLICY_OID=tsa_policy_oid or "",
    )
    return app


def ensure_case(app: Any, seal_id: str) -> None:
    """Insert the parent case row required by the FK constraints."""
    with app.app_context():
        from web.models.db_models import find_case_by_seal_id, insert_case

        if not find_case_by_seal_id(seal_id):
            insert_case(
                seal_id=seal_id,
                case_number="2026-TL-001",
                investigator="수사관",
                suspect_name="홍길동",
            )


def store_share(app: Any, seal_id: str, index: int, share: str) -> None:
    """Store a submitted share (s1 by the subject, s2 by the investigator)."""
    uploaded_by = {1: "suspect", 2: "investigator", 4: "admin"}[index]
    with app.app_context():
        from web.models.db_models import insert_key_share

        insert_key_share(seal_id, index, share, uploaded_by)


def sync_payload(
    material: Any,
    *,
    event_id: int = 1,
    event_type: str = "Sealing",
    record: Optional[dict] = None,
    wrapped_s3_b64: Optional[str] = None,
    include_wrapped: bool = True,
) -> dict:
    """Build the /sync/upload-record body for a synthetic seal."""
    body: dict[str, Any] = {
        "seal_id": material.seal_id,
        "event_id": event_id,
        "event_type": event_type,
        "record_json": json.dumps(
            record if record is not None else material.record,
            ensure_ascii=False,
        ),
    }
    if include_wrapped:
        body["wrapped_s3"] = wrapped_s3_b64 or material.wrapped_s3_b64
    return body


def sync_seal(client: Any, app: Any, material: Any, **kwargs: Any) -> Any:
    """Create the case and sync the record (+ wrapped s3) via the route."""
    ensure_case(app, material.seal_id)
    resp = client.post("/sync/upload-record", json=sync_payload(material, **kwargs))
    assert resp.status_code == 200, resp.get_json()
    return resp


def store_record_out_of_band(
    app: Any,
    material: Any,
    *,
    record: Optional[dict] = None,
    event_id: int = 1,
    event_type: str = "Sealing",
    wrapped_s3: Optional[bytes] = None,
) -> None:
    """Insert a record (and wrapped s3) directly, bypassing the sync checks.

    Stands for rows the sync route never vetted: written before it
    verified policies, by a host without a pinned CA, or by DB access.
    """
    ensure_case(app, material.seal_id)
    record_json = json.dumps(
        record if record is not None else material.record, ensure_ascii=False
    )
    with app.app_context():
        from web.models.db_models import insert_seal_record
        from web.models.release_models import insert_seal_record_with_wrapped_s3

        if wrapped_s3 is None:
            insert_seal_record(material.seal_id, event_id, event_type,
                               record_json)
        else:
            insert_seal_record_with_wrapped_s3(
                seal_id=material.seal_id, event_id=event_id,
                event_type=event_type, record_json=record_json,
                record_pdf=None, wrapped_s3=wrapped_s3,
            )


def post_form(client: Any, url: str, data: dict[str, str]) -> Any:
    """POST a form with a valid CSRF token in the session."""
    with client.session_transaction() as sess:
        sess["csrf_token"] = CSRF_TOKEN
    return client.post(url, data={**data, "csrf_token": CSRF_TOKEN})


def recover_standard(client: Any, material: Any, share: Optional[str] = None) -> Any:
    """POST the standard recovery form, presenting ``share`` (default: s2)."""
    presented = material.shares[1] if share is None else share
    return post_form(client, STANDARD_URL,
                     {"seal_id": material.seal_id, "share_data": presented})


ADMIN_USERNAME = "admin-test"


@functools.lru_cache(maxsize=1)
def _fixture_admin_hash() -> str:
    """One scrypt hash of a random, discarded password (once per session)."""
    from web.auth.passwords import hash_password

    return hash_password(secrets.token_urlsafe(24))


def login_admin(client: Any, username: str = ADMIN_USERNAME) -> str:
    """Sign the test client in as a named administrator; returns the username.

    The account is created in the client's app if missing (idempotent),
    with a password nobody knows, and the session is set as the login
    route sets it: account id and username.
    """
    from datetime import datetime, timezone

    with client.application.app_context():
        from web.models.admin_models import (
            find_admin_account_by_username,
            insert_admin_account,
        )

        account = find_admin_account_by_username(username)
        if account is None:
            insert_admin_account(
                username, _fixture_admin_hash(),
                datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            )
            account = find_admin_account_by_username(username)
    assert account is not None
    with client.session_transaction() as sess:
        sess["admin_id"] = account.id
        sess["admin_username"] = account.username
    return account.username


def create_admin(app: Any, username: str) -> str:
    """Create an administrator with a fresh random password; returns it."""
    password = secrets.token_urlsafe(18)
    with app.app_context():
        from web.auth.admin_auth import create_admin_account

        create_admin_account(username, password)
    return password


def login_with_password(client: Any, username: str, password: str) -> Any:
    """POST the admin login form."""
    return post_form(client, "/admin/login",
                     {"username": username, "password": password})


def login_from(client: Any, ip: str, username: str, password: str) -> Any:
    """POST the admin login form from a given client address (REMOTE_ADDR)."""
    with client.session_transaction() as sess:
        sess["csrf_token"] = CSRF_TOKEN
    return client.post(
        "/admin/login",
        data={"username": username, "password": password, "csrf_token": CSRF_TOKEN},
        environ_base={"REMOTE_ADDR": ip},
    )


class SlowDerivations:
    """Stand-in for ``web.auth.passwords._derive``: slows each derivation
    down so concurrent requests overlap, and counts calls and peak overlap."""

    def __init__(self, real: Any, delay: float) -> None:
        self._real = real
        self._delay = delay
        self._lock = threading.Lock()
        self._active = 0
        self.calls = 0
        self.peak = 0

    def __call__(self, *args: Any) -> bytes:
        with self._lock:
            self.calls += 1
            self._active += 1
            self.peak = max(self.peak, self._active)
        try:
            time.sleep(self._delay)
            return self._real(*args)
        finally:
            with self._lock:
                self._active -= 1


def login_burst(app: Any, logins: list[tuple[str, str, str]]) -> list[tuple[int, str]]:
    """POST the ``(ip, username, password)`` logins at the same moment, one
    thread and test client each; returns ``(status, page text)`` in order."""
    barrier = threading.Barrier(len(logins))
    replies: list[tuple[int, str]] = [(0, "")] * len(logins)

    def send(index: int, ip: str, username: str, password: str) -> None:
        client = app.test_client()
        barrier.wait(timeout=30)
        resp = login_from(client, ip, username, password)
        replies[index] = (resp.status_code, resp.get_data(as_text=True))

    threads = [threading.Thread(target=send, args=(i, *login))
               for i, login in enumerate(logins)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert not any(thread.is_alive() for thread in threads), "a login hung"
    assert all(status for status, _ in replies), f"a login raised: {replies}"
    return replies


def admin_login_failures(app: Any, ip: str) -> int:
    """Failed admin logins recorded in ``auth_failures`` for a client address."""
    with app.app_context():
        from web.models.db_models import count_recent_auth_failures
        from web.routes.admin import _LOGIN_FAILURE_KEY

        return count_recent_auth_failures(_LOGIN_FAILURE_KEY, ip, 3600)


def admin_login_pending(app: Any, ip: str) -> int:
    """Admin login reservations of a client address still in progress."""
    with app.app_context():
        from web.models.db_models import count_recent_auth_failures
        from web.routes.admin import _LOGIN_PENDING_KEY

        return count_recent_auth_failures(_LOGIN_PENDING_KEY, ip, 3600)


def add_pending_logins(app: Any, ip: str, count: int) -> None:
    """Stand for ``count`` admin logins of the address still being checked."""
    with app.app_context():
        from web.models.db_models import record_auth_failure
        from web.routes.admin import _LOGIN_PENDING_KEY

        for _ in range(count):
            record_auth_failure(_LOGIN_PENDING_KEY, ip)


def recovered_key(client: Any, seal_id: str) -> Optional[str]:
    """The key the route stored in the session, if any."""
    with client.session_transaction() as sess:
        return sess.get(f"recovered_key_{seal_id}")


def audit_rows(app: Any, seal_id: str) -> list[dict]:
    """All release-audit rows for a seal, oldest first."""
    with app.app_context():
        from web.models.release_models import find_release_audit

        return find_release_audit(seal_id)
