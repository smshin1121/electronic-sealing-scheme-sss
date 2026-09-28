"""A HEAD request never runs a form route's POST logic (stage F, F5).

Flask answers HEAD on every route that accepts GET, and the CSRF hook
(:func:`web.app._setup_csrf`) lets GET, HEAD and OPTIONS through without a
token. Until v1.2 the form routes below tested ``request.method == "GET"``
and ran their POST logic for any other method, so a HEAD request with a
form body reached it without a CSRF token (found by F2 on the registration
form, fixed there in F2). Browsers do not send a cross-site HEAD with a
body; this closes the gap for every form route, whatever the client.

Each case sends the form a POST would send, as HEAD without a token, and
checks that nothing the POST would write was written: a login attempt
reservation, a stored share, an audit row or a failed-authentication row.

Synthetic data only.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from tests.fixtures.release_web import ensure_case, login_admin, make_release_app

pytestmark = pytest.mark.integration

SEAL_ID = "S-20260928-F5F5F5"
S1 = "1-" + "ab" * 32
S2 = "2-" + "cd" * 32


@pytest.fixture()
def app(tmp_path, monkeypatch):
    app = make_release_app(tmp_path, monkeypatch)
    ensure_case(app, SEAL_ID)
    return app


def _count(app: Any, table: str) -> int:
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def _subject_client(app: Any) -> Any:
    client = app.test_client()
    with client.session_transaction() as sess:
        sess[f"auth_{SEAL_ID}"] = True
    return client


def _admin_client(app: Any) -> Any:
    client = app.test_client()
    login_admin(client)
    return client


# (route, form, client factory, table the POST would write to)
CASES = [
    ("/admin/login", {"username": "admin-test", "password": "x" * 16},
     lambda app: app.test_client(), "auth_failures"),
    ("/admin/emergency-recover", {"seal_id": SEAL_ID, "reason": "test"},
     _admin_client, "release_audit"),
    ("/investigator/upload-share", {"seal_id": SEAL_ID, "share_data": S2},
     lambda app: app.test_client(), "key_shares"),
    ("/investigator/recover-key", {"seal_id": SEAL_ID, "share_data": S2},
     lambda app: app.test_client(), "release_audit"),
    ("/investigator/recover-key-timelock", {"seal_id": SEAL_ID, "share_data": S2},
     lambda app: app.test_client(), "release_audit"),
    (f"/suspect/auth/{SEAL_ID}",
     {"name": "someone", "birth_date": "19000101", "phone": "0100000000"},
     lambda app: app.test_client(), "auth_failures"),
    ("/suspect/upload-share", {"seal_id": SEAL_ID, "share_data": S1},
     _subject_client, "key_shares"),
    (f"/suspect/upload-share/{SEAL_ID}", {"share_data": S1},
     _subject_client, "key_shares"),
]


@pytest.mark.parametrize("url, form, make_client, table", CASES,
                         ids=[case[0] for case in CASES])
def test_head_with_a_form_body_writes_nothing(app, url, form, make_client, table) -> None:
    client = make_client(app)
    before = _count(app, table)

    resp = client.open(url, method="HEAD", data=form)

    assert resp.status_code == 200
    assert resp.get_data() == b""
    assert _count(app, table) == before


@pytest.mark.parametrize("url, form, make_client, table", CASES,
                         ids=[case[0] for case in CASES])
def test_get_still_shows_the_form(app, url, form, make_client, table) -> None:
    resp = make_client(app).get(url)

    assert resp.status_code == 200
