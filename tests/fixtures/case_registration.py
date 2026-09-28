"""Case registration for the stage F, F2 tests (synthetic data only).

Since F2 the registration form needs a signed-in administrator
(:func:`admin_client`), and a signed seal record creates its own case on
its first sync. :func:`creatable_record` adds what that needs to a
synthetic seal's record: the investigator in ``case_info`` and the subject
in ``signer_info``, as the desktop's sealing process writes them.
"""

from __future__ import annotations

from typing import Any, Optional

from tests.fixtures.release_web import ADMIN_USERNAME, login_admin, post_form

REGISTER_URL = "/investigator/register-case"
SYNC_URL = "/sync/upload-record"
CASE_NUMBER = "2026-F2-001"
INVESTIGATOR = "수사관F"
SUBJECT = {
    "name": "정하늘",
    "email": "jung.haneul@example.org",
    "birth_date": "1992-07-15",
    "phone": "010-5823-1946",
}
# Every representation of the synthetic subject: none may be stored in
# plaintext, logged or answered.
IDENTITY_TEXTS = (
    "정하늘", "jung.haneul@example.org", "jung.haneul", "1992-07-15",
    "19920715", "010-5823-1946", "01058231946",
)


def creatable_record(
    material: Any,
    *,
    case_info: Optional[dict] = None,
    signer_info: Optional[dict] = None,
    **extra: Any,
) -> dict:
    """The seal's (signed) record with the fields that create its case."""
    record = dict(material.record)
    case = {**(record.get("case_info") or {}), "investigator": INVESTIGATOR,
            **(case_info or {})}
    signer = {**SUBJECT, "cert_fingerprint": "cd" * 32, **(signer_info or {})}
    return {**record, "case_info": case, "signer_info": signer, **extra}


def without(mapping: dict, key: str) -> dict:
    """A copy of ``mapping`` without ``key``."""
    return {name: value for name, value in mapping.items() if name != key}


def admin_client(app: Any, username: str = ADMIN_USERNAME) -> Any:
    """A new test client signed in as a named administrator.

    The account is created if missing; create it once before requests run
    in parallel (two threads creating it at once would collide).
    """
    client = app.test_client()
    login_admin(client, username)
    return client


def registration_form(seal_id: str, **overrides: str) -> dict[str, str]:
    """The registration form for ``seal_id`` with other identity values."""
    form = {
        "seal_id": seal_id, "case_number": "2026-F2-FORM", "investigator": "수사관G",
        "suspect_name": "한가람", "suspect_email": "han.garam@example.org",
        "suspect_birth": "1985-02-20", "suspect_phone": "010-7777-2020",
        "auth_level": "basic",
    }
    form.update(overrides)
    return form


def register_as_admin(app: Any, form: dict[str, str],
                      username: str = ADMIN_USERNAME) -> Any:
    """POST the registration form from a signed-in administrator's client."""
    return post_form(admin_client(app, username), REGISTER_URL, form)


def slow_case_creation(monkeypatch: Any, delay: float) -> None:
    """Hold every protected case creation for ``delay`` seconds.

    The identity is protected inside the seal's write lock, after the case
    was found missing and before its row is inserted, so two first syncs
    started together both hold the lock (SQLite: one waits) at that point.
    """
    import time

    from web.privacy import case_identity

    real = case_identity.protect_identity

    def slow(*args: Any, **kwargs: Any) -> Any:
        time.sleep(delay)
        return real(*args, **kwargs)

    monkeypatch.setattr(case_identity, "protect_identity", slow)
