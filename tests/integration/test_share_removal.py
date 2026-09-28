"""An administrator removes a wrong stored share, audited (stage F, gate fix).

Fable gate review of stage F, finding 1: one share per (seal, slot,
generation), never replaced, so after a reseal one wrong upload into the
slot of the new generation (the earlier generation's share, or garbage)
refused the genuine share for good and the releases that combine the
stored share 1 with the new policy ended in ``commitment_mismatch``. The
tests replay that scenario and its remedy on the standard and the strict
time-locked path, and check the removal's rules: an administrator session,
a reason, POST only, one transaction with its audit row (a failed audit
write removes nothing), no share value on the page or in the log.

Codex review R3: the form names the row the administrator saw, so a stale
form or a repeated POST removes nothing once the genuine share is back
(409; finding 1); a list that cannot be read keeps the 503 and is shown as
unreadable (finding 2); a failed removal logs its reason, and a refused
form is logged (finding 4). Fable re-check, finding 4: one test posts the
removal form as the share page renders it. Not covered: a delete that finds
no row after the select (rowcount), and removals racing uploads, syncs or
releases.

Synthetic data only.
"""

from __future__ import annotations

import logging
import sqlite3
from html.parser import HTMLParser
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.release_pki import (
    load_test_signer,
    make_seal_material,
    tsa_trust_settings,
)
from tests.fixtures.release_web import (
    ADMIN_USERNAME,
    audit_rows,
    login_admin,
    make_release_app,
    post_form,
    recover_standard,
    recovered_key,
    sync_payload,
    sync_seal,
)
from tests.fixtures.share_uploads import (
    MSG_ASK_REMOVAL,
    MSG_SYNC_FIRST,
    share_row_id,
    share_rows,
    take_flashes,
    upload_owner_share,
)

pytestmark = pytest.mark.integration

REMOVE_URL = "/admin/shares/remove"
TIMELOCK_URL = "/investigator/recover-key-timelock"
MSG_TARGET = "봉인 ID, 조각 번호(1-4), 세대"
MSG_REASON = "삭제 사유를 입력해 주세요"
MSG_CHANGED = "화면을 연 뒤 이 칸의 키 조각이 바뀌었습니다"


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


@pytest.fixture()
def app(tmp_path, monkeypatch, release_pki, release_tsa, master_key):
    return make_release_app(
        tmp_path, monkeypatch,
        ca_cert_path=str(release_pki.ca_cert_path),
        master_key_path=master_key,
        tsa_url=release_tsa,
        tsa_cert_path=str(release_pki.tsa_cert_path),
        **tsa_trust_settings(release_pki),
    )


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


def _resealed_with_a_wrong_share(app: Any, seal_id: str, master_key: str,
                                 signer: Any, mode: str = "standard") -> tuple[Any, Any, Any]:
    """Generation 1 synced with its share 1 stored, generation 2 synced, and
    the old share 1 uploaded again, by mistake, into generation 2's slot.
    Returns (generation 1, generation 2, the subject's client)."""
    first, second = (make_seal_material(seal_id=seal_id, master_key_path=master_key,
                                        signer=signer, mode=mode, generation=g)
                     for g in (1, 2))
    client = app.test_client()
    sync_seal(client, app, first)
    subject = app.test_client()
    assert upload_owner_share(subject, seal_id, first.shares[0]).status_code == 302
    assert client.post("/sync/upload-record", json=sync_payload(
        second, event_id=2, event_type="Resealing")).status_code == 200
    assert upload_owner_share(subject, seal_id, first.shares[0]).status_code == 302
    take_flashes(subject)
    return first, second, subject


def _admin(app: Any, username: str = ADMIN_USERNAME) -> Any:
    client = app.test_client()
    login_admin(client, username)
    return client


class _RemovalForms(HTMLParser):
    """The hidden fields of every removal form on the share page."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, str]] = []
        self._current: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag == "form" and values.get("action", "").endswith(REMOVE_URL):
            self._current = {}
        elif tag == "input" and self._current is not None and values.get("type") == "hidden":
            self._current[values["name"]] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def _rendered_forms(client: Any, seal_id: str) -> list[dict[str, str]]:
    parser = _RemovalForms()
    parser.feed(client.get(f"/admin/shares?seal_id={seal_id}").get_data(as_text=True))
    return parser.forms


def _drop_audit_table(app: Any) -> None:
    conn = sqlite3.connect(app.config["SQLITE_PATH"])
    try:
        conn.execute("DROP TABLE share_removal_audit")
        conn.commit()
    finally:
        conn.close()


def _remove(client: Any, seal_id: str, slot: int, generation: int,
            reason: str = "wrong share uploaded after the reseal",
            row_id: int | None = None) -> Any:
    """POST the removal form of one listed share; ``row_id`` defaults to the
    row stored there now (the list the administrator just saw)."""
    if row_id is None:
        row_id = share_row_id(client.application, seal_id, slot, generation)
    return post_form(client, REMOVE_URL, {"seal_id": seal_id, "share_index": str(slot),
                                          "generation": str(generation),
                                          "share_row_id": str(row_id), "reason": reason})


def _removals(app: Any, seal_id: str) -> list[dict]:
    with app.app_context():
        from web.models.share_removal_models import find_share_removals

        return find_share_removals(seal_id)


def _sha256(share: str) -> str:
    import hashlib

    return hashlib.sha256(share.strip().lower().encode("utf-8")).hexdigest()


class TestTheBlockedGenerationAndItsRemedy:
    def test_standard_release_after_the_wrong_share_is_removed(
        self, app, master_key, signer
    ) -> None:
        seal_id = "S-20260928-F7RM01"
        first, second, subject = _resealed_with_a_wrong_share(app, seal_id, master_key, signer)

        refused = upload_owner_share(subject, seal_id, second.shares[0])
        blocked = recover_standard(app.test_client(), second)
        removed = _remove(_admin(app), seal_id, 1, 2)
        stored = upload_owner_share(subject, seal_id, second.shares[0])
        investigator = app.test_client()
        released = recover_standard(investigator, second)

        body = refused.get_data(as_text=True)
        assert refused.status_code == 409 and MSG_SYNC_FIRST in body and MSG_ASK_REMOVAL in body
        assert blocked.status_code == 400
        assert removed.status_code == 302
        assert stored.status_code == 302
        assert released.status_code == 302
        assert recovered_key(investigator, seal_id) == second.key_hex
        assert share_rows(app, seal_id) == [(1, 1, first.shares[0]), (1, 2, second.shares[0])]
        [removal] = _removals(app, seal_id)
        assert (removal["share_index"], removal["generation"], removal["operator"],
                removal["reason"], removal["uploaded_by"]) == (
            1, 2, ADMIN_USERNAME, "wrong share uploaded after the reseal", "suspect")
        assert removal["share_sha256"] == _sha256(first.shares[0])
        assert audit_rows(app, seal_id)[-1]["detail"] == "shares=1+2; share 1 of generation 2"

    def test_strict_time_locked_release_after_the_wrong_share_is_removed(
        self, app, master_key, signer
    ) -> None:
        seal_id = "S-20260928-F7RM02"
        _, second, subject = _resealed_with_a_wrong_share(app, seal_id, master_key, signer,
                                                          mode="strict")

        blocked = post_form(app.test_client(), TIMELOCK_URL,
                            {"seal_id": seal_id, "share_data": second.shares[1]})
        assert _remove(_admin(app), seal_id, 1, 2).status_code == 302
        assert upload_owner_share(subject, seal_id, second.shares[0]).status_code == 302
        investigator = app.test_client()
        released = post_form(investigator, TIMELOCK_URL,
                             {"seal_id": seal_id, "share_data": second.shares[1]})

        assert blocked.status_code == 403
        assert released.status_code == 302
        assert recovered_key(investigator, seal_id) == second.key_hex


class TestTheRemovalsRules:
    def test_an_administrator_session_is_required(self, app, master_key, signer) -> None:
        seal_id = "S-20260928-F7RM03"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        before = share_rows(app, seal_id)

        resp = _remove(app.test_client(), seal_id, 1, 2)

        assert resp.status_code == 302 and resp.headers["Location"].endswith("/admin/login")
        assert share_rows(app, seal_id) == before and _removals(app, seal_id) == []

    @pytest.mark.parametrize("form, message", [
        ({"share_index": "1", "generation": "2", "reason": ""}, MSG_REASON),
        ({"share_index": "1", "generation": "2", "reason": "   "}, MSG_REASON),
        ({"share_index": "1", "generation": "2", "reason": "x" * 2001}, MSG_REASON),
        ({"share_index": "5", "generation": "2", "reason": "r"}, MSG_TARGET),
        ({"share_index": "1", "generation": "-1", "reason": "r"}, MSG_TARGET),
        ({"share_index": "one", "generation": "2", "reason": "r"}, MSG_TARGET),
        ({"share_index": "١", "generation": "2", "reason": "r"}, MSG_TARGET),
        ({"share_index": "1", "generation": "٢", "reason": "r"}, MSG_TARGET),
        ({"share_index": "1", "generation": "2", "share_row_id": "", "reason": "r"},
         MSG_TARGET),
        ({"share_index": "1", "generation": "2", "share_row_id": "0", "reason": "r"},
         MSG_TARGET),
        ({"share_index": "1", "generation": "2", "share_row_id": "x7", "reason": "r"},
         MSG_TARGET),
    ], ids=["no-reason", "blank-reason", "long-reason", "slot-5", "negative-generation",
            "word-slot", "non-ascii-slot-digit", "non-ascii-generation-digit",
            "no-row", "row-0", "word-row"])
    def test_invalid_input_removes_nothing(self, app, master_key, signer, form,
                                           message) -> None:
        seal_id = "S-20260928-F7RM04"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        before = share_rows(app, seal_id)
        row_id = str(share_row_id(app, seal_id, 1, 2))

        resp = post_form(_admin(app), REMOVE_URL,
                         {"seal_id": seal_id, "share_row_id": row_id, **form})

        assert resp.status_code == 400 and message in resp.get_data(as_text=True)
        assert share_rows(app, seal_id) == before and _removals(app, seal_id) == []

    def test_nothing_stored_there_is_404_without_an_audit_row(
        self, app, master_key, signer
    ) -> None:
        seal_id = "S-20260928-F7RM05"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)

        resp = _remove(_admin(app), seal_id, 2, 2, row_id=1)

        assert resp.status_code == 404 and _removals(app, seal_id) == []

    def test_a_failed_audit_write_removes_nothing(self, app, master_key, signer) -> None:
        seal_id = "S-20260928-F7RM06"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        before = share_rows(app, seal_id)
        admin = _admin(app)
        row_id = share_row_id(app, seal_id, 1, 2)
        _drop_audit_table(app)

        resp = _remove(admin, seal_id, 1, 2, row_id=row_id)

        assert resp.status_code == 503
        assert share_rows(app, seal_id) == before
        assert "조각 삭제 기록을 읽을 수 없습니다" in resp.get_data(as_text=True)

    def test_head_removes_nothing(self, app, master_key, signer) -> None:
        seal_id = "S-20260928-F7RM07"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        before = share_rows(app, seal_id)

        resp = _admin(app).open(REMOVE_URL, method="HEAD", data={
            "seal_id": seal_id, "share_index": "1", "generation": "2",
            "share_row_id": str(share_row_id(app, seal_id, 1, 2)), "reason": "r"})

        assert resp.status_code == 405
        assert share_rows(app, seal_id) == before and _removals(app, seal_id) == []

    def test_the_page_and_the_log_carry_no_share_value(
        self, app, master_key, signer, caplog
    ) -> None:
        seal_id = "S-20260928-F7RM08"
        first, _, _ = _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        admin = _admin(app)
        listed = admin.get(f"/admin/shares?seal_id={seal_id}").get_data(as_text=True)
        caplog.set_level(logging.WARNING)

        _remove(admin, seal_id, 1, 2, reason="reason in the log")
        after = admin.get(f"/admin/shares?seal_id={seal_id}").get_data(as_text=True)

        value = first.shares[0].split("-", 1)[1]
        assert "봉인 정책 세대" in listed and value not in listed
        assert value not in after and _sha256(first.shares[0])[:16] in after
        assert "reason in the log" in after
        lines = [r.getMessage() for r in caplog.records if "Share removal" in r.getMessage()]
        assert len(lines) == 1
        assert (f"admin={ADMIN_USERNAME}" in lines[0] and "slot=1" in lines[0]
                and "generation=2" in lines[0] and "reason in the log" in lines[0])
        assert value not in lines[0] and _sha256(first.shares[0]) not in lines[0]

class TestStaleFormsAndStorageFaults:
    """Codex review R3, findings 1, 2 and 4."""

    def test_a_stale_form_leaves_the_genuine_share(
        self, app, master_key, signer, caplog
    ) -> None:
        seal_id = "S-20260928-F7RM09"
        _, second, subject = _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        seen = share_row_id(app, seal_id, 1, 2)  # both administrators list this row
        first_admin, second_admin = _admin(app), _admin(app, "admin-second")
        caplog.set_level(logging.WARNING)

        removed = _remove(first_admin, seal_id, 1, 2, row_id=seen)
        stored = upload_owner_share(subject, seal_id, second.shares[0])
        stale = _remove(second_admin, seal_id, 1, 2, row_id=seen)
        repeated = _remove(first_admin, seal_id, 1, 2, row_id=seen)
        investigator = app.test_client()
        released = recover_standard(investigator, second)

        assert (removed.status_code, stored.status_code) == (302, 302)
        assert stale.status_code == 409 and MSG_CHANGED in stale.get_data(as_text=True)
        assert repeated.status_code == 409
        assert (1, 2, second.shares[0]) in share_rows(app, seal_id)
        assert len(_removals(app, seal_id)) == 1
        assert released.status_code == 302
        assert recovered_key(investigator, seal_id) == second.key_hex
        changed = [r.getMessage() for r in caplog.records
                   if r.getMessage().startswith("Share removal changed")]
        assert len(changed) == 2 and f"row={seen}" in changed[0]

    def test_a_repeated_post_before_the_re_upload_finds_nothing(
        self, app, master_key, signer
    ) -> None:
        seal_id = "S-20260928-F7RM10"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        admin = _admin(app)
        seen = share_row_id(app, seal_id, 1, 2)

        first = _remove(admin, seal_id, 1, 2, row_id=seen)
        again = _remove(admin, seal_id, 1, 2, row_id=seen)

        assert (first.status_code, again.status_code) == (302, 404)
        assert len(_removals(app, seal_id)) == 1

    def test_a_post_without_the_csrf_token_removes_nothing(
        self, app, master_key, signer
    ) -> None:
        seal_id = "S-20260928-F7RM11"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        before = share_rows(app, seal_id)

        resp = _admin(app).post(REMOVE_URL, data={
            "seal_id": seal_id, "share_index": "1", "generation": "2",
            "share_row_id": str(share_row_id(app, seal_id, 1, 2)), "reason": "r"})

        assert resp.status_code == 403
        assert share_rows(app, seal_id) == before and _removals(app, seal_id) == []

    def test_a_disabled_administrator_removes_nothing(self, app, master_key, signer) -> None:
        seal_id = "S-20260928-F7RM12"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        before = share_rows(app, seal_id)
        admin = _admin(app, "admin-disabled")
        with app.app_context():
            from web.auth.admin_auth import disable_admin_account

            disable_admin_account("admin-disabled")

        resp = _remove(admin, seal_id, 1, 2)

        assert resp.status_code == 302 and resp.headers["Location"].endswith("/admin/login")
        assert share_rows(app, seal_id) == before and _removals(app, seal_id) == []

    def test_share_4_and_an_earlier_generation_can_be_removed(
        self, app, master_key, signer
    ) -> None:
        seal_id = "S-20260928-F7RM13"
        first, second, _ = _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        with app.app_context():
            from web.models.share_models import store_key_share

            store_key_share(seal_id, 4, second.shares[3], "admin", generation=2)
        admin = _admin(app)

        older = _remove(admin, seal_id, 1, 1, reason="earlier generation")
        fourth = _remove(admin, seal_id, 4, 2, reason="share 4")

        assert (older.status_code, fourth.status_code) == (302, 302)
        assert share_rows(app, seal_id) == [(1, 2, first.shares[0])]
        assert [(r["share_index"], r["generation"]) for r in _removals(app, seal_id)] == [
            (1, 1), (4, 2)]

    def test_unreadable_lists_keep_the_503(self, app, master_key, signer, monkeypatch) -> None:
        seal_id = "S-20260928-F7RM14"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        before = share_rows(app, seal_id)
        admin = _admin(app)
        row_id = share_row_id(app, seal_id, 1, 2)
        _drop_audit_table(app)

        def broken(*_: Any) -> Any:
            raise RuntimeError("connection lost")

        monkeypatch.setattr("web.routes.admin.find_admin_share_summaries", broken)
        monkeypatch.setattr("web.routes.admin.list_share_summaries", broken)
        removal = _remove(admin, seal_id, 1, 2, row_id=row_id)
        listing = admin.get(f"/admin/shares?seal_id={seal_id}")

        page = removal.get_data(as_text=True)
        assert (removal.status_code, listing.status_code) == (503, 503)
        assert "관리자 키 조각 목록을 읽을 수 없습니다" in page
        assert f"봉인 {seal_id}의 저장 조각을 읽을 수 없습니다" in page
        assert "조각 삭제 기록을 읽을 수 없습니다" in page
        assert "등록된 관리자 키 조각이 없습니다" not in page
        assert "에 저장된 조각이 없습니다" not in page
        assert share_rows(app, seal_id) == before

    def test_a_failed_removal_logs_its_reason(self, app, master_key, signer, caplog) -> None:
        seal_id = "S-20260928-F7RM15"
        first, _, _ = _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        admin = _admin(app)
        row_id = share_row_id(app, seal_id, 1, 2)
        _drop_audit_table(app)
        caplog.set_level(logging.WARNING)

        _remove(admin, seal_id, 1, 2, reason="reason of the failed removal", row_id=row_id)

        [record] = [r for r in caplog.records if "Share removal failed" in r.getMessage()]
        message = record.getMessage()
        assert record.levelno == logging.ERROR
        assert "reason of the failed removal" in message and f"row={row_id}" in message
        assert first.shares[0].split("-", 1)[1] not in message

    def test_a_refused_form_is_logged(self, app, master_key, signer, caplog) -> None:
        seal_id = "S-20260928-F7RM16"
        _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        caplog.set_level(logging.WARNING)

        post_form(_admin(app), REMOVE_URL, {
            "seal_id": seal_id, "share_index": "9", "generation": "2",
            "share_row_id": "1", "reason": "refused reason"})

        [line] = [r.getMessage() for r in caplog.records
                  if r.levelno == logging.WARNING and "Share removal refused" in r.getMessage()]
        assert "(invalid target)" in line and f"admin={ADMIN_USERNAME}" in line
        assert "slot='9'" in line and "refused reason" in line

    def test_the_rendered_form_removes_the_listed_share(
        self, app, master_key, signer
    ) -> None:
        """Fable re-check, finding 4: the fields as the page renders them
        (the CSRF token included) reach the parser under the same names."""
        seal_id = "S-20260928-F7RM17"
        first, second, subject = _resealed_with_a_wrong_share(app, seal_id, master_key, signer)
        admin = _admin(app)
        listed = share_row_id(app, seal_id, 1, 2)

        forms = _rendered_forms(admin, seal_id)
        [form] = [f for f in forms if (f["share_index"], f["generation"]) == ("1", "2")]
        resp = admin.post(REMOVE_URL, data={**form, "reason": "posted from the page"})
        stored = upload_owner_share(subject, seal_id, second.shares[0])

        assert sorted(form) == ["csrf_token", "generation", "seal_id", "share_index",
                                "share_row_id"]
        assert (form["seal_id"], form["share_row_id"]) == (seal_id, str(listed))
        assert (resp.status_code, stored.status_code) == (302, 302)
        assert share_rows(app, seal_id) == [(1, 1, first.shares[0]), (1, 2, second.shares[0])]
        [removal] = _removals(app, seal_id)
        assert (removal["seal_id"], removal["reason"]) == (seal_id, "posted from the page")
