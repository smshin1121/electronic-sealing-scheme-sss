"""Share uploads through the web routes, and the stored share rows (stage F, F1).

Synthetic data only. ``upload_owner_share`` stands for the subject: it sets
the session flag the authentication route sets after a successful subject
authentication (``auth_<seal_id>``), as the route tests do, and then posts
the real upload form, so the upload route itself runs unchanged.
``share_rows`` reads ``key_shares`` through the app's own connection, so it
works on SQLite and on MariaDB.
"""

from __future__ import annotations

from typing import Any

from tests.fixtures.release_web import CSRF_TOKEN, post_form

OWNER_URL = "/suspect/upload-share/{seal_id}"
INVESTIGATOR_URL = "/investigator/upload-share"
MSG_IDENTICAL = "이미 저장된 조각과 같습니다"
MSG_SYNC_FIRST = "재봉인 기록이 동기화되었는지 확인하고"
MSG_ASK_REMOVAL = "관리자에게 그 조각의 삭제를 요청해 주세요"


def upload_owner_share(client: Any, seal_id: str, share: str) -> Any:
    """POST the subject's upload form (slot 1) in an authenticated session."""
    with client.session_transaction() as sess:
        sess[f"auth_{seal_id}"] = True
        sess["csrf_token"] = CSRF_TOKEN
    return client.post(OWNER_URL.format(seal_id=seal_id), data={
        "seal_id": seal_id, "share_data": share, "csrf_token": CSRF_TOKEN})


def upload_investigator_share(client: Any, seal_id: str, share: str) -> Any:
    """POST the investigator's upload form (slot 2; no authentication)."""
    return post_form(client, INVESTIGATOR_URL,
                     {"seal_id": seal_id, "share_data": share})


def take_flashes(client: Any) -> list[tuple[str, str]]:
    """The flashed ``(category, message)`` pairs a redirect left in the
    session; they are removed, so the next request starts without them."""
    with client.session_transaction() as sess:
        return [tuple(item) for item in sess.pop("_flashes", [])]


def share_rows(app: Any, seal_id: str) -> list[tuple[int, int, str]]:
    """``(slot, generation, share)`` of every stored share of the seal,
    ordered by slot and generation."""
    with app.app_context():
        from web.models.db_models import execute_query

        rows = execute_query(
            """SELECT share_index, generation, share_data FROM key_shares
               WHERE seal_id = ? ORDER BY share_index, generation""",
            (seal_id,), fetch_all=True,
        ) or []
    values = [(row["share_index"], row["generation"], row["share_data"])
              if hasattr(row, "keys") else tuple(row) for row in rows]
    return [(int(index), int(generation), str(data))
            for index, generation, data in values]


def share_row_id(app: Any, seal_id: str, slot: int, generation: int) -> int:
    """The row id of the share stored for (seal, slot, generation), as the
    administrator's share list shows it (the removal form sends it back)."""
    with app.app_context():
        from web.models.share_removal_models import list_share_summaries

        [row_id] = [share.row_id for share in list_share_summaries(seal_id)
                    if (share.index, share.generation) == (slot, generation)]
    return row_id
