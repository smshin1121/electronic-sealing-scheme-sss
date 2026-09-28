"""The administrator's removal of a stored key share (stage F, gate fix).

Serves ``POST /admin/shares/remove`` (:mod:`web.routes.admin`), which a
signed-in administrator (E4) submits from the share list of one seal. The
form names the seal, the slot, the policy generation and the row id of the
stored share the administrator saw, and a reason; the share value is never
shown, asked for or logged. The removal and its audit row are one
transaction (:func:`web.models.share_removal_models.remove_key_share`); a
failure removes nothing (503). When another share occupies the slot and
generation by then (the form was stale, or a POST was repeated after the
genuine share was uploaded again), nothing is removed either (409; Codex
review R3, finding 1).

Why it exists: the upload routes keep the first share stored for a slot
and generation (:mod:`web.share_upload`), so a wrong share uploaded into
the slot of the seal's current generation blocked the genuine one (Fable
gate review of stage F, finding 1). After the removal the genuine share can
be uploaded again.

What this module logs, with the administrator, the seal, the slot, the
generation, the expected row and the reason (``%r``, clipped), never a
share value or digest: a form it refuses (400) at WARNING; every answer of
the model (removed, not found, changed) at WARNING; a storage failure at
ERROR with its traceback. A request turned away before it (no signed-in
administrator, or a failed CSRF check) is not logged here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .models.share_models import MAX_GENERATION, SHARE_SLOTS
from .models.share_removal_models import (
    CHANGED,
    MAX_REASON_LENGTH,
    NOT_FOUND,
    remove_key_share,
)

logger = logging.getLogger(__name__)

MAX_SEAL_ID_LENGTH = 64
_LOG_TEXT_LIMIT = 200
_LOG_FIELD_LIMIT = 20

_MSG_REMOVED = ("봉인 {seal_id}의 {slot}번 키 조각(세대 {generation})을 삭제하고 "
                "감사 기록을 남겼습니다. 올바른 조각을 다시 업로드할 수 있습니다.")
_MSG_NOT_FOUND = "해당 봉인·조각 번호·세대에 저장된 키 조각이 없습니다."
_MSG_CHANGED = ("화면을 연 뒤 이 칸의 키 조각이 바뀌었습니다(다른 삭제나 새 업로드). "
                "아무것도 삭제하지 않았습니다. 목록을 다시 조회해 확인해 주세요.")
_MSG_FAILED = ("키 조각을 삭제하지 못했습니다(감사 기록을 남길 수 없거나 저장소 "
               "오류). 아무것도 바뀌지 않았습니다. 잠시 후 다시 시도해 주세요.")
_MSG_INVALID = "봉인 ID, 조각 번호(1-4), 세대(0 이상의 정수)를 확인해 주세요."
_MSG_REASON = f"삭제 사유를 입력해 주세요({MAX_REASON_LENGTH}자 이하)."


@dataclass(frozen=True)
class RemovalAnswer:
    """The route's answer: HTTP status, flash category and message, and the
    seal to show next (``''`` when the form named none)."""

    status: int
    category: str
    message: str
    seal_id: str = ""


def remove_from_form(form: Mapping[str, Any], operator: str) -> RemovalAnswer:
    """Validate the removal form, remove the share and answer."""
    seal_id = str(form.get("seal_id") or "").strip()
    slot = _int(form.get("share_index"))
    generation = _int(form.get("generation"))
    row_id = _int(form.get("share_row_id"))
    reason = str(form.get("reason") or "").strip()
    if (not seal_id or len(seal_id) > MAX_SEAL_ID_LENGTH or slot not in SHARE_SLOTS
            or generation is None or not 0 <= generation <= MAX_GENERATION
            or row_id is None or row_id < 1):
        _log_refusal(form, operator, "invalid target")
        return RemovalAnswer(400, "danger", _MSG_INVALID, seal_id[:MAX_SEAL_ID_LENGTH])
    if not reason or len(reason) > MAX_REASON_LENGTH:
        _log_refusal(form, operator, "invalid reason")
        return RemovalAnswer(400, "danger", _MSG_REASON, seal_id)
    target = (operator, seal_id[:_LOG_TEXT_LIMIT], slot, generation, row_id,
              reason[:_LOG_TEXT_LIMIT])
    try:
        removal = remove_key_share(
            seal_id, slot, generation, expected_row_id=row_id, operator=operator,
            reason=reason,
            removed_at=datetime.now(tz=timezone.utc).isoformat(timespec="seconds"))
    except Exception:  # the audit row or the delete failed: rolled back
        logger.exception("Share removal failed, nothing removed: admin=%s seal_id=%r "
                         "slot=%s generation=%s row=%s reason=%r", *target)
        return RemovalAnswer(503, "danger", _MSG_FAILED, seal_id)
    logger.warning("Share removal %s: admin=%s seal_id=%r slot=%s generation=%s "
                   "row=%s reason=%r", removal.status, *target)
    if removal.status == NOT_FOUND:
        return RemovalAnswer(404, "warning", _MSG_NOT_FOUND, seal_id)
    if removal.status == CHANGED:
        return RemovalAnswer(409, "warning", _MSG_CHANGED, seal_id)
    return RemovalAnswer(200, "success", _MSG_REMOVED.format(
        seal_id=seal_id, slot=slot, generation=generation), seal_id)


def _log_refusal(form: Mapping[str, Any], operator: str, why: str) -> None:
    """A refused form at WARNING, its fields as submitted (``%r``, clipped)."""
    def raw(name: str, limit: int = _LOG_FIELD_LIMIT) -> str:
        return str(form.get(name) or "")[:limit]

    logger.warning("Share removal refused (%s): admin=%s seal_id=%r slot=%r "
                   "generation=%r row=%r reason=%r", why, operator,
                   raw("seal_id", _LOG_TEXT_LIMIT), raw("share_index"),
                   raw("generation"), raw("share_row_id"),
                   raw("reason", _LOG_TEXT_LIMIT))


def _int(value: Any) -> Any:
    """A decimal integer from a form field, else ``None``."""
    text = str(value if value is not None else "").strip()
    return int(text) if text.isascii() and text.isdigit() and len(text) <= 10 else None
