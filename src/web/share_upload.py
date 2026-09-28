"""Uploads of key shares 1 and 2, versioned by policy generation (stage F, F1).

The subject's route (slot 1, after the subject's authentication;
:mod:`web.routes.suspect`) and the investigator's route (slot 2,
unauthenticated; :mod:`web.routes.investigator`) check and store a share
through this module:

  - Format, checked before the case is looked up and before anything is
    stored: the share is stripped and lower-cased and must be
    ``<slot>-<hex digits>`` with the route's own slot, at most 4096
    characters (the share-file bound of the sync contract, section 5).
    Anything else is refused with 400.
  - Generation: the generation of the seal's newest authenticated policy
    (:func:`web.release_selection.current_generation`: the high-water
    mark's, else the stored maximum as sync admission bootstraps it, else
    0), decided under the seal's write lock in the transaction that stores
    the share. For a seal without a mark the stored records are read
    (decrypted, their policies verified) before that lock is taken, so this
    work never holds it; under the lock the mark is read again, and one
    created meanwhile (by sync admission or a release) decides. The upload
    neither seeds the mark nor enrolls the seal. When the stored records
    cannot be read to find it (a record stored before E3b and not
    converted, or the privacy keys unavailable), nothing is stored (503).
  - Outcome (:func:`web.models.share_models.store_key_share`): stored; the
    same share already stored for that generation (answered as success,
    no new row); or another share stored for it (409, naming the
    generation: a share from a reseal must be uploaded after the resealing
    record has been synchronized, and a wrong share stored first can be
    removed by an administrator, :mod:`web.share_removal`). Success is
    answered only for a share that is stored now or was stored before.

Share values are never logged or echoed: log lines name the seal (``%r``,
clipped), the slot, the generation and the outcome.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from flask import current_app

from .models.release_models import find_record_jsons_newest_first
from .models.share_models import (
    SHARE_CONFLICT,
    SHARE_IDENTICAL,
    ShareWrite,
    store_key_share,
)
from .models.sync_models import find_high_water
from .privacy.keys import PrivacyError
from .release_selection import current_generation, stored_generation

logger = logging.getLogger(__name__)

MAX_SHARE_LENGTH = 4096
_HEX_DIGITS = re.compile(r"[0-9a-f]+")
_MAX_LOG_ID_LEN = 200

_MSG_TOO_LONG = ("키 조각이 너무 깁니다 (최대 4096자). 발급받은 키 조각을 그대로 "
                 "입력해 주세요.")
_MSG_OTHER_SLOT = ("이 화면에서는 {slot}번 키 조각만 올릴 수 있습니다. "
                   "'{slot}-'로 시작하는 키 조각을 입력해 주세요.")
_MSG_NOT_HEX = ("키 조각 형식이 올바르지 않습니다. '{slot}-' 뒤에는 16진수"
                "(0-9, a-f)만 올 수 있습니다.")
_MSG_STORED = {1: "키 조각이 업로드되었습니다.",
               2: "수사관 키 조각이 업로드되었습니다."}
_MSG_IDENTICAL = "이미 저장된 조각과 같습니다. 새로 저장하지 않았습니다."
_MSG_CONFLICT = (
    "이 봉인의 현재 버전(세대 {generation})에는 다른 {slot}번 키 조각이 이미 "
    "저장되어 있어 이 조각을 저장하지 않았습니다. 재봉인으로 새로 받은 키 "
    "조각이라면 재봉인 기록이 동기화되었는지 확인하고 동기화된 뒤에 다시 "
    "업로드해 주세요. 이미 동기화되었거나 잘못된 조각이 먼저 저장된 경우에는 "
    "관리자에게 그 조각의 삭제를 요청해 주세요."
)
_MSG_GENERATION_UNKNOWN = (
    "봉인 기록을 읽을 수 없어 이 봉인의 현재 세대를 확인하지 못했으므로 키 "
    "조각을 저장하지 않았습니다. 관리자에게 문의해 주세요."
)
_MSG_FAILED = "키 조각 업로드 중 오류가 발생했습니다."


@dataclass(frozen=True)
class UploadReply:
    """HTTP status, flash message and flash category of an upload answer."""

    status: int
    message: str
    category: str = "danger"

    @property
    def ok(self) -> bool:
        """The share is stored: now, or already (the identical share)."""
        return self.status == 200


def checked_share(raw: str, slot: int) -> tuple[str, Optional[UploadReply]]:
    """The share in stored form, or ``("", 400 reply)`` when malformed."""
    share = (raw or "").strip().lower()
    if len(share) > MAX_SHARE_LENGTH:
        return "", UploadReply(400, _MSG_TOO_LONG)
    index, dash, digits = share.partition("-")
    if not dash or index != str(slot):
        return "", UploadReply(400, _MSG_OTHER_SLOT.format(slot=slot))
    if not _HEX_DIGITS.fullmatch(digits):
        return "", UploadReply(400, _MSG_NOT_HEX.format(slot=slot))
    return share, None


def store_uploaded_share(
    seal_id: str, slot: int, share: str, uploaded_by: str
) -> UploadReply:
    """Store a checked share under the seal's current generation."""
    ca_path = (current_app.config.get("POLICY_CA_CERT_PATH") or "").strip() or None
    try:
        stored = _stored_generation_unless_marked(seal_id, ca_path)
        written = store_key_share(
            seal_id, slot, share, uploaded_by,
            generation=lambda: current_generation(
                seal_id, find_record_jsons_newest_first, ca_path=ca_path,
                stored=stored))
    except PrivacyError as exc:
        logger.warning("Key share not stored: the seal's generation could not "
                       "be read (%s): seal_id=%r slot=%d",
                       type(exc).__name__, _clip(seal_id), slot)
        return UploadReply(503, _MSG_GENERATION_UNKNOWN)
    except Exception:
        logger.exception("Key share upload failed: seal_id=%r slot=%d",
                         _clip(seal_id), slot)
        return UploadReply(500, _MSG_FAILED)
    return _reply(seal_id, slot, written)


def _stored_generation_unless_marked(
    seal_id: str, ca_path: Optional[str]
) -> Optional[int]:
    """For a seal without a mark, the stored maximum, read now: before the
    seal's write lock is taken (``None`` when the seal has a mark)."""
    if find_high_water(seal_id) is not None:
        return None
    return stored_generation(seal_id, find_record_jsons_newest_first,
                             ca_path=ca_path)


def _reply(seal_id: str, slot: int, written: ShareWrite) -> UploadReply:
    """The answer to a store; the log names the outcome, never the share."""
    where = (_clip(seal_id), slot, written.generation)
    if written.outcome == SHARE_CONFLICT:
        logger.warning("Key share upload refused (409): another share is stored "
                       "for seal_id=%r slot=%d generation=%d", *where)
        return UploadReply(409, _MSG_CONFLICT.format(
            generation=written.generation, slot=slot))
    if written.outcome == SHARE_IDENTICAL:
        logger.info("Key share upload matched the stored share: seal_id=%r "
                    "slot=%d generation=%d", *where)
        return UploadReply(200, _MSG_IDENTICAL, "info")
    logger.info("Key share stored: seal_id=%r slot=%d generation=%d", *where)
    return UploadReply(200, _MSG_STORED.get(slot, _MSG_STORED[1]), "success")


def _clip(text: str) -> str:
    return text[:_MAX_LOG_ID_LEN]
