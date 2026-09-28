"""Policy generation of a reseal (stage E, E2a).

Sealing signs generation 1 (:data:`FIRST_POLICY_GENERATION`). A reseal
signs the previous generation + 1. The previous generation is the higher
of

  - the policy of the record the operator loaded at R1, and
  - the policy of the record this desktop stored for the seal (its
    ``seal_records`` table keeps one row per seal, the latest),

so an older record file cannot make a reseal repeat or lower a generation
this desktop already signed. A record without a policy (legacy) and a
stage D version-1 policy count as generation 0, so resealing either
yields generation 1.

As for the seal mode (:mod:`desktop.seal_mode_guard`), the desktop holds no
trust anchor: the previous policy's signature is not verified here. A
present policy must satisfy the schema, or the reseal is refused. The
release host enforces the order: sync admission refuses a verified policy
below the seal's high-water mark, or at it with another digest.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any, Mapping

from .signature.seal_policy import (
    MAX_POLICY_GENERATION,
    PolicyError,
    policy_generation,
)

logger = logging.getLogger(__name__)


def next_policy_generation(db_path: str, prev_record: Mapping[str, Any]) -> int:
    """Generation of the policy a reseal of ``prev_record`` signs.

    Raises:
        ValueError: When a present policy (loaded or stored) is malformed,
            the stored record cannot be read, or the generation space is
            exhausted.
    """
    seal_id = prev_record.get("seal_id")
    previous = max(
        record_generation(prev_record, "불러온 기록"),
        _stored_generation(db_path, seal_id),
    )
    if previous >= MAX_POLICY_GENERATION:
        raise ValueError(
            f"봉인 정책 세대가 최대값({MAX_POLICY_GENERATION})에 이르러 "
            f"더 재봉인할 수 없습니다 ({seal_id})."
        )
    return previous + 1


def record_generation(record: Mapping[str, Any], label: str) -> int:
    """Generation of the policy a record carries (0 without a policy).

    Raises:
        ValueError: When the record carries a malformed policy.
    """
    if "policy" not in record:
        return 0
    try:
        return policy_generation(record["policy"])
    except PolicyError as exc:
        raise ValueError(
            f"{label}의 봉인 정책을 읽을 수 없어 재봉인 세대를 정할 수 "
            f"없습니다: {exc}"
        ) from exc


def _stored_generation(db_path: str, seal_id: Any) -> int:
    """Generation of the record this desktop stored for the seal (0: none).

    A database without the table, no row, or a case placeholder without a
    record count as 0; any other read failure refuses the reseal.
    """
    from .db import get_seal_record

    if not isinstance(seal_id, str) or not seal_id:
        return 0
    try:
        row = get_seal_record(db_path, seal_id)
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc):
            raise ValueError(
                f"이 PC의 기록 DB를 읽을 수 없어 재봉인 세대를 정할 수 "
                f"없습니다 ({seal_id}): {exc}"
            ) from exc
        return 0
    except (sqlite3.Error, ValueError) as exc:  # incl. JSONDecodeError
        raise ValueError(
            f"이 PC에 저장된 기록을 읽을 수 없어 재봉인 세대를 정할 수 "
            f"없습니다 ({seal_id}): {exc}"
        ) from exc
    record = row.get("record_json") if row else None
    if not isinstance(record, dict) or record.get("seal_id") != seal_id:
        return 0
    return record_generation(record, "이 PC에 저장된 기록")
