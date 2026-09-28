"""HTTP status and user-facing message for release-gate denials.

The gate returns stable reason codes; routes map them here. The standard
and admin entries keep the v1.0.1 status codes and messages, with one
exception: the standard path answers a failed recombination and a
commitment mismatch alike, as the time-locked path does, so a response
cannot show whether the stored owner share has a full-width payload (the
audit row keeps the two reasons apart). Internal details (TSA errors,
policy verification causes) never reach the user and stay in the audit
trail and server log.
"""

from __future__ import annotations

from typing import Any

_MSG_SEAL_MODE = (
    "봉인 기록의 복구 방식(seal_mode)을 검증할 수 없어 복원을 거부합니다."
)
_MSG_POLICY_INVALID = "봉인 정책의 서명을 검증할 수 없어 복원을 거부합니다."
_MSG_INTERNAL = "키 복원을 처리할 수 없습니다. 관리자에게 문의해 주세요."
_MSG_TL_CHECK = "해제 조건 검증에 실패하여 시간 잠금 해제를 거부합니다."
_MSG_TL_TSA = "검증된 시각(TSA)을 확인할 수 없어 시간 잠금 해제를 거부합니다."
_MSG_POLICY_REQUIRED = "인증된 봉인 정책이 없는 기록이어서 복원을 거부합니다."
_MSG_STANDARD_NO_MATCH = (
    "입력한 키 조각으로는 봉인 기록의 확인값과 맞는 키를 복원할 수 없습니다. "
    "키 조각을 다시 확인해 주세요."
)
_MSG_POLICY_UNVERIFIABLE = (
    "인증된 봉인 정책이 등록된 봉인인데 이를 검증할 기준 인증서가 설정되지 않아 "
    "복원을 거부합니다."
)

_STANDARD: dict[str, tuple[int, str]] = {
    "record_unreadable": (500, _MSG_SEAL_MODE),
    "seal_mode_unresolvable": (500, _MSG_SEAL_MODE),
    "unlock_time_unresolvable": (
        500, "봉인 기록의 열람 제한 시각(unlock_time)을 검증할 수 없어 "
             "복원을 거부합니다."),
    "unlock_time_invalid": (
        500, "봉인 기록의 열람 제한 시각이 올바르지 않아 복원을 거부합니다."),
    # One answer for both: a stored s1 whose payload is not 64 hex digits
    # fails strict recombination, one that is reaches the commitment check.
    "recovery_failed": (400, _MSG_STANDARD_NO_MATCH),
    "commitment_unresolvable": (
        500, "봉인 기록의 복구키 확인값을 검증할 수 없어 복원을 거부합니다."),
    "commitment_mismatch": (400, _MSG_STANDARD_NO_MATCH),
    "policy_invalid": (403, _MSG_POLICY_INVALID),
    "policy_required": (403, _MSG_POLICY_REQUIRED),
    "policy_unverifiable": (403, _MSG_POLICY_UNVERIFIABLE),
    "commitment_missing": (
        403, "봉인 기록에 복구키 확인값이 없어 입력한 키 조각을 검증할 수 없으므로 "
             "복원을 거부합니다. 관리자 비상 복구를 이용해 주세요."),
    "owner_share_missing": (400, "피압수자 키 조각(1)이 업로드되지 않았습니다."),
    "owner_share_malformed": (
        400, "피압수자 키 조각(1) 자리에 조각 1 형식이 아닌 값이 있습니다."),
    "investigator_share_missing": (400, "수사관 키 조각(2)을 입력해 주세요."),
    "investigator_share_malformed": (
        400, "입력한 수사관 키 조각이 조각 2 형식이 아닙니다."),
}

_TIMELOCK: dict[str, tuple[int, str]] = {
    "record_missing": (403, "동기화된 봉인 기록이 없어 시간 잠금 해제를 거부합니다."),
    "record_unreadable": (500, _MSG_SEAL_MODE),
    "policy_legacy": (
        403, "인증된 봉인 정책이 없는 기록이어서 시간 잠금 해제를 할 수 없습니다."),
    "policy_unverifiable": (
        403, "봉인 정책을 검증할 기준 인증서가 설정되지 않아 시간 잠금 해제를 "
             "거부합니다."),
    "policy_invalid": (403, _MSG_POLICY_INVALID),
    "policy_expired": (
        403, "봉인 정책 인증서의 유효기간이 지나 시간 잠금 해제를 할 수 없습니다. "
             "표준 복구나 관리자 비상 복구를 이용해 주세요."),
    "config_missing": (503, "시간 잠금 해제 설정(TSA·KMS)이 없어 해제를 거부합니다."),
    "kms_unavailable": (
        503, "시스템 키 조각을 풀 KMS 키를 사용할 수 없어 시간 잠금 해제를 거부합니다. "
             "관리자에게 문의해 주세요."),
    "investigator_share_missing": (400, "수사관 키 조각(2)을 입력해 주세요."),
    "investigator_share_malformed": (
        400, "입력한 수사관 키 조각이 조각 2 형식이 아닙니다."),
    "owner_share_missing": (
        400, "엄격 모드 봉인은 피압수자 키 조각(1)이 있어야 해제할 수 있습니다."),
    "owner_share_malformed": (
        400, "업로드된 피압수자 키 조각이 조각 1 형식이 아닙니다."),
    "wrapped_s3_missing": (400, "시스템 키 조각(3)이 동기화되지 않았습니다."),
    "tsa_failed": (503, _MSG_TL_TSA),
    "policy_digest_mismatch": (403, _MSG_TL_CHECK),
    "s3_unwrap_failed": (403, _MSG_TL_CHECK),
    "s3_malformed": (403, _MSG_TL_CHECK),
    "recovery_failed": (403, _MSG_TL_CHECK),
    "commitment_mismatch": (403, _MSG_TL_CHECK),
}

_ADMIN: dict[str, tuple[int, str]] = {
    "operator_required": (
        403, "관리자 계정을 확인할 수 없어 비상 복구를 거부합니다."),
    "reason_required": (400, "비상 복구 사유를 입력해 주세요."),
    "admin_share_missing": (400, "관리자 키 조각(4)이 존재하지 않습니다."),
    "admin_share_malformed": (
        400, "관리자 키 조각(4) 자리에 조각 4 형식이 아닌 값이 있습니다."),
    "other_share_missing": (400, "복원에 필요한 다른 키 조각이 존재하지 않습니다."),
    "other_share_malformed": (
        400, "다른 키 조각 자리의 값이 그 번호의 조각 형식이 아닙니다."),
    "policy_required": (403, "인증된 봉인 정책이 없는 기록이어서 비상 복구를 거부합니다."),
    "policy_unverifiable": (403, _MSG_POLICY_UNVERIFIABLE),
    "record_unreadable": (500, _MSG_SEAL_MODE),
    "seal_mode_unresolvable": (500, _MSG_SEAL_MODE),
    "policy_invalid": (403, "봉인 정책의 서명을 검증할 수 없어 비상 복구를 거부합니다."),
    "recovery_failed": (500, "키 복원에 실패했습니다."),
    "commitment_mismatch": (
        400, "복원된 키가 봉인 기록의 확인값과 일치하지 않습니다."),
}

_TABLES = {"standard": _STANDARD, "timelock": _TIMELOCK, "admin": _ADMIN}


def denial_response(decision: Any, share_count: int = 0) -> tuple[int, str]:
    """(HTTP status, message) for a denied :class:`ReleaseDecision`."""
    if decision.reason in ("before_unlock", "tsa_time_before_unlock"):
        return 403, (
            "열람 제한 기간이 경과하지 않아 키 복원이 제한됩니다. "
            f"(해제 시각: {decision.unlock_time_iso})"
        )
    if decision.reason == "insufficient_shares":
        return 400, f"키 조각이 부족합니다. 현재 {share_count}개 / 최소 2개 필요"
    table = _TABLES.get(decision.path, {})
    return table.get(decision.reason, (500, _MSG_INTERNAL))
