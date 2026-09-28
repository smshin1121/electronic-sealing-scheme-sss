"""Schema and canonical form of the seal policy (split from :mod:`seal_policy`).

A seal policy is the JSON object

    {"v": 2, "seal_id", "case_no", "seal_mode", "unlock_time_iso",
     "key_commitment", "generation"}

serialized canonically (sorted keys, ``(",", ":")`` separators, UTF-8,
``ensure_ascii=False``). ``generation`` (stage E, E2a) is a positive
integer that orders the policies of one seal: sealing signs generation 1
and each reseal the previous generation + 1. The stage D form without it
(``"v": 1``, the other six fields) is still accepted and counts as
generation 0. Signing, verification and the release bindings stay in
:mod:`desktop.signature.seal_policy`, which re-exports these names.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Mapping, Optional

from .exceptions import SignatureError

# Version signed at sealing and resealing (with a generation), and the
# stage D form without one (implicit generation 0), still accepted.
SEAL_POLICY_VERSION = 2
LEGACY_POLICY_VERSION = 1
FIRST_POLICY_GENERATION = 1
MAX_POLICY_GENERATION = 2 ** 31 - 1  # fits the INT columns of both schemas

_V1_KEYS = frozenset({
    "v", "seal_id", "case_no", "seal_mode", "unlock_time_iso",
    "key_commitment",
})
_POLICY_KEYS = {
    LEGACY_POLICY_VERSION: _V1_KEYS,
    SEAL_POLICY_VERSION: _V1_KEYS | {"generation"},
}
_SEAL_MODES = frozenset({"standard", "strict"})
_COMMITMENT_RE = re.compile(r"[0-9a-f]{64}")
_UNLOCK_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
_MAX_SEAL_ID_LEN = 64
_MAX_CASE_NO_LEN = 128


class PolicyError(SignatureError):
    """A seal policy could not be built, signed, loaded or bound."""


def build_policy(
    *,
    seal_id: str,
    case_no: str,
    seal_mode: str,
    unlock_time_iso: str,
    key_commitment: str,
    generation: Optional[int] = None,
) -> dict[str, Any]:
    """Build and validate a policy object (a new dict).

    With a ``generation`` the policy has version 2; without one it has the
    stage D version 1 (implicit generation 0).
    """
    fields = {
        "seal_id": seal_id,
        "case_no": case_no,
        "seal_mode": seal_mode,
        "unlock_time_iso": unlock_time_iso,
        "key_commitment": key_commitment,
    }
    if generation is None:
        return _validated({**fields, "v": LEGACY_POLICY_VERSION})
    return _validated({**fields, "v": SEAL_POLICY_VERSION,
                       "generation": generation})


def policy_from_record(
    record: Mapping[str, Any], *, generation: Optional[int] = None
) -> dict[str, Any]:
    """Derive the policy object from a sealing/resealing record.

    Raises:
        PolicyError: If a required field is missing or malformed.
    """
    if not isinstance(record, Mapping):
        raise PolicyError("record must be a JSON object")
    case_info = record.get("case_info")
    case_no = (
        case_info.get("case_number") if isinstance(case_info, Mapping) else None
    )
    return build_policy(
        seal_id=record.get("seal_id"),  # type: ignore[arg-type]
        case_no=case_no,  # type: ignore[arg-type]
        seal_mode=record.get("seal_mode"),  # type: ignore[arg-type]
        unlock_time_iso=record.get("unlock_time_iso"),  # type: ignore[arg-type]
        key_commitment=record.get("key_commitment"),  # type: ignore[arg-type]
        generation=generation,
    )


def canonicalize_policy(policy: Mapping[str, Any]) -> bytes:
    """Return the canonical UTF-8 JSON bytes of a validated policy.

    Raises:
        PolicyError: If the object violates the version-1 or -2 schema.
    """
    normalized = _validated(policy)
    try:
        return json.dumps(
            normalized, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PolicyError("policy is not canonically serializable") from exc


def policy_digest(policy: Mapping[str, Any]) -> bytes:
    """SHA-256 of the canonical policy bytes."""
    return hashlib.sha256(canonicalize_policy(policy)).digest()


def policy_generation(policy: Mapping[str, Any]) -> int:
    """Generation of a policy: its ``generation`` (v2), or 0 (v1).

    Raises:
        PolicyError: If the object violates the schema.
    """
    return _validated(policy).get("generation", 0)


def _validated(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Check the version-1 or -2 schema and return a new plain dict."""
    if not isinstance(policy, Mapping):
        raise PolicyError("policy must be a JSON object")
    version = policy.get("v")
    keys = _POLICY_KEYS.get(version) if type(version) is int else None
    if keys is None:
        raise PolicyError("unsupported policy version")
    if set(policy.keys()) != keys:
        raise PolicyError(f"policy fields must be exactly {sorted(keys)}")
    _require_text(policy["seal_id"], "seal_id", _MAX_SEAL_ID_LEN)
    _require_text(policy["case_no"], "case_no", _MAX_CASE_NO_LEN)
    mode = policy["seal_mode"]
    if not isinstance(mode, str) or mode not in _SEAL_MODES:
        raise PolicyError("policy seal_mode must be 'standard' or 'strict'")
    parse_unlock_time(policy["unlock_time_iso"])
    commitment = policy["key_commitment"]
    if not isinstance(commitment, str) or not _COMMITMENT_RE.fullmatch(
        commitment
    ):
        raise PolicyError("policy key_commitment must be 64 lowercase hex")
    if "generation" in keys:
        _require_generation(policy["generation"])
    return {key: policy[key] for key in sorted(keys)}


def _require_generation(value: Any) -> None:
    """A version-2 generation is an integer from 1 to 2^31 - 1."""
    if type(value) is not int or not (
        FIRST_POLICY_GENERATION <= value <= MAX_POLICY_GENERATION
    ):
        raise PolicyError(
            f"policy generation must be an integer from "
            f"{FIRST_POLICY_GENERATION} to {MAX_POLICY_GENERATION}"
        )


def _require_text(value: Any, name: str, max_len: int) -> None:
    """Require a non-empty, bounded string without control characters."""
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise PolicyError(f"policy {name} must be a non-empty string")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise PolicyError(f"policy {name} contains control characters")


def parse_unlock_time(value: Any) -> datetime:
    """Parse a policy unlock time (ISO 8601 UTC, ``Z`` suffix).

    Raises:
        PolicyError: If the value is not a well-formed UTC timestamp.
    """
    if not isinstance(value, str) or not _UNLOCK_RE.fullmatch(value):
        raise PolicyError("policy unlock_time_iso must be YYYY-MM-DDThh:mm:ssZ")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PolicyError("policy unlock_time_iso is not a valid time") from exc
