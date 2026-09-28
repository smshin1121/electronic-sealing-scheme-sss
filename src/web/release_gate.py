"""Single release gate for every key-release route (stage D).

Every release path -- standard (s1+s2), time-locked (s2+s3) and admin
(s4 + another share) -- goes through this module. It resolves the record
the decision rests on ONCE, classifies its policy (:mod:`seal_policy`),
applies the path rule below, and appends one audit row per attempt (a
release is returned only after its audit row was written).

================  ======================  =====================  =========================
record policy     standard (s1+s2)        time-locked (s2+s3)    admin (s4+other)
================  ======================  =====================  =========================
no record         deny [3][5]             deny                   allow; reason; flag [3]
legacy            v1.0.1 checks [3][5]    deny                   allow; reason; flag [3]
unverifiable [1]  v1.0.1 checks [3][5]    deny                   allow; reason; flag [3]
invalid [2]       deny                    deny                   deny
expired [4]       policy values,          deny                   policy mode + commitment,
                  server-UTC gate                                no time gate (override)
verified          policy values,          TSA-verified release   policy mode + commitment,
                  server-UTC gate                                no time gate (override)
unreadable JSON   deny                    deny                   deny
================  ======================  =====================  =========================

[1] complete policy but no pinned CA configured (``POLICY_CA_CERT_PATH``).
[2] partial fields (e.g. missing signature), bad chain/EKU, a certificate
    not yet valid, signature or schema failure, or another seal_id.
[3] denied as ``policy_required`` when ``RELEASE_REQUIRE_POLICY`` is set.
[4] chain, EKU, signature and seal_id verify, but the policy certificate
    or its pinned CA has since expired: the signed values are authentic,
    but only the paths that also need the owner's or an administrator's
    share accept them.
[5] released only against the record's key commitment; a record without
    one, or no record, is denied: the stored s1 combined with a chosen s2
    would reveal s1. Admin keeps the v1.0.1 unverified release for such
    records and relies on trusting the authenticated administrator with
    the result: slot 2 can be planted through the unauthenticated upload
    route, and when s1 is absent a result over a planted s2 reveals s4.

Record selection (stage E, E2a; :mod:`web.release_selection`): records
whose policy is neither verified nor expired are ignored (they may be
stripped copies from the sync route). With a high-water mark
(``policy_high_water``), the decision rests on the newest record carrying
exactly the mark's policy; records are read one at a time, newest first,
down to it, and any other authenticated record -- below the mark (an older
generation replayed under a newer event) or with another policy at or
above it (written outside sync admission) -- is ignored. The mark is the
highest generation among the seal's stored authenticated records: sync
admission bootstraps it from the stored records, refuses a policy below it
or another digest at it, and raises it with every store. Without a mark
(records stored before E2a, while no CA was pinned, or out of band) every
record is read, the highest generation decides (version-1 policies count
as 0; the newest event among equals), and that record seeds the mark.
Finding the record enrolls the seal if it was not enrolled yet.
Only when no stored record carries an authenticated policy does the newest
record decide, as in v1.0.1. A seal enrolled at sync (``policy_enrollment``)
or with a mark, with no record carrying a usable policy, is denied on every
path: as ``invalid`` when a pinned CA rejects its records or only records
without the mark's policy verify, as ``unverifiable`` when no CA is pinned
(the v1.0.1 fallback applies only to seals never enrolled).

Share selection: both investigator paths take s2 from the request (a
possession proof; this reference app has no investigator accounts), never
from slot 2, which the unauthenticated upload route lets anyone fill
first. Its presence and format are checked before any record is read, so
a request without a well-formed share learns nothing about the seal (it is
audited as ``not_evaluated``). Standard combines it with the stored owner
share s1 (submitted through the authenticated subject route); the
time-locked path with the released s3, and in strict mode s1; admin uses
s4 and the lowest other stored slot. Every share must carry its own index
prefix, and released audit rows name the slots used (``shares=1+2``).

Operator: an admin attempt names the administrator account that made it,
recorded in its audit row (``operator``); a blank or over-long one is denied
as ``operator_required`` (recorded as ``''``). Other paths record ``''``.

The standard path deliberately makes no TSA round trip (a TSA outage must
not block it). The time-locked path is fail-closed: it requires a verified
policy, the KMS master key, the TSA URL, the pinned TSA CA and policy OID
(``RELEASE_TSA_CERT_PATH`` is an optional TSA certificate pin); a deny-only
local clock pre-check; a fresh TSA token over
``SHA-256(b"ESS-S3-RELEASE-v1" || SHA-256(policy) || challenge)`` accepted
under the pinned TSA profile (:mod:`desktop.signature.tsa_profile`: chain,
EKU, ESS, policy OID, accuracy; a rejection is ``tsa_failed`` with the
failure code first in the detail) whose genTime minus accuracy is not
before the unlock time (every later audit row, an unexpected error's
``internal_error`` included, keeps the token and names the rule and
accuracy); the policy digest re-checked right before the s3 unwrap (bound
to seal_id and policy digest); mode-aware recombination; and the full key
commitment.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import partial
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from flask import current_app

from desktop.crypto.exceptions import KMSError
from desktop.crypto.local_kms import decrypt_envelope_with_key, load_master_key
from desktop.crypto.sss_strict import SEAL_MODE_STRICT, recover_key_for_mode
from desktop.signature.seal_policy import (
    POLICY_EXPIRED,
    POLICY_INVALID,
    POLICY_LEGACY,
    POLICY_UNVERIFIABLE,
    POLICY_VERIFIED,
    VerifiedPolicy,
    release_imprint,
    s3_wrap_aad,
)
from desktop.signature.tsa_client import request_timestamp_trusted
from desktop.signature.tsa_profile import (
    TsaTrustProfile, is_dotted_oid, release_rule_note,
)
from desktop.signature.types import VerifiedTimestamp

from .models.db_models import (
    find_latest_key_commitment,
    find_latest_seal_mode,
    find_latest_unlock_time,
)
from .models.release_models import (
    ReleaseAuditEntry,
    find_record_jsons_newest_first,
    find_share_by_index,
    find_wrapped_s3_newest_first,
    has_wrapped_s3,
    insert_release_audit,
)
from .release_selection import STATUS_NO_RECORD, STATUS_UNREADABLE, select_record

logger = logging.getLogger(__name__)

PATH_STANDARD = "standard"
PATH_TIMELOCK = "timelock"
PATH_ADMIN = "admin"

OUTCOME_RELEASED = "released"
OUTCOME_DENIED = "denied"

STATUS_NOT_EVALUATED = "not_evaluated"
_STATUS_UNKNOWN = "unknown"

_AUTHENTIC_STATUSES = frozenset({POLICY_VERIFIED, POLICY_EXPIRED})
_TIMELOCK_POLICY_DENIAL = {
    STATUS_NO_RECORD: "record_missing",
    STATUS_UNREADABLE: "record_unreadable",
    POLICY_LEGACY: "policy_legacy",
    POLICY_UNVERIFIABLE: "policy_unverifiable",
    POLICY_INVALID: "policy_invalid",
    POLICY_EXPIRED: "policy_expired",
}
# At most 64 hex digits. Shares are values below the field prime
# 2^256 + 297; all but the 297 values from 2^256 up fit (about 6% have fewer
# digits). Those rare shares (about 2^-248 per share) are refused here and
# need the admin path: a longer value would let the requester make the
# vendored combiner pick a larger field, whose output width depends on s1.
_S2_SHARE_RE = re.compile(r"2-[0-9a-f]{1,64}")
_S3_SHARE_RE = re.compile(r"3-[0-9a-f]{1,128}")
_ADMIN_SLOT = 4
_CHALLENGE_BYTES = 32
_KEY_BYTES = 32
_MAX_DETAIL_LEN = 500
_MAX_OPERATOR_REASON_LEN = 2000
_MAX_OPERATOR_LEN = 64
_MAX_LOG_ID_LEN = 200


@dataclass(frozen=True)
class ReleaseDecision:
    """Outcome of one release attempt (the key only when allowed); ``slots``
    names the admin share slots selected (``2+4``), also on a later denial."""

    allowed: bool
    path: str
    reason: str
    policy_status: str
    detail: str = ""
    unlock_time_iso: str = ""
    slots: str = ""
    key_hex: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class _PolicyContext:
    """The classified record a decision rests on, resolved once."""

    status: str
    policy: Optional[VerifiedPolicy] = None
    detail: str = ""
    enrolled: bool = False


@dataclass(frozen=True)
class _TsaEvidence:
    """Audit copy of the verified TSA token used for a decision; ``rule``
    (the time rule and its values) ends every later audit detail."""

    token_sha256: str
    token_b64: str
    challenge_hex: str
    gen_time_iso: str
    rule: str = ""

    @classmethod
    def of(cls, stamp: VerifiedTimestamp, challenge: bytes,
           unlock_time: datetime) -> "_TsaEvidence":
        """Evidence of a token accepted under the pinned TSA profile."""
        return cls(stamp.token_sha256,
                   base64.b64encode(stamp.token).decode("ascii"),
                   challenge.hex(), stamp.gen_time.isoformat(),
                   release_rule_note(stamp, unlock_time))

    def annotate(self, finish: Callable[..., Any]) -> Callable[..., Any]:
        """``finish`` that records this evidence and appends ``rule``."""
        return lambda outcome, reason, *, detail="", **kw: finish(
            outcome, reason, detail=_join(detail, self.rule), evidence=self,
            **kw)


@dataclass(frozen=True)
class _ReleaseConfig:
    """Release-host configuration of the time-locked path
    (``tsa_cert_path``: the optional TSA certificate pin)."""

    master_key_path: str
    tsa_url: str
    tsa_cert_path: str
    missing: tuple[str, ...]
    tsa_profile: TsaTrustProfile = TsaTrustProfile("", "")


def _utc_now() -> datetime:
    """The release host's clock (UTC); deny-only on the time-locked path."""
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def release_standard(seal_id: str, presented_share: str) -> ReleaseDecision:
    """Standard path: the presented s2 and stored s1, server-UTC unlock gate."""
    s2, unmet = _presented_s2(presented_share or "")
    return _guarded(seal_id, PATH_STANDARD, "", lambda ctx: _standard(
        seal_id, s2, ctx
    ), unmet=unmet)


def release_timelock(seal_id: str, presented_share: str) -> ReleaseDecision:
    """Time-locked path: the presented s2 (+ stored s1 if strict) and s3."""
    s2, unmet = _presented_s2(presented_share or "")
    return _guarded(seal_id, PATH_TIMELOCK, "", lambda ctx: _timelock(
        seal_id, s2, ctx
    ), unmet=unmet)


def release_admin(
    seal_id: str, operator_reason: str, shares: Mapping[int, str], *,
    operator: str,
) -> ReleaseDecision:
    """Admin override: s4 plus another stored share; reason and operator
    (the administrator's username) required."""
    reason = (operator_reason or "").strip()
    name = (operator or "").strip()
    if len(name) > _MAX_OPERATOR_LEN:  # not a username; never truncated
        name = ""
    return _guarded(seal_id, PATH_ADMIN, reason, lambda ctx: _admin(
        seal_id, reason, name, dict(shares), ctx
    ), operator=name)


def _guarded(
    seal_id: str,
    path: str,
    operator_reason: str,
    decide: Callable[[_PolicyContext], ReleaseDecision],
    *,
    unmet: str = "",
    operator: str = "",
) -> ReleaseDecision:
    """Resolve the policy once, decide, and fail closed on any error.

    ``unmet`` is a request precondition that already failed (a missing or
    malformed presented share): the attempt is denied and audited before
    any record of the seal is read. ``operator`` reaches the audit row on
    these two exits too.
    """
    ctx = _PolicyContext(_STATUS_UNKNOWN)
    try:
        if unmet:
            ctx = _PolicyContext(STATUS_NOT_EVALUATED)
            return _finish(seal_id, path, ctx, OUTCOME_DENIED, unmet,
                           operator_reason=operator_reason, operator=operator)
        ctx = _resolve_policy(seal_id)
        return decide(ctx)
    except Exception:
        logger.exception("Release gate error: seal_id=%r path=%s",
                         _clip(seal_id, _MAX_LOG_ID_LEN), path)
        return _finish(seal_id, path, ctx, OUTCOME_DENIED, "internal_error",
                       operator_reason=operator_reason, operator=operator)


def _resolve_policy(seal_id: str) -> _PolicyContext:
    """The record the decision rests on (see "Record selection" above).

    The records are read through this module's
    ``find_record_jsons_newest_first``, newest first.
    """
    ca_path = (current_app.config.get("POLICY_CA_CERT_PATH") or "").strip()
    chosen = select_record(seal_id, find_record_jsons_newest_first,
                           ca_path=ca_path or None)
    return _PolicyContext(chosen.status, chosen.policy, chosen.detail,
                          chosen.enrolled)


def _unauthenticated_denial(ctx: _PolicyContext) -> str:
    """Reason to deny an unauthenticated record, or "" for v1.0.1 behaviour.

    An enrolled seal never falls back; neither does any seal when
    ``RELEASE_REQUIRE_POLICY`` is set.
    """
    if ctx.enrolled:
        return "policy_unverifiable"
    if current_app.config.get("RELEASE_REQUIRE_POLICY"):
        return "policy_required"
    return ""


# ---------------------------------------------------------------------------
# Standard path (s1 + s2)
# ---------------------------------------------------------------------------

def _standard(seal_id: str, s2: str, ctx: _PolicyContext) -> ReleaseDecision:
    finish = partial(_finish, seal_id, PATH_STANDARD, ctx)
    s1, share_problem = _stored_owner_share(seal_id)
    if share_problem:
        return finish(OUTCOME_DENIED, share_problem)
    selected = [s1, s2]
    if ctx.status == STATUS_UNREADABLE:
        return finish(OUTCOME_DENIED, "record_unreadable", detail=ctx.detail)
    if ctx.status == POLICY_INVALID:
        return finish(OUTCOME_DENIED, "policy_invalid", detail=ctx.detail)
    if ctx.status in _AUTHENTIC_STATUSES and ctx.policy is not None:
        return _standard_verified(ctx.policy, ctx.detail, selected, finish)
    denial = _unauthenticated_denial(ctx)
    if denial:
        return finish(OUTCOME_DENIED, denial, detail=ctx.detail)
    return _standard_legacy(seal_id, selected, ctx, finish)


def _standard_verified(
    policy: VerifiedPolicy, note: str, shares: list[str],
    finish: Callable[..., Any],
) -> ReleaseDecision:
    """Same checks as v1.0.1, with values taken from the authenticated policy."""
    if _utc_now() < policy.unlock_time:
        return finish(OUTCOME_DENIED, "before_unlock",
                      unlock_time_iso=policy.unlock_time.isoformat())
    key_hex = _recover_or_none(policy.seal_mode, shares)
    if key_hex is None:
        return finish(OUTCOME_DENIED, "recovery_failed")
    if not _commitment_matches(key_hex, policy.key_commitment):
        return finish(OUTCOME_DENIED, "commitment_mismatch")
    return finish(OUTCOME_RELEASED, "released", key_hex=key_hex,
                  detail=_join("shares=1+2", note))


def _standard_legacy(
    seal_id: str, shares: list[str], ctx: _PolicyContext,
    finish: Callable[..., Any],
) -> ReleaseDecision:
    """v1.0.1 checks on unauthenticated record fields, commitment required.

    Same order as v1.0.1, except that the commitment is looked up before
    recombining and its absence denies: s2 comes from the request, and the
    stored s1 combined with a chosen s2 yields a value from which s1
    follows, so an unchecked reconstruction is never returned.
    """
    try:
        mode = find_latest_seal_mode(seal_id)
    except ValueError:
        return finish(OUTCOME_DENIED, "seal_mode_unresolvable")
    if mode is None:
        logger.warning("No synced sealing record for %r; applying legacy "
                       "standard mode", _clip(seal_id, _MAX_LOG_ID_LEN))
        mode = "standard"
    try:
        unlock_iso = find_latest_unlock_time(seal_id)
    except ValueError:
        return finish(OUTCOME_DENIED, "unlock_time_unresolvable")
    if unlock_iso is not None:
        unlock_dt = _parse_legacy_unlock(unlock_iso)
        if unlock_dt is None:
            return finish(OUTCOME_DENIED, "unlock_time_invalid")
        if _utc_now() < unlock_dt:
            return finish(OUTCOME_DENIED, "before_unlock",
                          unlock_time_iso=unlock_dt.isoformat())
    try:
        commitment = find_latest_key_commitment(seal_id)
    except ValueError:
        return finish(OUTCOME_DENIED, "commitment_unresolvable")
    if commitment is None:
        return finish(OUTCOME_DENIED, "commitment_missing", detail=_join(
            "no key_commitment to verify the presented share", ctx.detail))
    key_hex = _recover_or_none(mode, shares)
    if key_hex is None:
        return finish(OUTCOME_DENIED, "recovery_failed")
    if not _commitment_matches(key_hex, commitment):
        return finish(OUTCOME_DENIED, "commitment_mismatch")
    return finish(OUTCOME_RELEASED, "released", key_hex=key_hex,
                  detail=_join("shares=1+2", ctx.detail))


def _parse_legacy_unlock(unlock_iso: str) -> Optional[datetime]:
    """Parse a legacy unlock time (``Z`` or offset form); None if invalid."""
    try:
        parsed = datetime.fromisoformat(unlock_iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Time-locked path (s2 + s3)
# ---------------------------------------------------------------------------

def _timelock(seal_id: str, s2: str, ctx: _PolicyContext) -> ReleaseDecision:
    finish = partial(_finish, seal_id, PATH_TIMELOCK, ctx)
    if ctx.status != POLICY_VERIFIED or ctx.policy is None:
        reason = _TIMELOCK_POLICY_DENIAL.get(ctx.status, "policy_invalid")
        return finish(OUTCOME_DENIED, reason, detail=ctx.detail)
    policy = ctx.policy
    config = _release_config()
    if config.missing:
        return finish(OUTCOME_DENIED, "config_missing",
                      detail=", ".join(config.missing))
    shares, share_problem = _timelock_shares(seal_id, policy.seal_mode, s2)
    if share_problem:
        return finish(OUTCOME_DENIED, share_problem)
    # Only existence here: the envelopes are read after the clock and TSA
    # checks, one at a time.
    if not has_wrapped_s3(seal_id):
        return finish(OUTCOME_DENIED, "wrapped_s3_missing")
    unlock_iso = policy.unlock_time.isoformat()
    if _utc_now() < policy.unlock_time:
        return finish(OUTCOME_DENIED, "before_unlock", unlock_time_iso=unlock_iso,
                      detail="release host clock before unlock time; no TSA "
                             "request made")
    challenge = os.urandom(_CHALLENGE_BYTES)
    imprint = release_imprint(policy.digest, challenge)
    try:  # certificate validity also at the host clock (can only deny more)
        stamp = request_timestamp_trusted(imprint, config.tsa_url,
                                          config.tsa_profile, at=_utc_now())
        evidence = _TsaEvidence.of(stamp, challenge, policy.unlock_time)
    except Exception as exc:  # any transport/parse/verify failure denies
        code = getattr(exc, "code", "") or "tsa_error"
        return finish(OUTCOME_DENIED, "tsa_failed", detail=f"{code}: {exc}")
    finish = evidence.annotate(partial(finish, unlock_time_iso=unlock_iso))
    try:  # an unexpected error from here on keeps the evidence (Codex F7)
        # RFC 3161 2.4.2: genTime - accuracy is the earliest time of issuance.
        if stamp.earliest_gen_time < policy.unlock_time:
            return finish(OUTCOME_DENIED, "tsa_time_before_unlock")
        return _unwrap_and_combine(policy, shares, config, imprint, challenge,
                                   finish)
    except Exception:
        logger.exception("Release gate error after the TSA check: seal_id=%r "
                         "path=%s", _clip(seal_id, _MAX_LOG_ID_LEN), PATH_TIMELOCK)
        return finish(OUTCOME_DENIED, "internal_error")


def _unwrap_and_combine(
    policy: VerifiedPolicy,
    shares: list[str],
    config: _ReleaseConfig,
    imprint: bytes,
    challenge: bytes,
    finish: Callable[..., Any],
) -> ReleaseDecision:
    """Re-check the policy digest, unwrap s3, recombine, check commitment."""
    # D5: the verified policy object is the only one used (no re-read);
    # its digest is recomputed and re-bound to the TSA imprint right here.
    if not policy.recheck_digest() or not hmac.compare_digest(
        release_imprint(policy.digest, challenge), imprint
    ):
        return finish(OUTCOME_DENIED, "policy_digest_mismatch")
    # The key is loaded once: a failure here is the release host's, not an
    # envelope's, and is not counted as one.
    try:
        master_key = load_master_key(config.master_key_path)
    except KMSError:
        logger.exception("Release master key unavailable")
        return finish(OUTCOME_DENIED, "kms_unavailable",
                      detail="master key unavailable")
    plaintext, skipped = _unwrap_first(
        find_wrapped_s3_newest_first(policy.seal_id), master_key,
        s3_wrap_aad(policy.seal_id, policy.digest),
    )
    note = (f"{skipped} envelope(s) that do not authenticate skipped"
            if skipped else "")
    if plaintext is None:
        return finish(OUTCOME_DENIED, "s3_unwrap_failed", detail=note)
    s3 = _decode_s3(plaintext)
    if s3 is None:
        return finish(OUTCOME_DENIED, "s3_malformed", detail=note)
    key_hex = _recover_or_none(policy.seal_mode, [*shares, s3])
    if key_hex is None:
        return finish(OUTCOME_DENIED, "recovery_failed", detail=note)
    if not _commitment_matches(key_hex, policy.key_commitment):
        return finish(OUTCOME_DENIED, "commitment_mismatch", detail=note)
    used = "shares=1+2+3" if policy.seal_mode == SEAL_MODE_STRICT else "shares=2+3"
    return finish(OUTCOME_RELEASED, "released", key_hex=key_hex,
                  detail=_join(used, note))


def _unwrap_first(
    envelopes: Iterable[bytes], master_key: bytes, aad: bytes
) -> tuple[Optional[bytes], int]:
    """The newest envelope that authenticates under ``aad``, and how many
    newer ones did not.

    A copy of the seal's own signed record passes sync under any new
    event, carrying whatever envelope was attached to it. The AES-GCM tag
    binds an envelope to the seal and the policy digest, so an envelope
    that fails it (malformed, or wrapped for another policy) is skipped
    instead of deciding the release. The count goes to the audit detail.
    Envelopes are consumed lazily: older ones are never read once one
    authenticates.
    """
    skipped = 0
    for wrapped in envelopes:
        try:
            return decrypt_envelope_with_key(wrapped, master_key, aad=aad), skipped
        except KMSError:  # this envelope only: too short, or tag mismatch
            skipped += 1
    return None, skipped


def _release_config() -> _ReleaseConfig:
    """Read the time-locked path configuration; absent values are missing
    (a malformed policy OID too; the TSA certificate pin is optional)."""
    cfg = current_app.config
    master = (cfg.get("RELEASE_KMS_MASTER_KEY_PATH") or "").strip()
    url = (cfg.get("RELEASE_TSA_URL") or "").strip()
    cert = (cfg.get("RELEASE_TSA_CERT_PATH") or "").strip()
    tsa_ca = (cfg.get("RELEASE_TSA_CA_CERT_PATH") or "").strip()
    policy_oid = (cfg.get("RELEASE_TSA_POLICY_OID") or "").strip()
    missing = [
        name for name, ok in (
            ("RELEASE_KMS_MASTER_KEY_PATH", bool(master) and os.path.isfile(master)),
            ("RELEASE_TSA_URL", bool(url)),
            ("RELEASE_TSA_CA_CERT_PATH", bool(tsa_ca) and os.path.isfile(tsa_ca)),
            ("RELEASE_TSA_POLICY_OID", is_dotted_oid(policy_oid)),
            ("RELEASE_TSA_CERT_PATH", not cert or os.path.isfile(cert)),
        ) if not ok
    ]
    return _ReleaseConfig(master, url, cert, tuple(missing),
                          TsaTrustProfile(tsa_ca, policy_oid, cert))


def _presented_s2(presented_share: str) -> tuple[str, str]:
    """The investigator share entered in the request (possession proof).

    Only its presence and index-2 format are checked here, before any
    record is read; a wrong share (another seal's, or the owner's s1
    relabelled) fails the key commitment, so no key is released.
    """
    s2 = presented_share.strip().lower()
    if not s2:
        return "", "investigator_share_missing"
    if not _S2_SHARE_RE.fullmatch(s2):
        return "", "investigator_share_malformed"
    return s2, ""


def _timelock_shares(seal_id: str, mode: str, s2: str) -> tuple[list[str], str]:
    """The presented s2; strict mode also needs the stored owner share s1."""
    if mode != SEAL_MODE_STRICT:
        return [s2], ""
    s1, problem = _stored_owner_share(seal_id)
    if problem:
        return [], problem
    return [s1, s2], ""


def _decode_s3(plaintext: bytes) -> Optional[str]:
    """The unwrapped s3 must be an index-3 share string."""
    try:
        share = plaintext.decode("ascii")
    except UnicodeDecodeError:
        return None
    return share if _S3_SHARE_RE.fullmatch(share) else None


# ---------------------------------------------------------------------------
# Admin path (s4 + another share)
# ---------------------------------------------------------------------------

def _admin(
    seal_id: str, reason: str, operator: str, shares: dict[int, str],
    ctx: _PolicyContext,
) -> ReleaseDecision:
    """Authenticated override on stored shares.

    Unlike the standard path it may release an unauthenticated record
    without a commitment (flagged). That relies on trusting the
    authenticated administrator with the result: the other share can come
    from slot 2, which anyone can fill through the unauthenticated upload
    route, and a reconstruction over a planted s2 reveals s4.
    """
    finish = partial(_finish, seal_id, PATH_ADMIN, ctx, operator_reason=reason,
                     operator=operator)
    if not operator:
        return finish(OUTCOME_DENIED, "operator_required")
    if not reason:
        return finish(OUTCOME_DENIED, "reason_required")
    stored = {index: share for index, share in shares.items() if share}
    if len(stored) < 2:
        return finish(OUTCOME_DENIED, "insufficient_shares",
                      detail=f"{len(stored)} share(s) stored")
    selected, share_problem = _admin_shares(stored)
    if share_problem:
        return finish(OUTCOME_DENIED, share_problem)
    other_index, other, admin_share = selected
    finish = partial(finish, slots=f"{other_index}+{_ADMIN_SLOT}")
    if ctx.status == STATUS_UNREADABLE:
        return finish(OUTCOME_DENIED, "record_unreadable", detail=ctx.detail)
    if ctx.status == POLICY_INVALID:
        return finish(OUTCOME_DENIED, "policy_invalid", detail=ctx.detail)
    commitment: Optional[str] = None
    if ctx.status in _AUTHENTIC_STATUSES and ctx.policy is not None:
        mode, commitment = ctx.policy.seal_mode, ctx.policy.key_commitment
    elif _unauthenticated_denial(ctx):
        return finish(OUTCOME_DENIED, _unauthenticated_denial(ctx),
                      detail=ctx.detail)
    else:
        try:
            mode = find_latest_seal_mode(seal_id) or "standard"
        except ValueError:
            return finish(OUTCOME_DENIED, "seal_mode_unresolvable")
        logger.warning("Admin override on an unauthenticated record: "
                       "seal_id=%r policy_status=%s",
                       _clip(seal_id, _MAX_LOG_ID_LEN), ctx.status)
    try:
        key_hex = recover_key_for_mode(mode, [other, admin_share])
    except Exception:
        return finish(OUTCOME_DENIED, "recovery_failed")
    if commitment is not None and not _commitment_matches(key_hex, commitment):
        return finish(OUTCOME_DENIED, "commitment_mismatch")
    return finish(OUTCOME_RELEASED, "released", key_hex=key_hex,
                  detail=_join(f"shares={other_index}+{_ADMIN_SLOT}", ctx.detail))


def _admin_shares(stored: dict[int, str]) -> tuple[tuple[int, str, str], str]:
    """s4 and the lowest other stored slot, each holding its own index."""
    empty = (0, "", "")
    admin_share, problem = _slot_share(stored, _ADMIN_SLOT)
    if problem:
        return empty, f"admin_share_{problem}"
    other_index = next((i for i in sorted(stored) if i != _ADMIN_SLOT), None)
    if other_index is None:
        return empty, "other_share_missing"
    other, problem = _slot_share(stored, other_index)
    if problem:
        return empty, f"other_share_{problem}"
    return (other_index, other, admin_share), ""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _stored_owner_share(seal_id: str) -> tuple[str, str]:
    """The owner share s1 (submitted through the authenticated subject route)."""
    s1 = find_share_by_index(seal_id, 1)
    if not s1:
        return "", "owner_share_missing"
    if not s1.startswith("1-"):
        return "", "owner_share_malformed"
    return s1, ""


def _slot_share(stored: Mapping[int, str], index: int) -> tuple[str, str]:
    """The share stored in ``index``: ``(share, "")`` or ``("", problem)``."""
    share = stored.get(index)
    if not share:
        return "", "missing"
    if not share.startswith(f"{index}-"):
        return "", "malformed"
    return share, ""


def _recover_or_none(mode: str, shares: Sequence[str]) -> Optional[str]:
    """Mode-aware recombination; strict uses all shares, standard two."""
    selected = list(shares) if mode == SEAL_MODE_STRICT else list(shares[:2])
    try:
        return recover_key_for_mode(mode, selected)
    except Exception:
        logger.warning("Key recombination failed (mode=%s, %d shares)",
                       mode, len(selected))
        return None


def _commitment_matches(key_hex: str, commitment: str) -> bool:
    """Check SHA-256(key) against the full commitment with one fixed hash.

    One fixed-size hash and one comparison run for every reconstruction; a
    value outside the 256-bit key space is hashed as a fixed placeholder
    and never matches. This removes the skipped hash on odd-width values.
    It is not a constant-time guarantee: the integer conversion, and the
    vendored combiner's own choice of field, still depend on the values.
    """
    try:
        value = int(key_hex, 16)
    except (TypeError, ValueError):
        value = -1
    in_range = 0 <= value < 1 << (8 * _KEY_BYTES)
    data = value.to_bytes(_KEY_BYTES, "big") if in_range else bytes(_KEY_BYTES)
    actual = hashlib.sha256(data).hexdigest()
    matches = hmac.compare_digest(actual.encode("ascii"),
                                  str(commitment).encode("utf-8"))
    return matches and in_range


def _join(first: str, second: str) -> str:
    return "; ".join(part for part in (first, second) if part)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _finish(
    seal_id: str,
    path: str,
    ctx: _PolicyContext,
    outcome: str,
    reason: str,
    *,
    detail: str = "",
    operator_reason: str = "",
    operator: str = "",
    slots: str = "",
    evidence: Optional[_TsaEvidence] = None,
    unlock_time_iso: str = "",
    key_hex: Optional[str] = None,
) -> ReleaseDecision:
    """Write the audit row, then return the decision (fail-closed)."""
    entry = ReleaseAuditEntry(
        seal_id=seal_id, path=path, policy_status=ctx.status,
        outcome=outcome, reason=reason, created_at=_utc_now().isoformat(),
        policy_digest=ctx.policy.digest_hex if ctx.policy else "",
        detail=_clip(detail, _MAX_DETAIL_LEN),
        operator_reason=_clip(operator_reason, _MAX_OPERATOR_REASON_LEN),
        tsa_token_sha256=evidence.token_sha256 if evidence else "",
        tsa_token=evidence.token_b64 if evidence else "",
        tsa_challenge=evidence.challenge_hex if evidence else "",
        tsa_gen_time=evidence.gen_time_iso if evidence else "",
        operator=operator,
    )
    released = outcome == OUTCOME_RELEASED
    try:
        insert_release_audit(entry)
    except Exception:
        logger.exception("Release audit write failed: seal_id=%r path=%s",
                         _clip(seal_id, _MAX_LOG_ID_LEN), path)
        if released:
            return ReleaseDecision(False, path, "audit_unavailable",
                                   ctx.status, detail="audit write failed",
                                   slots=slots)
    logger.info("Release %s: seal_id=%r path=%s reason=%s policy=%s", outcome,
                _clip(seal_id, _MAX_LOG_ID_LEN), path, reason, ctx.status)
    return ReleaseDecision(
        allowed=released, path=path, reason=reason, policy_status=ctx.status,
        detail=entry.detail, unlock_time_iso=unlock_time_iso, slots=slots,
        key_hex=key_hex if released else None,
    )
