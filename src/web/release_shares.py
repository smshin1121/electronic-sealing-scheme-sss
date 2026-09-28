"""The shares a release combines, and the order they are tried in (stage F, F1).

Split from :mod:`web.release_gate` (see "Share selection" there), which
decides and audits; recombination and the commitment check stay there and
reach :func:`first_match` as arguments.

  - Presented shares: the investigator's s2 from the request must be
    ``2-`` followed by 1 to 64 hex digits (:func:`presented_s2`); the
    unwrapped s3 must be ``3-`` and 1 to 128 hex digits (:func:`decode_s3`).
  - Stored shares are versioned by policy generation (``key_shares`` holds
    one share per seal, slot and generation;
    :mod:`web.models.share_models`). For the deciding policy's generation G
    they are tried G first, then the other generations, highest first, the
    lower slot first within a generation (:func:`by_preference`).
  - A stored value is a candidate only when it carries its own slot's index
    prefix (``1-`` in slot 1, ``4-`` in slot 4, ...). A slot whose stored
    values are all empty is missing; one whose values all lack the prefix
    is malformed (the reasons of v1.1).
  - Owner share s1 (standard path; strict time-locked path;
    :func:`owner_shares`, :func:`owner_attempts`): every usable slot-1
    share, in order, each with the presented share(s).
  - Admin path under an authenticated policy (:func:`admin_pool`,
    :func:`admin_pairs`): every usable s4 in order, each paired with every
    usable share of the other slots, in order.
  - Admin path without an authenticated policy
    (:func:`generation_0_admin_shares`): only generation-0 shares, s4 and
    the lowest other slot, exactly as v1.1 (:func:`admin_shares`).
  - :func:`first_match` returns the first attempt whose recombination
    matches the key commitment, which is the only arbiter.

Bound: the unique key allows one share per slot and generation, so a
release tries at most one owner share per generation stored for slot 1,
and on the admin path at most the stored s4 shares times the stored shares
of the other slots. Nothing here logs a share.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Callable, Optional, Union

from .models.share_models import StoredShare

OWNER_SLOT = 1
ADMIN_SLOT = 4
GENERATION_0_ONLY = ("without an authenticated policy only generation-0 "
                     "shares are used")
# Longest "tried: ..." audit note (tried_note), and the smallest budget it
# accepts: room for the fallback "tried: <n> stored share combination(s)"
# with a ten-digit n.
TRIED_NOTE_BUDGET = 200
MIN_TRIED_NOTE_BUDGET = 48

# At most 64 hex digits. Shares are values below the field prime
# 2^256 + 297; all but the 297 values from 2^256 up fit (about 6% have fewer
# digits). Those rare shares (about 2^-248 per share) are refused here and
# need the admin path: a longer value would let the requester make the
# vendored combiner pick a larger field, whose output width depends on s1.
_S2_SHARE_RE = re.compile(r"2-[0-9a-f]{1,64}")
_S3_SHARE_RE = re.compile(r"3-[0-9a-f]{1,128}")

Shares = Union[Mapping[int, str], Iterable[StoredShare]]
# (the stored shares an attempt uses, the share strings it recombines)
Attempt = tuple[tuple[StoredShare, ...], list[str]]
Match = tuple[Optional[str], tuple[StoredShare, ...], str]


@dataclass(frozen=True)
class AdminPool:
    """The usable stored shares of the admin path."""

    admin: tuple[StoredShare, ...]
    others: tuple[StoredShare, ...]


def presented_s2(presented_share: str) -> tuple[str, str]:
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


def decode_s3(plaintext: bytes) -> Optional[str]:
    """The unwrapped s3 must be an index-3 share string."""
    try:
        share = plaintext.decode("ascii")
    except UnicodeDecodeError:
        return None
    return share if _S3_SHARE_RE.fullmatch(share) else None


def as_stored_shares(shares: Shares) -> tuple[StoredShare, ...]:
    """Stored shares; a ``{slot: share}`` mapping (the v1.x call shape of
    :func:`web.release_gate.release_admin`) counts as generation 0."""
    if isinstance(shares, Mapping):
        return tuple(StoredShare(int(index), 0, str(share or ""))
                     for index, share in shares.items())
    return tuple(shares)


def by_preference(rows: Iterable[StoredShare], generation: int) -> tuple[StoredShare, ...]:
    """``generation`` first, then the others highest first; lower slot first."""
    return tuple(sorted(rows, key=lambda row: (
        row.generation != generation, -row.generation, row.index)))


def usable(row: StoredShare) -> bool:
    """Whether a stored value carries its own slot's index prefix."""
    return bool(row.data) and row.data.startswith(f"{row.index}-")


def filled_slots(rows: Iterable[StoredShare]) -> set[int]:
    """The slots holding a non-empty share in some generation."""
    return {row.index for row in rows if row.data}


def owner_shares(rows: Iterable[StoredShare]) -> tuple[tuple[StoredShare, ...], str]:
    """The usable stored owner shares, or why there is none."""
    stored = [row for row in rows if row.index == OWNER_SLOT and row.data]
    return _usable_or_problem(stored, "owner_share")


def owner_attempts(
    owner: Iterable[StoredShare], generation: int, *presented: str
) -> list[Attempt]:
    """One attempt per stored owner share, in order, with ``presented``."""
    return [((row,), [row.data, *presented])
            for row in by_preference(owner, generation)]


def admin_pool(rows: Iterable[StoredShare]) -> tuple[Optional[AdminPool], str]:
    """The usable s4 and other shares, or the v1.1 reason there are none."""
    stored = [row for row in rows if row.data]
    admin, problem = _usable_or_problem(
        [row for row in stored if row.index == ADMIN_SLOT], "admin_share")
    if problem:
        return None, problem
    others, problem = _usable_or_problem(
        [row for row in stored if row.index != ADMIN_SLOT], "other_share")
    if problem:
        return None, problem
    return AdminPool(admin, others), ""


def admin_pairs(pool: AdminPool, generation: int) -> list[tuple[StoredShare, StoredShare]]:
    """``(other, s4)`` pairs to try: s4 in order, each with the others in order."""
    others = by_preference(pool.others, generation)
    return [(other, admin) for admin in by_preference(pool.admin, generation)
            for other in others]


def admin_attempts(pairs: Iterable[tuple[StoredShare, StoredShare]]) -> list[Attempt]:
    """One attempt per ``(other, s4)`` pair, in order."""
    return [(pair, [pair[0].data, pair[1].data]) for pair in pairs]


def admin_slots(used: Sequence[StoredShare]) -> str:
    """``2+4``: the other share's slot and the admin slot."""
    return f"{used[0].index}+{ADMIN_SLOT}"


def generation_0_admin_shares(
    rows: Iterable[StoredShare],
) -> tuple[tuple[StoredShare, ...], str]:
    """v1.1's s4 and lowest other slot, among the generation-0 shares."""
    selected, problem = admin_shares(
        {row.index: row.data for row in rows if row.generation == 0 and row.data})
    if problem:
        return (), problem
    other_index, other, admin = selected
    return (StoredShare(other_index, 0, other), StoredShare(ADMIN_SLOT, 0, admin)), ""


def first_match(
    attempts: Iterable[Attempt],
    recover: Callable[[list[str]], Optional[str]],
    matches: Callable[[str], bool],
) -> Match:
    """The first attempt whose recombination matches the key commitment.

    ``recover`` recombines an attempt's shares (``None`` when it fails) and
    ``matches`` checks a key against the commitment; the release gate
    passes its own. Returns the key and the stored shares it used, or
    ``(None, (), reason)``: ``recovery_failed`` when no attempt recombined,
    else ``commitment_mismatch``. A value that does not match is dropped at
    once and never leaves this function.
    """
    recombined = False
    for used, shares in attempts:
        key_hex = recover(shares)
        if key_hex is None:
            continue
        recombined = True
        if matches(key_hex):
            return key_hex, used, ""
    return None, (), "commitment_mismatch" if recombined else "recovery_failed"


def released_note(label: str, used: Sequence[StoredShare]) -> str:
    """``shares=1+2; share 1 of generation 2`` (the release's audit detail)."""
    return "; ".join(part for part in (label, generation_note(used)) if part)


def generation_note(used: Sequence[StoredShare]) -> str:
    """``share 1 of generation 1, share 4 of generation 2``."""
    return ", ".join(_named(row) for row in used)


def tried_note(attempts: Sequence[Attempt], budget: int = TRIED_NOTE_BUDGET) -> str:
    """The stored shares of attempts that matched nothing (audit detail).

    At most ``budget`` characters: the attempts that fit, in order, then how
    many more were tried (Codex stage F review, R1-1), or only their number
    when not even one fits. The release gate puts this note last in the
    audit detail, so its 500-character clip can only shorten this list,
    never the selection note or the TSA rule before it.

    Raises:
        ValueError: ``budget`` is below :data:`MIN_TRIED_NOTE_BUDGET`, too
            small for the count (Codex stage F review, round 2, N1).
    """
    if budget < MIN_TRIED_NOTE_BUDGET:
        raise ValueError(f"tried_note budget {budget} is below {MIN_TRIED_NOTE_BUDGET}")
    tried = [" + ".join(_named(row) for row in used) for used, _ in attempts if used]
    if not tried:
        return ""
    text = "tried: " + " | ".join(tried)
    if len(text) <= budget:
        return text
    kept: list[str] = []
    for entry in tried:
        more = len(tried) - len(kept) - 1
        if len("tried: " + " | ".join([*kept, entry]) + f" | ... ({more} more)") > budget:
            break
        kept.append(entry)
    if not kept:
        return f"tried: {len(tried)} stored share combination(s)"
    return "tried: " + " | ".join(kept) + f" | ... ({len(tried) - len(kept)} more)"


def slot_share(stored: Mapping[int, str], index: int) -> tuple[str, str]:
    """The share stored in ``index``: ``(share, "")`` or ``("", problem)``."""
    share = stored.get(index)
    if not share:
        return "", "missing"
    if not share.startswith(f"{index}-"):
        return "", "malformed"
    return share, ""


def admin_shares(stored: Mapping[int, str]) -> tuple[tuple[int, str, str], str]:
    """s4 and the lowest other stored slot, each holding its own index (v1.1)."""
    empty = (0, "", "")
    admin_share, problem = slot_share(stored, ADMIN_SLOT)
    if problem:
        return empty, f"admin_share_{problem}"
    other_index = next((i for i in sorted(stored) if i != ADMIN_SLOT), None)
    if other_index is None:
        return empty, "other_share_missing"
    other, problem = slot_share(stored, other_index)
    if problem:
        return empty, f"other_share_{problem}"
    return (other_index, other, admin_share), ""


def _usable_or_problem(
    stored: list[StoredShare], name: str
) -> tuple[tuple[StoredShare, ...], str]:
    if not stored:
        return (), f"{name}_missing"
    found = tuple(row for row in stored if usable(row))
    return (found, "") if found else ((), f"{name}_malformed")


def _named(row: StoredShare) -> str:
    return f"share {row.index} of generation {row.generation}"
