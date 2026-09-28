"""Seal-mode wording shared by the seal, unseal and reseal wizards.

Pure helpers (no Tk) that turn a record's ``seal_mode`` into what the
wizards show: the mode label and the shares a key recovery needs
(standard: any two of s1-s4; strict: the subject's s1 plus one
institutional share). The mode itself is read with
:func:`desktop.record.seal_mode_of`, so a record with an unknown mode, or
one that disagrees with its signed policy, is shown as a problem instead
of being read as standard.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

from desktop.share_file import fingerprint_of  # noqa: F401 (re-exported for the wizards)

from .i18n import t

MODE_STANDARD = "standard"
MODE_STRICT = "strict"
SEAL_MODES = (MODE_STANDARD, MODE_STRICT)
# Section 3.3.2: standard stays the procedural default (availability);
# strict is chosen per seal, with the subject's informed consent.
DEFAULT_SEAL_MODE = MODE_STANDARD


@dataclass(frozen=True)
class SealModeView:
    """What a wizard shows about a record's seal mode.

    Attributes:
        mode: ``"standard"``/``"strict"``, or None when the record's mode
            cannot be determined.
        label: Localized mode label.
        shares: Localized recovery-share requirement ("" when unknown).
        problem: True when the record's mode is invalid or inconsistent.
    """

    mode: Optional[str]
    label: str
    shares: str
    problem: bool = False


def mode_label(mode: str) -> str:
    """Localized label of a valid mode."""
    return t("mode.strict") if mode == MODE_STRICT else t("mode.standard")


def recovery_shares_text(mode: str) -> str:
    """Localized statement of the shares a recovery needs in ``mode``."""
    return t("mode.shares_strict") if mode == MODE_STRICT else t("mode.shares_standard")


def keysplit_title(mode: str) -> str:
    """Localized title of the key-split result for ``mode``."""
    return (
        t("keysplit.complete_strict") if mode == MODE_STRICT
        else t("keysplit.complete_title")
    )


def key_shares_summary(mode: str) -> str:
    """Localized one-line description of the four shares for ``mode``."""
    return (
        t("summary.key_shares_strict") if mode == MODE_STRICT
        else t("summary.key_shares_standard")
    )


def describe_seal_mode(record: Optional[Mapping[str, Any]]) -> SealModeView:
    """Describe the mode that governs ``record`` (never raises)."""
    from desktop.record import RecordValidationError, seal_mode_of

    if not isinstance(record, Mapping):
        return SealModeView(None, t("mode.problem").format(v="-"), "", True)
    try:
        mode = seal_mode_of(record)
    except RecordValidationError as exc:
        return SealModeView(None, t("mode.problem").format(v=exc), "", True)
    label = t("mode.legacy") if "seal_mode" not in record else mode_label(mode)
    return SealModeView(mode, label, recovery_shares_text(mode))


def seal_mode_rows(
    record: Optional[Mapping[str, Any]], *, kept: bool = False
) -> list[tuple[str, ...]]:
    """SummaryView rows for a record's mode and its recovery requirement.

    Args:
        record: The record whose mode is shown.
        kept: Word the mode as carried over from the previous record
            (resealing).
    """
    view = describe_seal_mode(record)
    label = t("mode.kept").format(v=view.label) if kept and not view.problem else view.label
    if view.problem:
        rows: list[tuple[str, ...]] = [(t("summary.seal_mode"), label, "danger")]
    elif view.mode == MODE_STRICT:
        rows = [(t("summary.seal_mode"), label, "warning")]
    else:
        rows = [(t("summary.seal_mode"), label)]
    if view.shares:
        rows.append((t("summary.recovery_shares"), view.shares))
    return rows
