"""Seal-policy group of the seal wizard's S2 step.

Holds the two choices that S4 writes into the record before S5 signs it:

* the seal mode — ``standard`` (preselected, the procedural default of
  Section 3.3.2) or ``strict``. Choosing strict shows a warning that
  without the subject's share (s1) the key can never be recovered, and the
  wizard proceeds only after the consent box is ticked. Switching back to
  standard clears the consent, so it is asked again;
* the unlock days of the time-locked share (moved here from S6, where the
  value arrived after the record had already been signed).
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from .i18n import t
from .seal_mode_view import DEFAULT_SEAL_MODE, MODE_STANDARD, MODE_STRICT
from .theme import get_color, get_font

_TEXT_WRAP = 560


class SealPolicyPanel(ttk.LabelFrame):
    """Seal mode (standard / strict with consent) and unlock days."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        min_days: int,
        max_days: int,
        default_days: int,
    ) -> None:
        super().__init__(master, text=t("mode.section_title"), padding=(8, 4))
        self._min_days = min_days
        self._max_days = max_days
        self._mode_var = tk.StringVar(value=DEFAULT_SEAL_MODE)
        self._consent_var = tk.BooleanVar(value=False)
        self._days_var = tk.IntVar(value=default_days)

        self._build_mode_row()
        self._build_strict_notice()
        self._build_unlock_row()
        self._on_mode_change()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_mode_row(self) -> None:
        row = tk.Frame(self)
        row.pack(fill="x", pady=4)
        tk.Label(
            row, text=f"* {t('mode.label')}", anchor="w", width=20,
            font=get_font("body"),
        ).pack(side="left")
        self.standard_radio = tk.Radiobutton(
            row, text=t("mode.standard"), value=MODE_STANDARD,
            variable=self._mode_var, command=self._on_mode_change,
        )
        self.standard_radio.pack(side="left")
        self.strict_radio = tk.Radiobutton(
            row, text=t("mode.strict"), value=MODE_STRICT,
            variable=self._mode_var, command=self._on_mode_change,
        )
        self.strict_radio.pack(side="left", padx=(12, 0))

    def _build_strict_notice(self) -> None:
        self._notice = tk.Frame(self)
        tk.Label(
            self._notice, text=t("mode.strict_warning"),
            fg=get_color("danger_text"), font=get_font("body"),
            wraplength=_TEXT_WRAP, justify="left", anchor="w",
        ).pack(fill="x", pady=(2, 4))
        self.consent_check = tk.Checkbutton(
            self._notice, text=t("mode.strict_consent"),
            variable=self._consent_var, wraplength=_TEXT_WRAP,
            justify="left", anchor="w",
        )
        self.consent_check.pack(fill="x")

    def _build_unlock_row(self) -> None:
        self._unlock_row = tk.Frame(self)
        self._unlock_row.pack(fill="x", pady=4)
        tk.Label(
            self._unlock_row, text=t("seal.unlock_label"), anchor="w", width=20,
        ).pack(side="left")
        self.unlock_spin = tk.Spinbox(
            self._unlock_row, from_=self._min_days, to=self._max_days,
            textvariable=self._days_var, width=6,
        )
        self.unlock_spin.pack(side="left")
        tk.Label(self._unlock_row, text=t("seal.unlock_range")).pack(
            side="left", padx=8
        )

    def _on_mode_change(self) -> None:
        """Show the strict warning and consent only while strict is chosen."""
        if self.mode == MODE_STRICT:
            self._notice.pack(fill="x", pady=(0, 4), before=self._unlock_row)
            return
        self._consent_var.set(False)
        self._notice.pack_forget()

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        """The chosen seal mode."""
        return self._mode_var.get()

    @property
    def consented(self) -> bool:
        """Whether the strict-mode consent box is ticked."""
        return bool(self._consent_var.get())

    def strict_notice_shown(self) -> bool:
        """Whether the strict warning and consent are on screen."""
        return bool(self._notice.winfo_manager())

    def unlock_days(self) -> Optional[int]:
        """The unlock days, or None when not an integer in range."""
        try:
            days = int(self._days_var.get())
        except (tk.TclError, ValueError):
            return None
        return days if self._min_days <= days <= self._max_days else None

    def validation_errors(self) -> list[str]:
        """Localized messages for every choice that blocks the wizard."""
        errors: list[str] = []
        if self.mode == MODE_STRICT and not self.consented:
            errors.append(t("validate.strict_consent"))
        if self.unlock_days() is None:
            errors.append(t("validate.unlock_range").format(
                min=self._min_days, max=self._max_days,
            ))
        return errors

    def focus_first_error(self) -> None:
        """Move focus to the first choice that blocks the wizard."""
        if self.mode == MODE_STRICT and not self.consented:
            self.consent_check.focus_set()
        elif self.unlock_days() is None:
            self.unlock_spin.focus_set()
