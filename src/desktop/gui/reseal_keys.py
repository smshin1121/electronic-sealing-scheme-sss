"""Key steps of the reseal wizard: R7 split and handout, R8 save, leaving.

Mixed into :class:`desktop.gui.reseal_wizard.ResealWizard` (stage E, E1 fix
round, B3(c)): the orchestration around the new key's shares lives here so
that the wizard module keeps its step layouts.

* R7: the first Next splits the new key (``run_r7_split_key``) and hands
  shares 1 and 2 to the handout panel; R7 -> R8 once both are saved to files.
* R8: the reseal is saved on a worker (``run_r8_save``); the wizard is busy
  meanwhile, a failure is shown and Next retries.
* Leaving: while shares 1/2 are held but unsaved, or saved while the reseal
  is not (R8 not run or failed), every way out (Cancel, Escape, and the main
  window's menus, Exit and X through :meth:`leave_question`) asks first,
  default No. On leaving, partial output is removed and the key material
  (shares, and the process that holds the key) is released.

The mixin relies on the wizard's ``_data``, ``_handout_panel``, ``_busy``,
``_set_busy``, ``_set_nav_message``, ``_refresh_r8_summary``,
``_cleanup_partial_encryption``, ``_cancel_btn``, ``_r7_result``,
``_async_cancel`` and ``_on_cancel``.
"""

from __future__ import annotations

import logging
from tkinter import messagebox
from typing import Any, Optional

from .i18n import t
from .progress_dialog import run_async
from .seal_mode_view import (
    MODE_STANDARD,
    MODE_STRICT,
    fingerprint_of,
    keysplit_title,
    recovery_shares_text,
)

logger = logging.getLogger(__name__)

# (title, message) i18n keys of the questions asked before leaving.
UNSAVED_SHARES_QUESTION = ("nav.unsaved_title", "nav.unsaved_msg")
UNRECORDED_RESEAL_QUESTION = ("nav.unrecorded_title", "nav.unrecorded_msg")


class ResealKeyStepsMixin:
    """R7/R8 orchestration and leaving with key material (see module doc)."""

    # ------------------------------------------------------------------
    # R7: split the new key, hand out shares 1 and 2
    # ------------------------------------------------------------------

    def _validate_r7(self) -> bool:
        """First Next splits the key; R7 -> R8 once shares 1 and 2 are in files."""
        self._set_nav_message("")
        process = self._data.get("_process")
        if process is None:
            return True
        if not self._handout_panel.loaded:
            # The unlock time was fixed in the R6 record (R4 setting).
            self._split_r7(process)
            return False
        if not self._handout_panel.all_saved():
            self._set_nav_message(t("handout.save_both_first"))
            return False
        return True

    def _split_r7(self, process: Any) -> None:
        """Split the new key and hand shares 1 and 2 to the R7 panel."""
        try:
            result = process.run_r7_split_key()
        except Exception as exc:
            messagebox.showerror(
                t("keysplit.error"), str(exc), parent=self.winfo_toplevel()
            )
            return
        shares = result["shares"]
        self._share_prints = tuple(fingerprint_of(share) for share in shares)
        self._data["unlock_time_iso"] = result["unlock_time_iso"]
        self._handout_panel.load(
            self._data.get("seal_id", ""), shares[:2],
            self._data.get("seal_mode", MODE_STANDARD),
        )
        self._refresh_r7_result()
        self._set_nav_message(t("handout.save_then_next"), kind="info")

    def _refresh_r7_result(self) -> None:
        """Display key split results (fingerprints, never share text)."""
        self._r7_result.configure(state="normal")
        self._r7_result.delete("1.0", "end")

        unlock_time = self._data.get("unlock_time_iso", "N/A")
        mode = self._data.get("seal_mode", MODE_STANDARD)

        if len(self._share_prints) == 4:
            # Fingerprints only: visible share prefixes XOR to key bytes in
            # strict mode (s1 = R, s2-s4 = X).
            prints = self._share_prints
            lines = [
                keysplit_title(mode),
                "",
                t("keysplit.share_subject").format(v=prints[0]),
                t("keysplit.share_investigator").format(v=prints[1]),
                t("keysplit.share_system").format(v=prints[2]),
                t("keysplit.share_admin").format(v=prints[3]),
                t("keysplit.fingerprint_note"),
                "",
                f"  unlock_time: {unlock_time}",
                t("keysplit.recovery").format(v=recovery_shares_text(mode)),
                "",
                t("keysplit.subject_store"),
                t("keysplit.investigator_store"),
                t("keysplit.system_store"),
            ]
            if mode == MODE_STRICT:
                lines += ["", t("mode.strict_warning")]
        else:
            lines = [t("keysplit.run_prompt")]

        self._r7_result.insert("1.0", "\n".join(lines))
        self._r7_result.configure(state="disabled")

    # ------------------------------------------------------------------
    # R8: save the reseal
    # ------------------------------------------------------------------

    def _validate_r8(self) -> bool:
        """Completion needs the saved reseal; after a failure Next retries."""
        if self._data.get("_process") is None or self._data.get("reseal_saved"):
            return True
        self._ensure_r8_saved()
        return False

    def _r8_badge(self, saved: bool) -> tuple[str, str]:
        """R8 badge: complete once saved, saving while busy, else not saved."""
        if saved:
            return t("common.complete"), "success"
        if self._busy:
            return t("reseal.saving_badge"), "warning"
        return t("reseal.not_saved_badge"), "danger"

    def _ensure_r8_saved(self) -> None:
        """Save the reseal (R8) on a worker, once; the wizard is busy meanwhile.

        Busy keeps completion, navigation and the window's close button
        waiting for the save; a failure is shown and Next retries.
        """
        process = self._data.get("_process")
        if process is None or self._data.get("reseal_saved") or self._busy:
            return
        self._set_busy(True, t("reseal.saving"))
        self._refresh_r8_summary()  # badge: saving
        run_async(
            self, process.run_r8_save, self._on_r8_saved,
            self._on_r8_save_error, cancel_event=self._async_cancel,
        )

    def _on_r8_saved(self, result: Any) -> None:
        # The result (with the shares) is not kept; only that it was saved.
        # A saved reseal is completed, not cancelled.
        self._data["reseal_saved"] = True
        self._set_busy(False)
        self._cancel_btn.configure(state="disabled")
        self._refresh_r8_summary()
        logger.info("R8 저장 완료: %s", result.seal_id)

    def _on_r8_save_error(self, exc: Exception) -> None:
        logger.warning("R8 저장 오류: %s", exc)
        self._set_busy(False)
        self._refresh_r8_summary()  # badge: not saved
        messagebox.showerror(
            t("reseal.save_failed_title"),
            t("reseal.save_failed_msg").format(v=exc),
            parent=self.winfo_toplevel(),
        )
        self._set_nav_message(t("reseal.save_failed_retry"))

    # ------------------------------------------------------------------
    # Leaving with key material
    # ------------------------------------------------------------------

    def has_unsaved_shares(self) -> bool:
        """The new key is split but shares 1/2 are not yet in files (R7)."""
        return self._handout_panel.has_unsaved()

    def leave_question(self) -> Optional[tuple[str, str]]:
        """What leaving now must ask first, as (title, message) i18n keys.

        Shares 1/2 split but unsaved: they are lost (``nav.unsaved_*``).
        Both saved, the reseal not saved (R8 not run or failed): the handed
        out shares belong to a key this PC's database does not record
        (``nav.unrecorded_*``). None: nothing is lost by leaving.
        """
        panel = self._handout_panel
        if panel.has_unsaved():
            return UNSAVED_SHARES_QUESTION
        if panel.holds_shares() and not self._data.get("reseal_saved"):
            return UNRECORDED_RESEAL_QUESTION
        return None

    def _handle_cancel(self) -> None:
        """Cancel and Escape: ask first; a saved reseal is completed, not cancelled.

        With key material at stake the question is the main window's own
        (default: stay); otherwise the plain cancel confirmation.
        """
        if self._busy or self._data.get("reseal_saved"):
            return
        question = self.leave_question()
        parent = self.winfo_toplevel()
        if question is None:
            confirmed = messagebox.askyesno(
                t("cancel.title"), t("reseal.cancel_confirm"), parent=parent
            )
        else:
            title, message = question
            confirmed = messagebox.askyesno(
                t(title), t(message), icon="warning", default="no", parent=parent
            )
        if confirmed:
            self._leave()

    def _leave(self) -> None:
        """The operator leaves: partial output removed, key material released."""
        self._cleanup_partial_encryption()  # reads the process: first
        self._release_key_material()
        if self._on_cancel is not None:
            self._on_cancel()

    def _release_key_material(self) -> dict[str, Any]:
        """Drop the shares and the process (key, shares); at completion or leaving.

        Returns the completion data for the application, without either.
        """
        self._handout_panel.clear()
        self._data = {k: v for k, v in self._data.items() if k != "_process"}
        return dict(self._data)
