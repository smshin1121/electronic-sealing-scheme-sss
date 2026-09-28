"""Share handout panel of the seal (S6) and reseal (R7) wizards (stage E, E1b).

After a key split the operator saves share 1 (for the subject) and share 2
(for the investigator) to two separate ``.share`` files chosen in a save
dialog (:mod:`desktop.share_file` writes, never overwrites, and reads each
file back). The panel shows only the fingerprint and the saved path of a
share, never its contents; in strict mode it states that share 1 must go to
the subject. The wizards continue only once both shares are saved, and call
:meth:`ShareHandoutPanel.clear` at completion to drop the shares.
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Optional, Sequence

from desktop.share_file import (
    SHARE_FILE_SUFFIX,
    SavedShare,
    ShareFileError,
    default_share_filename,
    write_share_file,
)

from .i18n import t
from .theme import get_color, get_font

logger = logging.getLogger(__name__)

AskSavePath = Callable[..., Any]

_HANDED_OUT = (1, 2)
_TEXT_WRAP = 560
_ERROR_KEYS = {
    "exists": "handout.error_exists",
    "same_path": "handout.error_same_path",
    "extension": "handout.error_extension",
    "verify": "handout.error_verify",
    "io": "handout.error_io",
    "format": "handout.error_format",
    "index": "handout.error_format",
}


def share_file_rows(saved: Sequence[SavedShare]) -> list[tuple[str, str]]:
    """SummaryView rows for saved share files (path and fingerprint only)."""
    return [
        (
            t(f"summary.share{share.index}_file"),
            t("handout.saved").format(path=share.path, fingerprint=share.fingerprint),
        )
        for share in saved
    ]


class ShareHandoutPanel(ttk.LabelFrame):
    """Save shares 1 and 2 to separate files; fingerprints and paths only."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        ask_save_path: Optional[AskSavePath] = None,
    ) -> None:
        super().__init__(master, text=t("handout.title"), padding=(8, 4))
        self._ask_save_path = ask_save_path or filedialog.asksaveasfilename
        self._seal_id = ""
        # The shares to hand out ({1: s1, 2: s2}); None before load and
        # after clear. Nothing else in the panel holds share text.
        self._shares: Optional[dict[int, str]] = None
        self._saved: dict[int, SavedShare] = {}
        self._buttons: dict[int, tk.Button] = {}
        self._status: dict[int, tk.Label] = {}
        self._build()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build(self) -> None:
        tk.Label(
            self, text=t("handout.intro"), font=get_font("small"),
            wraplength=_TEXT_WRAP, justify="left", anchor="w",
        ).pack(fill="x", pady=(0, 4))
        self._strict_notice = tk.Label(
            self, text=t("handout.strict_notice"), fg=get_color("danger_text"),
            font=get_font("body"), wraplength=_TEXT_WRAP, justify="left",
            anchor="w",
        )
        self._rows = tk.Frame(self)
        self._rows.pack(fill="x")
        for index in _HANDED_OUT:
            self._build_row(index)

    def _build_row(self, index: int) -> None:
        row = tk.Frame(self._rows)
        row.pack(fill="x", pady=2)
        tk.Label(
            row, text=t(f"handout.share{index}_label"), anchor="w", width=28,
            font=get_font("body"),
        ).pack(side="left")
        button = tk.Button(
            row, text=t("handout.save"), state="disabled",
            command=lambda: self.save(index),
        )
        button.pack(side="left", padx=(0, 8))
        status = tk.Label(
            row, text=t("handout.not_saved"), anchor="w", justify="left",
            fg=get_color("text_secondary"), font=get_font("small"),
            wraplength=_TEXT_WRAP - 200,
        )
        status.pack(side="left", fill="x", expand=True)
        self._buttons[index] = button
        self._status[index] = status

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def load(self, seal_id: str, shares: Sequence[str], mode: str) -> None:
        """Take shares 1 and 2 (``shares[0]``, ``shares[1]``) to hand out.

        ``seal_id`` only names the suggested files. The wizards pass an ID
        already checked (S4 record format; R1 plain token); anything else
        gets the generic names ``share1_subject.share`` and so on.
        """
        self._seal_id = _file_name_seal_id(seal_id)
        self._shares = {1: shares[0], 2: shares[1]}
        self._saved = {}
        for index in _HANDED_OUT:
            self._buttons[index].configure(state="normal")
            self._status[index].configure(
                text=t("handout.not_saved"), fg=get_color("text_secondary")
            )
        if mode == "strict":
            self._strict_notice.pack(fill="x", pady=(0, 4), before=self._rows)
        else:
            self._strict_notice.pack_forget()

    @property
    def loaded(self) -> bool:
        """Whether a split was loaded (the shares may since be cleared)."""
        return self._shares is not None or bool(self._saved)

    def holds_shares(self) -> bool:
        """Whether share text is still held in memory."""
        return self._shares is not None

    def all_saved(self) -> bool:
        """Whether shares 1 and 2 are both saved and verified."""
        return all(index in self._saved for index in _HANDED_OUT)

    def has_unsaved(self) -> bool:
        """Shares are held that are not saved yet (leaving would lose them)."""
        return self._shares is not None and not self.all_saved()

    def saved(self) -> tuple[SavedShare, ...]:
        """The saved files, by share index."""
        return tuple(self._saved[index] for index in sorted(self._saved))

    def strict_notice_shown(self) -> bool:
        """Whether the strict-mode notice is on screen."""
        return bool(self._strict_notice.winfo_manager())

    def button(self, index: int) -> tk.Button:
        """The save button of share ``index`` (1 or 2)."""
        return self._buttons[index]

    def clear(self) -> None:
        """Drop the shares (at completion, or when the wizard is left).

        The saved paths stay shown. Safe while the panel is being destroyed
        (the wizards call it from their ``<Destroy>`` handlers).
        """
        self._shares = None
        for index in _HANDED_OUT:
            if index not in self._saved:
                try:
                    self._buttons[index].configure(state="disabled")
                except tk.TclError:
                    pass  # already destroyed

    # ------------------------------------------------------------------
    # Saving
    # ------------------------------------------------------------------

    def save(self, index: int) -> Optional[SavedShare]:
        """Ask for a file and save share ``index`` to it (once)."""
        if self._shares is None or index in self._saved:
            return None
        path = self._ask_save_path(
            parent=self.winfo_toplevel(),
            title=t(f"handout.dialog_title{index}"),
            defaultextension=SHARE_FILE_SUFFIX,
            initialfile=default_share_filename(self._seal_id, index),
            filetypes=[(t("filedialog.share_files"), f"*{SHARE_FILE_SUFFIX}")],
            confirmoverwrite=False,  # the writer refuses existing files
        )
        if not path or not isinstance(path, str):
            return None  # dialog cancelled
        taken = [saved.path for saved in self._saved.values()]
        try:
            saved = write_share_file(
                path, self._shares[index], index=index, taken_paths=taken
            )
        except ShareFileError as exc:
            messagebox.showerror(
                t("handout.error_title"), self._error_text(exc),
                parent=self.winfo_toplevel(),
            )
            return None
        self._saved = {**self._saved, index: saved}
        self._buttons[index].configure(state="disabled")
        self._status[index].configure(
            text=t("handout.saved").format(
                path=saved.path, fingerprint=saved.fingerprint
            ),
            fg=get_color("success_text"),
        )
        if saved.temp_left:
            messagebox.showwarning(
                t("handout.temp_left_title"),
                t("handout.temp_left_msg").format(path=saved.temp_left),
                parent=self.winfo_toplevel(),
            )
        return saved

    @staticmethod
    def _error_text(error: ShareFileError) -> str:
        key = _ERROR_KEYS.get(error.reason, "handout.error_io")
        return t(key).format(path=error.path, detail=error.detail)


def _file_name_seal_id(seal_id: str) -> str:
    """``seal_id`` if it may appear in a file name, else ``""``."""
    try:
        default_share_filename(seal_id, 1)
    except ValueError:
        logger.warning("Seal ID not usable in a file name; generic share file names")
        return ""
    return seal_id
