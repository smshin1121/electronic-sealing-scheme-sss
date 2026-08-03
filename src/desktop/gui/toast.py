"""Toast notification system for the digital evidence electronic sealing system.

Displays brief, auto-dismissing popup messages at the bottom-right corner
of the application window. Supports stacking multiple toasts.
Styled per DESIGN.md Toast Notifications: white bg, left color border, card shadow.
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

from .theme import COLORS, FONTS

# Map toast types to their left-border accent colors (DESIGN.md)
_TOAST_ACCENT: dict[str, str] = {
    "info": COLORS["info"],        # #3498db
    "success": COLORS["success"],  # #15be53
    "error": COLORS["danger"],     # #ea2261
    "warning": COLORS["warning"],  # #f39c12
}

# Map toast types to text color (high-contrast variants for text on white)
_TOAST_TEXT_COLOR: dict[str, str] = {
    "info": COLORS["text"],
    "success": COLORS["text"],
    "error": COLORS["danger_text"],
    "warning": COLORS["text"],
}

# Gap between stacked toasts (heights are measured per-toast so that
# multi-line messages do not overlap)
_TOAST_GAP = 8


class _ToastPopup:
    """A single toast popup window."""

    def __init__(
        self,
        root: tk.Tk,
        message: str,
        accent_color: str,
        text_color: str,
        y_offset: int,
        duration: int,
        on_close: callable,
    ) -> None:
        self._root = root
        self._on_close = on_close
        self._after_id: Optional[str] = None

        self._window = tk.Toplevel(root)
        self._window.wm_overrideredirect(True)
        self._window.attributes("-topmost", True)

        # Outer frame with accent color (acts as left border)
        outer = tk.Frame(self._window, bg=accent_color)
        outer.pack(fill="both", expand=True)

        # Inner frame: white background, shifted right by 3px for left border effect
        inner = tk.Frame(outer, bg=COLORS["card_bg"], padx=16, pady=10)
        inner.pack(fill="both", expand=True, padx=(3, 0))

        tk.Label(
            inner,
            text=message,
            bg=COLORS["card_bg"],
            fg=text_color,
            font=FONTS["body"],
            anchor="w",
        ).pack(fill="x")

        # Position at bottom-right of root window
        self._window.update_idletasks()
        toast_width = max(self._window.winfo_reqwidth(), 300)
        toast_height = self._window.winfo_reqheight()
        # Expose the real height so the manager can stack without overlap
        self.height = toast_height

        root_x = root.winfo_rootx()
        root_y = root.winfo_rooty()
        root_w = root.winfo_width()
        root_h = root.winfo_height()

        x = root_x + root_w - toast_width - 16
        y = root_y + root_h - toast_height - 16 - y_offset

        self.width = toast_width
        self._window.wm_geometry(f"{toast_width}x{toast_height}+{x}+{y}")

        # Schedule auto-dismiss
        self._after_id = root.after(duration, self.close)

    def move_to(self, y_offset: int) -> None:
        """Reposition the toast for the given stack offset from the bottom."""
        try:
            root_x = self._root.winfo_rootx()
            root_y = self._root.winfo_rooty()
            root_w = self._root.winfo_width()
            root_h = self._root.winfo_height()

            x = root_x + root_w - self.width - 16
            y = root_y + root_h - self.height - 16 - y_offset
            self._window.wm_geometry(f"+{x}+{y}")
        except tk.TclError:
            pass

    def close(self) -> None:
        """Destroy the toast window and notify the manager."""
        if self._after_id is not None:
            try:
                self._root.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

        try:
            self._window.destroy()
        except Exception:
            pass

        self._on_close(self)


class ToastManager:
    """Manages toast notification display and stacking.

    Usage::

        manager = ToastManager()
        manager.show(root, "Operation complete!", toast_type="success")
        manager.show(root, "Something went wrong.", toast_type="error", duration=5000)
    """

    def __init__(self) -> None:
        self._active_toasts: list[_ToastPopup] = []

    def show(
        self,
        root: tk.Tk,
        message: str,
        toast_type: str = "info",
        duration: int = 3000,
    ) -> None:
        """Display a toast notification.

        Args:
            root: The root Tk window to anchor the toast to.
            message: The message text to display.
            toast_type: One of "info", "success", "error", "warning".
            duration: Auto-dismiss delay in milliseconds.
        """
        accent_color = _TOAST_ACCENT.get(toast_type, _TOAST_ACCENT["info"])
        text_color = _TOAST_TEXT_COLOR.get(toast_type, COLORS["text"])
        # Stack by the ACTUAL height of each active toast (multi-line safe)
        y_offset = sum(
            getattr(toast, "height", 0) + _TOAST_GAP
            for toast in self._active_toasts
        )

        toast = _ToastPopup(
            root=root,
            message=message,
            accent_color=accent_color,
            text_color=text_color,
            y_offset=y_offset,
            duration=duration,
            on_close=self._on_toast_close,
        )
        self._active_toasts.append(toast)

    def _on_toast_close(self, toast: _ToastPopup) -> None:
        """Remove a closed toast and restack the remaining ones."""
        if toast in self._active_toasts:
            self._active_toasts.remove(toast)
        self._restack()

    def _restack(self) -> None:
        """Reposition remaining toasts so no gap is left by closed ones."""
        y_offset = 0
        for toast in self._active_toasts:
            toast.move_to(y_offset)
            y_offset += getattr(toast, "height", 0) + _TOAST_GAP
