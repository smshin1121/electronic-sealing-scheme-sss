"""Enhanced signature capture pad with legal-grade features.

Replaces the basic SignaturePad from widgets.py with pressure simulation,
visual guides, signature confirmation workflow, and time recording.
"""

from __future__ import annotations

import hashlib
import io
import logging
import math
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import Optional

from .i18n import t
from .theme import COLORS, FONTS, get_color, get_font

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_INK_COLOR = "#1a237e"  # ink color — intentionally fixed
_GUIDE_COLOR = COLORS["guide_line"]
_GUIDE_FONT = (FONTS["header"][0], FONTS["header"][1] + 2)
_BASELINE_DASH = (4, 4)

_SPEED_SLOW = 5.0  # px/ms threshold for slow movement
_SPEED_FAST = 15.0  # px/ms threshold for fast movement
_WIDTH_SLOW = 3.0  # line width for slow strokes
_WIDTH_FAST = 1.0  # line width for fast strokes
_SPLINE_STEPS = 12


class EnhancedSignaturePad(tk.Frame):
    """Enhanced signature capture pad with legal-grade features.

    Features:
    - Visual guide text and baseline
    - Pressure simulation based on mouse speed
    - Signature confirmation dialog
    - Time recording (start/end)
    - Signer info display
    - PNG export with SHA-256 hashing
    """

    CANVAS_WIDTH = 480
    CANVAS_HEIGHT = 360

    def __init__(
        self,
        master: tk.Widget,
        *,
        label_text: str = "",
        required: bool = False,
    ) -> None:
        super().__init__(master)
        self._required = required
        self._has_signature = False
        self._confirmed = False
        self._last_x: Optional[int] = None
        self._last_y: Optional[int] = None
        self._last_time: Optional[float] = None
        self._lines: list[tuple[int, int, int, int]] = []

        self._sign_start_time: Optional[datetime] = None
        self._sign_end_time: Optional[datetime] = None

        self._signer_name: str = ""
        self._signer_date: str = ""
        self._saved_image_path: str = ""

        self._build_ui(label_text)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self, label_text: str) -> None:
        """Build the complete signature pad UI."""
        display_text = f"* {label_text}" if self._required else label_text

        # Header row with label and buttons
        header = tk.Frame(self)
        header.pack(fill="x")

        tk.Label(
            header,
            text=display_text,
            anchor="w",
            font=get_font("subheader"),
        ).pack(side="left")

        # Confirm button — primary purple
        self._confirm_btn = tk.Button(
            header,
            text=t("sig.complete"),
            command=self._on_confirm_click,
            fg=get_color("text_light"),
            bg=get_color("primary"),
            activebackground=get_color("primary_hover"),
            activeforeground="white",
            relief="flat",
            font=get_font("small"),
        )
        self._confirm_btn.pack(side="right", padx=(4, 0))

        # Clear button — ghost style
        self._clear_btn = tk.Button(
            header,
            text=t("sig.clear"),
            command=self.clear,
            fg=get_color("primary"),
            bg=get_color("card_bg"),
            activebackground=get_color("hover"),
            activeforeground=get_color("primary"),
            relief="solid",
            bd=1,
            font=get_font("small"),
        )
        self._clear_btn.pack(side="right")

        # Canvas — flat border with subtle border color
        self.canvas = tk.Canvas(
            self,
            width=self.CANVAS_WIDTH,
            height=self.CANVAS_HEIGHT,
            bg="white",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=get_color("border"),
        )
        self.canvas.pack(padx=4, pady=4)

        # Draw visual guides
        self._draw_guides()

        # Bind mouse events
        self.canvas.bind("<Button-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)

        # Signer info label (initially empty)
        self._info_label = tk.Label(
            self,
            text="",
            font=get_font("small"),
            fg=COLORS["text_secondary"],
            anchor="w",
        )
        self._info_label.pack(fill="x", padx=4)

        # Status label for confirmation state
        self._status_label = tk.Label(
            self,
            text="",
            font=get_font("small"),
            anchor="w",
        )
        self._status_label.pack(fill="x", padx=4)

    def _draw_guides(self) -> None:
        """Draw guide text and baseline on the canvas."""
        # Center guide text
        cx = self.CANVAS_WIDTH // 2
        cy = self.CANVAS_HEIGHT // 2
        self.canvas.create_text(
            cx, cy,
            text=t("sig.guide"),
            fill=_GUIDE_COLOR,
            font=_GUIDE_FONT,
            tags="guide",
        )

        # Dashed baseline near bottom
        baseline_y = self.CANVAS_HEIGHT - 30
        self.canvas.create_line(
            30, baseline_y,
            self.CANVAS_WIDTH - 30, baseline_y,
            fill=_GUIDE_COLOR,
            dash=_BASELINE_DASH,
            tags="guide_line",
        )

    # ------------------------------------------------------------------
    # Mouse event handlers
    # ------------------------------------------------------------------

    def _on_press(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        """Handle mouse button press to start a stroke."""
        if self._confirmed:
            return

        # Remove guide text on first stroke
        if not self._has_signature:
            self.canvas.delete("guide")
            self._sign_start_time = datetime.now()

        self._last_x = event.x
        self._last_y = event.y
        self._last_time = time.monotonic() * 1000  # ms

    def _on_drag(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        """Handle mouse drag to draw a stroke with pressure simulation."""
        if self._confirmed:
            return
        if self._last_x is None or self._last_y is None:
            return

        now_ms = time.monotonic() * 1000
        dt = now_ms - (self._last_time or now_ms)

        # Calculate speed-based line width
        line_width = self._calculate_width(
            self._last_x, self._last_y, event.x, event.y, dt,
        )

        self.canvas.create_line(
            self._last_x,
            self._last_y,
            event.x,
            event.y,
            width=line_width,
            fill=_INK_COLOR,
            capstyle="round",
            joinstyle="round",
            smooth=True,
            splinesteps=_SPLINE_STEPS,
        )

        self._lines.append((self._last_x, self._last_y, event.x, event.y))
        self._has_signature = True

        self._last_x = event.x
        self._last_y = event.y
        self._last_time = now_ms

    def _on_release(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        """Handle mouse button release to end a stroke."""
        self._last_x = None
        self._last_y = None
        self._last_time = None

    @staticmethod
    def _calculate_width(
        x1: int, y1: int, x2: int, y2: int, dt: float,
    ) -> float:
        """Calculate line width based on mouse movement speed.

        Slow movement (< 5 px/ms) -> 3px width
        Fast movement (> 15 px/ms) -> 1px width
        Intermediate -> linear interpolation
        """
        if dt <= 0:
            return _WIDTH_SLOW

        dist = math.sqrt((x2 - x1) ** 2 + (y2 - y1) ** 2)
        speed = dist / dt  # px/ms

        if speed <= _SPEED_SLOW:
            return _WIDTH_SLOW
        if speed >= _SPEED_FAST:
            return _WIDTH_FAST

        # Linear interpolation between slow and fast
        ratio = (speed - _SPEED_SLOW) / (_SPEED_FAST - _SPEED_SLOW)
        return _WIDTH_SLOW + ratio * (_WIDTH_FAST - _WIDTH_SLOW)

    # ------------------------------------------------------------------
    # Confirmation workflow
    # ------------------------------------------------------------------

    def _on_confirm_click(self) -> None:
        """Show preview dialog for signature confirmation."""
        if not self._has_signature:
            return

        if self._confirmed:
            return

        self._show_preview_dialog()

    def _show_preview_dialog(self) -> None:
        """Display a preview Toplevel for signature confirmation.

        Uses transient + lift + focus_force instead of grab_set()
        to avoid blocking the main window.
        Disables confirm button while dialog is open to prevent duplicate calls.
        """
        # Disable confirm button to prevent duplicate dialog opens
        self._confirm_btn.configure(state="disabled")

        dialog = tk.Toplevel(self)
        dialog.title(t("sig.preview_title"))
        dialog.resizable(False, False)
        dialog.transient(self.winfo_toplevel())
        # Do NOT use grab_set() — it can block the main window
        dialog.focus_force()
        dialog.lift()
        dialog.attributes("-topmost", True)
        dialog.after(100, lambda: dialog.attributes("-topmost", False))

        # Clean dialog styling
        dialog.configure(bg=get_color("card_bg"))

        tk.Label(
            dialog,
            text=t("sig.preview_text"),
            font=get_font("header"),
            fg=get_color("heading"),
            bg=get_color("card_bg"),
        ).pack(padx=16, pady=(16, 8))

        # Scale the preview so the dialog fits on the screen even at
        # high DPI scaling / small displays (keeps the aspect ratio).
        try:
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
        except tk.TclError:
            screen_w, screen_h = 1280, 800
        scale = min(
            1.0,
            max(0.3, (screen_w - 160) / self.CANVAS_WIDTH),
            max(0.3, (screen_h - 320) / self.CANVAS_HEIGHT),
        )
        preview_w = int(self.CANVAS_WIDTH * scale)
        preview_h = int(self.CANVAS_HEIGHT * scale)

        # Create a preview canvas copying the current signature
        preview_canvas = tk.Canvas(
            dialog,
            width=preview_w,
            height=preview_h,
            bg="white",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=get_color("border"),
        )
        preview_canvas.pack(padx=16, pady=8)

        # Redraw the baseline on preview (scaled)
        baseline_y = preview_h - int(30 * scale)
        preview_canvas.create_line(
            int(30 * scale), baseline_y,
            preview_w - int(30 * scale), baseline_y,
            fill=_GUIDE_COLOR,
            dash=_BASELINE_DASH,
        )

        # Reproduce all strokes on the preview canvas (scaled)
        for x1, y1, x2, y2 in self._lines:
            preview_canvas.create_line(
                x1 * scale, y1 * scale, x2 * scale, y2 * scale,
                width=max(1, round(2 * scale)),
                fill=_INK_COLOR,
                capstyle="round",
                smooth=True,
                splinesteps=_SPLINE_STEPS,
            )

        # Buttons
        btn_frame = tk.Frame(dialog, bg=get_color("card_bg"))
        btn_frame.pack(padx=16, pady=(8, 16))

        def on_accept() -> None:
            try:
                self._confirmed = True
                self._sign_end_time = datetime.now()
                self._disable_canvas()
                self._status_label.configure(
                    text=t("sig.confirmed"),
                    fg=COLORS["success_text"],
                )
            except Exception:
                pass
            finally:
                dialog.destroy()

        def on_retry() -> None:
            self._confirm_btn.configure(state="normal")
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", on_retry)

        # Accept — primary purple, large clickable area
        accept_btn = tk.Button(
            btn_frame,
            text=t("sig.accept"),
            command=on_accept,
            fg=get_color("text_light"),
            bg=get_color("primary"),
            activebackground=get_color("primary_hover"),
            activeforeground="white",
            relief="raised",
            width=14,
            height=2,
            font=get_font("button"),
            cursor="hand2",
        )
        accept_btn.pack(side="left", padx=8)

        # Retry — ghost style, large clickable area
        retry_btn = tk.Button(
            btn_frame,
            text=t("sig.retry"),
            command=on_retry,
            fg=get_color("primary"),
            bg=get_color("card_bg"),
            activebackground=get_color("hover"),
            activeforeground=get_color("primary"),
            relief="raised",
            width=14,
            height=2,
            font=get_font("button"),
            cursor="hand2",
        )
        retry_btn.pack(side="left", padx=8)

        # Center dialog over parent
        dialog.update_idletasks()
        parent = self.winfo_toplevel()
        px = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(px, 0)}+{max(py, 0)}")

    def _disable_canvas(self) -> None:
        """Disable drawing on the canvas after confirmation."""
        self.canvas.unbind("<Button-1>")
        self.canvas.unbind("<B1-Motion>")
        self.canvas.unbind("<ButtonRelease-1>")
        self._clear_btn.configure(state="disabled")
        self._confirm_btn.configure(state="disabled")

    def _enable_canvas(self) -> None:
        """Re-enable drawing on the canvas."""
        self.canvas.bind("<Button-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self._clear_btn.configure(state="normal")
        self._confirm_btn.configure(state="normal")

    # ------------------------------------------------------------------
    # Signer info
    # ------------------------------------------------------------------

    def set_signer_info(self, name: str, date: str) -> None:
        """Display signer name and date below the canvas."""
        self._signer_name = name
        self._signer_date = date
        self._info_label.configure(
            text=t("sig.signer_info").format(name=name, date=date),
        )

    # ------------------------------------------------------------------
    # Export / hashing
    # ------------------------------------------------------------------

    def save_as_png(self, filepath: str) -> bool:
        """Save the signature canvas as a PNG file using PIL.

        Pipeline: canvas.postscript -> PIL Image -> PNG

        Returns:
            True if saved successfully, False otherwise.
        """
        if not self._has_signature:
            return False

        try:
            from PIL import Image

            # Generate PostScript from canvas
            ps_data = self.canvas.postscript(colormode="color")

            # Convert PS to PIL Image
            img = Image.open(io.BytesIO(ps_data.encode("utf-8")))
            img.save(filepath, "PNG")

            self._saved_image_path = str(Path(filepath).resolve())
            logger.info("Signature saved as PNG: %s", self._saved_image_path)
            return True
        except Exception:
            logger.exception("Failed to save signature as PNG")
            return False

    def get_signature_hash(self) -> str:
        """Return the SHA-256 hash of the signature image data.

        If the signature has been saved as PNG, hashes the file content.
        Otherwise, hashes the PostScript representation.
        """
        if not self._has_signature:
            return ""

        try:
            if self._saved_image_path and Path(self._saved_image_path).exists():
                data = Path(self._saved_image_path).read_bytes()
            else:
                ps_data = self.canvas.postscript(colormode="color")
                data = ps_data.encode("utf-8")

            return hashlib.sha256(data).hexdigest()
        except Exception:
            logger.exception("Failed to compute signature hash")
            return ""

    def get_signature_data(self) -> dict:
        """Return a complete signature data dictionary.

        Returns:
            Dictionary containing image_path, hash, timestamps,
            and signer information.
        """
        return {
            "image_path": self._saved_image_path,
            "hash_sha256": self.get_signature_hash(),
            "sign_start": (
                self._sign_start_time.isoformat()
                if self._sign_start_time
                else ""
            ),
            "sign_end": (
                self._sign_end_time.isoformat()
                if self._sign_end_time
                else ""
            ),
            "signer_name": self._signer_name,
            "signer_date": self._signer_date,
        }

    # ------------------------------------------------------------------
    # Backward-compatible API
    # ------------------------------------------------------------------

    def get_lines(self) -> list[tuple[int, int, int, int]]:
        """Return the raw line coordinate data for serialization."""
        return list(self._lines)

    def is_valid(self) -> bool:
        """Return True if signature exists and has been confirmed."""
        if self._required:
            return self._has_signature and self._confirmed
        return True

    def clear(self) -> None:
        """Erase all strokes and reset the pad completely."""
        self.canvas.delete("all")
        self._lines = []
        self._has_signature = False
        self._confirmed = False
        self._sign_start_time = None
        self._sign_end_time = None
        self._saved_image_path = ""

        self._status_label.configure(text="")
        self._enable_canvas()
        self._draw_guides()

    def save(self, filepath: str) -> bool:
        """Save the signature (backward-compatible alias for save_as_png)."""
        return self.save_as_png(filepath)
