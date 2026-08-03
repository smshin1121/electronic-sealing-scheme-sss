"""Common reusable GUI widgets for the sealing system.

Provides LabeledEntry, FileSelector, and SignaturePad widgets
used across multiple wizard screens.
Styled per DESIGN.md Forms specification.
"""

from __future__ import annotations

import calendar
import tkinter as tk
from datetime import date, datetime
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any, Optional

from .i18n import t
from .theme import COLORS, FONTS, ToolTip, get_color, get_font

# Default lower bound for calendar year selection.
CALENDAR_MIN_YEAR = 1970


def is_return_navigation_safe(widget: Optional[tk.Misc]) -> bool:
    """Return True when a global <Return> press may trigger wizard navigation.

    Blocks navigation while focus is inside interactive input widgets
    (entries, multi-line text, spinboxes, comboboxes, buttons, lists)
    so Enter keeps its native meaning there.
    """
    if widget is None:
        return True
    blocked = (
        tk.Entry,
        tk.Text,
        tk.Spinbox,
        tk.Listbox,
        tk.Button,
        tk.Checkbutton,
        tk.Radiobutton,
        ttk.Entry,      # also covers ttk.Combobox / ttk.Spinbox
        ttk.Button,
        ttk.Checkbutton,
        ttk.Radiobutton,
    )
    return not isinstance(widget, blocked)


class LabeledEntry(tk.Frame):
    """A composite widget combining a label with an entry field.

    Attributes:
        label: The descriptive label widget.
        entry: The text entry widget.
    """

    def __init__(
        self,
        master: tk.Widget,
        label_text: str,
        *,
        width: int = 40,
        show: str = "",
        required: bool = False,
        readonly: bool = False,
        tooltip: str = "",
    ) -> None:
        super().__init__(master)
        self._required = required

        display_text = f"* {label_text}" if required else label_text

        # Use a vertical container so the error label can sit below the entry
        self._row = tk.Frame(self)
        self._row.pack(fill="x")

        self.label = tk.Label(
            self._row,
            text=display_text,
            anchor="w",
            width=20,
            font=get_font("body"),
            fg=get_color("text"),
        )
        self.label.pack(side="left", padx=(0, 8))

        self._var = tk.StringVar()
        state = "readonly" if readonly else "normal"
        self.entry = tk.Entry(
            self._row,
            textvariable=self._var,
            width=width,
            show=show,
            state=state,
            font=get_font("body"),
            relief="solid",
            bd=1,
            highlightthickness=2,
            highlightcolor=get_color("primary"),
            highlightbackground=get_color("border"),
        )
        self.entry.pack(side="left", fill="x", expand=True)

        # Error label (initially hidden) — ruby color per DESIGN.md
        self._error_label = tk.Label(
            self,
            text=t("common.required"),
            fg=get_color("danger"),
            font=get_font("small"),
            anchor="w",
        )
        # Not packed initially -- shown only on validation failure

        # Tooltip
        if tooltip:
            ToolTip(self.entry, tooltip)

        # FocusOut validation for required fields
        if not readonly:
            self.entry.bind("<FocusOut>", self._on_focus_out)

    def _on_focus_out(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        """Validate the field when focus leaves the entry."""
        if self.is_valid():
            self.clear_error()
        else:
            self.highlight_error()

    def get(self) -> str:
        """Return the current text value."""
        return self._var.get().strip()

    def set(self, value: str) -> None:
        """Set the text value."""
        self._var.set(value)

    def is_valid(self) -> bool:
        """Return True if the field satisfies its requirement."""
        if self._required:
            return len(self.get()) > 0
        return True

    def highlight_error(self, message: Optional[str] = None) -> None:
        """Highlight the entry to indicate a validation error.

        Args:
            message: Optional custom error text; defaults to the
                generic "required" message.
        """
        self.entry.configure(
            highlightbackground=get_color("danger"),
            highlightcolor=get_color("danger"),
        )
        self._error_label.configure(text=message or t("common.required"))
        self._error_label.pack(fill="x", padx=(0, 0), pady=(2, 0), anchor="e")

    def clear_error(self) -> None:
        """Remove the error highlight."""
        self.entry.configure(
            highlightbackground=get_color("border"),
            highlightcolor=get_color("primary"),
        )
        self._error_label.pack_forget()

    def focus_field(self) -> None:
        """Move keyboard focus to the entry widget."""
        self.entry.focus_set()


class DateEntry(tk.Frame):
    """Date input widget with text entry and calendar popup button.

    Provides the same API as LabeledEntry (get, set, is_valid,
    highlight_error, clear_error) so it can be used as a drop-in replacement.
    """

    def __init__(
        self,
        master: tk.Widget,
        label_text: str,
        *,
        required: bool = False,
        tooltip: str = "",
        max_year_offset: int = 1,
    ) -> None:
        super().__init__(master)
        self._required = required
        # Upper year bound is dynamic: current year + offset.
        # Use offset 0 for birth-date fields (no future years).
        self._max_year_offset = max_year_offset

        display_text = f"* {label_text}" if required else label_text

        self._row = tk.Frame(self)
        self._row.pack(fill="x")

        self.label = tk.Label(
            self._row,
            text=display_text,
            anchor="w",
            width=20,
            font=get_font("body"),
            fg=get_color("text"),
        )
        self.label.pack(side="left", padx=(0, 8))

        self._var = tk.StringVar()
        self.entry = tk.Entry(
            self._row,
            textvariable=self._var,
            width=36,
            font=get_font("body"),
            relief="solid",
            bd=1,
            highlightthickness=2,
            highlightcolor=get_color("primary"),
            highlightbackground=get_color("border"),
        )
        self.entry.pack(side="left", fill="x", expand=True)

        self._cal_btn = tk.Button(
            self._row,
            text="\U0001f4c5",
            command=self._show_calendar,
            fg=get_color("primary"),
            bg=get_color("card_bg"),
            activebackground=get_color("hover"),
            activeforeground=get_color("primary"),
            relief="solid",
            bd=1,
            font=get_font("body"),
            width=3,
        )
        self._cal_btn.pack(side="left", padx=(4, 0))

        # Error label (initially hidden)
        self._error_label = tk.Label(
            self,
            text=t("common.required"),
            fg=get_color("danger"),
            font=get_font("small"),
            anchor="w",
        )

        if tooltip:
            ToolTip(self.entry, tooltip)

        self.entry.bind("<FocusOut>", self._on_focus_out)

    def _on_focus_out(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        if self.is_valid():
            self.clear_error()
        else:
            self.highlight_error()

    def _show_calendar(self) -> None:
        """Open a calendar popup Toplevel dialog."""
        dialog = tk.Toplevel(self)
        dialog.title(t("cal.title"))
        dialog.resizable(False, False)
        dialog.transient(self.winfo_toplevel())
        dialog.focus_force()
        dialog.lift()
        dialog.attributes("-topmost", True)
        dialog.after(100, lambda: dialog.attributes("-topmost", False))
        dialog.configure(bg=get_color("card_bg"))

        # Parse current value or default to 1970-01-01
        try:
            current = datetime.strptime(self._var.get().strip(), "%Y-%m-%d").date()
        except (ValueError, TypeError):
            current = date(1970, 1, 1)

        year_var = tk.IntVar(value=current.year)
        month_var = tk.IntVar(value=current.month)

        # Header: year/month spinboxes
        header_frame = tk.Frame(dialog, bg=get_color("card_bg"))
        header_frame.pack(fill="x", padx=8, pady=(8, 4))

        tk.Label(
            header_frame, text=t("cal.year"),
            bg=get_color("card_bg"), font=get_font("small"),
        ).pack(side="left", padx=(0, 2))
        year_spin = tk.Spinbox(
            header_frame, from_=CALENDAR_MIN_YEAR, to=self.max_year(),
            textvariable=year_var, width=6, font=get_font("body"),
            command=lambda: _refresh_grid(),
        )
        year_spin.pack(side="left", padx=(0, 8))

        tk.Label(
            header_frame, text=t("cal.month"),
            bg=get_color("card_bg"), font=get_font("small"),
        ).pack(side="left", padx=(0, 2))
        month_spin = tk.Spinbox(
            header_frame, from_=1, to=12,
            textvariable=month_var, width=4, font=get_font("body"),
            command=lambda: _refresh_grid(),
        )
        month_spin.pack(side="left", padx=(0, 8))

        # Today button
        today_btn = tk.Button(
            header_frame, text=t("cal.today"),
            command=lambda: _select_today(),
            fg=get_color("primary"),
            bg=get_color("card_bg"),
            activebackground=get_color("hover"),
            relief="solid", bd=1,
            font=get_font("small"),
        )
        today_btn.pack(side="right")

        # Day-of-week header
        days_header = tk.Frame(dialog, bg=get_color("card_bg"))
        days_header.pack(fill="x", padx=8)
        day_names = t("cal.days_ko").split(",")
        for d_name in day_names:
            tk.Label(
                days_header, text=d_name, width=5,
                bg=get_color("card_bg"),
                fg=get_color("text_secondary"),
                font=get_font("small"),
            ).pack(side="left")

        # Date grid frame
        grid_frame = tk.Frame(dialog, bg=get_color("card_bg"))
        grid_frame.pack(fill="both", padx=8, pady=(0, 8))

        today = date.today()

        def _select_date(y: int, m: int, d: int) -> None:
            self._var.set(f"{y:04d}-{m:02d}-{d:02d}")
            self.clear_error()
            dialog.destroy()

        def _select_today() -> None:
            _select_date(today.year, today.month, today.day)

        def _refresh_grid() -> None:
            for child in grid_frame.winfo_children():
                child.destroy()

            try:
                y = year_var.get()
                m = month_var.get()
            except (tk.TclError, ValueError):
                return

            if m < 1 or m > 12 or y < CALENDAR_MIN_YEAR or y > self.max_year():
                return

            cal = calendar.monthcalendar(y, m)
            for week in cal:
                row_frame = tk.Frame(grid_frame, bg=get_color("card_bg"))
                row_frame.pack(fill="x")
                for day_val in week:
                    if day_val == 0:
                        tk.Label(
                            row_frame, text="", width=5,
                            bg=get_color("card_bg"),
                        ).pack(side="left")
                    else:
                        is_today = (y == today.year and m == today.month and day_val == today.day)
                        btn_bg = get_color("primary_light") if is_today else get_color("card_bg")
                        btn_fg = get_color("primary_deep") if is_today else get_color("text")
                        btn = tk.Button(
                            row_frame, text=str(day_val), width=4,
                            command=lambda dy=day_val, yr=y, mo=m: _select_date(yr, mo, dy),
                            bg=btn_bg, fg=btn_fg,
                            activebackground=get_color("hover"),
                            relief="flat", bd=0,
                            font=get_font("small"),
                        )
                        btn.pack(side="left", padx=1, pady=1)

        _refresh_grid()

        # Bind spinbox value changes via key release as well
        year_spin.bind("<KeyRelease>", lambda _e: _refresh_grid())
        month_spin.bind("<KeyRelease>", lambda _e: _refresh_grid())

        # Center dialog over parent
        dialog.update_idletasks()
        parent_win = self.winfo_toplevel()
        px = parent_win.winfo_rootx() + (parent_win.winfo_width() - dialog.winfo_width()) // 2
        py = parent_win.winfo_rooty() + (parent_win.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(px, 0)}+{max(py, 0)}")

    # ---- Public API (same as LabeledEntry) ----

    def max_year(self) -> int:
        """Return the dynamic upper year bound for the calendar."""
        return date.today().year + self._max_year_offset

    def get(self) -> str:
        """Return the current text value."""
        return self._var.get().strip()

    def set(self, value: str) -> None:
        """Set the text value."""
        self._var.set(value)

    def is_valid(self) -> bool:
        """Return True if the field satisfies its requirement."""
        if self._required:
            return len(self.get()) > 0
        return True

    def focus_field(self) -> None:
        """Move keyboard focus to the entry widget."""
        self.entry.focus_set()

    def highlight_error(self, message: Optional[str] = None) -> None:
        """Highlight the entry to indicate a validation error."""
        self.entry.configure(
            highlightbackground=get_color("danger"),
            highlightcolor=get_color("danger"),
        )
        self._error_label.configure(text=message or t("common.required"))
        self._error_label.pack(fill="x", padx=(0, 0), pady=(2, 0), anchor="e")

    def clear_error(self) -> None:
        """Remove the error highlight."""
        self.entry.configure(
            highlightbackground=get_color("border"),
            highlightcolor=get_color("primary"),
        )
        self._error_label.pack_forget()


class FileSelector(tk.Frame):
    """A composite widget for selecting a file or directory.

    Displays a label, a readonly path field, and a browse button.
    """

    def __init__(
        self,
        master: tk.Widget,
        label_text: str,
        *,
        select_dir: bool = False,
        filetypes: Optional[list[tuple[str, str]]] = None,
        required: bool = False,
        tooltip: str = "",
    ) -> None:
        super().__init__(master)
        self._select_dir = select_dir
        self._filetypes = filetypes or [(t("filedialog.all_files"), "*.*")]
        self._required = required

        display_text = f"* {label_text}" if required else label_text

        self._row = tk.Frame(self)
        self._row.pack(fill="x")

        self.label = tk.Label(
            self._row,
            text=display_text,
            anchor="w",
            width=20,
            font=get_font("body"),
            fg=get_color("text"),
        )
        self.label.pack(side="left", padx=(0, 8))

        self._var = tk.StringVar()
        self.path_entry = tk.Entry(
            self._row,
            textvariable=self._var,
            width=40,
            state="readonly",
            font=get_font("body"),
            relief="solid",
            bd=1,
            readonlybackground=get_color("card_bg"),
            highlightthickness=1,
            highlightcolor=get_color("primary"),
            highlightbackground=get_color("border"),
        )
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        # Browse button — ghost style
        self.browse_btn = tk.Button(
            self._row,
            text=t("common.browse"),
            command=self._browse,
            fg=get_color("primary"),
            bg=get_color("card_bg"),
            activebackground=get_color("hover"),
            activeforeground=get_color("primary"),
            relief="solid",
            bd=1,
            font=get_font("small"),
        )
        self.browse_btn.pack(side="left")

        # Status label for showing selection result
        self._status_label = tk.Label(
            self._row,
            text="",
            font=get_font("small"),
            anchor="w",
        )
        self._status_label.pack(side="left", padx=(4, 0))

        # Error label (initially hidden)
        self._error_label = tk.Label(
            self,
            text=t("common.required"),
            fg=get_color("danger"),
            font=get_font("small"),
            anchor="w",
        )

        # Tooltip
        if tooltip:
            ToolTip(self.path_entry, tooltip)

    def _browse(self) -> None:
        """Open a file or directory selection dialog."""
        if self._select_dir:
            path = filedialog.askdirectory(title=t("filedialog.select_folder"))
        else:
            path = filedialog.askopenfilename(
                title=t("filedialog.select_file"),
                filetypes=self._filetypes,
            )
        if path:
            self._var.set(path)
            self._status_label.configure(text="\u2713", fg=get_color("success_text"))
            self.clear_error()

    def get(self) -> str:
        """Return the selected path."""
        return self._var.get().strip()

    def set(self, value: str) -> None:
        """Set the path value programmatically."""
        self._var.set(value)

    def is_valid(self) -> bool:
        """Return True if a valid path is selected."""
        if self._required:
            p = self.get()
            return len(p) > 0 and Path(p).exists()
        return True

    def focus_field(self) -> None:
        """Move keyboard focus to the browse button."""
        self.browse_btn.focus_set()

    def highlight_error(self, message: Optional[str] = None) -> None:
        """Highlight the selector to indicate a validation error."""
        self.path_entry.configure(
            highlightbackground=get_color("danger"),
            highlightcolor=get_color("danger"),
        )
        self._error_label.configure(text=message or t("common.required"))
        self._error_label.pack(fill="x", pady=(2, 0), anchor="e")

    def clear_error(self) -> None:
        """Remove the error highlight."""
        self.path_entry.configure(
            highlightbackground=get_color("border"),
            highlightcolor=get_color("primary"),
        )
        self._error_label.pack_forget()


class SignaturePad(tk.Frame):
    """A simple canvas-based signature pad for capturing handwritten signatures.

    Users can draw on the canvas with the mouse.  The signature can be
    exported as a PNG image via the ``save`` method.
    """

    CANVAS_WIDTH = 400
    CANVAS_HEIGHT = 150
    LINE_WIDTH = 2
    LINE_COLOR = "#1a237e"  # ink color — allowed hardcoded

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
        self._last_x: Optional[int] = None
        self._last_y: Optional[int] = None
        self._lines: list[tuple[int, int, int, int]] = []

        display_text = f"* {label_text}" if required else label_text
        header = tk.Frame(self)
        header.pack(fill="x")
        tk.Label(
            header,
            text=display_text,
            anchor="w",
            font=get_font("subheader"),
            fg=get_color("heading"),
        ).pack(side="left")

        # Clear button — ghost style
        tk.Button(
            header,
            text=t("sig.clear"),
            command=self.clear,
            fg=get_color("primary"),
            bg=get_color("card_bg"),
            activebackground=get_color("hover"),
            relief="solid",
            bd=1,
            font=get_font("small"),
        ).pack(side="right")

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

        self.canvas.bind("<Button-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)

    def _on_press(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        self._last_x = event.x
        self._last_y = event.y

    def _on_drag(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if self._last_x is not None and self._last_y is not None:
            self.canvas.create_line(
                self._last_x,
                self._last_y,
                event.x,
                event.y,
                width=self.LINE_WIDTH,
                fill=self.LINE_COLOR,
                capstyle="round",
                smooth=True,
            )
            self._lines.append((self._last_x, self._last_y, event.x, event.y))
            self._has_signature = True
        self._last_x = event.x
        self._last_y = event.y

    def _on_release(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        self._last_x = None
        self._last_y = None

    def clear(self) -> None:
        """Erase all strokes from the canvas."""
        self.canvas.delete("all")
        self._lines = []
        self._has_signature = False

    def is_valid(self) -> bool:
        """Return True if any strokes have been drawn."""
        if self._required:
            return self._has_signature
        return True

    def save(self, filepath: str) -> bool:
        """Save the signature as a PostScript file.

        For actual PNG export, an external library (Pillow) would be needed.
        This saves as EPS which can be converted later.

        Returns:
            True if the file was written successfully.
        """
        if not self._has_signature:
            return False
        try:
            self.canvas.postscript(file=filepath, colormode="color")
            return True
        except tk.TclError:
            return False

    def get_lines(self) -> list[tuple[int, int, int, int]]:
        """Return the raw line coordinate data for serialization."""
        return list(self._lines)


class ScrolledFrame(tk.Frame):
    """A vertically scrollable frame container.

    Place content into the ``body`` attribute.  The inner frame is
    stretched to the canvas width so children can use ``fill="x"``.
    Mouse-wheel scrolling is active while the pointer is inside.
    """

    def __init__(self, master: tk.Widget, *, bg: Optional[str] = None) -> None:
        bg = bg or get_color("bg")
        super().__init__(master, bg=bg)

        self._canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg=bg)
        self._vsb = ttk.Scrollbar(
            self, orient="vertical", command=self._canvas.yview
        )
        self.body = tk.Frame(self._canvas, bg=bg)
        self._window = self._canvas.create_window(
            (0, 0), window=self.body, anchor="nw"
        )
        self._canvas.configure(yscrollcommand=self._vsb.set)

        self._vsb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self.body.bind("<Configure>", self._on_body_configure, add="+")
        self._canvas.bind("<Configure>", self._on_canvas_configure, add="+")
        self._canvas.bind("<Enter>", self._bind_wheel, add="+")
        self._canvas.bind("<Leave>", self._unbind_wheel, add="+")
        self.bind("<Destroy>", self._on_destroy, add="+")

    def _on_body_configure(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        self._canvas.itemconfigure(self._window, width=event.width)

    def _is_scrollable(self) -> bool:
        try:
            return self.body.winfo_reqheight() > self._canvas.winfo_height()
        except tk.TclError:
            return False

    def _on_wheel(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if self._is_scrollable():
            self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _bind_wheel(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        try:
            self._canvas.bind_all("<MouseWheel>", self._on_wheel)
        except tk.TclError:
            pass

    def _unbind_wheel(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        # <Leave> also fires when the pointer moves onto a child widget;
        # only release the global binding when truly outside.
        try:
            px, py = self.winfo_pointerxy()
            under = self.winfo_containing(px, py)
            w: Optional[tk.Misc] = under
            while w is not None:
                if w is self:
                    return
                w = getattr(w, "master", None)
            self._canvas.unbind_all("<MouseWheel>")
        except (tk.TclError, KeyError):
            pass

    def _on_destroy(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if event.widget is self:
            try:
                self._canvas.unbind_all("<MouseWheel>")
            except tk.TclError:
                pass

    def scroll_to_top(self) -> None:
        """Reset the scroll position to the top."""
        try:
            self._canvas.yview_moveto(0.0)
        except tk.TclError:
            pass


class SummaryView(ScrolledFrame):
    """Card-based summary renderer for wizard preview/completion steps.

    Replaces the old ASCII-art ``tk.Text`` dumps with section cards
    containing a two-column label/value grid and colored status badges.

    Section dict format::

        {
            "title": "사건 정보",
            "badge": ("일치", "success"),          # optional
            "rows": [
                ("사건번호", "2026-123"),          # plain row
                ("해시 검증", "통과", "success"),  # status-colored value
                ("", "안내 문구만 있는 행"),       # note row (spans width)
            ],
        }
    """

    _STATUS_TOKENS = {
        "success": "success_text",
        "danger": "danger_text",
        "warning": "warning_text",
        "info": "info_text",
    }

    VALUE_WRAP = 560

    def __init__(self, master: tk.Widget) -> None:
        super().__init__(master, bg=get_color("bg"))

    @staticmethod
    def _strip_brackets(text: str) -> str:
        """Strip bracket/space decoration from legacy i18n section titles."""
        return text.strip("[] ")

    def render(self, sections: list[dict[str, Any]]) -> None:
        """Clear and re-render all section cards."""
        for child in self.body.winfo_children():
            child.destroy()

        for section in sections:
            self._render_section(section)
        self.scroll_to_top()

    # ------------------------------------------------------------------

    def _render_section(self, section: dict[str, Any]) -> None:
        card = tk.Frame(
            self.body,
            bg=get_color("card_bg"),
            highlightthickness=1,
            highlightbackground=get_color("border"),
        )
        card.pack(fill="x", pady=(0, 8), padx=(0, 4))

        inner = tk.Frame(card, bg=get_color("card_bg"), padx=14, pady=10)
        inner.pack(fill="both", expand=True)

        # Title row (+ optional badge)
        title = section.get("title", "")
        if title or section.get("badge"):
            title_row = tk.Frame(inner, bg=get_color("card_bg"))
            title_row.pack(fill="x", pady=(0, 6))
            if title:
                tk.Label(
                    title_row,
                    text=title,
                    font=get_font("subheader"),
                    fg=get_color("heading"),
                    bg=get_color("card_bg"),
                    anchor="w",
                ).pack(side="left")
            badge = section.get("badge")
            if badge:
                badge_text, badge_status = badge
                tk.Label(
                    title_row,
                    text=f"● {badge_text}",
                    font=get_font("badge"),
                    fg=self._status_color(badge_status),
                    bg=get_color("card_bg"),
                ).pack(side="right")

        grid = tk.Frame(inner, bg=get_color("card_bg"))
        grid.pack(fill="x")
        grid.grid_columnconfigure(1, weight=1)

        for row_idx, row in enumerate(section.get("rows", [])):
            label = row[0]
            value = row[1]
            status = row[2] if len(row) > 2 else None
            if label:
                tk.Label(
                    grid,
                    text=label,
                    font=get_font("small"),
                    fg=get_color("text_secondary"),
                    bg=get_color("card_bg"),
                    anchor="nw",
                    justify="left",
                ).grid(row=row_idx, column=0, sticky="nw", padx=(0, 16), pady=2)
                value_col, colspan = 1, 1
            else:
                value_col, colspan = 0, 2

            fg = self._status_color(status) if status else get_color("text")
            font = (
                (FONTS["body"][0], FONTS["body"][1], "bold")
                if status
                else get_font("body")
            )
            tk.Label(
                grid,
                text=str(value),
                font=font,
                fg=fg,
                bg=get_color("card_bg"),
                anchor="nw",
                justify="left",
                wraplength=self.VALUE_WRAP,
            ).grid(
                row=row_idx, column=value_col, columnspan=colspan,
                sticky="nw", pady=2,
            )

    @classmethod
    def _status_color(cls, status: Optional[str]) -> str:
        token = cls._STATUS_TOKENS.get(status or "", "text")
        return get_color(token)
