"""Central theme configuration for the digital evidence electronic sealing system.

Provides color, font, spacing, radius, and shadow constants based on the
Stripe-inspired design system defined in DESIGN.md.
All GUI modules should import theme values from here instead of hardcoding.
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

COLORS = {
    # Primary Brand (Stripe-inspired)
    "primary": "#533afd",
    "primary_hover": "#4434d4",
    "primary_light": "#b9b9f9",
    "primary_deep": "#2e2b8c",

    # Headings & Text
    "heading": "#061b31",
    "text": "#273951",
    "text_secondary": "#64748d",
    "text_light": "#ffffff",

    # Semantic Process Colors
    "seal": "#2c3e50",
    "unseal": "#1a5276",
    "reseal": "#1e6e3e",

    # Status
    "danger": "#ea2261",
    "success": "#15be53",
    "warning": "#f39c12",
    "info": "#3498db",

    # High-contrast text variants for status colors (WCAG AA >= 4.5:1 on white).
    # Use these for foreground TEXT on light backgrounds; the base status
    # colors above remain for fills, bars, and dots.
    "success_text": "#0e7a3d",   # 5.4:1 on #ffffff
    "warning_text": "#9a6200",   # 5.1:1 on #ffffff
    "danger_text": "#c41d52",    # 5.8:1 on #ffffff
    "info_text": "#186ba0",      # 5.7:1 on #ffffff

    # Surfaces
    "bg": "#f8f9fb",
    "card_bg": "#ffffff",
    "border": "#e5edf5",
    "border_active": "#b9b9f9",
    "hover": "#e8e5ff",
    "selected": "#d9d4ff",

    # Dark sections
    "dark_bg": "#1c1e54",

    # Error
    "error_bg": "#fef2f5",
    "error_highlight": "#fde0e8",

    # Neutral / pending
    "pending_border": "#dee2e6",
    "guide_line": "#c0c0c0",

    # Active state variants
    "danger_hover": "#c41d52",

    # Shadow simulation
    "shadow": "#c8cdd5",
    "shadow_light": "#d0d5e0",

    # Step indicator background
    "step_bg": "#f0f2f5",

    # System panel background
    "panel_bg": "#f0f2f5",

    # Screen headers (deep navy banner used by dashboard / case manager /
    # section headers; wizards adopt these tokens in the next wave)
    "header_bg": "#061b31",
    "header_fg": "#ffffff",
    "header_fg_muted": "#a8c4e0",
    "header_hover_bg": "#0d2a47",

    # Wizard header accents (per process type)
    "wizard_header_seal": "#2c3e50",
    "wizard_header_unseal": "#1a5276",
    "wizard_header_reseal": "#1e6e3e",

    # Notice / alerts section header (deep purple)
    "notice_header": "#3d1a54",

    # Workflow action buttons (teal)
    "workflow_accent": "#1a8a5e",
    "workflow_accent_hover": "#15724e",

    # Quick-action card accents (dashboard cards; generic names so the
    # wizard wave can reuse them)
    "accent_seal": "#3366cc",
    "accent_unseal": "#1a5276",
    "accent_reseal": "#1e8e4e",
    "accent_info": "#7c3aed",
}

FONTS = {
    "title": ("맑은 고딕", 20, "normal"),
    "header": ("맑은 고딕", 14, "normal"),
    "subheader": ("맑은 고딕", 12, "bold"),
    "body": ("맑은 고딕", 11, "normal"),
    "small": ("맑은 고딕", 10, "normal"),
    "caption": ("맑은 고딕", 10, "normal"),
    "button": ("맑은 고딕", 11, "bold"),
    "badge": ("맑은 고딕", 9, "bold"),
    "mono": ("Consolas", 10, "normal"),
    "stat_number": ("맑은 고딕", 40, "bold"),
    "stat_label": ("맑은 고딕", 10, "bold"),
}

SPACING = {"xs": 4, "sm": 8, "md": 16, "lg": 24, "xl": 32, "2xl": 48}

RADIUS = {"sm": 4, "standard": 6, "md": 8, "lg": 12}

# NOTE: tkinter cannot render rgba() values — these are design-reference
# constants only (from DESIGN.md) and MUST NOT be passed to any widget
# option. For a shadow effect use the opaque COLORS["shadow"] /
# COLORS["shadow_light"] frame-offset technique instead.
SHADOWS = {
    "card": "rgba(50,50,93,0.12)",
    "hover": "rgba(50,50,93,0.15)",
    "ambient": "rgba(23,23,23,0.06)",
}


def get_color(name: str) -> str:
    """Return the hex color string for the given color name.

    Args:
        name: A key from the COLORS dictionary.

    Returns:
        The hex color string.

    Raises:
        KeyError: If the color name is not found.
    """
    if name not in COLORS:
        raise KeyError(f"Unknown color name: {name!r}. Available: {list(COLORS.keys())}")
    return COLORS[name]


def get_font(style: str) -> tuple:
    """Return the font tuple for the given style name.

    Args:
        style: A key from the FONTS dictionary.

    Returns:
        A tuple of (family, size) or (family, size, weight).

    Raises:
        KeyError: If the font style is not found.
    """
    if style not in FONTS:
        raise KeyError(f"Unknown font style: {style!r}. Available: {list(FONTS.keys())}")
    return FONTS[style]


def get_spacing(size: str) -> int:
    """Return the spacing value in pixels for the given size name.

    Args:
        size: A key from the SPACING dictionary (xs, sm, md, lg, xl, 2xl).

    Returns:
        The spacing value in pixels.

    Raises:
        KeyError: If the size name is not found.
    """
    if size not in SPACING:
        raise KeyError(f"Unknown spacing size: {size!r}. Available: {list(SPACING.keys())}")
    return SPACING[size]


def apply_theme(root: tk.Tk) -> None:
    """Apply the Stripe-inspired design system theme to ttk widgets.

    Configures ttk.Style for TButton, TFrame, Treeview, TEntry,
    and TLabelframe to match the DESIGN.md specifications.
    """
    # Force root window background
    root.configure(bg=COLORS["bg"])

    from tkinter import ttk as _ttk
    style = _ttk.Style()
    style.theme_use("clam")  # clam allows full color customization

    # Force all default backgrounds
    style.configure(".", background=COLORS["bg"])

    # TButton: primary purple, white text
    style.configure(
        "TButton",
        font=FONTS["button"],
        padding=(20, 8),
    )

    # Primary button style
    style.configure(
        "Primary.TButton",
        background=COLORS["primary"],
        foreground=COLORS["text_light"],
        font=FONTS["button"],
        padding=(20, 8),
    )
    style.map(
        "Primary.TButton",
        background=[("active", COLORS["primary_hover"]), ("disabled", "#a0a0c0")],
    )

    # Ghost button style
    style.configure(
        "Ghost.TButton",
        background=COLORS["card_bg"],
        foreground=COLORS["primary"],
        font=FONTS["button"],
        padding=(20, 8),
    )
    style.map(
        "Ghost.TButton",
        background=[("active", COLORS["hover"])],
    )

    # Danger button style
    style.configure(
        "Danger.TButton",
        background=COLORS["danger"],
        foreground=COLORS["text_light"],
        font=FONTS["button"],
        padding=(20, 8),
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#c41d52")],
    )

    # TFrame: page background
    style.configure("TFrame", background=COLORS["bg"])

    # Treeview
    style.configure(
        "Treeview",
        rowheight=30,
        font=FONTS["body"],
        background=COLORS["card_bg"],
        fieldbackground=COLORS["card_bg"],
        foreground=COLORS["text"],
    )
    style.configure(
        "Treeview.Heading",
        background=COLORS["bg"],
        foreground=COLORS["heading"],
        font=FONTS["subheader"],
    )
    style.map(
        "Treeview",
        background=[("selected", COLORS["selected"])],
        foreground=[("selected", COLORS["heading"])],
    )

    # TEntry: focus border purple
    style.configure(
        "TEntry",
        font=FONTS["body"],
        fieldbackground=COLORS["card_bg"],
    )
    style.map(
        "TEntry",
        bordercolor=[("focus", COLORS["primary"])],
        lightcolor=[("focus", COLORS["primary_light"])],
    )

    # TLabelframe
    style.configure(
        "TLabelframe",
        background=COLORS["card_bg"],
        bordercolor=COLORS["border"],
    )
    style.configure(
        "TLabelframe.Label",
        font=FONTS["subheader"],
        foreground=COLORS["heading"],
        background=COLORS["card_bg"],
    )

    # Focused buttons: Enter = click.  tk/ttk buttons have no default
    # <Return> binding (only <space>), and the wizards' Return guard
    # (is_return_navigation_safe) deliberately skips global navigation
    # while a button has focus — without this class binding, pressing
    # Enter on a focused button would be swallowed entirely.
    root.bind_class("Button", "<Return>", _invoke_focused_button)
    root.bind_class("TButton", "<Return>", _invoke_focused_button)


def _invoke_focused_button(event: "tk.Event[tk.Misc]") -> str:
    """Invoke the focused button on <Return>, mimicking a click.

    Returns "break" to stop the event from propagating to toplevel
    <Return> bindings (wizard '다음' navigation), so Enter on a button
    activates only that button.
    """
    widget = event.widget
    try:
        if str(widget.cget("state")) == "disabled":
            return "break"
        widget.invoke()  # type: ignore[attr-defined]
    except (tk.TclError, AttributeError):
        pass
    return "break"


class ToolTip:
    """A tooltip popup that appears on mouse hover over a widget.

    Usage::

        label = tk.Label(root, text="Hover me")
        ToolTip(label, "This is a tooltip message")
    """

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self._widget = widget
        self._text = text
        self._tip_window: Optional[tk.Toplevel] = None

        self._widget.bind("<Enter>", self._on_enter)
        self._widget.bind("<Leave>", self._on_leave)

    def _on_enter(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        """Show the tooltip when the mouse enters the widget."""
        if self._tip_window is not None:
            return

        x = self._widget.winfo_rootx() + 20
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4

        self._tip_window = tk.Toplevel(self._widget)
        self._tip_window.wm_overrideredirect(True)
        self._tip_window.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            self._tip_window,
            text=self._text,
            justify="left",
            background=COLORS["card_bg"],
            foreground=COLORS["text"],
            relief="solid",
            borderwidth=1,
            font=FONTS["small"],
            padx=8,
            pady=6,
        )
        label.pack()

    def _on_leave(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        """Hide the tooltip when the mouse leaves the widget."""
        if self._tip_window is not None:
            self._tip_window.destroy()
            self._tip_window = None
