"""Horizontal step indicator widget for wizard UX.

Renders a sequence of numbered circles connected by lines.
Each step has three visual states: completed, active, and pending.
Styled per DESIGN.md Step Indicator specifications.

Interaction:
- Mouse: clicks are accepted only within ``CLICK_RADIUS`` px of a
  step circle center (no infinite hit area).
- Keyboard: the widget is focusable (Tab); Left/Right moves the
  focused step among visitable steps (up to the active one) and
  Return/Space activates it.
"""

from __future__ import annotations

import math
import tkinter as tk
from typing import Optional

from .theme import COLORS, FONTS, get_color


class StepIndicator(tk.Canvas):
    """Horizontal step indicator showing circle + title + connecting lines."""

    CIRCLE_RADIUS = 16  # 32px diameter — more prominent
    LINE_HEIGHT = 3
    CLICK_RADIUS = 24   # max distance from a circle center to accept a click

    STATE_COMPLETED = "completed"  # Filled purple circle + white checkmark
    STATE_ACTIVE = "active"        # Filled purple circle + white number
    STATE_PENDING = "pending"      # Grey border + grey number

    def __init__(
        self,
        master: tk.Widget,
        steps: list[str],
        on_step_click: Optional[callable] = None,
        **kwargs: object,
    ) -> None:
        kwargs.setdefault("height", 68)
        kwargs.setdefault("highlightthickness", 0)
        kwargs.setdefault("bg", get_color("card_bg"))
        kwargs.setdefault("takefocus", 1)
        super().__init__(master, **kwargs)

        self._steps = list(steps)
        self._active_index = 0
        self._focus_index: Optional[int] = None
        self._on_step_click = on_step_click
        self._positions: list[int] = []
        self._circle_cy = self.CIRCLE_RADIUS + 4

        self.bind("<Configure>", self._on_configure)
        self.bind("<Button-1>", self._on_canvas_click)
        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)
        self.bind("<Left>", self._on_key_left)
        self.bind("<Right>", self._on_key_right)
        self.bind("<Return>", self._on_key_activate)
        self.bind("<space>", self._on_key_activate)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_active(self, index: int) -> None:
        """Set the given step as active.

        Steps before *index* become completed; steps after become pending.
        Out-of-range indices are clamped into the valid range.
        """
        if not self._steps:
            return
        index = max(0, min(index, len(self._steps) - 1))
        self._active_index = index
        # Keep keyboard focus within the visitable range
        if self._focus_index is not None:
            self._focus_index = min(self._focus_index, index)
        self._draw()

    # ------------------------------------------------------------------
    # Keyboard navigation
    # ------------------------------------------------------------------

    def _on_focus_in(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        if self._focus_index is None:
            self._focus_index = self._active_index
        self._draw()

    def _on_focus_out(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        self._focus_index = None
        self._draw()

    def _move_focus(self, delta: int) -> str:
        if self._focus_index is None:
            self._focus_index = self._active_index
        # Only already-visited steps (<= active) are visitable
        new_index = self._focus_index + delta
        self._focus_index = max(0, min(new_index, self._active_index))
        self._draw()
        return "break"

    def _on_key_left(self, _event: tk.Event) -> str:  # type: ignore[type-arg]
        return self._move_focus(-1)

    def _on_key_right(self, _event: tk.Event) -> str:  # type: ignore[type-arg]
        return self._move_focus(1)

    def _on_key_activate(self, _event: tk.Event) -> str:  # type: ignore[type-arg]
        # "break" prevents the wizard-level toplevel <Return> binding
        # from also advancing to the next step.
        if self._on_step_click is not None and self._focus_index is not None:
            self._on_step_click(self._focus_index)
        return "break"

    # ------------------------------------------------------------------
    # Internal drawing
    # ------------------------------------------------------------------

    def _on_configure(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        self._draw()

    def _draw(self) -> None:
        """Redraw the entire indicator."""
        self.delete("all")

        width = self.winfo_width()
        if width <= 1:
            return

        n = len(self._steps)
        if n == 0:
            return

        r = self.CIRCLE_RADIUS
        # Vertical center for circles -- leave room for label below
        cy = r + 4
        self._circle_cy = cy
        # Horizontal padding
        pad = max(r + 8, 30)
        usable = width - 2 * pad

        if n == 1:
            positions = [width // 2]
        else:
            spacing = usable / (n - 1)
            positions = [int(pad + i * spacing) for i in range(n)]

        self._positions = positions

        # Colors per DESIGN.md
        color_primary = get_color("primary")       # #533afd
        color_pending_border = get_color("pending_border")
        color_pending_text = get_color("text_secondary")  # #64748d
        color_line_done = get_color("primary")
        color_line_pending = get_color("pending_border")
        color_heading = get_color("heading")       # #061b31
        color_text_light = get_color("text_light")
        color_glow = get_color("border_active")

        # Draw connecting lines first (behind circles)
        for i in range(n - 1):
            x1 = positions[i] + r
            x2 = positions[i + 1] - r
            line_y = cy

            if i < self._active_index:
                line_color = color_line_done
            else:
                line_color = color_line_pending

            self.create_line(
                x1, line_y, x2, line_y,
                fill=line_color,
                width=self.LINE_HEIGHT,
            )

        # Draw circles and labels — bold active/completed, normal pending
        label_font_normal = (FONTS["body"][0], FONTS["body"][1])
        label_font_bold = (FONTS["body"][0], FONTS["body"][1], "bold")
        num_font = (FONTS["body"][0], FONTS["body"][1], "bold")
        check_font = (FONTS["subheader"][0], FONTS["subheader"][1] + 1, "bold")

        for i, (cx, step_name) in enumerate(zip(positions, self._steps)):
            state = self._get_state(i)

            if state == self.STATE_COMPLETED:
                # Filled purple circle
                self.create_oval(
                    cx - r, cy - r, cx + r, cy + r,
                    fill=color_primary,
                    outline=color_primary,
                    width=2,
                )
                # White checkmark — larger
                self.create_text(
                    cx, cy,
                    text="✓",
                    fill=color_text_light,
                    font=check_font,
                )
            elif state == self.STATE_ACTIVE:
                # Outer glow ring
                glow_r = r + 3
                self.create_oval(
                    cx - glow_r, cy - glow_r, cx + glow_r, cy + glow_r,
                    fill="",
                    outline=color_glow,
                    width=2,
                )
                # Filled purple circle + white number
                self.create_oval(
                    cx - r, cy - r, cx + r, cy + r,
                    fill=color_primary,
                    outline=color_primary,
                    width=2,
                )
                # White number bold
                self.create_text(
                    cx, cy,
                    text=str(i + 1),
                    fill=color_text_light,
                    font=num_font,
                )
            else:
                # Pending: border only + grey number
                self.create_oval(
                    cx - r, cy - r, cx + r, cy + r,
                    fill=get_color("card_bg"),
                    outline=color_pending_border,
                    width=2,
                )
                # Grey number
                self.create_text(
                    cx, cy,
                    text=str(i + 1),
                    fill=color_pending_text,
                    font=num_font,
                )

            # Keyboard focus ring (dashed) around the focused step
            try:
                has_focus = self.focus_get() is self
            except (KeyError, tk.TclError):
                has_focus = False
            if self._focus_index == i and has_focus:
                ring_r = r + 6
                self.create_oval(
                    cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r,
                    fill="",
                    outline=color_primary,
                    width=1,
                    dash=(3, 2),
                )

            # Step label below circle — bold for active
            if state == self.STATE_ACTIVE:
                label_color = color_heading
                label_font = label_font_bold
            elif state == self.STATE_COMPLETED:
                label_color = color_heading
                label_font = label_font_normal
            else:
                label_color = color_pending_text
                label_font = label_font_normal

            self.create_text(
                cx, cy + r + 12,
                text=step_name,
                fill=label_color,
                font=label_font,
                anchor="n",
            )

    def _get_state(self, index: int) -> str:
        """Return the visual state for the step at *index*."""
        if index < self._active_index:
            return self.STATE_COMPLETED
        if index == self._active_index:
            return self.STATE_ACTIVE
        return self.STATE_PENDING

    def _on_canvas_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        """Invoke the callback if the click lands near a step circle.

        Only clicks within ``CLICK_RADIUS`` px of a circle center are
        accepted — clicks in the empty space between steps are ignored.
        """
        if not self._on_step_click or not self._positions:
            return

        cy = self._circle_cy
        for i, cx in enumerate(self._positions):
            dist = math.hypot(event.x - cx, event.y - cy)
            if dist <= self.CLICK_RADIUS:
                self._focus_index = i
                self._on_step_click(i)
                return
