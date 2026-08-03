"""Home dashboard for the digital evidence electronic sealing system.

Displays statistics, quick-action cards, system status, alerts,
and recent case history in a responsive grid layout.
Styled per DESIGN.md Stripe-inspired design system.

DB queries run on a background worker thread; results are marshalled
back to the Tk main loop via ``after()`` so the UI never freezes.
"""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import tkinter as tk
from pathlib import Path
from typing import Any, Callable, Optional

from .i18n import t
from .theme import COLORS, FONTS, SPACING, get_color, get_font, get_spacing

logger = logging.getLogger(__name__)

# Process color keys mapped to stat cards
_PROCESS_COLORS = {
    "seal_count": "seal",
    "unseal_count": "unseal",
    "reseal_count": "reseal",
}


class Dashboard(tk.Frame):
    """Home dashboard frame with stats, quick actions, system status, and history."""

    def __init__(self, master: tk.Widget, app: Any, **kwargs: Any) -> None:
        super().__init__(master, **kwargs)
        self._app = app
        self._loading = False
        # Thread-safe channel: worker threads put results here and the Tk
        # main loop polls it (after() is not safe to call off-thread).
        self._result_queue: queue.Queue = queue.Queue()
        self._poll_after_id: Optional[str] = None
        # Cancel any pending poll timer on destroy — otherwise the timer
        # fires after the widget's Tcl command is deleted and Tk prints
        # an "invalid command name" background error.
        self.bind("<Destroy>", self._cancel_poll, add="+")
        self.configure(bg=get_color("bg"))

        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)
        self.rowconfigure(3, weight=1)

        self._build_title(row=0)
        self._build_stat_cards(row=1)
        self._build_quick_actions(row=2)
        self._build_system_panel(row=1)
        self._build_recent_history(row=3)

        self.refresh()

    # ------------------------------------------------------------------
    # Title — deep navy header (DESIGN.md Navigation Header)
    # ------------------------------------------------------------------

    def _build_title(self, row: int) -> None:
        header_bg = get_color("header_bg")
        title_frame = tk.Frame(self, bg=header_bg)
        title_frame.grid(row=row, column=0, columnspan=2, sticky="ew",
                         padx=0, pady=0)

        inner = tk.Frame(title_frame, bg=header_bg, height=56)
        inner.pack(fill="x")
        inner.pack_propagate(False)

        tk.Label(
            inner,
            text=t("dashboard.title"),
            font=get_font("title"),
            fg=get_color("header_fg"),
            bg=header_bg,
        ).pack(side="left", padx=get_spacing("lg"), pady=0)

        self._refresh_btn = tk.Button(
            inner,
            text=t("dashboard.refresh"),
            font=get_font("small"),
            command=self._on_manual_refresh,
            relief="flat",
            bg=header_bg,
            fg=get_color("header_fg_muted"),
            activebackground=get_color("header_hover_bg"),
            activeforeground=get_color("header_fg"),
            cursor="hand2",
            bd=0,
        )
        self._refresh_btn.pack(side="right", padx=get_spacing("lg"))

    # ------------------------------------------------------------------
    # Stat cards (top row) — large number + label + process color divider
    # ------------------------------------------------------------------

    def _build_stat_cards(self, row: int) -> None:
        self._stat_frame = tk.Frame(self, bg=get_color("bg"))
        self._stat_frame.grid(row=row, column=0, sticky="ew",
                              padx=get_spacing("md"), pady=get_spacing("sm"))

        configs = [
            ("dashboard.seal_count", "seal", "seal_count"),
            ("dashboard.unseal_count", "unseal", "unseal_count"),
            ("dashboard.reseal_count", "reseal", "reseal_count"),
        ]
        self._stat_labels: dict[str, tk.Label] = {}

        for idx, (label_key, color_key, stat_key) in enumerate(configs):
            self._stat_frame.columnconfigure(idx, weight=1)

            process_color = get_color(color_key)

            # Shadow frame (outer) for drop-shadow effect
            shadow = tk.Frame(self._stat_frame, bg=get_color("shadow"))
            shadow.grid(row=0, column=idx, sticky="ew",
                        padx=get_spacing("xs"), pady=get_spacing("xs"))

            # Inner card sits inside shadow with 2px offset (right + bottom)
            card = tk.Frame(shadow, bg=get_color("card_bg"))
            card.pack(fill="both", expand=True, padx=(0, 3), pady=(0, 3))

            # 4px process-color bar at TOP — highly visible
            top_bar = tk.Frame(card, height=4, bg=process_color)
            top_bar.pack(fill="x")

            # Content area with padding
            content = tk.Frame(card, bg=get_color("card_bg"),
                               padx=get_spacing("md"), pady=get_spacing("sm"))
            content.pack(fill="both", expand=True)

            # Large stat number — 40px bold
            num_label = tk.Label(
                content,
                text="0",
                font=get_font("stat_number"),
                fg=get_color("heading"),
                bg=get_color("card_bg"),
            )
            num_label.pack(pady=(get_spacing("sm"), 0))
            self._stat_labels[stat_key] = num_label

            # Label — 10px bold uppercase
            tk.Label(
                content,
                text=t(label_key).upper(),
                font=get_font("stat_label"),
                fg=get_color("text_secondary"),
                bg=get_color("card_bg"),
            ).pack(pady=(0, get_spacing("xs")))

    # ------------------------------------------------------------------
    # Quick action cards (2x2 grid) — white bg, border, hover/focus effects
    # ------------------------------------------------------------------

    def _build_quick_actions(self, row: int) -> None:
        self._action_frame = tk.Frame(self, bg=get_color("bg"))
        self._action_frame.grid(row=row, column=0, sticky="nsew",
                                padx=get_spacing("md"), pady=get_spacing("sm"))
        self._action_frame.columnconfigure(0, weight=1)
        self._action_frame.columnconfigure(1, weight=1)
        self._action_frame.rowconfigure(0, weight=1)
        self._action_frame.rowconfigure(1, weight=1)

        actions = [
            ("dashboard.quick_seal", "dashboard.quick_seal_desc", "seal", self._app._on_seal, 0, 0),
            ("dashboard.quick_unseal", "dashboard.quick_unseal_desc", "unseal", self._app._on_unseal, 0, 1),
            ("dashboard.quick_reseal", "dashboard.quick_reseal_desc", "reseal", self._app._on_reseal, 1, 0),
            ("dashboard.quick_cases", "dashboard.quick_cases_desc", "info", self._app._on_case_manager, 1, 1),
        ]

        for title_key, desc_key, color_key, callback, r, c in actions:
            self._make_action_card(
                self._action_frame, t(title_key), t(desc_key), color_key, callback, r, c,
            )

    def _make_action_card(
        self,
        parent: tk.Widget,
        title: str,
        description: str,
        color_key: str,
        callback: Callable[[], None],
        grid_row: int,
        grid_col: int,
    ) -> None:
        # Left accent bar color from theme tokens
        _action_colors = {
            "seal": get_color("accent_seal"),
            "unseal": get_color("accent_unseal"),
            "reseal": get_color("accent_reseal"),
            "info": get_color("accent_info"),
        }
        bar_color = _action_colors.get(color_key, get_color("primary"))

        # Shadow wrapper — also the keyboard-focusable element with a
        # visible focus ring (highlightcolor shows when focused)
        shadow = tk.Frame(
            parent,
            bg=get_color("shadow"),
            cursor="hand2",
            takefocus=1,
            highlightthickness=2,
            highlightbackground=get_color("bg"),
            highlightcolor=get_color("primary"),
        )
        shadow.grid(row=grid_row, column=grid_col, sticky="nsew",
                    padx=get_spacing("xs"), pady=get_spacing("xs"))

        card = tk.Frame(shadow, bg=get_color("card_bg"))
        card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        # Left 4px color bar
        color_bar = tk.Frame(card, width=4, bg=bar_color)
        color_bar.pack(side="left", fill="y")

        inner = tk.Frame(card, bg=get_color("card_bg"),
                         padx=get_spacing("lg"), pady=get_spacing("lg"))
        inner.pack(fill="both", expand=True)

        title_label = tk.Label(
            inner,
            text=title,
            font=get_font("subheader"),
            fg=get_color(color_key),
            bg=get_color("card_bg"),
            anchor="w",
        )
        title_label.pack(fill="x")

        desc_label = tk.Label(
            inner,
            text=description,
            font=get_font("small"),
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
            anchor="w",
        )
        desc_label.pack(fill="x", pady=(get_spacing("sm"), 0))

        hover_bg = get_color("hover")
        normal_bg = get_color("card_bg")

        def _set_bg(color: str) -> None:
            card.configure(bg=color)
            inner.configure(bg=color)
            title_label.configure(bg=color)
            desc_label.configure(bg=color)

        def _on_enter(_e: tk.Event) -> None:  # type: ignore[type-arg]
            _set_bg(hover_bg)

        def _on_leave(_e: tk.Event) -> None:  # type: ignore[type-arg]
            _set_bg(normal_bg)

        def _activate(_e: tk.Event) -> None:  # type: ignore[type-arg]
            callback()

        for widget in (shadow, card, inner, title_label, desc_label, color_bar):
            widget.bind("<Enter>", _on_enter)
            widget.bind("<Leave>", _on_leave)
            widget.bind("<Button-1>", _activate)

        # Keyboard access: focus ring + Return/Space activation
        shadow.bind("<FocusIn>", _on_enter)
        shadow.bind("<FocusOut>", _on_leave)
        shadow.bind("<Return>", _activate)
        shadow.bind("<space>", _activate)

    # ------------------------------------------------------------------
    # System status + alerts (right panel) — card style
    # ------------------------------------------------------------------

    def _build_system_panel(self, row: int) -> None:
        _panel_bg = get_color("panel_bg")

        # Shadow wrapper for system panel
        shadow = tk.Frame(self, bg=get_color("shadow"))
        shadow.grid(row=row, column=1, rowspan=3, sticky="nsew",
                    padx=(0, get_spacing("md")),
                    pady=get_spacing("sm"))

        panel = tk.Frame(shadow, bg=_panel_bg)
        panel.pack(fill="both", expand=True, padx=(0, 3), pady=(0, 3))

        # System status header with dark accent
        status_header = tk.Frame(panel, bg=get_color("header_bg"), height=36)
        status_header.pack(fill="x")
        status_header.pack_propagate(False)
        tk.Label(
            status_header,
            text=t("dashboard.system_status"),
            font=get_font("header"),
            fg=get_color("header_fg"),
            bg=get_color("header_bg"),
            anchor="w",
        ).pack(fill="x", padx=get_spacing("md"), pady=get_spacing("xs"))

        # DB status with 12px dot
        self._db_status_frame = tk.Frame(panel, bg=_panel_bg)
        self._db_status_frame.pack(fill="x", padx=get_spacing("md"),
                                    pady=(get_spacing("sm"), get_spacing("xs")))
        self._db_dot = tk.Canvas(
            self._db_status_frame, width=12, height=12,
            bg=_panel_bg, highlightthickness=0,
        )
        self._db_dot.pack(side="left", padx=(0, get_spacing("xs")))
        self._db_status_label = tk.Label(
            self._db_status_frame,
            text="",
            font=get_font("body"),
            fg=get_color("text"),
            bg=_panel_bg,
            anchor="w",
        )
        self._db_status_label.pack(side="left", fill="x")

        # Master key status with 12px dot
        self._key_status_frame = tk.Frame(panel, bg=_panel_bg)
        self._key_status_frame.pack(fill="x", padx=get_spacing("md"),
                                     pady=(0, get_spacing("md")))
        self._key_dot = tk.Canvas(
            self._key_status_frame, width=12, height=12,
            bg=_panel_bg, highlightthickness=0,
        )
        self._key_dot.pack(side="left", padx=(0, get_spacing("xs")))
        self._key_status_label = tk.Label(
            self._key_status_frame,
            text="",
            font=get_font("body"),
            fg=get_color("text"),
            bg=_panel_bg,
            anchor="w",
        )
        self._key_status_label.pack(side="left", fill="x")

        # Alerts header with accent
        alerts_header = tk.Frame(panel, bg=get_color("notice_header"), height=36)
        alerts_header.pack(fill="x")
        alerts_header.pack_propagate(False)
        tk.Label(
            alerts_header,
            text=t("dashboard.alerts"),
            font=get_font("header"),
            fg=get_color("header_fg"),
            bg=get_color("notice_header"),
            anchor="w",
        ).pack(fill="x", padx=get_spacing("md"), pady=get_spacing("xs"))

        self._alert_frame = tk.Frame(panel, bg=_panel_bg)
        self._alert_frame.pack(fill="both", expand=True,
                               padx=get_spacing("md"), pady=(get_spacing("xs"), get_spacing("md")))

    # ------------------------------------------------------------------
    # Recent history (bottom) — grid-aligned table with i18n headers
    # ------------------------------------------------------------------

    def _build_recent_history(self, row: int) -> None:
        # Shadow wrapper
        shadow = tk.Frame(self, bg=get_color("shadow"))
        shadow.grid(row=row, column=0, sticky="nsew",
                    padx=get_spacing("md"), pady=get_spacing("sm"))

        history_frame = tk.Frame(shadow, bg=get_color("card_bg"))
        history_frame.pack(fill="both", expand=True, padx=(0, 3), pady=(0, 3))

        # Dark header for recent activity
        hist_header = tk.Frame(history_frame, bg=get_color("header_bg"), height=36)
        hist_header.pack(fill="x")
        hist_header.pack_propagate(False)
        tk.Label(
            hist_header,
            text=t("dashboard.recent_activity"),
            font=get_font("header"),
            fg=get_color("header_fg"),
            bg=get_color("header_bg"),
            anchor="w",
        ).pack(fill="x", padx=get_spacing("md"), pady=get_spacing("xs"))

        # Grid table (header + data rows share the same grid columns)
        self._history_table = tk.Frame(history_frame, bg=get_color("card_bg"))
        self._history_table.pack(fill="both", expand=True)
        self._history_table.columnconfigure(0, weight=0, minsize=170)
        self._history_table.columnconfigure(1, weight=0, minsize=110)
        self._history_table.columnconfigure(2, weight=1)

        self._render_history_placeholder(t("dashboard.loading"))

    def _render_history_header(self) -> int:
        """Render the column header row; returns the next free grid row."""
        header_bg = get_color("bg")
        for col, key in enumerate(
            ("dashboard.col_time", "dashboard.col_type", "dashboard.col_seal_id")
        ):
            tk.Label(
                self._history_table,
                text=t(key),
                font=get_font("caption"),
                fg=get_color("text_secondary"),
                bg=header_bg,
                anchor="w",
                padx=get_spacing("sm"),
                pady=4,
            ).grid(row=0, column=col, sticky="ew")

        sep = tk.Frame(self._history_table, height=1, bg=get_color("border"))
        sep.grid(row=1, column=0, columnspan=3, sticky="ew")
        return 2

    def _clear_history_table(self) -> None:
        for child in self._history_table.winfo_children():
            child.destroy()

    def _render_history_placeholder(self, text: str) -> None:
        self._clear_history_table()
        self._render_history_header()
        tk.Label(
            self._history_table,
            text=text,
            font=get_font("body"),
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
        ).grid(row=2, column=0, columnspan=3, pady=get_spacing("md"))

    def _render_history_empty_state(self) -> None:
        """Empty state with guidance text and a call-to-action button."""
        self._clear_history_table()
        self._render_history_header()

        tk.Label(
            self._history_table,
            text=t("dashboard.no_activity"),
            font=get_font("subheader"),
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
        ).grid(row=2, column=0, columnspan=3, pady=(get_spacing("md"), 2))
        tk.Label(
            self._history_table,
            text=t("dashboard.no_activity_hint"),
            font=get_font("small"),
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
        ).grid(row=3, column=0, columnspan=3)
        tk.Button(
            self._history_table,
            text=t("dashboard.empty_cta"),
            command=self._app._on_seal,
            font=get_font("button"),
            fg=get_color("text_light"),
            bg=get_color("primary"),
            activebackground=get_color("primary_hover"),
            activeforeground=get_color("text_light"),
            relief="flat",
            bd=0,
            padx=get_spacing("md"),
            pady=4,
            cursor="hand2",
        ).grid(row=4, column=0, columnspan=3, pady=get_spacing("sm"))

    def _render_history_rows(self, cases: list[dict]) -> None:
        self._clear_history_table()
        next_row = self._render_history_header()

        for idx, case in enumerate(cases):
            self._add_history_row(case, idx, next_row + idx)

    def _add_history_row(self, case: dict, row_idx: int, grid_row: int) -> None:
        normal_bg = (
            get_color("card_bg") if row_idx % 2 == 0 else get_color("bg")
        )
        created = case.get("created_at", "")
        status = case.get("status", "")
        seal_id = case.get("seal_id", "")
        type_text = _status_to_type(status)

        cells: list[tk.Label] = []
        for col, text in enumerate((created, type_text, seal_id)):
            label = tk.Label(
                self._history_table,
                text=text,
                font=get_font("body"),
                fg=get_color("text"),
                bg=normal_bg,
                anchor="w",
                padx=get_spacing("sm"),
                pady=5,
                cursor="hand2",
            )
            label.grid(row=grid_row, column=col, sticky="ew")
            cells.append(label)

        # First cell carries keyboard focus for the whole row
        focus_cell = cells[0]
        focus_cell.configure(
            takefocus=1,
            highlightthickness=1,
            highlightbackground=normal_bg,
            highlightcolor=get_color("primary"),
        )

        hover_bg = get_color("hover")

        def _set_bg(color: str) -> None:
            for cell in cells:
                cell.configure(bg=color)

        def _on_enter(_e: tk.Event) -> None:  # type: ignore[type-arg]
            _set_bg(hover_bg)

        def _on_leave(_e: tk.Event) -> None:  # type: ignore[type-arg]
            _set_bg(normal_bg)

        def _activate(_e: tk.Event) -> None:  # type: ignore[type-arg]
            self._open_case_detail(seal_id)

        for cell in cells:
            cell.bind("<Enter>", _on_enter)
            cell.bind("<Leave>", _on_leave)
            cell.bind("<Button-1>", _activate)

        focus_cell.bind("<FocusIn>", _on_enter)
        focus_cell.bind("<FocusOut>", _on_leave)
        focus_cell.bind("<Return>", _activate)
        focus_cell.bind("<space>", _activate)

    def _open_case_detail(self, seal_id: str) -> None:
        try:
            from .case_detail_dialog import CaseDetailDialog
            CaseDetailDialog(self, self._app.db_path, seal_id)
        except Exception as exc:
            logger.warning("케이스 상세 열기 실패: %s", exc)

    # ------------------------------------------------------------------
    # Refresh / data loading (async)
    # ------------------------------------------------------------------

    def _on_manual_refresh(self) -> None:
        """Handle the manual refresh button — refresh with a toast on done."""
        self.refresh(notify=True)

    def refresh(self, *, notify: bool = False) -> None:
        """Reload dashboard data on a worker thread and update the UI.

        Args:
            notify: When True, show a toast once the refresh completes.
        """
        if self._loading:
            return
        self._loading = True
        self._show_loading_state()

        worker = threading.Thread(
            target=self._load_data_worker,
            args=(notify,),
            daemon=True,
            name="dashboard-refresh",
        )
        worker.start()
        self._poll_worker_result()

    def _poll_worker_result(self) -> None:
        """Poll the result queue from the Tk main loop (thread-safe)."""
        self._poll_after_id = None
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return

        try:
            data, notify = self._result_queue.get_nowait()
        except queue.Empty:
            self._poll_after_id = self.after(100, self._poll_worker_result)
            return

        self._apply_data(data, notify)

    def _cancel_poll(self, _event: "tk.Event | None" = None) -> None:
        """Cancel the pending poll timer (bound to <Destroy>)."""
        if self._poll_after_id is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except tk.TclError:
                pass
            self._poll_after_id = None

    def _show_loading_state(self) -> None:
        """Show subtle loading placeholders while data is being fetched."""
        for label in self._stat_labels.values():
            label.configure(text="…")
        self._render_history_placeholder(t("dashboard.loading"))

    def _load_data_worker(self, notify: bool) -> None:
        """Run all DB queries off the main thread; deliver via after()."""
        data: dict[str, Any] = {
            "stats": None,
            "db_ok": False,
            "key_exists": False,
            "expiring": [],
            "cases": [],
        }

        db_path = self._app.db_path

        # DB connectivity check
        if db_path:
            try:
                conn = sqlite3.connect(db_path)
                try:
                    conn.execute("SELECT 1")
                finally:
                    conn.close()
                data["db_ok"] = True
            except Exception:
                data["db_ok"] = False

        # Statistics
        if data["db_ok"]:
            try:
                from ..db.sqlite_store import get_dashboard_stats
                data["stats"] = get_dashboard_stats(db_path)
            except Exception as exc:
                logger.warning("대시보드 통계 조회 실패: %s", exc)

            try:
                from ..db.sqlite_store import get_expiring_seals
                data["expiring"] = get_expiring_seals(db_path, days=3)
            except Exception as exc:
                logger.warning("만료 임박 조회 실패: %s", exc)

            try:
                from ..db.sqlite_store import get_recent_cases
                data["cases"] = get_recent_cases(db_path, limit=5)
            except Exception as exc:
                logger.warning("최근 이력 조회 실패: %s", exc)

        # Master key check
        try:
            data["key_exists"] = (
                Path.home() / ".enc_envelope" / "master.key"
            ).exists()
        except Exception:
            data["key_exists"] = False

        # Hand off to the Tk main loop via the polled queue (thread-safe)
        self._result_queue.put((data, notify))

    def _apply_data(self, data: dict[str, Any], notify: bool) -> None:
        """Apply worker results to the UI (main thread only)."""
        self._loading = False
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return

        self._apply_stats(data.get("stats"))
        self._apply_system_status(
            db_ok=bool(data.get("db_ok")),
            key_exists=bool(data.get("key_exists")),
        )
        self._apply_alerts(data.get("expiring") or [])
        self._apply_history(data.get("cases") or [])

        if notify:
            toasts = getattr(self._app, "toasts", None)
            if toasts is not None:
                toasts.show(
                    self._app.root, t("dashboard.refresh_done"),
                    toast_type="info",
                )

    def _apply_stats(self, stats: Optional[dict]) -> None:
        if stats is None:
            na = t("dashboard.stat_na")
            for label in self._stat_labels.values():
                label.configure(text=na)
            return
        self._stat_labels["seal_count"].configure(text=str(stats.get("sealed_only", 0)))
        self._stat_labels["unseal_count"].configure(text=str(stats.get("unsealed", 0)))
        self._stat_labels["reseal_count"].configure(text=str(stats.get("resealed", 0)))

    def _draw_status_dot(self, canvas: tk.Canvas, color: str) -> None:
        """Draw a filled 12px circle on a status dot canvas."""
        canvas.delete("all")
        canvas.create_oval(0, 0, 12, 12, fill=color, outline=color)

    def _apply_system_status(self, *, db_ok: bool, key_exists: bool) -> None:
        if db_ok:
            self._draw_status_dot(self._db_dot, get_color("success"))
            self._db_status_label.configure(
                text=f"{t('dashboard.db_status')}: {t('dashboard.db_ok')}",
                fg=get_color("text"),
            )
        else:
            self._draw_status_dot(self._db_dot, get_color("danger"))
            self._db_status_label.configure(
                text=f"{t('dashboard.db_status')}: {t('dashboard.db_fail')}",
                fg=get_color("danger_text"),
            )

        if key_exists:
            self._draw_status_dot(self._key_dot, get_color("success"))
            self._key_status_label.configure(
                text=f"{t('dashboard.master_key')}: {t('dashboard.key_exists')}",
                fg=get_color("text"),
            )
        else:
            self._draw_status_dot(self._key_dot, get_color("danger"))
            self._key_status_label.configure(
                text=f"{t('dashboard.master_key')}: {t('dashboard.key_missing')}",
                fg=get_color("danger_text"),
            )

    def _apply_alerts(self, expiring: list[dict]) -> None:
        for child in self._alert_frame.winfo_children():
            child.destroy()

        if not expiring:
            tk.Label(
                self._alert_frame,
                text=f"✔ {t('dashboard.no_alerts')}",
                font=get_font("body"),
                fg=get_color("success_text"),
                bg=get_color("panel_bg"),
                anchor="w",
            ).pack(fill="x")
            return

        for item in expiring:
            seal_id = item.get("seal_id", "")
            unlock_str = item.get("unlock_time", "")
            # Alert with left 3px ruby border
            alert_container = tk.Frame(self._alert_frame, bg=get_color("danger"))
            alert_container.pack(fill="x", pady=2)
            alert_inner = tk.Frame(alert_container, bg=get_color("card_bg"))
            alert_inner.pack(fill="x", padx=(3, 0))  # 3px left ruby border
            tk.Label(
                alert_inner,
                text=f"⚠ {seal_id} — {t('dashboard.expiring_seal')}: {unlock_str}",
                font=get_font("small"),
                fg=get_color("warning_text"),
                bg=get_color("card_bg"),
                anchor="w",
                padx=get_spacing("xs"),
                pady=2,
            ).pack(fill="x")

    def _apply_history(self, cases: list[dict]) -> None:
        if not cases:
            self._render_history_empty_state()
            return
        self._render_history_rows(cases)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _status_to_type(status: str) -> str:
    """Convert status code like S1U1R0 to a display type string."""
    if not status:
        return t("status.seal")
    # Check for reseal first (R >= 1)
    if "R" in status:
        try:
            r_val = int(status.split("R")[-1])
            if r_val >= 1:
                return t("status.reseal")
        except (ValueError, IndexError):
            pass
    # Check for unseal (U >= 1)
    if "U" in status:
        try:
            parts = status.split("U")
            u_part = parts[-1].split("R")[0] if "R" in parts[-1] else parts[-1]
            u_val = int(u_part)
            if u_val >= 1:
                return t("status.unseal")
        except (ValueError, IndexError):
            pass
    return t("status.seal")
