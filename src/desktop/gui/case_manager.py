"""Case management screen for viewing, searching, and managing seal cases.

Provides a Treeview-based list of all cases with search, detail view,
artifact browsing, history timeline, and deletion capabilities.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING, Any, Callable, Optional

from .i18n import t
from .theme import COLORS, FONTS, get_color, get_font

if TYPE_CHECKING:
    from .app import MainApp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def _get_columns() -> tuple:
    """Return column definitions with i18n-aware headers."""
    return (
        ("seal_id", t("case.col_seal_id"), 140),
        ("case_number", t("case.col_case_number"), 110),
        ("suspect_name", t("case.col_suspect"), 80),
        ("investigator", t("case.col_investigator"), 80),
        ("status", t("case.col_status"), 70),
        ("created_at", t("case.col_date"), 130),
    )

_ALT_ROW_BG = COLORS["bg"]       # #f8f9fb page background for alt rows
_SELECT_BG = COLORS["selected"]  # #e8e5ff purple-tinted selection

def _get_status_filter_options() -> list[str]:
    return [t("case.status_all"), t("case.status_sealed"), t("case.status_unsealed"), t("case.status_resealed")]


# _STATUS_FILTER_OPTIONS removed — use _get_status_filter_options() instead


class CaseManager(tk.Frame):
    """Case management panel with search, list, and action buttons."""

    def __init__(
        self,
        master: tk.Widget,
        app: MainApp,
        *,
        on_back: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(master)
        self._app = app
        self._on_back = on_back
        self._all_cases: list[dict[str, Any]] = []
        self._loading = False
        self._selection_buttons: list[tk.Button] = []
        # Thread-safe channel: worker threads put results here and the Tk
        # main loop polls it (after() is not safe to call off-thread).
        self._result_queue: queue.Queue = queue.Queue()
        self._poll_after_id: Optional[str] = None
        # Cancel any pending poll timer on destroy — otherwise the timer
        # fires after the widget's Tcl command is deleted and Tk prints
        # an "invalid command name" background error.
        self.bind("<Destroy>", self._cancel_poll, add="+")

        self._build_header()
        self._build_search_bar()
        self._build_treeview()
        self._build_action_bar()
        self._update_action_states()
        self._refresh_list()

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _build_header(self) -> None:
        # Dark navy header for strong visual identity
        _case_header_bg = get_color("header_bg")
        header = tk.Frame(self, bg=_case_header_bg, height=56)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text=t("case.title"),
            fg=get_color("header_fg"),
            bg=_case_header_bg,
            font=get_font("title"),
        ).pack(side="left", padx=16)

        tk.Button(
            header,
            text=t("case.back_home"),
            command=self._go_back,
            bg=_case_header_bg,
            fg=get_color("header_fg_muted"),
            activebackground=get_color("header_hover_bg"),
            activeforeground=get_color("header_fg"),
            relief="flat",
            font=get_font("small"),
            bd=0,
        ).pack(side="right", padx=16, pady=8)

        # New Case button in header
        tk.Button(
            header,
            text=t("case.new_case"),
            command=self._on_new_case,
            bg=get_color("primary"),
            fg=get_color("text_light"),
            activebackground=get_color("primary_hover"),
            activeforeground=get_color("text_light"),
            relief="flat",
            font=get_font("button"),
            bd=0,
            padx=12,
            pady=2,
        ).pack(side="right", padx=4, pady=8)

    def _build_search_bar(self) -> None:
        bar = tk.Frame(self, padx=16, pady=8)
        bar.pack(fill="x")

        tk.Label(bar, text=t("case.search_label"), font=get_font("body")).pack(side="left")
        self._search_var = tk.StringVar()
        self._search_entry = tk.Entry(
            bar, textvariable=self._search_var, width=30, font=get_font("body")
        )
        self._search_entry.pack(side="left", padx=(8, 4))
        self._search_entry.bind("<Return>", lambda _e: self._do_search())

        tk.Button(
            bar, text=t("case.search"), command=self._do_search, font=get_font("small")
        ).pack(side="left", padx=2)
        tk.Button(
            bar, text=t("case.refresh"), command=self._refresh_list, font=get_font("small")
        ).pack(side="left", padx=2)

        # Status filter dropdown
        tk.Label(bar, text=t("case.status_filter"), font=get_font("body")).pack(side="left", padx=(16, 4))
        self._status_filter_var = tk.StringVar(value=t("case.status_all"))
        status_combo = ttk.Combobox(
            bar,
            textvariable=self._status_filter_var,
            values=_get_status_filter_options(),
            state="readonly",
            width=10,
        )
        status_combo.pack(side="left", padx=2)
        status_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_filter())

        self._count_label = tk.Label(
            bar, text="", font=get_font("small"), fg=get_color("text_secondary")
        )
        self._count_label.pack(side="right")

    def _build_treeview(self) -> None:
        tree_frame = tk.Frame(self, padx=16)
        tree_frame.pack(fill="both", expand=True)

        col_ids = [c[0] for c in _get_columns()]
        self._tree = ttk.Treeview(
            tree_frame,
            columns=col_ids,
            show="headings",
            selectmode="browse",
        )

        # Configure style for alternating rows — DESIGN.md Treeview
        style = ttk.Style()
        style.configure(
            "Case.Treeview",
            rowheight=30,
            background=get_color("card_bg"),
            fieldbackground=get_color("card_bg"),
            foreground=get_color("text"),
            font=get_font("body"),
        )
        style.configure(
            "Case.Treeview.Heading",
            background=get_color("bg"),
            foreground=get_color("heading"),
            font=get_font("subheader"),
        )
        style.map(
            "Case.Treeview",
            background=[("selected", get_color("selected"))],
            foreground=[("selected", get_color("heading"))],
        )
        self._tree.configure(style="Case.Treeview")
        self._tree.tag_configure("odd", background=_ALT_ROW_BG)
        self._tree.tag_configure("even", background=get_color("card_bg"))

        for col_id, heading, width in _get_columns():
            self._tree.heading(
                col_id,
                text=heading,
                command=lambda c=col_id: self._sort_by_column(c),
            )
            self._tree.column(col_id, width=width, minwidth=60)

        scrollbar_y = ttk.Scrollbar(
            tree_frame, orient="vertical", command=self._tree.yview
        )
        self._tree.configure(yscrollcommand=scrollbar_y.set)

        self._tree.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")

        self._tree.bind("<Double-1>", lambda _e: self._on_detail())
        self._tree.bind("<Button-3>", self._show_context_menu)
        self._tree.bind("<<TreeviewSelect>>", lambda _e: self._update_action_states())

        # Empty-state overlay (shown when the list has no cases)
        self._empty_frame = tk.Frame(tree_frame, bg=get_color("card_bg"))
        tk.Label(
            self._empty_frame,
            text=t("case.empty_state"),
            font=get_font("subheader"),
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
        ).pack(pady=(0, 4))
        tk.Label(
            self._empty_frame,
            text=t("case.empty_state_hint"),
            font=get_font("small"),
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
        ).pack(pady=(0, 8))
        tk.Button(
            self._empty_frame,
            text=t("case.new_case"),
            command=self._on_new_case,
            font=get_font("button"),
            fg=get_color("text_light"),
            bg=get_color("primary"),
            activebackground=get_color("primary_hover"),
            activeforeground=get_color("text_light"),
            relief="flat",
            bd=0,
            padx=12,
            pady=4,
            cursor="hand2",
        ).pack()

    def _set_empty_state(self, show: bool) -> None:
        """Show or hide the empty-state overlay above the treeview."""
        if show:
            self._empty_frame.place(relx=0.5, rely=0.4, anchor="center")
        else:
            self._empty_frame.place_forget()

    def _build_action_bar(self) -> None:
        """Two-row action bar; selection-dependent buttons start disabled.

        Row 1: record viewing actions + delete (right).
        Row 2: workflow actions — keeps the bar usable at 800px width.
        """
        bar = tk.Frame(self, padx=16, pady=4, bg=get_color("bg"))
        bar.pack(fill="x")
        row1 = tk.Frame(bar, bg=get_color("bg"))
        row1.pack(fill="x", pady=(0, 4))
        row2 = tk.Frame(bar, bg=get_color("bg"))
        row2.pack(fill="x", pady=(0, 4))

        # Primary action buttons — purple filled style
        ghost_cfg = {
            "font": get_font("button"),
            "width": 12,
            "fg": get_color("text_light"),
            "bg": get_color("primary"),
            "activebackground": get_color("primary_hover"),
            "activeforeground": get_color("text_light"),
            "relief": "flat",
            "bd": 0,
            "padx": 8,
            "pady": 4,
        }

        for text_key, command in (
            ("case.detail", self._on_detail),
            ("case.artifacts", self._on_artifacts),
            ("case.history", self._on_history),
            ("case.open_pdf", self._on_open_pdf),
        ):
            btn = tk.Button(row1, text=t(text_key), command=command, **ghost_cfg)
            btn.pack(side="left", padx=4)
            self._selection_buttons.append(btn)

        # Workflow action buttons — teal style
        workflow_cfg = {
            "font": get_font("button"),
            "width": 14,
            "fg": get_color("text_light"),
            "bg": get_color("workflow_accent"),
            "activebackground": get_color("workflow_accent_hover"),
            "activeforeground": get_color("text_light"),
            "relief": "flat",
            "bd": 0,
            "padx": 8,
            "pady": 4,
        }

        for text_key, command in (
            ("case.start_seal", self._on_start_seal),
            ("case.start_unseal", self._on_start_unseal),
            ("case.start_reseal", self._on_start_reseal),
        ):
            btn = tk.Button(row2, text=t(text_key), command=command, **workflow_cfg)
            btn.pack(side="left", padx=4)
            self._selection_buttons.append(btn)

        # Delete button — danger style
        delete_btn = tk.Button(
            row1,
            text=t("case.delete"),
            command=self._on_delete,
            fg=get_color("text_light"),
            bg=get_color("danger"),
            activebackground=get_color("danger_hover"),
            activeforeground=get_color("text_light"),
            font=get_font("button"),
            width=12,
            relief="flat",
        )
        delete_btn.pack(side="right", padx=4)
        self._selection_buttons.append(delete_btn)

    def _update_action_states(self) -> None:
        """Enable selection-dependent buttons only when a case is selected."""
        state = "normal" if self._tree.selection() else "disabled"
        for btn in self._selection_buttons:
            try:
                btn.configure(state=state)
            except tk.TclError:
                pass

    # ------------------------------------------------------------------
    # Data operations
    # ------------------------------------------------------------------

    def _refresh_list(self) -> None:
        """Reload all cases from DB on a worker thread and populate the tree."""
        self._search_var.set("")
        self._load_cases_async(keyword=None)

    def _do_search(self) -> None:
        keyword = self._search_var.get().strip()
        if not keyword:
            self._refresh_list()
            return
        self._load_cases_async(keyword=keyword)

    def _load_cases_async(self, *, keyword: Optional[str]) -> None:
        """Query the case list off the main thread; apply via after()."""
        if self._loading:
            return
        self._loading = True
        self._count_label.configure(text=t("case.loading"))

        def _worker() -> None:
            cases: list[dict[str, Any]] = []
            try:
                if keyword:
                    from desktop.db import search_cases
                    cases = search_cases(self._app.db_path, keyword)
                else:
                    from desktop.db import list_all_cases
                    cases = list_all_cases(self._app.db_path)
            except Exception as exc:
                logger.error("케이스 목록 조회 실패: %s", exc)
                cases = []

            # Hand off to the Tk main loop via the polled queue (thread-safe)
            self._result_queue.put(cases)

        threading.Thread(
            target=_worker, daemon=True, name="case-list-load"
        ).start()
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
            cases = self._result_queue.get_nowait()
        except queue.Empty:
            self._poll_after_id = self.after(100, self._poll_worker_result)
            return

        self._apply_cases(cases)

    def _cancel_poll(self, _event: "tk.Event | None" = None) -> None:
        """Cancel the pending poll timer (bound to <Destroy>)."""
        if self._poll_after_id is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except tk.TclError:
                pass
            self._poll_after_id = None

    def _apply_cases(self, cases: list[dict[str, Any]]) -> None:
        """Apply worker results to the tree (main thread only)."""
        self._loading = False
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        self._all_cases = cases
        self._populate_tree(cases)

    def _populate_tree(self, cases: list[dict[str, Any]]) -> None:
        self._tree.delete(*self._tree.get_children())
        for idx, case in enumerate(cases):
            tag = "odd" if idx % 2 == 1 else "even"
            self._tree.insert(
                "",
                "end",
                iid=case["seal_id"],
                values=(
                    case.get("seal_id", ""),
                    case.get("case_number", ""),
                    case.get("suspect_name", ""),
                    case.get("investigator", ""),
                    case.get("status", ""),
                    case.get("created_at", ""),
                ),
                tags=(tag,),
            )
        self._count_label.configure(text=t("case.total_count").format(count=len(cases)))
        self._set_empty_state(len(cases) == 0)
        self._update_action_states()

    def _sort_by_column(self, col: str) -> None:
        """Sort treeview by the given column."""
        items = [
            (self._tree.set(iid, col), iid)
            for iid in self._tree.get_children("")
        ]
        items.sort(key=lambda t: t[0])
        for idx, (_val, iid) in enumerate(items):
            self._tree.move(iid, "", idx)
            tag = "odd" if idx % 2 == 1 else "even"
            self._tree.item(iid, tags=(tag,))

    def _get_selected_seal_id(self) -> Optional[str]:
        selection = self._tree.selection()
        if not selection:
            messagebox.showwarning(t("case.select_required_title"), t("case.select_required"))
            return None
        return selection[0]

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _on_detail(self) -> None:
        seal_id = self._get_selected_seal_id()
        if seal_id is None:
            return
        from .case_detail_dialog import CaseDetailDialog
        CaseDetailDialog(self.winfo_toplevel(), self._app.db_path, seal_id)

    def _on_artifacts(self) -> None:
        seal_id = self._get_selected_seal_id()
        if seal_id is None:
            return
        from .case_detail_dialog import ArtifactsWindow
        ArtifactsWindow(self.winfo_toplevel(), self._app.db_path, seal_id)

    def _on_history(self) -> None:
        seal_id = self._get_selected_seal_id()
        if seal_id is None:
            return
        from .case_detail_dialog import HistoryWindow
        HistoryWindow(self.winfo_toplevel(), self._app.db_path, seal_id)

    def _on_open_pdf(self) -> None:
        seal_id = self._get_selected_seal_id()
        if seal_id is None:
            return
        try:
            from desktop.db import get_case_detail
            detail = get_case_detail(self._app.db_path, seal_id)
        except Exception as exc:
            messagebox.showerror(t("common.error"), f"{exc}")
            return

        if detail is None:
            messagebox.showwarning(t("case.not_found_title"), t("case.not_found"))
            return

        pdf_path = detail.get("pdf_path", "")
        if not pdf_path or not os.path.exists(pdf_path):
            messagebox.showwarning(t("case.not_found_title"), f"{t('pdf.not_found')}\n{pdf_path}")
            return

        try:
            os.startfile(pdf_path)
        except Exception as exc:
            messagebox.showerror(t("common.error"), f"{t('pdf.open_failed')}: {exc}")

    def _on_delete(self) -> None:
        seal_id = self._get_selected_seal_id()
        if seal_id is None:
            return

        if not messagebox.askyesno(
            t("case.delete_confirm_title"),
            t("case.delete_confirm_msg").format(seal_id=seal_id),
        ):
            return

        try:
            from desktop.db import delete_case
            deleted = delete_case(self._app.db_path, seal_id)
            if deleted:
                toasts = getattr(self._app, "toasts", None)
                if toasts is not None:
                    toasts.show(
                        self._app.root,
                        t("case.delete_toast").format(seal_id=seal_id),
                        toast_type="success",
                    )
                else:
                    messagebox.showinfo(
                        t("case.delete_done"), f"'{seal_id}' {t('case.delete_done')}"
                    )
                self._refresh_list()
            else:
                messagebox.showwarning(t("case.not_found_title"), t("case.not_found"))
        except Exception as exc:
            messagebox.showerror(t("common.error"), f"{exc}")

    def _show_context_menu(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        """Show right-click context menu on the treeview."""
        iid = self._tree.identify_row(event.y)
        if not iid:
            return
        self._tree.selection_set(iid)

        menu = tk.Menu(self._tree, tearoff=0)
        menu.add_command(label=t("case.detail"), command=self._on_detail)
        menu.add_command(label=t("case.artifacts"), command=self._on_artifacts)
        menu.add_command(label=t("case.history"), command=self._on_history)
        menu.add_command(label=t("case.open_pdf"), command=self._on_open_pdf)
        menu.add_separator()
        menu.add_command(label=t("case.delete"), command=self._on_delete, foreground=get_color("danger"))
        menu.tk_popup(event.x_root, event.y_root)

    def _apply_filter(self) -> None:
        """Filter the case list by selected status (S/U/R pattern matching)."""
        filter_value = self._status_filter_var.get()
        if filter_value in (t("case.status_all"), "All", "전체"):
            self._populate_tree(self._all_cases)
            return

        filtered: list[dict[str, Any]] = []
        for c in self._all_cases:
            status = c.get("status", "")
            if filter_value in (t("case.status_sealed"), "Sealed", "봉인"):
                # 봉인만: S>=1, U=0, R=0
                if "U0" in status and "R0" in status:
                    filtered.append(c)
            elif filter_value in (t("case.status_unsealed"), "Unsealed", "봉인해제"):
                # 봉인해제: U>=1
                if "U0" not in status and "U" in status:
                    filtered.append(c)
            elif filter_value in (t("case.status_resealed"), "Resealed", "재봉인"):
                # 재봉인: R>=1
                if "R0" not in status and "R" in status:
                    filtered.append(c)
        self._populate_tree(filtered)

    # ------------------------------------------------------------------
    # Workflow action handlers
    # ------------------------------------------------------------------

    def _on_new_case(self) -> None:
        """Open the New Case dialog."""
        dlg = NewCaseDialog(self.winfo_toplevel(), self._app.db_path)
        self.winfo_toplevel().wait_window(dlg)
        if dlg.created_seal_id:
            self._refresh_list()

    def _get_selected_case_data(self) -> Optional[dict[str, Any]]:
        """Return full case row for the selected item, or None."""
        selection = self._tree.selection()
        if not selection:
            messagebox.showwarning(
                t("case.select_required_title"),
                t("case.no_selection"),
                parent=self.winfo_toplevel(),
            )
            return None
        seal_id = selection[0]
        for case in self._all_cases:
            if case["seal_id"] == seal_id:
                return dict(case)
        return None

    def _on_start_seal(self) -> None:
        """Start seal wizard from selected case."""
        case = self._get_selected_case_data()
        if case is None:
            return
        status = case.get("status", "")
        if status and "S1" in status:
            messagebox.showwarning(
                t("common.warning"),
                t("case.seal_not_available"),
                parent=self.winfo_toplevel(),
            )
            return
        # Fetch full case info for prefill
        try:
            from desktop.db import get_case_for_seal
            case_data = get_case_for_seal(self._app.db_path, case["seal_id"])
        except Exception:
            case_data = case
        if case_data is None:
            case_data = case
        self._app._on_seal_with_case(case_data)

    def _on_start_unseal(self) -> None:
        """Start unseal wizard from selected case."""
        case = self._get_selected_case_data()
        if case is None:
            return
        status = case.get("status", "")
        if "S1" not in status or ("U1" in status):
            messagebox.showwarning(
                t("common.warning"),
                t("case.unseal_not_available"),
                parent=self.winfo_toplevel(),
            )
            return
        try:
            from desktop.db import get_case_for_unseal
            case_data = get_case_for_unseal(self._app.db_path, case["seal_id"])
        except Exception:
            case_data = case
        if case_data is None:
            case_data = case
        self._app._on_unseal_with_case(case_data)

    def _on_start_reseal(self) -> None:
        """Start reseal wizard from selected case."""
        case = self._get_selected_case_data()
        if case is None:
            return
        status = case.get("status", "")
        if "U1" not in status:
            messagebox.showwarning(
                t("common.warning"),
                t("case.reseal_not_available"),
                parent=self.winfo_toplevel(),
            )
            return
        # For reseal we need the unseal record path
        try:
            from desktop.db import get_case_for_unseal
            case_data = get_case_for_unseal(self._app.db_path, case["seal_id"])
        except Exception:
            case_data = case
        if case_data is None:
            case_data = case
        self._app._on_reseal_with_case(case_data)

    def _go_back(self) -> None:
        if self._on_back is not None:
            self._on_back()


class NewCaseDialog(tk.Toplevel):
    """Modal dialog for creating a new case before sealing."""

    def __init__(self, parent: tk.Widget, db_path: str) -> None:
        super().__init__(parent)
        self.title(t("case.new_case_title"))
        self.geometry("420x320")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._db_path = db_path
        self.created_seal_id: str = ""

        self._build_ui()

    def _build_ui(self) -> None:
        pad = {"padx": 16, "pady": 4}

        tk.Label(
            self, text=t("case.new_case_title"),
            font=get_font("header"),
        ).pack(anchor="w", padx=16, pady=(12, 4))

        # Case number
        tk.Label(self, text=t("case.case_number_input"), font=get_font("body")).pack(
            anchor="w", padx=16, pady=(8, 0)
        )
        self._case_number_var = tk.StringVar()
        tk.Entry(self, textvariable=self._case_number_var, width=40, font=get_font("body")).pack(
            padx=16, fill="x"
        )

        # Investigator
        tk.Label(self, text=t("case.investigator_input"), font=get_font("body")).pack(
            anchor="w", padx=16, pady=(8, 0)
        )
        self._investigator_var = tk.StringVar()
        tk.Entry(self, textvariable=self._investigator_var, width=40, font=get_font("body")).pack(
            padx=16, fill="x"
        )

        # Suspect name (optional)
        tk.Label(self, text=t("case.suspect_input"), font=get_font("body")).pack(
            anchor="w", padx=16, pady=(8, 0)
        )
        self._suspect_var = tk.StringVar()
        tk.Entry(self, textvariable=self._suspect_var, width=40, font=get_font("body")).pack(
            padx=16, fill="x"
        )

        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill="x", padx=16, pady=(16, 12))

        tk.Button(
            btn_frame, text=t("common.cancel"), width=10,
            command=self.destroy,
            font=get_font("button"),
        ).pack(side="right", padx=4)

        tk.Button(
            btn_frame, text=t("case.create"), width=10,
            command=self._do_create,
            fg=get_color("text_light"),
            bg=get_color("primary"),
            activebackground=get_color("primary_hover"),
            activeforeground=get_color("text_light"),
            relief="flat",
            font=get_font("button"),
        ).pack(side="right", padx=4)

    def _do_create(self) -> None:
        case_number = self._case_number_var.get().strip()
        investigator = self._investigator_var.get().strip()
        suspect_name = self._suspect_var.get().strip()

        if not case_number or not investigator:
            messagebox.showwarning(
                t("common.input_error"),
                t("case.case_number_input") + "\n" + t("case.investigator_input"),
                parent=self,
            )
            return

        try:
            from desktop.db import create_case
            seal_id = create_case(
                self._db_path,
                case_number=case_number,
                investigator=investigator,
                suspect_name=suspect_name,
            )
            self.created_seal_id = seal_id
            messagebox.showinfo(
                t("common.info"),
                t("case.create_success").format(seal_id=seal_id),
                parent=self,
            )
            self.destroy()
        except Exception as exc:
            messagebox.showerror(
                t("common.error"),
                t("case.create_fail").format(error=str(exc)),
                parent=self,
            )
