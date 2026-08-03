"""Case detail dialog with tabbed view for case info, files, history, and artifacts.

Provides three dialog classes:
- CaseDetailDialog: Full tabbed detail view
- ArtifactsWindow: Standalone artifact file list
- HistoryWindow: Standalone history timeline

Design follows the Stripe-inspired theme (theme.py tokens only — no
hardcoded colors/fonts): deep-navy header band with a status badge,
card-based info sections, badge/timeline history, and copyable
readonly entries for hashes.

Window sizing is content-based: the toplevel is built first, then
sized from ``winfo_reqwidth``/``winfo_reqheight`` (clamped to the
screen) with a DPI-aware minimum, so all columns are fully visible
on open without manual resizing.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk
from typing import Any, Optional

from .i18n import t
from .theme import COLORS, ToolTip, get_color, get_font, get_spacing
from .widgets import ScrolledFrame, SummaryView

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event type display names
# ---------------------------------------------------------------------------

def _get_event_label(raw: str) -> str:
    """Return i18n-aware event type label."""
    _map = {
        "seal": "event.seal",
        "Sealing": "event.seal",
        "unseal": "event.unseal",
        "Unsealing": "event.unseal",
        "reseal": "event.reseal",
        "Resealing": "event.reseal",
    }
    key = _map.get(raw)
    return t(key) if key else raw


def _event_color_token(event_type: str) -> str:
    """Return a WCAG-safe text color token for an event type."""
    et = event_type.lower()
    if "unseal" in et:
        return "danger_text"
    if "reseal" in et:
        return "success_text"
    return "info_text"


_ALT_ROW_BG = COLORS["hover"]

# ---------------------------------------------------------------------------
# Status derivation (from history summary, e.g. "S1U1R1")
# ---------------------------------------------------------------------------

_SUMMARY_RE = re.compile(r"S(\d+)U(\d+)R(\d+)")

# kind -> (i18n label key, badge bg token, badge fg token)
_BADGE_STYLE: dict[str, tuple[str, str, str]] = {
    "sealed": ("case.status_sealed", "accent_seal", "text_light"),
    "unsealed": ("case.status_unsealed", "warning", "heading"),
    "resealed": ("case.status_resealed", "accent_reseal", "text_light"),
    "unknown": ("case_detail.status_unknown", "border", "heading"),
}


def _derive_status_kind(record: dict[str, Any]) -> tuple[str, str]:
    """Derive the case status kind from the record history summary.

    Returns:
        (kind, summary) where kind is one of "sealed", "unsealed",
        "resealed", "unknown" and summary is the raw "SxUyRz" string
        (may be empty).
    """
    history = record.get("history", {})
    summary = ""
    if isinstance(history, dict):
        summary = str(history.get("summary", "") or "")

    match = _SUMMARY_RE.search(summary)
    if not match:
        return ("unknown", summary)

    seal_n, unseal_n, reseal_n = (int(g) for g in match.groups())
    if reseal_n > 0:
        return ("resealed", summary)
    if unseal_n > 0:
        return ("unsealed", summary)
    if seal_n > 0:
        return ("sealed", summary)
    return ("unknown", summary)


# ---------------------------------------------------------------------------
# Content-based window sizing (fix for initially clipped columns)
# ---------------------------------------------------------------------------

def _ui_scale(win: tk.Misc) -> float:
    """Return the display scale factor relative to 96 DPI (>= 1.0)."""
    try:
        return max(1.0, win.winfo_fpixels("1i") / 96.0)
    except tk.TclError:
        return 1.0


def _fit_window_to_content(
    win: tk.Toplevel, *, base_min_w: int, base_min_h: int
) -> None:
    """Size a toplevel from its content's requested size.

    Must be called AFTER all widgets are built. The window becomes
    ``max(required, DPI-scaled minimum)`` clamped to the screen, so
    fixed-width content (e.g. Treeview columns) is fully visible on
    open regardless of display scaling.
    """
    win.update_idletasks()
    scale = _ui_scale(win)
    min_w = int(base_min_w * scale)
    min_h = int(base_min_h * scale)
    max_w = int(win.winfo_screenwidth() * 0.9)
    max_h = int(win.winfo_screenheight() * 0.85)

    width = min(max(win.winfo_reqwidth(), min_w), max_w)
    height = min(max(win.winfo_reqheight(), min_h), max_h)

    x = max((win.winfo_screenwidth() - width) // 2, 0)
    y = max((win.winfo_screenheight() - height) // 3, 0)
    win.geometry(f"{width}x{height}+{x}+{y}")
    win.minsize(min(min_w, width), min(min_h, height))


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------

def _create_artifact_tree(
    parent: tk.Widget, artifacts: list[dict[str, Any]]
) -> ttk.Treeview:
    """Build the artifact Treeview with font-measured column widths.

    Column widths are measured from the actual heading/body fonts so
    Korean headers are never clipped, and ``minwidth`` guards against
    shrinking below the header width. All columns stretch on resize.
    """
    specs: list[tuple[str, str, str, bool]] = [
        ("file_name", t("case_detail.col_filename"), "evidence_20260401.dd.enc", True),
        ("file_type", t("case_detail.col_type"), "JSON", False),
        ("size", t("case_detail.col_size"), "1023.9 MB", False),
        (
            "file_path",
            t("case_detail.col_path"),
            "artifacts/record.pdf",
            True,
        ),
    ]
    tree = ttk.Treeview(
        parent,
        columns=tuple(s[0] for s in specs),
        show="headings",
        selectmode="browse",
    )

    head_font = tkfont.Font(font=get_font("subheader"))
    body_font = tkfont.Font(font=get_font("body"))
    pad = get_spacing("lg")
    for cid, heading, sample, stretch in specs:
        tree.heading(cid, text=heading)
        head_w = head_font.measure(heading) + pad
        tree.column(
            cid,
            width=max(head_w, body_font.measure(sample) + pad),
            minwidth=head_w,
            stretch=stretch,
        )

    tree.tag_configure("odd", background=_ALT_ROW_BG)
    tree.tag_configure("even", background=COLORS["card_bg"])

    for idx, art in enumerate(artifacts):
        path = art.get("file_path", "")
        name = os.path.basename(path) if path else ""
        size = _format_size(art.get("size_bytes", 0))
        tag = "odd" if idx % 2 == 1 else "even"
        tree.insert(
            "", "end",
            values=(name, art.get("file_type", ""), size, path),
            tags=(tag,),
        )

    tree.bind("<Double-1>", lambda _e: _open_selected_file(tree))
    tree.bind("<Button-3>", lambda e: _show_context_menu(e, tree))
    return tree


def _build_close_bar(win: tk.Misc, on_close: Any) -> None:
    """Pack a themed close-button bar at the bottom of the window."""
    bar = tk.Frame(win, bg=get_color("bg"))
    bar.pack(side="bottom", fill="x",
             padx=get_spacing("md"), pady=(0, get_spacing("md")))
    tk.Button(
        bar,
        text=t("common.close"),
        command=on_close,
        font=get_font("button"),
        bg=get_color("card_bg"),
        fg=get_color("primary"),
        activebackground=get_color("hover"),
        activeforeground=get_color("primary_hover"),
        relief="flat",
        bd=0,
        highlightthickness=1,
        highlightbackground=get_color("border"),
        cursor="hand2",
        padx=get_spacing("lg"),
        pady=get_spacing("xs"),
    ).pack(side="right")


def _make_card(parent: tk.Widget) -> tk.Frame:
    """Create a bordered card frame (SummaryView card pattern)."""
    card = tk.Frame(
        parent,
        bg=get_color("card_bg"),
        highlightthickness=1,
        highlightbackground=get_color("border"),
    )
    card.pack(fill="x", padx=get_spacing("md"), pady=(get_spacing("sm"), 0))
    return card


def _populate_history(body: tk.Frame, events: list[dict[str, Any]]) -> None:
    """Render the history timeline into a ScrolledFrame body."""
    if not events:
        tk.Label(
            body,
            text=t("case_detail.no_history"),
            font=get_font("body"),
            fg=get_color("text_secondary"),
            bg=get_color("bg"),
        ).pack(pady=get_spacing("xl"))
        return

    card = _make_card(body)
    inner = tk.Frame(
        card, bg=get_color("card_bg"),
        padx=get_spacing("md"), pady=get_spacing("md"),
    )
    inner.pack(fill="both", expand=True)

    for idx, event in enumerate(events):
        _render_timeline_item(inner, idx + 1, event, last=(idx == len(events) - 1))


def _render_timeline_item(
    parent: tk.Frame, seq: int, event: dict[str, Any], *, last: bool
) -> None:
    """Render a single timeline entry: colored dot, badge-style label,
    timestamp, actor, and optional reason line."""
    card_bg = get_color("card_bg")
    event_type = event.get("event", event.get("seal_type", ""))
    label = _get_event_label(event_type)
    color = get_color(_event_color_token(event_type))

    start = event.get("timestamp", event.get("start_time", ""))
    end = event.get("end_time", "")
    actor = event.get("actor", event.get("investigator", ""))
    reason = event.get("reason", "")
    time_str = f"{start} ~ {end}" if end else str(start)

    row = tk.Frame(parent, bg=card_bg)
    row.pack(fill="x", pady=(0, get_spacing("xs")))
    row.grid_columnconfigure(1, weight=1)

    tk.Label(
        row, text="●", fg=color, bg=card_bg, font=get_font("body"),
    ).grid(row=0, column=0, sticky="nw", padx=(0, get_spacing("sm")))

    head = tk.Frame(row, bg=card_bg)
    head.grid(row=0, column=1, sticky="ew")
    body_font = get_font("body")
    tk.Label(
        head,
        text=f"{seq}. {label}",
        font=(body_font[0], body_font[1], "bold"),
        fg=color,
        bg=card_bg,
    ).pack(side="left")
    tk.Label(
        head, text=time_str, font=get_font("small"),
        fg=get_color("text_secondary"), bg=card_bg,
    ).pack(side="left", padx=(get_spacing("md"), 0))
    if actor:
        tk.Label(
            head, text=str(actor), font=get_font("small"),
            fg=get_color("text"), bg=card_bg,
        ).pack(side="left", padx=(get_spacing("md"), 0))

    if reason:
        tk.Label(
            row,
            text=f"{t('case_detail.reason_prefix')} {reason}",
            font=get_font("small"),
            fg=get_color("text_secondary"),
            bg=card_bg,
            anchor="w",
            justify="left",
            wraplength=SummaryView.VALUE_WRAP,
        ).grid(row=1, column=1, sticky="w")

    if not last:
        ttk.Separator(parent, orient="horizontal").pack(
            fill="x", pady=(0, get_spacing("xs"))
        )


# ---------------------------------------------------------------------------
# CaseDetailDialog — tabbed detail view
# ---------------------------------------------------------------------------

class CaseDetailDialog(tk.Toplevel):
    """Tabbed dialog showing full case detail.

    Header band (seal id, case number, status badge) + 4 tabs
    (info cards / file cards / history timeline / artifact list) +
    close bar. Esc closes the dialog.
    """

    BASE_MIN_WIDTH = 760
    BASE_MIN_HEIGHT = 540

    def __init__(self, parent: tk.Widget, db_path: str, seal_id: str) -> None:
        super().__init__(parent)
        # Hide while building so the user never sees an unsized window.
        self.withdraw()
        self.title(f"{t('case_detail.title')} — {seal_id}")
        self.configure(bg=get_color("bg"))
        self.transient(parent.winfo_toplevel())

        self._db_path = db_path
        self._seal_id = seal_id
        self._detail: dict[str, Any] = {}
        #: readonly entries holding copyable values (hashes) — also used
        #: by the regression tests.
        self._hash_entries: list[tk.Entry] = []
        self._artifacts_tree: Optional[ttk.Treeview] = None

        self._load_data()
        self._build_ui()

        # Size from content AFTER building (content-based fix for the
        # "columns clipped on open" bug), then show.
        _fit_window_to_content(
            self,
            base_min_w=self.BASE_MIN_WIDTH,
            base_min_h=self.BASE_MIN_HEIGHT,
        )
        self.deiconify()

        self.bind("<Escape>", lambda _e: self.destroy())
        try:
            self.grab_set()
        except tk.TclError:  # not viewable yet (e.g. headless tests)
            pass

    # ------------------------------------------------------------------

    def _load_data(self) -> None:
        try:
            from desktop.db import get_case_detail
            result = get_case_detail(self._db_path, self._seal_id)
            self._detail = result if result is not None else {}
        except Exception as exc:
            logger.error("상세 조회 실패: %s", exc)
            self._detail = {}

    def _build_ui(self) -> None:
        self._build_header()
        _build_close_bar(self, self.destroy)

        notebook = ttk.Notebook(self)
        notebook.pack(
            fill="both", expand=True,
            padx=get_spacing("md"),
            pady=(get_spacing("md"), get_spacing("sm")),
        )
        notebook.add(self._build_info_tab(notebook), text=t("case_detail.tab_info"))
        notebook.add(self._build_files_tab(notebook), text=t("case_detail.tab_files"))
        notebook.add(self._build_history_tab(notebook), text=t("case_detail.tab_history"))
        notebook.add(self._build_artifacts_tab(notebook), text=t("case_detail.tab_artifacts"))

    # -- Header band -------------------------------------------------------

    def _build_header(self) -> None:
        record = self._detail.get("record", {})
        case_info = record.get("case_info", {})
        case_number = (
            case_info.get("case_number", record.get("case_number", "")) or "—"
        )
        kind, summary = _derive_status_kind(record)
        label_key, bg_token, fg_token = _BADGE_STYLE[kind]

        header_bg = get_color("header_bg")
        band = tk.Frame(self, bg=header_bg)
        band.pack(side="top", fill="x")

        inner = tk.Frame(band, bg=header_bg)
        inner.pack(fill="x", padx=get_spacing("lg"), pady=get_spacing("md"))

        left = tk.Frame(inner, bg=header_bg)
        left.pack(side="left", fill="x", expand=True)
        tk.Label(
            left,
            text=self._seal_id,
            font=get_font("header"),
            fg=get_color("header_fg"),
            bg=header_bg,
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            left,
            text=f"{t('case_detail.case_number')} · {case_number}",
            font=get_font("small"),
            fg=get_color("header_fg_muted"),
            bg=header_bg,
            anchor="w",
        ).pack(anchor="w")

        badge_text = f"{t(label_key)}  {summary}".strip()
        self._status_badge = tk.Label(
            inner,
            text=badge_text,
            font=get_font("badge"),
            bg=get_color(bg_token),
            fg=get_color(fg_token),
            padx=get_spacing("md"),
            pady=get_spacing("xs"),
        )
        self._status_badge.pack(side="right", padx=(get_spacing("md"), 0))

    # -- Tab 1: Basic info (SummaryView cards) ------------------------------

    def _build_info_tab(self, parent: tk.Widget) -> tk.Widget:
        record = self._detail.get("record", {})
        case_info = record.get("case_info", {})
        process_info = record.get("process_info", {})
        signer_info = record.get("signer_info", {})

        view = SummaryView(parent)
        sections: list[dict[str, Any]] = [
            {
                "title": t("case_detail.section_case"),
                "rows": [
                    (t("case_detail.seal_id"), self._seal_id),
                    (t("case_detail.case_number"),
                     case_info.get("case_number", record.get("case_number", ""))),
                    (t("case_detail.seizure_time"), case_info.get("seizure_time", "")),
                    (t("case_detail.seizure_location"), case_info.get("seizure_location", "")),
                    (t("case_detail.storage_type"), case_info.get("storage_type", "")),
                ],
            },
            {
                "title": t("case_detail.section_subject"),
                "rows": [
                    (t("case_detail.name"),
                     signer_info.get("name", case_info.get("suspect", ""))),
                    (t("case_detail.email"), signer_info.get("email", "")),
                    (t("case_detail.dob"), signer_info.get("birth_date", "")),
                    (t("case_detail.phone"), signer_info.get("phone", "")),
                ],
            },
            {
                "title": t("case_detail.section_investigator"),
                "rows": [
                    (t("case_detail.investigator"),
                     case_info.get("investigator", process_info.get("investigator", ""))),
                    (t("case_detail.process_type"),
                     process_info.get("type", record.get("type", ""))),
                    (t("case_detail.start_time"), process_info.get("start_time", "")),
                    (t("case_detail.end_time"), process_info.get("end_time", "")),
                    (t("case_detail.created_at"), self._detail.get("created_at", "") or ""),
                ],
            },
        ]
        view.render(sections)
        return view

    # -- Tab 2: File info (cards with copyable hashes) ----------------------

    def _build_files_tab(self, parent: tk.Widget) -> tk.Widget:
        record = self._detail.get("record", {})
        file_info = record.get("file_info", {}) or {}

        sf = ScrolledFrame(parent, bg=get_color("bg"))

        originals = file_info.get("original_files") or []
        results = file_info.get("result_files") or []

        if not originals and not results:
            if file_info:
                self._render_raw_json(sf.body, file_info)
            else:
                tk.Label(
                    sf.body,
                    text=t("case_detail.no_files"),
                    font=get_font("body"),
                    fg=get_color("text_secondary"),
                    bg=get_color("bg"),
                ).pack(pady=get_spacing("xl"))
            return sf

        hash_match = file_info.get("hash_match")
        badge: Optional[tuple[str, str]] = None
        if hash_match is True:
            badge = (t("case_detail.hash_match"), "success_text")
        elif hash_match is False:
            badge = (t("case_detail.hash_mismatch"), "danger_text")

        if originals:
            self._render_file_section(
                sf.body, t("case_detail.section_original_files"),
                originals, kind="original", badge=badge,
            )
        if results:
            self._render_file_section(
                sf.body, t("case_detail.section_result_files"),
                results, kind="result",
            )
        for extra_key, extra_title_key in (
            ("unknown_files", "case_detail.section_unknown_files"),
            ("derived_files", "case_detail.section_derived_files"),
        ):
            extras = file_info.get(extra_key) or []
            if extras:
                self._render_file_section(
                    sf.body, t(extra_title_key), extras, kind="plain",
                )
        return sf

    def _render_file_section(
        self,
        parent: tk.Widget,
        title: str,
        files: list[Any],
        *,
        kind: str,
        badge: Optional[tuple[str, str]] = None,
    ) -> None:
        card_bg = get_color("card_bg")
        card = _make_card(parent)
        inner = tk.Frame(
            card, bg=card_bg, padx=get_spacing("md"), pady=get_spacing("sm"),
        )
        inner.pack(fill="both", expand=True)

        title_row = tk.Frame(inner, bg=card_bg)
        title_row.pack(fill="x", pady=(0, get_spacing("xs")))
        tk.Label(
            title_row, text=title, font=get_font("subheader"),
            fg=get_color("heading"), bg=card_bg, anchor="w",
        ).pack(side="left")
        if badge:
            badge_text, badge_token = badge
            tk.Label(
                title_row,
                text=f"● {badge_text}",
                font=get_font("badge"),
                fg=get_color(badge_token),
                bg=card_bg,
            ).pack(side="right")

        for f in files:
            if not isinstance(f, dict):
                tk.Label(
                    inner, text=str(f), font=get_font("body"),
                    fg=get_color("text"), bg=card_bg, anchor="w",
                ).pack(anchor="w")
                continue

            filename = f.get("filename", f.get("name", ""))
            body_font = get_font("body")
            tk.Label(
                inner,
                text=str(filename),
                font=(body_font[0], body_font[1], "bold"),
                fg=get_color("text"),
                bg=card_bg,
                anchor="w",
            ).pack(anchor="w", pady=(get_spacing("xs"), 0))

            grid = tk.Frame(inner, bg=card_bg)
            grid.pack(fill="x", padx=(get_spacing("md"), 0))
            grid.grid_columnconfigure(1, weight=1)

            row = 0
            row = self._kv_row(
                grid, row, t("case_detail.file_size"),
                _format_size(f.get("size", 0)),
            )
            if kind == "original":
                for hash_label, hash_key in (("MD5", "md5"), ("SHA-256", "sha256")):
                    value = f.get(hash_key, "")
                    if value:
                        row = self._kv_row(
                            grid, row, hash_label, value, copyable=True,
                        )
                if f.get("mtime"):
                    row = self._kv_row(
                        grid, row, t("case_detail.file_mtime"), f["mtime"],
                    )
            elif kind == "result":
                if f.get("encryption_algo"):
                    row = self._kv_row(
                        grid, row, t("case_detail.enc_algo"),
                        f["encryption_algo"],
                    )
                if f.get("enc_ended_time"):
                    row = self._kv_row(
                        grid, row, t("case_detail.enc_ended"),
                        f["enc_ended_time"],
                    )

    def _kv_row(
        self,
        grid: tk.Frame,
        row: int,
        label: str,
        value: Any,
        *,
        copyable: bool = False,
    ) -> int:
        """Add one label/value row to a card grid; return the next row index.

        Copyable values render as readonly (selectable) mono entries with
        a full-value tooltip so long hashes can be copied.
        """
        card_bg = get_color("card_bg")
        tk.Label(
            grid, text=label, font=get_font("small"),
            fg=get_color("text_secondary"), bg=card_bg, anchor="nw",
        ).grid(row=row, column=0, sticky="nw",
               padx=(0, get_spacing("md")), pady=1)

        if copyable:
            entry = tk.Entry(
                grid,
                font=get_font("mono"),
                relief="flat",
                bd=0,
                highlightthickness=0,
                readonlybackground=card_bg,
                fg=get_color("text"),
                width=44,
            )
            entry.insert(0, str(value))
            entry.configure(state="readonly")
            entry.grid(row=row, column=1, sticky="ew", pady=1)
            ToolTip(entry, str(value))
            self._hash_entries.append(entry)
        else:
            tk.Label(
                grid,
                text=str(value),
                font=get_font("body"),
                fg=get_color("text"),
                bg=card_bg,
                anchor="nw",
                justify="left",
                wraplength=SummaryView.VALUE_WRAP,
            ).grid(row=row, column=1, sticky="nw", pady=1)
        return row + 1

    def _render_raw_json(self, parent: tk.Widget, data: dict[str, Any]) -> None:
        """Fallback: render unrecognized file_info as readonly JSON text."""
        card = _make_card(parent)
        text = tk.Text(
            card,
            wrap="word",
            font=get_font("mono"),
            bg=get_color("card_bg"),
            fg=get_color("text"),
            relief="flat",
            bd=0,
            highlightthickness=0,
            padx=get_spacing("md"),
            pady=get_spacing("sm"),
            height=18,
        )
        text.insert("1.0", json.dumps(data, ensure_ascii=False, indent=2))
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)

    # -- Tab 3: History timeline --------------------------------------------

    def _build_history_tab(self, parent: tk.Widget) -> tk.Widget:
        record = self._detail.get("record", {})
        history = record.get("history", {})

        events: list[dict[str, Any]]
        if isinstance(history, dict):
            events = list(history.get("events", []))
        elif isinstance(history, list):
            events = list(history)
        else:
            events = []

        sf = ScrolledFrame(parent, bg=get_color("bg"))
        _populate_history(sf.body, events)
        return sf

    # -- Tab 4: Artifacts -----------------------------------------------------

    def _build_artifacts_tab(self, parent: tk.Widget) -> tk.Frame:
        frame = tk.Frame(
            parent, bg=get_color("bg"),
            padx=get_spacing("sm"), pady=get_spacing("sm"),
        )
        try:
            from desktop.db import get_case_artifacts
            artifacts = get_case_artifacts(self._db_path, self._seal_id)
        except Exception:
            artifacts = []

        tree = _create_artifact_tree(frame, artifacts)
        self._artifacts_tree = tree
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return frame


# ---------------------------------------------------------------------------
# ArtifactsWindow -- standalone artifact viewer
# ---------------------------------------------------------------------------

class ArtifactsWindow(tk.Toplevel):
    """Standalone window listing artifacts for a case."""

    BASE_MIN_WIDTH = 680
    BASE_MIN_HEIGHT = 360

    def __init__(self, parent: tk.Widget, db_path: str, seal_id: str) -> None:
        super().__init__(parent)
        self.withdraw()
        self.title(f"{t('case_detail.tab_artifacts')} — {seal_id}")
        self.configure(bg=get_color("bg"))
        self.transient(parent.winfo_toplevel())

        try:
            from desktop.db import get_case_artifacts
            artifacts = get_case_artifacts(db_path, seal_id)
        except Exception:
            artifacts = []

        self._build(artifacts)
        _fit_window_to_content(
            self,
            base_min_w=self.BASE_MIN_WIDTH,
            base_min_h=self.BASE_MIN_HEIGHT,
        )
        self.deiconify()
        self.bind("<Escape>", lambda _e: self.destroy())
        try:
            self.grab_set()
        except tk.TclError:
            pass

    def _build(self, artifacts: list[dict[str, Any]]) -> None:
        _build_close_bar(self, self.destroy)

        frame = tk.Frame(self, bg=get_color("bg"))
        frame.pack(
            fill="both", expand=True,
            padx=get_spacing("md"),
            pady=(get_spacing("md"), get_spacing("sm")),
        )
        tree = _create_artifact_tree(frame, artifacts)
        self._artifacts_tree = tree
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")


# ---------------------------------------------------------------------------
# HistoryWindow -- standalone history timeline
# ---------------------------------------------------------------------------

class HistoryWindow(tk.Toplevel):
    """Standalone window showing case history timeline."""

    BASE_MIN_WIDTH = 620
    BASE_MIN_HEIGHT = 420

    def __init__(self, parent: tk.Widget, db_path: str, seal_id: str) -> None:
        super().__init__(parent)
        self.withdraw()
        self.title(f"{t('case_detail.tab_history')} — {seal_id}")
        self.configure(bg=get_color("bg"))
        self.transient(parent.winfo_toplevel())

        try:
            from desktop.db import get_case_history
            events = get_case_history(db_path, seal_id)
        except Exception:
            events = []

        self._build(events)
        _fit_window_to_content(
            self,
            base_min_w=self.BASE_MIN_WIDTH,
            base_min_h=self.BASE_MIN_HEIGHT,
        )
        self.deiconify()
        self.bind("<Escape>", lambda _e: self.destroy())
        try:
            self.grab_set()
        except tk.TclError:
            pass

    def _build(self, events: list[dict[str, Any]]) -> None:
        _build_close_bar(self, self.destroy)

        sf = ScrolledFrame(self, bg=get_color("bg"))
        sf.pack(
            fill="both", expand=True,
            padx=get_spacing("md"),
            pady=(get_spacing("md"), get_spacing("sm")),
        )
        _populate_history(sf.body, events)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_size(size_bytes: int) -> str:
    if size_bytes == 0:
        return "-"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def _open_selected_file(tree: ttk.Treeview) -> None:
    selection = tree.selection()
    if not selection:
        return
    values = tree.item(selection[0], "values")
    if not values or len(values) < 4:
        return
    file_path = values[3]
    if not file_path or not os.path.exists(file_path):
        messagebox.showwarning(t("common.warning"), f"{t('artifact.file_not_found')}:\n{file_path}")
        return
    try:
        os.startfile(file_path)
    except Exception as exc:
        messagebox.showerror(t("common.error"), f"{exc}")


def _show_context_menu(event: tk.Event, tree: ttk.Treeview) -> None:
    """Show right-click context menu for artifact treeview."""
    iid = tree.identify_row(event.y)
    if not iid:
        return
    tree.selection_set(iid)
    values = tree.item(iid, "values")
    if not values or len(values) < 4:
        return
    file_path = values[3]

    menu = tk.Menu(tree, tearoff=0)
    menu.add_command(
        label=t("artifact.open"),
        command=lambda: _try_open(file_path),
    )
    menu.add_command(
        label=t("artifact.open_folder"),
        command=lambda: _try_open_folder(file_path),
    )
    menu.add_command(
        label=t("artifact.copy_path"),
        command=lambda: _copy_to_clipboard(tree, file_path),
    )
    menu.tk_popup(event.x_root, event.y_root)


def _try_open(path: str) -> None:
    if os.path.exists(path):
        try:
            os.startfile(path)
        except Exception as exc:
            messagebox.showerror(t("common.error"), f"{exc}")
    else:
        messagebox.showwarning(t("common.warning"), f"{t('artifact.file_not_found')}: {path}")


def _try_open_folder(path: str) -> None:
    folder = os.path.dirname(path)
    if os.path.isdir(folder):
        try:
            os.startfile(folder)
        except Exception as exc:
            messagebox.showerror(t("common.error"), f"{exc}")
    else:
        messagebox.showwarning(t("common.warning"), f"{t('artifact.folder_not_found')}: {folder}")


def _copy_to_clipboard(widget: tk.Widget, text: str) -> None:
    widget.clipboard_clear()
    widget.clipboard_append(text)
    # update_idletasks() flushes the clipboard without re-entering the
    # event loop (update() risks re-entrancy during event handling)
    widget.update_idletasks()
