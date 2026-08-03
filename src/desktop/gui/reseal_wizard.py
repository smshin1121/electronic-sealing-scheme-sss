"""Reseal process wizard (R1 through R8).

Guides the investigator through the complete resealing workflow:
R1 - Load previous unseal record JSON
R2 - File comparison results (known / unknown files)
R3 - Unknown file classification UI
R4 - Reseal info input (investigator, reason, participation)
R5 - Encryption progress
R6 - Reseal record preview
R7 - Key split results + unlock_time setting
R8 - Completion summary
"""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from datetime import datetime, timedelta, timezone
from tkinter import messagebox
from typing import TYPE_CHECKING, Any, Callable, Optional

from .i18n import t
from .progress_dialog import run_async
from .step_indicator import StepIndicator
from .theme import FONTS, get_color, get_font
from .widgets import (
    FileSelector,
    LabeledEntry,
    ScrolledFrame,
    SummaryView,
    is_return_navigation_safe,
)

if TYPE_CHECKING:
    from .app import MainApp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MIN_UNLOCK_DAYS = 1
MAX_UNLOCK_DAYS = 30
DEFAULT_UNLOCK_DAYS = 10
MIN_CHUNK_GB = 1
MAX_CHUNK_GB = 64
# 1 GiB default — matches the sealing wizard and the paper's recommendation.
DEFAULT_CHUNK_GB = 1


class ResealWizard(tk.Frame):
    """Multi-step wizard for the resealing process.

    Each step is built as a separate frame.  Navigation buttons
    (이전 / 다음) control the visible frame.
    """

    TOTAL_STEPS = 8

    def __init__(
        self,
        master: tk.Widget,
        app: MainApp,
        *,
        on_complete: Optional[Callable[[dict[str, Any]], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
        prefill_data: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(master)
        self._app = app
        self._on_complete = on_complete
        self._on_cancel = on_cancel
        self._prefill_data = prefill_data
        self._current_step = 0
        self._data: dict[str, Any] = {}
        self._busy = False
        self._r2_running = False
        self._r2_error = ""
        self._record_task_running = False
        # Set on destroy so pending run_async results are discarded.
        self._async_cancel = threading.Event()
        # Active ProgressDialog (encryption) — joined before cleanup.
        self._active_dialog: Optional[Any] = None

        self._steps: list[tk.Frame] = []
        self._validators: list[Callable[[], bool]] = []

        self._build_layout()
        self._build_steps()
        self._apply_prefill()
        self._show_step(0)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        """Create the outer layout: header, step indicator, content area, nav bar."""
        # Header — process-colored banner (theme token)
        header_bg = get_color("wizard_header_reseal")
        self._header = tk.Frame(self, bg=header_bg, height=56)
        self._header.pack(fill="x")
        self._header.pack_propagate(False)

        self._title_label = tk.Label(
            self._header,
            text=t("reseal.title"),
            fg=get_color("header_fg"),
            bg=header_bg,
            font=get_font("title"),
        )
        self._title_label.pack(side="left", padx=16)
        self._step_label = tk.Label(
            self._header,
            text="",
            fg=get_color("header_fg_muted"),
            bg=header_bg,
            font=get_font("body"),
        )
        self._step_label.pack(side="right", padx=16)

        # Step indicator with subtle background
        step_bg_frame = tk.Frame(self, bg=get_color("step_bg"))
        step_bg_frame.pack(fill="x")
        self._step_indicator = StepIndicator(step_bg_frame, steps=[
            t("reseal.step1"), t("reseal.step2"), t("reseal.step3"),
            t("reseal.step4"), t("reseal.step5"), t("reseal.step6"),
            t("reseal.step7"), t("reseal.step8"),
        ], on_step_click=self._on_step_click, bg=get_color("step_bg"))
        self._step_indicator.pack(fill="x", padx=16, pady=(8, 4))

        # Navigation bar — pack BEFORE content so it always gets space allocated.
        nav = tk.Frame(self, bg=get_color("card_bg"))
        nav.pack(fill="x", side="bottom")
        nav_border = tk.Frame(nav, height=1, bg=get_color("border"))
        nav_border.pack(fill="x", side="top")
        nav_inner = tk.Frame(nav, bg=get_color("card_bg"), padx=16, pady=8)
        nav_inner.pack(fill="x")

        # Cancel button — danger ghost
        self._cancel_btn = tk.Button(
            nav_inner, text=t("common.cancel"), width=12,
            command=self._handle_cancel,
            fg=get_color("danger"),
            bg=get_color("card_bg"),
            activebackground=get_color("error_bg"),
            activeforeground=get_color("danger"),
            relief="solid",
            bd=1,
            font=get_font("button"),
            padx=12, pady=6,
        )
        self._cancel_btn.pack(side="left")

        # Inline validation / busy message
        self._nav_msg_label = tk.Label(
            nav_inner,
            text="",
            fg=get_color("danger_text"),
            bg=get_color("card_bg"),
            font=get_font("small"),
            anchor="w",
        )
        self._nav_msg_label.pack(side="left", padx=(12, 0))

        # Next button — prominent purple
        self._next_btn = tk.Button(
            nav_inner, text=t("common.next"), width=12,
            command=self._go_next,
            fg=get_color("text_light"),
            bg=get_color("primary"),
            activebackground=get_color("primary_hover"),
            activeforeground=get_color("text_light"),
            relief="flat",
            font=(FONTS["button"][0], FONTS["button"][1] + 2, "bold"),
            padx=16, pady=6,
        )
        self._next_btn.pack(side="right")

        # Prev button — ghost style
        self._prev_btn = tk.Button(
            nav_inner, text=t("common.prev"), width=12,
            command=self._go_prev,
            fg=get_color("primary"),
            bg=get_color("card_bg"),
            activebackground=get_color("hover"),
            activeforeground=get_color("primary"),
            relief="solid",
            bd=1,
            font=get_font("button"),
            padx=12, pady=6,
        )
        self._prev_btn.pack(side="right", padx=(0, 8))

        # Content area — page background (packed AFTER nav so nav is guaranteed space)
        self._content = tk.Frame(self, bg=get_color("bg"), padx=24, pady=16)
        self._content.pack(fill="both", expand=True)

        # Keyboard shortcuts — save previous bindings and restore them
        # on destroy so no stale callbacks remain on the toplevel.
        top = self.winfo_toplevel()
        self._bound_toplevel = top
        self._saved_return_binding = top.bind("<Return>")
        self._saved_escape_binding = top.bind("<Escape>")
        self._return_funcid = top.bind("<Return>", self._on_return_key)
        self._escape_funcid = top.bind("<Escape>", self._on_escape_key)
        self.bind("<Destroy>", self._on_destroy, add="+")

    def _on_destroy(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if event.widget is not self:
            return
        self._async_cancel.set()
        self._cleanup_partial_encryption()
        try:
            top = self._bound_toplevel
            if top.winfo_exists():
                # 자신이 설치한 바인딩일 때만 복원 — 새 위자드가 이미
                # 자신의 바인딩을 설치했다면 덮어쓰지 않는다.
                current = top.bind("<Return>") or ""
                if self._return_funcid and self._return_funcid in current:
                    top.bind("<Return>", self._saved_return_binding or "")
                current = top.bind("<Escape>") or ""
                if self._escape_funcid and self._escape_funcid in current:
                    top.bind("<Escape>", self._saved_escape_binding or "")
        except tk.TclError:
            pass

    def _cleanup_partial_encryption(self) -> None:
        """Remove partial .enc / .enc.progress left by an unfinished R5 run.

        Called when the wizard is destroyed before encryption completed.
        The session AES 키가 소실되는 시점이므로 부분 산출물은 resume이
        불가능하다. 완료된 암호화(``encrypt_done``)는 절대 건드리지
        않으며, 삭제 실패는 로그만 남긴다.

        삭제 전에 암호화 워커 스레드에 취소를 보내고 종료를 기다린다 —
        워커가 파일을 열어 둔 채 삭제하면 Windows 공유 위반이 나거나,
        삭제 직후 워커가 파일을 다시 만들 수 있기 때문이다.
        """
        import os
        if self._data.get("encrypt_done"):
            return
        process = self._data.get("_process")
        if process is None:
            return

        dlg = self._active_dialog
        if dlg is not None and not dlg.cancel_and_join(timeout=5.0):
            logger.warning(
                "암호화 워커 종료 대기 실패 — 부분 산출물 삭제를 건너뜁니다."
            )
            return

        pending = process.state.get("r5_pending_enc_paths", [])
        for enc_path in pending:
            for path in (enc_path, enc_path + ".progress"):
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except OSError as exc:
                    logger.warning(
                        "부분 암호화 산출물 삭제 실패: %s (%s)", path, exc
                    )

    def _set_nav_message(self, text: str, *, kind: str = "error") -> None:
        color = get_color("danger_text") if kind == "error" else get_color("text_secondary")
        try:
            self._nav_msg_label.configure(text=text, fg=color)
        except tk.TclError:
            pass

    def _set_busy(self, busy: bool, message: str = "") -> None:
        """Toggle a background-work state: nav disabled + status message."""
        self._busy = busy
        state = "disabled" if busy else "normal"
        try:
            self._next_btn.configure(state=state)
            self._cancel_btn.configure(state=state)
            if busy:
                self._prev_btn.configure(state="disabled")
                self._set_nav_message(message, kind="info")
            else:
                self._set_nav_message("")
                if self._current_step > 0 and not (
                    self._current_step >= 4 and self._data.get("encrypt_done")
                ):
                    self._prev_btn.configure(state="normal")
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Step builders
    # ------------------------------------------------------------------

    def _build_steps(self) -> None:
        """Build all 8 step frames (form steps get a shared scroll container)."""
        plans: list[tuple[Callable[[tk.Frame], None], bool]] = [
            (self._build_r1, True),
            (self._build_r2, True),
            (self._build_r3, False),   # has its own scrolling canvas
            (self._build_r4, True),
            (self._build_r5, False),
            (self._build_r6, False),   # SummaryView scrolls internally
            (self._build_r7, True),
            (self._build_r8, False),   # SummaryView scrolls internally
        ]
        for builder, wrap in plans:
            if wrap:
                holder = ScrolledFrame(self._content, bg=get_color("bg"))
                builder(holder.body)
                self._steps.append(holder)
            else:
                frame = tk.Frame(self._content, bg=get_color("bg"))
                builder(frame)
                self._steps.append(frame)

    def _apply_prefill(self) -> None:
        """Apply prefill data from case workflow to R1 fields."""
        pf = self._prefill_data
        if not pf:
            return

        # Previous unseal record JSON path (derived from pdf_path)
        pdf_path = pf.get("pdf_path", "")
        seal_id = pf.get("seal_id", "")
        if pdf_path and seal_id and hasattr(self, "_prev_record_selector"):
            # The unseal record JSON is typically at:
            # <dir>/<seal_id>_record.json
            record_json_path = pf.get("record_json_path", "")
            if record_json_path:
                self._prev_record_selector.set(record_json_path)

        if seal_id:
            self._data["seal_id"] = seal_id

    # --- R1: Load previous record ----------------------------------------

    def _build_r1(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("reseal.r1_title"),
            font=get_font("subheader"),
        ).pack(anchor="w", pady=(0, 12))

        self._prev_record_selector = FileSelector(
            parent,
            t("reseal.prev_record"),
            required=True,
            filetypes=[
                (t("filedialog.json_files"), "*.json"),
                (t("filedialog.all_files"), "*.*"),
            ],
        )
        self._prev_record_selector.pack(fill="x", pady=4)

        # Target directory for resealing
        self._target_dir_selector = FileSelector(
            parent,
            t("reseal.target_dir"),
            select_dir=True,
            required=True,
        )
        self._target_dir_selector.pack(fill="x", pady=4)

        # Output directory
        self._output_dir_selector = FileSelector(
            parent,
            t("reseal.output_dir"),
            select_dir=True,
            required=True,
        )
        self._output_dir_selector.pack(fill="x", pady=4)

        # Preview area for loaded record
        tk.Label(
            parent,
            text=t("reseal.loaded_info"),
            font=get_font("stat_label"),
        ).pack(anchor="w", pady=(12, 4))

        self._r1_info = tk.Text(
            parent,
            wrap="word",
            state="disabled",
            font=get_font("caption"),
            bg=get_color("card_bg"),
            fg=get_color("text"),
            relief="solid",
            bd=1,
            highlightthickness=0,
            height=10,
        )
        self._r1_info.pack(fill="both", expand=True, pady=4)

        self._validators.append(self._validate_r1)

    def _validate_r1(self) -> bool:
        error_count = 0
        focus_target: Optional[FileSelector] = None

        if not self._prev_record_selector.is_valid():
            self._prev_record_selector.highlight_error(t("validate.prev_record"))
            error_count += 1
            focus_target = focus_target or self._prev_record_selector
        else:
            self._prev_record_selector.clear_error()

        if not self._target_dir_selector.is_valid():
            self._target_dir_selector.highlight_error(t("validate.target_dir"))
            error_count += 1
            focus_target = focus_target or self._target_dir_selector
        else:
            self._target_dir_selector.clear_error()

        if not self._output_dir_selector.is_valid():
            self._output_dir_selector.highlight_error(t("validate.select_output"))
            error_count += 1
            focus_target = focus_target or self._output_dir_selector
        else:
            self._output_dir_selector.clear_error()

        if error_count:
            self._set_nav_message(
                t("validate.fix_errors").format(count=error_count)
            )
            if focus_target is not None:
                focus_target.focus_field()
            return False

        self._set_nav_message("")

        # Load and validate via process
        try:
            from ..reseal_process import ResealProcess

            process = ResealProcess(db_path=self._app.db_path)
            record_path = self._prev_record_selector.get()
            result = process.run_r1_load(record_path)

            self._data["_process"] = process
            self._data["prev_record"] = result["prev_record"]
            self._data["seal_id"] = result["seal_id"]
            self._data["target_dir"] = self._target_dir_selector.get()
            self._data["output_dir"] = self._output_dir_selector.get()

            # Show loaded info
            self._show_r1_info(result["prev_record"])
            return True

        except Exception as exc:
            messagebox.showerror(
                t("reseal.record_error"), str(exc), parent=self.winfo_toplevel()
            )
            return False

    def _show_r1_info(self, record: dict[str, Any]) -> None:
        """Display loaded record summary."""
        self._r1_info.configure(state="normal")
        self._r1_info.delete("1.0", "end")
        lines = [
            f"  Seal ID: {record.get('seal_id', 'N/A')}",
            t("reseal.record_info_type").format(v=record.get('type', 'N/A')),
            t("reseal.record_info_case").format(v=record.get('case_number', 'N/A')),
            t("reseal.record_info_created").format(v=record.get('created_at', 'N/A')),
            f"  Summary: {record.get('summary', 'N/A')}",
        ]
        self._r1_info.insert("1.0", "\n".join(lines))
        self._r1_info.configure(state="disabled")

    # --- R2: File comparison results -------------------------------------

    def _build_r2(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("reseal.r2_title"),
            font=get_font("subheader"),
        ).pack(anchor="w", pady=(0, 12))

        # Known files section
        tk.Label(
            parent, text=t("reseal.known_files"), font=get_font("stat_label")
        ).pack(anchor="w", pady=(4, 2))

        self._r2_known_list = tk.Listbox(parent, height=6, font=get_font("caption"))
        self._r2_known_list.pack(fill="x", pady=2)

        # Unknown files section
        tk.Label(
            parent,
            text=t("reseal.unknown_files"),
            font=get_font("stat_label"),
            fg=get_color("danger_text"),
        ).pack(anchor="w", pady=(8, 2))

        self._r2_unknown_list = tk.Listbox(
            parent, height=6, font=get_font("caption")
        )
        self._r2_unknown_list.pack(fill="x", pady=2)

        self._r2_summary_label = tk.Label(
            parent, text="", anchor="w", font=get_font("caption")
        )
        self._r2_summary_label.pack(fill="x", pady=4)

        self._validators.append(self._validate_r2)

    def _validate_r2(self) -> bool:
        """R2 passes once the comparison finished WITHOUT an error.

        A failed comparison must never pass as an empty success — the
        error is shown, progress is blocked, and pressing 다음 retries.
        """
        if self._r2_running:
            return False
        if self._r2_error:
            self._set_nav_message(
                t("unseal.error_occurred").format(v=self._r2_error)
            )
            self._refresh_r2()  # retry on next attempt
            return False
        return True

    def _refresh_r2(self) -> None:
        """Run the file comparison on a worker thread and display results.

        Directory hashing can take a long time on large evidence sets —
        it must not run on the Tk main thread.
        """
        process = self._data.get("_process")
        if process is None:
            return
        if self._r2_running:
            return

        self._r2_running = True
        self._r2_error = ""
        self._r2_known_list.delete(0, "end")
        self._r2_unknown_list.delete(0, "end")
        self._r2_summary_label.configure(text=t("reseal.comparing"))
        self._set_busy(True, t("reseal.comparing"))

        target_dir = self._data.get("target_dir", "")

        def _task():  # type: ignore[no-untyped-def]
            return process.run_r2_compare(target_dir)

        def _ok(result):  # type: ignore[no-untyped-def]
            self._r2_running = False
            self._r2_error = ""
            self._data["known_files"] = result["known_files"]
            self._data["unknown_files"] = result["unknown_files"]
            self._populate_r2_lists()
            self._set_busy(False)

        def _err(exc: Exception) -> None:
            # 비교 실패를 "파일 0건" 성공으로 위장하지 않는다.
            self._r2_running = False
            self._r2_error = str(exc)
            logger.warning("R2 파일 비교 오류: %s", exc)
            self._r2_summary_label.configure(
                text=t("unseal.error_occurred").format(v=exc),
                fg=get_color("danger_text"),
            )
            self._set_busy(False)
            self._set_nav_message(t("unseal.error_occurred").format(v=exc))

        run_async(self, _task, _ok, _err, cancel_event=self._async_cancel)

    def _populate_r2_lists(self) -> None:
        """Fill the R2 listboxes from collected comparison data."""
        self._r2_known_list.delete(0, "end")
        for kf in self._data.get("known_files", []):
            name = kf.get("filename", "")
            size = kf.get("size", 0)
            self._r2_known_list.insert("end", f"{name}  ({size:,} bytes)")

        self._r2_unknown_list.delete(0, "end")
        for uf in self._data.get("unknown_files", []):
            name = uf.get("filename", "")
            size = uf.get("size", 0)
            cat = uf.get("suggested_category", "")
            self._r2_unknown_list.insert(
                "end", f"{name}  ({size:,} bytes) [{cat}]"
            )

        known_count = len(self._data.get("known_files", []))
        unknown_count = len(self._data.get("unknown_files", []))
        self._r2_summary_label.configure(
            text=t("reseal.file_summary").format(known=known_count, unknown=unknown_count)
        )

    # --- R3: Unknown file classification ---------------------------------

    def _build_r3(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("reseal.r3_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 8))

        tk.Label(
            parent,
            text=t("reseal.r3_guide"),
            font=get_font("caption"),
            bg=get_color("bg"),
            fg=get_color("text_secondary"),
        ).pack(anchor="w", pady=(0, 8))

        # Scrollable classification area
        self._r3_canvas = tk.Canvas(parent, height=280, bg=get_color("bg"),
                                    highlightthickness=0)
        self._r3_scrollbar = tk.Scrollbar(
            parent, orient="vertical", command=self._r3_canvas.yview
        )
        self._r3_inner_frame = tk.Frame(self._r3_canvas, bg=get_color("bg"))

        self._r3_inner_frame.bind(
            "<Configure>",
            lambda e: self._r3_canvas.configure(
                scrollregion=self._r3_canvas.bbox("all")
            ),
        )
        self._r3_canvas.create_window(
            (0, 0), window=self._r3_inner_frame, anchor="nw"
        )
        self._r3_canvas.configure(yscrollcommand=self._r3_scrollbar.set)

        self._r3_scrollbar.pack(side="right", fill="y")
        self._r3_canvas.pack(fill="both", expand=True)

        # Classification entries will be built dynamically
        self._r3_entries: list[dict[str, Any]] = []

        self._r3_status_label = tk.Label(
            parent, text="", anchor="w", fg=get_color("danger_text"),
            bg=get_color("bg"), font=get_font("small"),
        )
        self._r3_status_label.pack(fill="x", pady=4)

        self._validators.append(self._validate_r3)

    def _validate_r3(self) -> bool:
        """All unknown files must be classified before proceeding."""
        unknown_files = self._data.get("unknown_files", [])
        if not unknown_files:
            return True

        unclassified = 0
        classifications = []

        for entry in self._r3_entries:
            classification = entry["class_var"].get()
            if not classification:
                unclassified += 1
                continue

            info: dict[str, Any] = {
                "filepath": entry["filepath"],
                "filename": entry["filename"],
                "size": entry["size"],
                "sha256": entry["sha256"],
                "classification": classification,
                "parent_file": "",
                "derivation_reason": "",
            }

            if classification == "derived":
                parent = entry["parent_var"].get().strip()
                reason = entry["reason_var"].get().strip()
                if not parent:
                    unclassified += 1
                    continue
                info["parent_file"] = parent
                info["derivation_reason"] = reason

            classifications.append(info)

        if unclassified > 0:
            msg = t("validate.classification_incomplete").format(count=unclassified)
            self._r3_status_label.configure(text=msg)
            self._set_nav_message(msg)
            return False

        # Store classifications via process
        process = self._data.get("_process")
        if process is not None:
            try:
                from ..reseal_process import UnknownFileInfo

                classified = [
                    UnknownFileInfo(
                        filepath=c["filepath"],
                        filename=c["filename"],
                        size=c["size"],
                        sha256=c["sha256"],
                        suggested_category="",
                        classification=c["classification"],
                        parent_file=c.get("parent_file", ""),
                        derivation_reason=c.get("derivation_reason", ""),
                    )
                    for c in classifications
                ]
                process.set_r3_classifications(classified)
            except Exception as exc:
                logger.warning("R3 분류 저장 오류: %s", exc)

        self._data["classifications"] = classifications
        self._r3_status_label.configure(text="")
        self._set_nav_message("")
        return True

    def _refresh_r3(self) -> None:
        """Build classification UI for each unknown file."""
        # Clear existing entries
        for widget in self._r3_inner_frame.winfo_children():
            widget.destroy()
        self._r3_entries.clear()

        unknown_files = self._data.get("unknown_files", [])

        if not unknown_files:
            tk.Label(
                self._r3_inner_frame,
                text=t("reseal.r3_no_unknown"),
                font=get_font("small"),
                bg=get_color("bg"),
            ).pack(pady=20)
            return

        for idx, uf in enumerate(unknown_files):
            entry_frame = tk.LabelFrame(
                self._r3_inner_frame,
                text=f"[{idx + 1}] {uf.get('filename', '')}",
                font=get_font("badge"),
                padx=8,
                pady=4,
            )
            entry_frame.pack(fill="x", pady=4, padx=4)

            # File info
            size = uf.get("size", 0)
            cat = uf.get("suggested_category", "uncategorized")
            tk.Label(
                entry_frame,
                text=t("reseal.file_size_cat").format(size=f"{size:,}", cat=cat),
                font=get_font("caption"),
                fg=get_color("text_secondary"),
            ).pack(anchor="w")

            # Classification radio buttons
            class_var = tk.StringVar(value="")
            radio_frame = tk.Frame(entry_frame)
            radio_frame.pack(fill="x", pady=2)

            tk.Radiobutton(
                radio_frame,
                text=t("reseal.derived"),
                variable=class_var,
                value="derived",
            ).pack(side="left")
            tk.Radiobutton(
                radio_frame,
                text=t("reseal.excluded"),
                variable=class_var,
                value="excluded",
            ).pack(side="left", padx=16)

            # Derived file details (parent + reason)
            detail_frame = tk.Frame(entry_frame)
            detail_frame.pack(fill="x", pady=2)
            detail_frame.grid_columnconfigure(1, weight=1)
            detail_frame.grid_columnconfigure(3, weight=1)

            parent_var = tk.StringVar()
            tk.Label(detail_frame, text=t("reseal.parent_file"), width=10, anchor="w").grid(
                row=0, column=0, sticky="w"
            )
            parent_entry = tk.Entry(
                detail_frame, textvariable=parent_var, width=24
            )
            parent_entry.grid(row=0, column=1, sticky="ew", padx=4)

            reason_var = tk.StringVar()
            tk.Label(detail_frame, text=t("reseal.derivation_reason"), width=10, anchor="w").grid(
                row=0, column=2, sticky="w"
            )
            reason_entry = tk.Entry(
                detail_frame, textvariable=reason_var, width=24
            )
            reason_entry.grid(row=0, column=3, sticky="ew", padx=4)

            self._r3_entries.append(
                {
                    "filepath": uf.get("filepath", ""),
                    "filename": uf.get("filename", ""),
                    "size": size,
                    "sha256": uf.get("sha256", ""),
                    "class_var": class_var,
                    "parent_var": parent_var,
                    "reason_var": reason_var,
                }
            )

    # --- R4: Reseal info input -------------------------------------------

    def _build_r4(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("reseal.r4_title"),
            font=get_font("subheader"),
        ).pack(anchor="w", pady=(0, 12))

        self._r4_investigator = LabeledEntry(
            parent, t("reseal.investigator"), required=True
        )
        self._r4_investigator.pack(fill="x", pady=4)

        self._r4_reason = LabeledEntry(parent, t("reseal.reason"), required=True)
        self._r4_reason.pack(fill="x", pady=4)

        participation_frame = tk.Frame(parent)
        participation_frame.pack(fill="x", pady=8)
        tk.Label(
            participation_frame, text=t("reseal.participation"), anchor="w", width=20
        ).pack(side="left")
        self._r4_participation_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            participation_frame,
            text=t("reseal.participate"),
            variable=self._r4_participation_var,
        ).pack(side="left")

        # Chunk size
        chunk_frame = tk.Frame(parent)
        chunk_frame.pack(fill="x", pady=8)
        tk.Label(
            chunk_frame, text=f"* {t('reseal.chunk_size')}", anchor="w", width=20
        ).pack(side="left")
        self._r4_chunk_var = tk.IntVar(value=DEFAULT_CHUNK_GB)
        self._r4_chunk_spin = tk.Spinbox(
            chunk_frame,
            from_=MIN_CHUNK_GB,
            to=MAX_CHUNK_GB,
            textvariable=self._r4_chunk_var,
            width=6,
        )
        self._r4_chunk_spin.pack(side="left")
        tk.Label(chunk_frame, text=f"GB ({MIN_CHUNK_GB}~{MAX_CHUNK_GB})").pack(
            side="left", padx=8
        )

        self._validators.append(self._validate_r4)

    def _validate_r4(self) -> bool:
        error_count = 0
        focus_target: Optional[Any] = None

        if not self._r4_investigator.is_valid():
            self._r4_investigator.highlight_error(t("validate.investigator_required"))
            error_count += 1
            focus_target = focus_target or self._r4_investigator
        else:
            self._r4_investigator.clear_error()

        if not self._r4_reason.is_valid():
            self._r4_reason.highlight_error(t("validate.reseal_reason"))
            error_count += 1
            focus_target = focus_target or self._r4_reason
        else:
            self._r4_reason.clear_error()

        chunk_msg = ""
        try:
            chunk = self._r4_chunk_var.get()
            if not (MIN_CHUNK_GB <= chunk <= MAX_CHUNK_GB):
                chunk_msg = t("validate.chunk_range").format(
                    min=MIN_CHUNK_GB, max=MAX_CHUNK_GB
                )
        except (tk.TclError, ValueError):
            chunk_msg = t("validate.chunk_invalid")
        if chunk_msg:
            error_count += 1
            if focus_target is None:
                self._r4_chunk_spin.focus_set()

        if error_count:
            summary = chunk_msg if (chunk_msg and error_count == 1) else t(
                "validate.fix_errors"
            ).format(count=error_count)
            self._set_nav_message(summary)
            if focus_target is not None:
                focus_target.focus_field()
            return False

        self._set_nav_message("")
        self._data["investigator"] = self._r4_investigator.get()
        self._data["reason"] = self._r4_reason.get()
        self._data["subject_participated"] = self._r4_participation_var.get()
        self._data["chunk_size_gb"] = self._r4_chunk_var.get()

        # Set process config
        process = self._data.get("_process")
        if process is not None:
            try:
                from ..reseal_process import ResealConfig

                config = ResealConfig(
                    source_dir=self._data["target_dir"],
                    output_dir=self._data["output_dir"],
                    chunk_size_bytes=self._data["chunk_size_gb"] * (1024 ** 3),
                    investigator=self._data["investigator"],
                    reason=self._data["reason"],
                    subject_participated=self._data["subject_participated"],
                    unlock_days=self._data.get("unlock_days", 10),
                )
                process.set_config(config)
            except Exception as exc:
                logger.warning("R4 config 설정 오류: %s", exc)

        return True

    # --- R5: Encryption progress -----------------------------------------

    def _build_r5(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("reseal.r5_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._r5_status = tk.Text(
            parent,
            wrap="word",
            state="disabled",
            font=get_font("caption"),
            bg=get_color("card_bg"),
            fg=get_color("text"),
            relief="solid",
            bd=1,
            highlightthickness=0,
            height=16,
        )
        self._r5_status.pack(fill="both", expand=True, pady=4)

        self._r5_progress_label = tk.Label(
            parent, text=t("reseal.r5_waiting"), anchor="w",
            bg=get_color("bg"), fg=get_color("text_secondary"),
            font=get_font("small"),
        )
        self._r5_progress_label.pack(fill="x", pady=4)

        self._validators.append(self._validate_r5)

    def _validate_r5(self) -> bool:
        """R5 proceeds after encryption AND record generation complete.

        A failed record generation blocks progress; pressing 다음 again
        retries the generation instead of silently passing.
        """
        if not self._data.get("encrypt_done"):
            return False
        if self._data.get("record_done"):
            return True
        # Record generation failed or has not run — retry, block for now.
        if not self._record_task_running:
            self._ensure_r6_record()
        return False

    def _start_r5_encryption(self) -> None:
        """Launch encryption using ProgressDialog."""
        if self._data.get("encrypt_done"):
            self._ensure_r6_record()
            return

        process = self._data.get("_process")
        if process is None:
            self._update_r5_status(t("reseal.process_not_init"))
            return

        from .progress_dialog import ProgressDialog

        def task_fn(progress_cb):  # type: ignore[no-untyped-def]
            result = process.run_r5_encrypt(progress_cb=progress_cb)
            return result

        def on_complete(result):  # type: ignore[no-untyped-def]
            enc_count = len(result.get("enc_results", []))
            self._update_r5_status(t("reseal.enc_complete").format(v=enc_count))
            self._data["encrypt_result"] = result
            self._data["encrypt_done"] = True
            self._r5_progress_label.configure(text=t("progress.encrypt_complete"))

        def on_error(exc):  # type: ignore[no-untyped-def]
            # 사용자 취소는 오류가 아니다 — 조용한 상태 메시지만 표시.
            # (.enc/.enc.progress는 같은 세션 재시도 resume을 위해 유지)
            if dlg.was_cancelled:
                self._update_r5_status(t("progress.task_cancelled"))
                self._r5_progress_label.configure(
                    text=t("progress.task_cancelled")
                )
                return
            logger.exception("R5 암호화 오류")
            self._update_r5_status(t("unseal.error_occurred").format(v=exc))
            self._r5_progress_label.configure(text=t("unseal.error_occurred").format(v=exc))

        dlg = ProgressDialog(
            self.winfo_toplevel(),
            title=t("process.reseal_encrypt_title"),
            task_fn=task_fn,
            on_complete=on_complete,
            on_error=on_error,
        )
        self._active_dialog = dlg
        try:
            self.winfo_toplevel().wait_window(dlg)
        finally:
            self._active_dialog = None

        # Record (PDF) generation runs on a worker thread AFTER the
        # progress dialog closes — no main-thread freeze at 100%.
        self._ensure_r6_record()

    def _ensure_r6_record(self) -> None:
        """Generate the reseal record (R6) on a worker thread once."""
        if not self._data.get("encrypt_done"):
            return
        if self._data.get("record_done") or self._record_task_running:
            return
        process = self._data.get("_process")
        if process is None:
            self._data["record_done"] = True
            return

        self._record_task_running = True
        self._data.pop("record_error", None)
        self._update_r5_status(t("reseal.record_generating"))
        self._r5_progress_label.configure(text=t("reseal.record_generating"))
        self._set_busy(True, t("reseal.record_generating"))

        def _task():  # type: ignore[no-untyped-def]
            return process.run_r6_record()

        def _ok(result):  # type: ignore[no-untyped-def]
            self._record_task_running = False
            self._data["record_result"] = result
            self._data["record_done"] = True
            self._update_r5_status(t("reseal.record_generated"))
            self._r5_progress_label.configure(text=t("progress.encrypt_complete"))
            self._set_busy(False)

        def _err(exc: Exception) -> None:
            # 기록지 생성 실패는 성공으로 처리하지 않는다 — 진행을
            # 차단하고 오류를 표시하며, 다음 시도에서 재생성한다.
            self._record_task_running = False
            logger.warning("R6 기록지 생성 오류: %s", exc)
            self._data["record_done"] = False
            self._data["record_error"] = str(exc)
            self._update_r5_status(t("unseal.error_occurred").format(v=exc))
            self._r5_progress_label.configure(
                text=t("unseal.error_occurred").format(v=exc)
            )
            self._set_busy(False)
            self._set_nav_message(t("unseal.error_occurred").format(v=exc))

        run_async(self, _task, _ok, _err, cancel_event=self._async_cancel)

    def _update_r5_status(self, message: str) -> None:
        """Append a status line (must be called from main thread)."""
        self._r5_status.configure(state="normal")
        self._r5_status.insert("end", f"  {message}\n")
        self._r5_status.see("end")
        self._r5_status.configure(state="disabled")

    def _update_r5_status_safe(self, message: str) -> None:
        """Thread-safe status update."""
        self.after(0, lambda: self._update_r5_status(message))

    # --- R6: Reseal record preview ---------------------------------------

    def _build_r6(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("reseal.r6_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._r6_summary = SummaryView(parent)
        self._r6_summary.pack(fill="both", expand=True)

        self._validators.append(self._validate_r6)

    def _validate_r6(self) -> bool:
        """R6 always passes -- user reviews the content."""
        return True

    def _refresh_r6_preview(self) -> None:
        """Populate the reseal record preview cards."""
        record = self._data.get("record_result", {}).get("record_dict", {})
        seal_id = self._data.get("seal_id", "N/A")

        _yes = t("preview.yes")
        _no = t("preview.no")

        file_rows: list[tuple] = [
            (
                t("summary.known_files"),
                t("summary.count_files").format(v=len(self._data.get("known_files", []))),
            ),
            (
                t("summary.unknown_files"),
                t("summary.count_files").format(v=len(self._data.get("unknown_files", []))),
            ),
        ]

        classifications = self._data.get("classifications", [])
        derived = [c for c in classifications if c.get("classification") == "derived"]
        excluded = [
            c for c in classifications if c.get("classification") == "excluded"
        ]

        if derived:
            file_rows.append(
                (
                    t("summary.derived_files"),
                    t("summary.count_files").format(v=len(derived)),
                )
            )
            for d in derived:
                file_rows.append(
                    ("", t("preview.derived_item").format(
                        filename=d["filename"], parent=d.get("parent_file", "")
                    ).strip())
                )
        if excluded:
            file_rows.append(
                (
                    t("summary.excluded_files"),
                    t("summary.count_files").format(v=len(excluded)),
                )
            )
            for e in excluded:
                file_rows.append(("", f"- {e['filename']}"))

        from .record_preview import extract_case_number, extract_history_view

        history_events, history_summary = extract_history_view(record)
        history_rows: list[tuple] = []
        for idx, event in enumerate(history_events, 1):
            history_rows.append(
                ("", f"{idx}. {event['type']} - {event['actor']} ({event['time']})")
            )
        history_rows.append((t("summary.summary_code"), history_summary))

        sections = [
            {
                "title": t("preview.reseal_title").strip(),
                "rows": [
                    (t("summary.seal_id"), seal_id),
                    (t("summary.case_number"), extract_case_number(record)),
                ],
            },
            {
                "title": SummaryView._strip_brackets(t("preview.reseal_info")),
                "rows": [
                    (t("summary.reason"), self._data.get("reason", "")),
                    (t("summary.investigator"), self._data.get("investigator", "")),
                    (
                        t("summary.participated"),
                        _yes if self._data.get("subject_participated") else _no,
                    ),
                ],
            },
            {
                "title": SummaryView._strip_brackets(t("preview.file_status")),
                "rows": file_rows,
            },
            {
                "title": SummaryView._strip_brackets(t("preview.procedure_history")),
                "rows": history_rows,
            },
            {
                "title": "",
                "rows": [("", t("preview.confirm_next"))],
            },
        ]
        self._r6_summary.render(sections)

    # --- R7: Key split results + unlock_time -----------------------------

    def _build_r7(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("reseal.r7_title"),
            font=get_font("subheader"),
        ).pack(anchor="w", pady=(0, 12))

        self._r7_result = tk.Text(
            parent,
            wrap="word",
            state="disabled",
            font=get_font("caption"),
            bg=get_color("card_bg"),
            fg=get_color("text"),
            relief="solid",
            bd=1,
            highlightthickness=0,
            height=12,
        )
        self._r7_result.pack(fill="both", expand=True, pady=4)

        unlock_frame = tk.Frame(parent)
        unlock_frame.pack(fill="x", pady=8)
        tk.Label(
            unlock_frame, text=t("seal.unlock_label"), anchor="w", width=20
        ).pack(side="left")
        self._r7_unlock_days_var = tk.IntVar(value=DEFAULT_UNLOCK_DAYS)
        self._r7_unlock_spin = tk.Spinbox(
            unlock_frame,
            from_=MIN_UNLOCK_DAYS,
            to=MAX_UNLOCK_DAYS,
            textvariable=self._r7_unlock_days_var,
            width=6,
        )
        self._r7_unlock_spin.pack(side="left")
        tk.Label(
            unlock_frame, text=t("reseal.unlock_days").format(min=MIN_UNLOCK_DAYS, max=MAX_UNLOCK_DAYS)
        ).pack(side="left", padx=8)

        self._r7_status_label = tk.Label(parent, text="", anchor="w")
        self._r7_status_label.pack(fill="x", pady=4)

        self._validators.append(self._validate_r7)

    def _validate_r7(self) -> bool:
        try:
            days = self._r7_unlock_days_var.get()
            if not (MIN_UNLOCK_DAYS <= days <= MAX_UNLOCK_DAYS):
                raise ValueError
        except (tk.TclError, ValueError):
            self._set_nav_message(
                t("validate.unlock_range").format(
                    min=MIN_UNLOCK_DAYS, max=MAX_UNLOCK_DAYS
                )
            )
            self._r7_unlock_spin.focus_set()
            return False

        self._set_nav_message("")
        self._data["unlock_days"] = days

        # Run key split
        process = self._data.get("_process")
        if process is not None:
            try:
                result = process.run_r7_split_key(unlock_days=days)
                self._data["key_shares"] = result["shares"]
                self._data["unlock_time_iso"] = result["unlock_time_iso"]
                self._refresh_r7_result()
            except Exception as exc:
                messagebox.showerror(
                    t("keysplit.error"), str(exc), parent=self.winfo_toplevel()
                )
                return False

        return True

    def _refresh_r7_result(self) -> None:
        """Display key split results."""
        self._r7_result.configure(state="normal")
        self._r7_result.delete("1.0", "end")

        shares = self._data.get("key_shares")
        unlock_time = self._data.get("unlock_time_iso", "N/A")

        if shares and len(shares) == 4:
            lines = [
                t("keysplit.complete_title"),
                "",
                t("keysplit.share_subject").format(v=shares[0][:16]),
                t("keysplit.share_investigator").format(v=shares[1][:16]),
                t("keysplit.share_system").format(v=shares[2][:16]),
                t("keysplit.share_admin").format(v=shares[3][:16]),
                "",
                f"  unlock_time: {unlock_time}",
                "",
                t("keysplit.subject_store"),
                t("keysplit.investigator_store"),
                t("keysplit.system_store"),
            ]
        else:
            lines = [t("keysplit.run_prompt")]

        self._r7_result.insert("1.0", "\n".join(lines))
        self._r7_result.configure(state="disabled")

    # --- R8: Completion summary ------------------------------------------

    def _build_r8(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("reseal.r8_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._r8_summary = SummaryView(parent)
        self._r8_summary.pack(fill="both", expand=True, pady=4)

        self._validators.append(self._validate_r8)

    def _validate_r8(self) -> bool:
        """Final step -- always valid."""
        return True

    def _refresh_r8_summary(self) -> None:
        """Populate the final summary cards and save to DB."""
        seal_id = self._data.get("seal_id", "N/A")
        record_result = self._data.get("record_result", {})
        encrypt_result = self._data.get("encrypt_result", {})
        enc_results = encrypt_result.get("enc_results", [])

        enc_rows: list[tuple] = [
            (
                t("summary.enc_count"),
                t("summary.count_files").format(v=len(enc_results)),
            ),
        ]
        for er in enc_results:
            enc_rows.append(("", er.get("enc_filepath", "")))

        sections = [
            {
                "title": t("complete.reseal_title").strip(),
                "badge": (t("common.complete"), "success"),
                "rows": [
                    (t("summary.seal_id"), seal_id),
                ],
            },
            {
                "title": SummaryView._strip_brackets(t("complete.file_section")),
                "rows": enc_rows,
            },
            {
                "title": SummaryView._strip_brackets(t("complete.record_section")),
                "rows": [
                    (t("summary.record_json"), record_result.get("record_json_path", "N/A")),
                    (t("summary.record_pdf"), record_result.get("pdf_path", "N/A")),
                    (t("summary.unlock_time"), self._data.get("unlock_time_iso", "N/A")),
                ],
            },
            {
                "title": t("summary.notice"),
                "rows": [
                    ("", t("complete.reseal_saved").strip()),
                    ("", "\n".join(
                        line.strip()
                        for line in t("complete.reseal_key_instruction").splitlines()
                    ).strip()),
                ],
            },
        ]
        self._r8_summary.render(sections)

        # Save to DB (R8)
        self._run_r8_save()

    def _run_r8_save(self) -> None:
        """Run R8 save in background."""
        process = self._data.get("_process")
        if process is None:
            return

        def _save() -> None:
            try:
                result = process.run_r8_save()
                self._data["reseal_result"] = result
                logger.info("R8 저장 완료: %s", result.seal_id)
            except Exception as exc:
                logger.warning("R8 저장 오류: %s", exc)

        thread = threading.Thread(target=_save, daemon=True)
        thread.start()

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _show_step(self, index: int) -> None:
        """Display the given step frame and hide others."""
        for frame in self._steps:
            frame.pack_forget()
        holder = self._steps[index]
        holder.pack(fill="both", expand=True)
        if isinstance(holder, ScrolledFrame):
            holder.scroll_to_top()
        self._current_step = index
        self._set_nav_message("")

        step_num = index + 1
        step_names = ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"]
        self._step_label.configure(
            text=f"{step_names[index]} ({t('common.step_of').format(current=step_num, total=self.TOTAL_STEPS)})"
        )
        # R5(encryption) 이후에는 이전 버튼 비활성화
        if index >= 4 and self._data.get("encrypt_done"):
            self._prev_btn.configure(state="disabled")
        elif index > 0:
            self._prev_btn.configure(state="normal")
        else:
            self._prev_btn.configure(state="disabled")

        if index == self.TOTAL_STEPS - 1:
            self._next_btn.configure(text=t("common.complete"))
        else:
            self._next_btn.configure(text=t("common.next"))

        # Update step indicator
        self._step_indicator.set_active(index)

        # Refresh dynamic content
        if index == 1:
            self._refresh_r2()
        elif index == 2:
            self._refresh_r3()
        elif index == 4:
            self._start_r5_encryption()
        elif index == 5:
            self._refresh_r6_preview()
        elif index == 6:
            self._refresh_r7_result()
        elif index == 7:
            self._refresh_r8_summary()

    def _on_step_click(self, step_index: int) -> None:
        """Handle step indicator click to navigate or view past steps."""
        if self._busy:
            return
        current = self._current_step
        if step_index > current:
            return
        if step_index == current:
            return
        if self._data.get("encrypt_done") and step_index < 4:
            self._show_step_readonly(step_index)
            return
        self._show_step(step_index)

    def _show_step_readonly(self, index: int) -> None:
        """Show a past step in read-only mode with a 'back to current' button."""
        actual_step = self._current_step
        self._show_step(index)
        self._next_btn.configure(
            text=t("common.back_to_current"),
            command=lambda: self._return_to_actual(actual_step),
        )
        self._prev_btn.configure(state="disabled")

    def _return_to_actual(self, actual_step: int) -> None:
        """Return to the actual current step from readonly view."""
        self._next_btn.configure(
            text=t("common.next"),
            command=self._go_next,
        )
        self._show_step(actual_step)

    def _on_return_key(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        """Handle Return key — skip while focus is in an input widget."""
        if self._busy:
            return
        try:
            focused = self.winfo_toplevel().focus_get()
        except (KeyError, tk.TclError):
            return
        if not is_return_navigation_safe(focused):
            return
        self._go_next()

    def _on_escape_key(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        if self._busy:
            return
        self._handle_cancel()

    def _go_next(self) -> None:
        """Advance to the next step after validation."""
        if self._busy:
            return
        idx = self._current_step
        validator = self._validators[idx]
        if not validator():
            return

        if idx == self.TOTAL_STEPS - 1:
            if self._on_complete is not None:
                self._on_complete(self._data)
            return

        self._show_step(idx + 1)

    def _go_prev(self) -> None:
        """Return to the previous step."""
        if self._busy:
            return
        if self._current_step > 0:
            self._show_step(self._current_step - 1)

    def _handle_cancel(self) -> None:
        """Confirm cancellation with the user."""
        if messagebox.askyesno(
            t("cancel.title"),
            t("reseal.cancel_confirm"),
            parent=self.winfo_toplevel(),
        ):
            if self._on_cancel is not None:
                self._on_cancel()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_data(self, key: str, value: Any) -> None:
        """Set a data value from the orchestration process."""
        self._data[key] = value

    def get_data(self) -> dict[str, Any]:
        """Return a copy of all collected data."""
        return dict(self._data)

    def advance_to(self, step: int) -> None:
        """Programmatically show a given step (0-indexed)."""
        if 0 <= step < self.TOTAL_STEPS:
            self._show_step(step)
