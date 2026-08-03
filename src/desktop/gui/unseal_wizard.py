"""Unseal process wizard (U3 through U7).

Guides the investigator through the complete unsealing workflow:
U3 - Target file selection, seal record input, AES key input, unseal info
U4 - File-seal record cross verification results
U5 - Decryption progress
U6 - Unseal record preview
U7 - Completion summary (hash verification, record status)
"""

from __future__ import annotations

import logging
import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
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
AES_KEY_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def compute_preseal_validation(
    db_path: str, data: dict[str, Any]
) -> dict[str, Any]:
    """Run U3 validation + U4 verification; return state updates.

    Pure worker-thread logic (no tk access) extracted from the wizard so
    it can be unit-tested. On any exception the result reports
    ``all_matched=False`` with the error message in
    ``verification_error`` — a failed verification must NEVER default to
    success (evidence-integrity requirement).

    Args:
        db_path: SQLite store path for the UnsealProcess.
        data: Wizard data containing the U3 form inputs.

    Returns:
        Dict of updates to merge into the wizard data.
    """
    try:
        from ..unseal_process import UnsealConfig, UnsealProcess

        process = UnsealProcess(db_path=db_path)
        config = UnsealConfig(
            enc_filepath=data["enc_filepath"],
            seal_record_path=data["seal_record_path"],
            aes_key_hex=data["aes_key_hex"],
            output_dir=data["output_dir"],
            reason=data["reason"],
            investigator=data["investigator"],
            subject_participated=data["subject_participated"],
        )
        process.set_config(config)

        result_u3 = process.run_u3_validate()
        result_u4 = process.run_u4_verify()

        return {
            "seal_record": result_u3["seal_record"],
            "seal_id": result_u3["seal_id"],
            "_process": process,
            "verification_items": result_u4["items"],
            "all_matched": result_u4["all_matched"],
            "verification_error": "",
        }
    except Exception as exc:
        logger.warning("U3/U4 사전 검증 오류: %s", exc)
        return {
            "verification_items": [],
            "all_matched": False,
            "verification_error": str(exc),
        }


class UnsealWizard(tk.Frame):
    """Multi-step wizard for the unsealing process.

    Each step is built as a separate frame.  Navigation buttons
    (이전 / 다음) control the visible frame.
    """

    TOTAL_STEPS = 5

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
        self._record_task_running = False
        # Set on destroy so pending run_async results are discarded.
        self._async_cancel = threading.Event()

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
        header_bg = get_color("wizard_header_unseal")
        self._header = tk.Frame(self, bg=header_bg, height=56)
        self._header.pack(fill="x")
        self._header.pack_propagate(False)

        self._title_label = tk.Label(
            self._header,
            text=t("unseal.title"),
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
            t("unseal.step1"), t("unseal.step2"), t("unseal.step3"),
            t("unseal.step4"), t("unseal.step5"),
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
                    self._current_step >= 2 and self._data.get("decrypt_done")
                ):
                    self._prev_btn.configure(state="normal")
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Step builders
    # ------------------------------------------------------------------

    def _build_steps(self) -> None:
        """Build all 5 step frames (form steps get a shared scroll container)."""
        plans: list[tuple[Callable[[tk.Frame], None], bool]] = [
            (self._build_u3, True),
            (self._build_u4, False),
            (self._build_u5, False),
            (self._build_u6, False),
            (self._build_u7, False),
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
        """Apply prefill data from case workflow to U3 fields."""
        pf = self._prefill_data
        if not pf:
            return

        # Encrypted file path
        enc_filepath = pf.get("enc_filepath", "")
        if enc_filepath and hasattr(self, "_enc_selector"):
            self._enc_selector.set(enc_filepath)

        # Seal record JSON path
        record_json_path = pf.get("record_json_path", "")
        if record_json_path and hasattr(self, "_record_selector"):
            self._record_selector.set(record_json_path)

        # Seal ID
        seal_id = pf.get("seal_id", "")
        if seal_id:
            self._data["seal_id"] = seal_id

    # --- U3: Target selection + inputs -----------------------------------

    def _build_u3(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("unseal.u3_title"),
            font=get_font("subheader"),
        ).pack(anchor="w", pady=(0, 12))

        # .enc file selector
        self._enc_selector = FileSelector(
            parent,
            t("unseal.enc_file"),
            required=True,
            filetypes=[
                (t("filedialog.enc_files"), "*.enc"),
                (t("filedialog.all_files"), "*.*"),
            ],
        )
        self._enc_selector.pack(fill="x", pady=4)

        # Seal record JSON selector
        self._record_selector = FileSelector(
            parent,
            t("unseal.record_json"),
            required=True,
            filetypes=[
                (t("filedialog.json_files"), "*.json"),
                (t("filedialog.all_files"), "*.*"),
            ],
        )
        self._record_selector.pack(fill="x", pady=4)

        # Output directory
        self._output_selector = FileSelector(
            parent,
            t("unseal.output_dir"),
            select_dir=True,
            required=True,
        )
        self._output_selector.pack(fill="x", pady=4)

        # AES key input
        tk.Label(
            parent,
            text=t("unseal.aes_key_title"),
            font=get_font("stat_label"),
        ).pack(anchor="w", pady=(12, 4))

        key_frame = tk.Frame(parent)
        key_frame.pack(fill="x", pady=2)
        tk.Label(key_frame, text=f"* {t('unseal.aes_key')}", anchor="w", width=20).pack(
            side="left"
        )
        self._key_var = tk.StringVar()
        self._key_entry = tk.Entry(
            key_frame, textvariable=self._key_var, width=40, show="*",
            font=get_font("body"),
        )
        self._key_entry.pack(side="left", fill="x", expand=True)

        key_btn_frame = tk.Frame(parent)
        key_btn_frame.pack(fill="x", pady=2)
        tk.Button(
            key_btn_frame,
            text=t("unseal.key_load"),
            command=self._load_key_file,
        ).pack(side="left")
        self._key_show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            key_btn_frame,
            text=t("unseal.show_key"),
            variable=self._key_show_var,
            command=self._toggle_key_visibility,
        ).pack(side="left", padx=8)

        self._key_error_label = tk.Label(
            parent,
            text="",
            fg=get_color("danger_text"),
            font=get_font("small"),
            anchor="w",
        )
        self._key_error_label.pack(fill="x")

        # Unseal info
        tk.Label(
            parent,
            text=t("unseal.unseal_info"),
            font=get_font("stat_label"),
        ).pack(anchor="w", pady=(12, 4))

        self._reason_entry = LabeledEntry(parent, t("unseal.reason"), required=True)
        self._reason_entry.pack(fill="x", pady=2)

        self._investigator_entry = LabeledEntry(
            parent, t("unseal.investigator"), required=True
        )
        self._investigator_entry.pack(fill="x", pady=2)

        participation_frame = tk.Frame(parent)
        participation_frame.pack(fill="x", pady=4)
        tk.Label(
            participation_frame, text=t("unseal.participation"), anchor="w", width=20
        ).pack(side="left")
        self._participation_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            participation_frame,
            text=t("unseal.participate"),
            variable=self._participation_var,
        ).pack(side="left")

        self._validators.append(self._validate_u3)

    def _load_key_file(self) -> None:
        """Load AES key from a .key file."""
        path = filedialog.askopenfilename(
            title=t("filedialog.key_file_title"),
            filetypes=[
                (t("filedialog.key_files"), "*.key"),
                (t("filedialog.text_files"), "*.txt"),
                (t("filedialog.all_files"), "*.*"),
            ],
        )
        if path:
            try:
                content = Path(path).read_text(encoding="utf-8").strip()
                self._key_var.set(content)
            except Exception as exc:
                messagebox.showerror(t("common.error"), f"{t('keyfile.error')}: {exc}")

    def _toggle_key_visibility(self) -> None:
        """Toggle AES key visibility."""
        show = "" if self._key_show_var.get() else "*"
        self._key_entry.configure(show=show)

    def _validate_u3(self) -> bool:
        if self._busy:
            return False

        error_count = 0
        focus_target: Optional[Any] = None

        if not self._enc_selector.is_valid():
            self._enc_selector.highlight_error(t("validate.enc_file"))
            error_count += 1
            focus_target = focus_target or self._enc_selector
        else:
            self._enc_selector.clear_error()

        if not self._record_selector.is_valid():
            self._record_selector.highlight_error(t("validate.record_json"))
            error_count += 1
            focus_target = focus_target or self._record_selector
        else:
            self._record_selector.clear_error()

        if not self._output_selector.is_valid():
            self._output_selector.highlight_error(t("validate.select_output"))
            error_count += 1
            focus_target = focus_target or self._output_selector
        else:
            self._output_selector.clear_error()

        key_hex = self._key_var.get().strip()
        key_error = ""
        if not key_hex:
            key_error = t("validate.aes_key_empty")
        elif not AES_KEY_HEX_PATTERN.match(key_hex):
            key_error = t("validate.aes_key_invalid")
        if key_error:
            error_count += 1
            self._key_error_label.configure(text=key_error)
            if focus_target is None:
                self._key_entry.focus_set()
                focus_target = self._key_entry
        else:
            self._key_error_label.configure(text="")

        if not self._reason_entry.is_valid():
            self._reason_entry.highlight_error(t("validate.reason_required"))
            error_count += 1
            focus_target = focus_target or self._reason_entry
        else:
            self._reason_entry.clear_error()

        if not self._investigator_entry.is_valid():
            self._investigator_entry.highlight_error(t("validate.investigator_required"))
            error_count += 1
            focus_target = focus_target or self._investigator_entry
        else:
            self._investigator_entry.clear_error()

        if error_count:
            self._set_nav_message(
                t("validate.fix_errors").format(count=error_count)
            )
            if focus_target is not None and hasattr(focus_target, "focus_field"):
                focus_target.focus_field()
            return False

        self._set_nav_message("")
        self._data["enc_filepath"] = self._enc_selector.get()
        self._data["seal_record_path"] = self._record_selector.get()
        self._data["output_dir"] = self._output_selector.get()
        self._data["aes_key_hex"] = key_hex
        self._data["reason"] = self._reason_entry.get()
        self._data["investigator"] = self._investigator_entry.get()
        self._data["subject_participated"] = self._participation_var.get()

        # Run U3 validation + U4 verification on a worker thread —
        # hashing large .enc files must not freeze the UI.  Navigation
        # to U4 happens in the completion callback.
        self._start_u3_u4_validation()
        return False

    def _start_u3_u4_validation(self) -> None:
        """Run U3/U4 verification on a worker thread, then advance."""
        self._set_busy(True, t("unseal.verifying"))

        def _task() -> None:
            self._run_u3_u4_validation()

        def _done(_result: Any = None) -> None:
            self._set_busy(False)
            if self._current_step == 0:
                self._show_step(1)

        def _error(exc: Exception) -> None:
            # _run_u3_u4_validation handles its own errors; this is a
            # safety net for unexpected failures. A verification that
            # could not run must NEVER be reported as "no mismatch".
            logger.warning("U3/U4 검증 스레드 오류: %s", exc)
            self._data.setdefault("verification_items", [])
            self._data["all_matched"] = False
            self._data.setdefault("verification_error", str(exc))
            _done()

        run_async(self, _task, _done, _error, cancel_event=self._async_cancel)

    def _run_u3_u4_validation(self) -> None:
        """Run U3 validation and U4 verification via the process.

        Runs on a worker thread — must not touch tk widgets. Delegates
        to :func:`compute_preseal_validation`; exceptions there yield
        ``all_matched=False`` + ``verification_error`` (never a silent
        pass).
        """
        updates = compute_preseal_validation(self._app.db_path, self._data)
        self._data.update(updates)

    # --- U4: Verification results ----------------------------------------

    def _build_u4(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("unseal.u4_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._u4_summary = SummaryView(parent)
        self._u4_summary.pack(fill="both", expand=True)

        self._u4_warning_label = tk.Label(
            parent, text="", fg=get_color("danger_text"), bg=get_color("bg"),
            anchor="w", font=get_font("small"),
        )
        self._u4_warning_label.pack(fill="x", pady=4)

        self._validators.append(self._validate_u4)

    def _validate_u4(self) -> bool:
        """U4 gate: block on verification errors; confirm on mismatches."""
        # 검증 자체가 실패한 경우(봉인지 손상, 키 형식 오류 등)에는
        # "불일치 없음"처럼 통과시키지 않고 진행을 차단한다.
        verification_error = self._data.get("verification_error")
        if verification_error:
            messagebox.showerror(
                t("verify.error_title"),
                t("verify.error_block").format(v=verification_error),
                parent=self.winfo_toplevel(),
            )
            return False
        if not self._data.get("all_matched", False):
            proceed = messagebox.askyesno(
                t("mismatch.title"),
                t("mismatch.msg"),
                parent=self.winfo_toplevel(),
            )
            if not proceed:
                return False
            self._data["mismatch_acknowledged"] = True
        return True

    def _refresh_u4_results(self) -> None:
        """Populate the U4 verification result cards."""
        items = self._data.get("verification_items", [])
        seal_id = self._data.get("seal_id", "N/A")
        verification_error = self._data.get("verification_error", "")
        # 기본값은 실패 — 검증이 실행되지 않았거나 오류가 났다면
        # 성공으로 표시되어서는 안 된다.
        all_matched = (
            self._data.get("all_matched", False) and not verification_error
        )

        overall_badge = (
            (t("verify.match"), "success")
            if all_matched
            else (t("verify.mismatch"), "danger")
        )
        if verification_error:
            overall_badge = (t("verify.error_badge"), "danger")

        head_section = {
            "title": t("verify.title").strip(),
            "badge": overall_badge,
            "rows": [
                (t("summary.seal_id"), seal_id),
                (t("summary.source_file"), self._data.get("enc_filepath", "")),
            ],
        }

        item_rows: list[tuple] = []
        if items:
            for item in items:
                status = "success" if item.matched else "danger"
                status_text = t("verify.match") if item.matched else t("verify.mismatch")
                item_rows.append((item.filename, status_text, status))
                if item.expected_sha256:
                    item_rows.append(
                        (t("summary.expected_sha256"), item.expected_sha256)
                    )
                if item.actual_sha256:
                    item_rows.append(
                        (t("summary.actual_sha256"), item.actual_sha256)
                    )
        else:
            item_rows.append(("", t("verify.no_items").strip()))

        item_section = {
            "title": t("summary.verification"),
            "rows": item_rows,
        }

        result_rows: list[tuple] = []
        if verification_error:
            result_rows.append(
                (t("summary.result"), t("verify.error_badge"), "danger")
            )
            result_rows.append(
                (t("verify.error_label"), verification_error, "danger")
            )
            result_rows.append(("", t("verify.error_action").strip()))
            self._u4_warning_label.configure(text=t("verify.error_warning"))
        elif all_matched:
            result_rows.append(
                (t("summary.result"), t("verify.all_match").strip(" ><"), "success")
            )
            self._u4_warning_label.configure(text="")
        else:
            result_rows.append(
                (t("summary.result"), t("verify.has_mismatch").strip(" ><"), "danger")
            )
            result_rows.append(("", t("verify.mismatch_action").strip()))
            self._u4_warning_label.configure(text=t("verify.mismatch_warning"))

        self._u4_summary.render([
            head_section,
            item_section,
            {"title": "", "rows": result_rows},
        ])

    # --- U5: Decryption progress -----------------------------------------

    def _build_u5(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("unseal.u5_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._u5_status = tk.Text(
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
        self._u5_status.pack(fill="both", expand=True, pady=4)

        self._u5_progress_label = tk.Label(
            parent, text=t("unseal.u5_waiting"), anchor="w",
            bg=get_color("bg"), fg=get_color("text_secondary"),
            font=get_font("small"),
        )
        self._u5_progress_label.pack(fill="x", pady=4)

        self._validators.append(self._validate_u5)

    def _validate_u5(self) -> bool:
        """U5 proceeds after decryption AND record generation complete.

        A failed record generation blocks progress; pressing 다음 again
        retries the generation instead of silently passing.
        """
        if not self._data.get("decrypt_done"):
            return False
        if self._data.get("record_done"):
            return True
        # Record generation failed or has not run — retry, block for now.
        if not self._record_task_running:
            self._ensure_u6_record()
        return False

    def _start_u5_decryption(self) -> None:
        """Launch decryption using ProgressDialog."""
        if self._data.get("decrypt_done"):
            self._ensure_u6_record()
            return

        process = self._data.get("_process")
        if process is None:
            self._update_u5_status(t("unseal.process_not_init"))
            return

        from .progress_dialog import ProgressDialog

        def task_fn(progress_cb):  # type: ignore[no-untyped-def]
            result = process.run_u5_decrypt(progress_cb=progress_cb)
            return result

        def on_complete(result):  # type: ignore[no-untyped-def]
            self._data["decrypt_result"] = result
            self._data["decrypt_done"] = True

            self._update_u5_status(t("unseal.dec_complete").format(v=result['output_filepath']))
            self._update_u5_status(
                t("unseal.hash_result").format(v=t("preview.hash_pass") if result['hash_verified'] else t("preview.hash_fail"))
            )
            self._update_u5_status(
                t("unseal.sha256_result").format(v=t("complete.match") if result['sha256_match'] else t("complete.mismatch"))
            )
            self._update_u5_status(
                t("unseal.md5_result").format(v=t("complete.match") if result['md5_match'] else t("complete.mismatch"))
            )
            self._u5_progress_label.configure(text=t("progress.decrypt_complete"))

        def on_error(exc):  # type: ignore[no-untyped-def]
            # 사용자 취소는 오류가 아니다 — 조용한 상태 메시지만 표시.
            if dlg.was_cancelled:
                self._update_u5_status(t("progress.task_cancelled"))
                self._u5_progress_label.configure(
                    text=t("progress.task_cancelled")
                )
                return
            logger.exception("U5 복호화 오류")
            self._update_u5_status(t("unseal.error_occurred").format(v=exc))
            self._u5_progress_label.configure(text=t("unseal.error_occurred").format(v=exc))

        dlg = ProgressDialog(
            self.winfo_toplevel(),
            title=t("process.decryption_progress_title"),
            task_fn=task_fn,
            on_complete=on_complete,
            on_error=on_error,
        )
        self.winfo_toplevel().wait_window(dlg)

        # Record (PDF) generation runs on a worker thread AFTER the
        # progress dialog closes — no main-thread freeze at 100%.
        self._ensure_u6_record()

    def _ensure_u6_record(self) -> None:
        """Generate the unseal record (U6) on a worker thread once."""
        if not self._data.get("decrypt_done"):
            return
        if self._data.get("record_done") or self._record_task_running:
            return
        process = self._data.get("_process")
        if process is None:
            self._data["record_done"] = True
            return

        self._record_task_running = True
        self._data.pop("record_error", None)
        self._update_u5_status(t("unseal.record_generating"))
        self._u5_progress_label.configure(text=t("unseal.record_generating"))
        self._set_busy(True, t("unseal.record_generating"))

        def _task():  # type: ignore[no-untyped-def]
            return process.run_u6_record()

        def _ok(result):  # type: ignore[no-untyped-def]
            self._record_task_running = False
            self._data["record_result"] = result
            self._data["record_done"] = True
            self._update_u5_status(t("unseal.record_generated"))
            self._u5_progress_label.configure(text=t("progress.decrypt_complete"))
            self._set_busy(False)

        def _err(exc: Exception) -> None:
            # 기록지 생성 실패는 성공으로 처리하지 않는다 — 진행을
            # 차단하고 오류를 표시하며, 다음 시도에서 재생성한다.
            self._record_task_running = False
            logger.warning("U6 기록지 생성 오류: %s", exc)
            self._data["record_done"] = False
            self._data["record_error"] = str(exc)
            self._update_u5_status(t("unseal.error_occurred").format(v=exc))
            self._u5_progress_label.configure(
                text=t("unseal.error_occurred").format(v=exc)
            )
            self._set_busy(False)
            self._set_nav_message(t("unseal.error_occurred").format(v=exc))

        run_async(self, _task, _ok, _err, cancel_event=self._async_cancel)

    def _update_u5_status(self, message: str) -> None:
        """Append a status line to U5 (must be called from main thread)."""
        self._u5_status.configure(state="normal")
        self._u5_status.insert("end", f"  {message}\n")
        self._u5_status.see("end")
        self._u5_status.configure(state="disabled")

    def _update_u5_status_safe(self, message: str) -> None:
        """Thread-safe status update."""
        self.after(0, lambda: self._update_u5_status(message))

    # --- U6: Unseal record preview ---------------------------------------

    def _build_u6(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("unseal.u6_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._u6_summary = SummaryView(parent)
        self._u6_summary.pack(fill="both", expand=True)

        self._validators.append(self._validate_u6)

    def _validate_u6(self) -> bool:
        """U6 always passes -- user reviews the content."""
        return True

    def _refresh_u6_preview(self) -> None:
        """Populate the unseal record preview cards."""
        record = self._data.get("record_result", {}).get("record_dict", {})
        seal_id = self._data.get("seal_id", "N/A")
        decrypt = self._data.get("decrypt_result", {})

        _yes = t("preview.yes")
        _no = t("preview.no")
        _pass = t("preview.hash_pass")
        _fail = t("preview.hash_fail")

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
                "title": t("preview.unseal_title").strip(),
                "rows": [
                    (t("summary.seal_id"), seal_id),
                    (t("summary.case_number"), extract_case_number(record)),
                ],
            },
            {
                "title": SummaryView._strip_brackets(t("preview.unseal_info")),
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
                "title": SummaryView._strip_brackets(t("preview.decrypt_result")),
                "rows": [
                    (t("summary.output_file"), decrypt.get("output_filepath", "N/A")),
                    (
                        t("summary.hash_verified"),
                        _pass if decrypt.get("hash_verified") else _fail,
                        "success" if decrypt.get("hash_verified") else "danger",
                    ),
                    (
                        t("summary.sha256"),
                        _yes if decrypt.get("sha256_match") else _no,
                        "success" if decrypt.get("sha256_match") else "danger",
                    ),
                    (
                        t("summary.md5"),
                        _yes if decrypt.get("md5_match") else _no,
                        "success" if decrypt.get("md5_match") else "danger",
                    ),
                ],
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
        self._u6_summary.render(sections)

    # --- U7: Completion summary ------------------------------------------

    def _build_u7(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("unseal.u7_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._u7_summary = SummaryView(parent)
        self._u7_summary.pack(fill="both", expand=True, pady=4)

        self._validators.append(self._validate_u7)

    def _validate_u7(self) -> bool:
        """Final step -- always valid."""
        return True

    def _refresh_u7_summary(self) -> None:
        """Populate the final completion summary cards."""
        seal_id = self._data.get("seal_id", "N/A")
        decrypt = self._data.get("decrypt_result", {})
        record_result = self._data.get("record_result", {})

        _pass = t("preview.hash_pass")
        _fail = t("preview.hash_fail")
        _match = t("complete.match")
        _mismatch = t("complete.mismatch")
        hash_ok = bool(decrypt.get("hash_verified"))

        sections: list[dict[str, Any]] = [
            {
                "title": t("complete.unseal_title").strip(),
                "badge": (
                    (t("common.complete"), "success")
                    if hash_ok
                    else (t("hash.failed"), "danger")
                ),
                "rows": [
                    (t("summary.seal_id"), seal_id),
                    (t("summary.dec_file"), decrypt.get("output_filepath", "N/A")),
                ],
            },
            {
                "title": SummaryView._strip_brackets(t("complete.hash_result_section")),
                "rows": [
                    (
                        t("summary.hash_verified"),
                        _pass if hash_ok else _fail,
                        "success" if hash_ok else "danger",
                    ),
                    (
                        t("summary.sha256"),
                        _match if decrypt.get("sha256_match") else _mismatch,
                        "success" if decrypt.get("sha256_match") else "danger",
                    ),
                    (
                        t("summary.md5"),
                        _match if decrypt.get("md5_match") else _mismatch,
                        "success" if decrypt.get("md5_match") else "danger",
                    ),
                ],
            },
            {
                "title": SummaryView._strip_brackets(t("complete.record_section")),
                "rows": [
                    (t("summary.record_json"), record_result.get("record_json_path", "N/A")),
                    (t("summary.record_pdf"), record_result.get("pdf_path", "N/A")),
                ],
            },
        ]

        notice_rows: list[tuple] = []
        if not hash_ok:
            notice_rows.append(
                ("", "\n".join(
                    line.strip() for line in t("complete.hash_warn").splitlines()
                ).strip(), "danger")
            )
        if self._data.get("mismatch_acknowledged"):
            notice_rows.append(
                ("", t("complete.mismatch_note").strip(), "warning")
            )
        notice_rows.append(("", t("complete.unseal_saved").strip()))
        sections.append({"title": t("summary.notice"), "rows": notice_rows})

        self._u7_summary.render(sections)

        # Save to DB (U7)
        self._run_u7_save()

    def _run_u7_save(self) -> None:
        """Run U7 save in background."""
        process = self._data.get("_process")
        if process is None:
            return

        def _save() -> None:
            try:
                result = process.run_u7_save()
                self._data["unseal_result"] = result
                logger.info("U7 저장 완료: %s", result.seal_id)
            except Exception as exc:
                logger.warning("U7 저장 오류: %s", exc)

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
        step_names = ["U3", "U4", "U5", "U6", "U7"]
        self._step_label.configure(
            text=f"{step_names[index]} ({t('common.step_of').format(current=step_num, total=self.TOTAL_STEPS)})"
        )
        # U5(decryption) 이후에는 이전 버튼 비활성화
        if index >= 2 and self._data.get("decrypt_done"):
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
            self._refresh_u4_results()
        elif index == 2:
            self._start_u5_decryption()
        elif index == 3:
            self._refresh_u6_preview()
        elif index == 4:
            self._refresh_u7_summary()

    def _on_step_click(self, step_index: int) -> None:
        """Handle step indicator click to navigate or view past steps."""
        if self._busy:
            return
        current = self._current_step
        if step_index > current:
            return
        if step_index == current:
            return
        if self._data.get("decrypt_done") and step_index < 2:
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
            t("unseal.cancel_confirm"),
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
