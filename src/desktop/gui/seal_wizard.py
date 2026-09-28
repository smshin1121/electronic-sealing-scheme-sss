"""Seal process wizard (S1 through S7).

Guides the investigator through the complete sealing workflow:
S1 - File selection and encryption settings (encrypts via SealProcess.run_s1)
S2 - Seizure / sealing information, seal mode and unlock days
S3 - Subject (suspect) information
S4 - Seal record preview and review
S5 - Sealing: S4-S7 of SealProcess on a worker thread (record + policy,
     PAdES signature + TSA timestamp, key split by mode, save)
S6 - Key splitting results (unlock time read from the signed record)
S7 - Completion summary

Every seal goes through :class:`desktop.seal_process.SealProcess`; a step
that fails is shown and blocks the wizard, and no record is produced
without its signature and timestamp. The seal mode and the unlock days are
chosen at S2 because S4 writes them into the record before S5 signs it.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
import threading
import tkinter as tk
from datetime import datetime, timezone
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING, Any, Callable, Optional

from desktop.record import is_valid_seal_id
from desktop.seal_process import SealProcess, SealResult, seal_output_path

from .i18n import t
from .seal_mode_view import (
    MODE_STANDARD,
    MODE_STRICT,
    fingerprint_of,
    key_shares_summary,
    keysplit_title,
    recovery_shares_text,
    seal_mode_rows,
)
from .seal_policy_panel import SealPolicyPanel
from .seal_runner import start_background_seal
from .share_handout import ShareHandoutPanel, share_file_rows
from .step_indicator import StepIndicator
from .theme import FONTS, get_color, get_font
from .signature_pad import EnhancedSignaturePad
from .widgets import (
    DateEntry,
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
MIN_CHUNK_GB = 1
MAX_CHUNK_GB = 64
# 1 GiB default — fastest at the largest measured input and the finest
# resume granularity (see the segment-size sweep in the paper).
DEFAULT_CHUNK_GB = 1
MIN_UNLOCK_DAYS = 1
MAX_UNLOCK_DAYS = 30
DEFAULT_UNLOCK_DAYS = 10
# Wizard data handed to run_seal_steps (no key material, no process object).
_SEAL_REQUEST_KEYS = (
    "source_file", "output_dir", "chunk_size_gb", "case_number",
    "investigator", "seizure", "media", "subject", "signature_lines",
    "seal_mode", "unlock_days", "seal_id",
)
# Input widgets disabled when a past step is reviewed after sealing.
_INPUT_WIDGETS = (tk.Entry, tk.Spinbox, tk.Button, tk.Checkbutton, tk.Radiobutton,
                  ttk.Entry, ttk.Button, ttk.Checkbutton, ttk.Radiobutton)
# Accepted seizure date/time inputs (UTC, as prefilled by S2).
_SEIZURE_FORMATS = ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ")
# The saved seal kept by the wizard carries no share text.
_NO_SHARES = ("", "", "", "")


def _clean_multiline(text: str) -> str:
    """Strip per-line indentation from an i18n multiline message."""
    return "\n".join(line.strip() for line in text.splitlines()).strip()


def seizure_time_iso(text: str) -> Optional[str]:
    """Parse the S2 seizure date/time (UTC) into the record's ISO 8601 form.

    Returns ``YYYY-MM-DDThh:mm:ssZ``, or None when the text is not a valid
    ``YYYY-MM-DD HH:MM[:SS]`` or ISO 8601 UTC value.
    """
    value = text.strip()
    for fmt in _SEIZURE_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


class SealWizard(tk.Frame):
    """Multi-step wizard for the sealing process.

    Each step is built as a separate frame.  Navigation buttons
    control the visible frame.
    """

    TOTAL_STEPS = 7

    def __init__(
        self,
        master: tk.Widget,
        app: MainApp,
        *,
        on_complete: Optional[Callable[[dict[str, Any]], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
        prefill_data: Optional[dict[str, Any]] = None,
        process_factory: Optional[Callable[[], SealProcess]] = None,
        ask_share_path: Optional[Callable[..., Any]] = None,
    ) -> None:
        super().__init__(master)
        self._app = app
        self._on_complete = on_complete
        self._on_cancel = on_cancel
        self._prefill_data = prefill_data
        # The sealing process (created at S1); injectable for tests.
        self._process_factory = process_factory or (
            lambda: SealProcess(db_path=app.db_path)
        )
        self._process: Optional[SealProcess] = None
        # The save dialog of the S6 share handout (None: the Tk dialog).
        self._ask_share_path = ask_share_path
        # The saved seal, without share text: shares 1 and 2 live only in
        # the S6 handout panel until completion; 3 and 4 are wrapped in the DB.
        self._seal_result: Optional[SealResult] = None
        self._share_prints: tuple[str, ...] = ()
        self._current_step = 0
        # While a past step is reviewed read-only: the step to return to.
        self._review_return: Optional[int] = None
        self._data: dict[str, Any] = {}
        self._busy = False
        self._seal_running = False
        # Set on destroy so pending background results are discarded.
        self._async_cancel = threading.Event()
        # Active ProgressDialog (encryption) — joined before cleanup.
        self._active_dialog: Optional[Any] = None

        # Pre-set seal_id if provided by case workflow
        if prefill_data and prefill_data.get("seal_id"):
            self._data["seal_id"] = prefill_data["seal_id"]

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
        header_bg = get_color("wizard_header_seal")
        self._header = tk.Frame(self, bg=header_bg, height=56)
        self._header.pack(fill="x")
        self._header.pack_propagate(False)

        self._title_label = tk.Label(
            self._header,
            text=t("seal.title"),
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
            t("seal.step1"), t("seal.step2"), t("seal.step3"),
            t("seal.step4"), t("seal.step5"), t("seal.step6"), t("seal.step7"),
        ], on_step_click=self._on_step_click, bg=get_color("step_bg"))
        self._step_indicator.pack(fill="x", padx=16, pady=(8, 4))

        # Navigation bar — pack BEFORE content so it always gets space allocated.
        # In tkinter's packer, widgets packed later with expand=True can starve
        # earlier side="bottom" widgets when content is tall (e.g. S3).
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

        # Inline validation / busy message (replaces popup error lists)
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

        # Keyboard shortcuts on the toplevel.  Previous bindings are
        # preserved and restored when the wizard is destroyed so a
        # stale callback is never invoked after returning home.
        top = self.winfo_toplevel()
        self._bound_toplevel = top
        self._saved_return_binding = top.bind("<Return>")
        self._saved_escape_binding = top.bind("<Escape>")
        self._return_funcid = top.bind("<Return>", self._on_return_key)
        self._escape_funcid = top.bind("<Escape>", self._on_escape_key)
        self.bind("<Destroy>", self._on_destroy, add="+")

    def _on_destroy(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        """Restore the toplevel key bindings captured at build time."""
        if event.widget is not self:
            return
        self._async_cancel.set()
        self._cleanup_partial_encryption()
        # However the wizard is left: drop the shares and the process
        # (which holds the key and the shares).
        self._handout_panel.clear()
        self._process = None
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
        """Remove partial .enc / .enc.progress left by an unfinished run.

        Called when the wizard is destroyed before encryption completed.
        At that point the session AES key is lost, so the partial output
        can never be resumed and must not linger as a stale artifact.
        A completed encryption (``encryption_done``) is never touched.
        Deletion failures are logged only.

        Before deleting, the encryption worker (if any) is cancelled and
        joined — deleting while the worker holds the file open causes a
        Windows sharing violation, or the worker could recreate the file
        right after deletion.
        """
        import os
        if self._data.get("encryption_done"):
            return
        enc_path = self._data.get("enc_path_pending") or self._data.get("enc_path")
        if not enc_path:
            return

        dlg = self._active_dialog
        if dlg is not None and not dlg.cancel_and_join(timeout=5.0):
            logger.warning(
                "암호화 워커 종료 대기 실패 — 부분 산출물 삭제를 건너뜁니다."
            )
            return
        for path in (enc_path, enc_path + ".progress"):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError as exc:
                logger.warning("부분 암호화 산출물 삭제 실패: %s (%s)", path, exc)

    def _set_nav_message(self, text: str, *, kind: str = "error") -> None:
        """Show an inline message in the nav bar (empty text clears it)."""
        color = get_color("danger_text") if kind == "error" else get_color("text_secondary")
        try:
            self._nav_msg_label.configure(text=text, fg=color)
        except tk.TclError:
            pass

    def _sealed(self) -> bool:
        """True once S4-S7 completed: the seal is saved and final."""
        return bool(self._data.get("signature_done"))

    def is_busy(self) -> bool:
        """True while work runs that must not be left: the S1 encryption
        dialog (the window's X reaches the main window through its grab)
        and S4-S7 in the background."""
        return self._busy

    def has_unsaved_shares(self) -> bool:
        """The seal is saved but shares 1/2 are not yet in files (S6)."""
        return self._sealed() and self._handout_panel.has_unsaved()

    def leave_question(self) -> Optional[tuple[str, str]]:
        """What leaving now must ask first, as (title, message) i18n keys.

        Only unsaved shares at S6 (``nav.unsaved_*``): S7 stored the seal
        before the handout, and Cancel and Escape are off once it is saved.
        """
        if self.has_unsaved_shares():
            return ("nav.unsaved_title", "nav.unsaved_msg")
        return None

    def _set_busy(self, busy: bool, message: str = "") -> None:
        """Toggle background work: navigation and Cancel disabled + status.

        Cancel stays disabled once the seal is saved — the only way on is
        to complete, so the completion handler records the case metadata.
        """
        self._busy = busy
        try:
            self._next_btn.configure(state="disabled" if busy else "normal")
            self._cancel_btn.configure(
                state="disabled" if busy or self._sealed() else "normal"
            )
            if busy:
                self._prev_btn.configure(state="disabled")
                self._set_nav_message(message, kind="info")
                return
            self._set_nav_message("")
            if self._current_step > 0 and not (
                self._current_step >= 4 and self._sealed()
            ):
                self._prev_btn.configure(state="normal")
        except tk.TclError:
            pass

    def _ensure_process(self) -> SealProcess:
        """The wizard's sealing process (one per wizard, so S1 can resume)."""
        if self._process is None:
            self._process = self._process_factory()
        return self._process

    # ------------------------------------------------------------------
    # Step builders
    # ------------------------------------------------------------------

    def _build_steps(self) -> None:
        """Build all 7 step frames.

        Form steps are wrapped in a shared ScrolledFrame so content is
        reachable on small windows / enlarged fonts; summary steps use
        their own internally-scrolling SummaryView.
        """
        plans: list[tuple[Callable[[tk.Frame], None], bool]] = [
            (self._build_s1, True),
            (self._build_s2, True),
            (self._build_s3, True),
            (self._build_s4, False),
            (self._build_s5, False),
            (self._build_s6, True),
            (self._build_s7, False),
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
        """Apply prefill data from case workflow to S2 and S3 fields."""
        pf = self._prefill_data
        if not pf:
            return

        # S2 fields
        case_number = pf.get("case_number", "")
        if case_number and hasattr(self, "_case_number"):
            self._case_number.set(case_number)

        investigator = pf.get("investigator", "")
        if investigator and hasattr(self, "_investigator_name"):
            self._investigator_name.set(investigator)

        # S3 fields
        suspect_name = pf.get("suspect_name", "")
        if suspect_name and hasattr(self, "_subject_name"):
            self._subject_name.set(suspect_name)

    # --- S1: File selection + encryption settings -------------------------

    def _build_s1(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("seal.s1_title"),
            font=get_font("subheader"),
        ).pack(anchor="w", pady=(0, 12))

        self._file_selector = FileSelector(
            parent,
            t("seal.target_file"),
            required=True,
            filetypes=[
                (t("filedialog.disk_images"), "*.dd *.e01 *.vmdk *.img *.raw"),
                (t("filedialog.all_files"), "*.*"),
            ],
        )
        self._file_selector.pack(fill="x", pady=4)

        self._output_selector = FileSelector(
            parent,
            t("seal.output_dir"),
            select_dir=True,
            required=True,
        )
        self._output_selector.pack(fill="x", pady=4)

        chunk_frame = tk.Frame(parent)
        chunk_frame.pack(fill="x", pady=8)
        tk.Label(
            chunk_frame,
            text=f"* {t('seal.chunk_size')}",
            anchor="w",
            width=20,
        ).pack(side="left")
        self._chunk_var = tk.IntVar(value=DEFAULT_CHUNK_GB)
        self._chunk_spin = tk.Spinbox(
            chunk_frame,
            from_=MIN_CHUNK_GB,
            to=MAX_CHUNK_GB,
            textvariable=self._chunk_var,
            width=6,
        )
        self._chunk_spin.pack(side="left")
        tk.Label(chunk_frame, text=t("seal.chunk_range")).pack(side="left", padx=8)

        self._validators.append(self._validate_s1)

    def _validate_s1(self) -> bool:
        # A case registered with a legacy ID can never pass S4's record
        # schema; refuse it here, before the (possibly long) encryption.
        case_seal_id = self._data.get("seal_id")
        if case_seal_id and not is_valid_seal_id(case_seal_id):
            self._set_nav_message(
                t("validate.legacy_case_id").format(v=case_seal_id)
            )
            return False
        if self._data.get("encryption_done"):
            # The container is written; S5 puts the signed record next to
            # it, so the S1 inputs are fixed (their widgets are disabled).
            self._set_nav_message("")
            return True

        messages: list[str] = []
        focus_target: Optional[tk.Widget] = None

        if not self._file_selector.is_valid():
            self._file_selector.highlight_error(t("validate.select_file"))
            messages.append(t("validate.select_file"))
            focus_target = focus_target or self._file_selector.browse_btn
        else:
            self._file_selector.clear_error()

        if not self._output_selector.is_valid():
            self._output_selector.highlight_error(t("validate.select_output"))
            messages.append(t("validate.select_output"))
            focus_target = focus_target or self._output_selector.browse_btn
        else:
            self._output_selector.clear_error()

        try:
            chunk = self._chunk_var.get()
            if not (MIN_CHUNK_GB <= chunk <= MAX_CHUNK_GB):
                messages.append(
                    t("validate.chunk_range").format(min=MIN_CHUNK_GB, max=MAX_CHUNK_GB)
                )
                focus_target = focus_target or self._chunk_spin
        except (tk.TclError, ValueError):
            messages.append(t("validate.chunk_invalid"))
            focus_target = focus_target or self._chunk_spin

        if messages:
            summary = messages[0] if len(messages) == 1 else t(
                "validate.fix_errors"
            ).format(count=len(messages))
            self._set_nav_message(summary)
            if focus_target is not None:
                focus_target.focus_set()
            return False

        self._set_nav_message("")
        self._data["source_file"] = self._file_selector.get()
        self._data["output_dir"] = self._output_selector.get()
        self._data["chunk_size_gb"] = self._chunk_var.get()

        # S1 검증 통과 → 바로 암호화 수행 (ProgressDialog)
        self._run_encryption()
        return self._data.get("encryption_done", False)

    def _run_encryption(self) -> None:
        """S1: encrypt through SealProcess.run_s1 in a progress dialog.

        MD5/SHA-256 are computed inline during the single encryption pass.
        The process keeps the AES key: a retry after a cancel or an error
        reuses it, so ``.enc.progress`` resume never mixes keys. The key
        never enters the wizard data.
        """
        from .progress_dialog import ProgressDialog

        process = self._ensure_process()
        source = self._data["source_file"]
        output_dir = self._data["output_dir"]
        chunk_gb = self._data["chunk_size_gb"]
        # Recorded first, so a wizard destroyed before encryption completes
        # can remove the partial output.
        self._data["enc_path_pending"] = seal_output_path(source, output_dir)

        def task_fn(progress_cb):  # type: ignore[no-untyped-def]
            result = process.run_s1(source, output_dir, chunk_gb,
                                    progress_cb=progress_cb)
            return {k: v for k, v in result.items() if k != "aes_key_hex"}

        def on_complete(result):  # type: ignore[no-untyped-def]
            self._data["enc_path"] = result["enc_filepath"]
            # Inline single-pass hashes for the S4 preview and S7 summary.
            self._data["file_metadata"] = dict(result["metadata"])
            self._data["enc_meta"] = dict(result.get("enc_metadata") or {})
            self._data["encryption_done"] = True
            self._disable_inputs(self._steps[0])

        notice: list[str] = []

        def on_error(exc):
            # 사용자 취소는 오류가 아니다 — 조용한 상태 메시지만 표시.
            # (.enc/.enc.progress는 같은 세션 재시도 resume을 위해 유지)
            if dlg.was_cancelled:
                notice.append(t("progress.task_cancelled"))  # shown after busy
                return
            messagebox.showerror(
                t("encrypt.failed_title"),
                f"{t('encrypt.failed_msg')}:\n{exc}",
                parent=self.winfo_toplevel(),
            )

        # Busy while the dialog runs: its grab does not stop the window's X.
        self._set_busy(True, t("process.encryption_progress_title"))
        try:
            dlg = ProgressDialog(
                self.winfo_toplevel(),
                title=t("process.encryption_progress_title"),
                task_fn=task_fn,
                on_complete=on_complete,
                on_error=on_error,
            )
            self._active_dialog = dlg
            self.winfo_toplevel().wait_window(dlg)
        finally:
            self._active_dialog = None
            self._set_busy(False)
        if notice:
            self._set_nav_message(notice[0], kind="info")

        # 시간 정보 저장
        self._data["encrypt_start_time"] = dlg.start_time_iso
        self._data["encrypt_end_time"] = dlg.end_time_iso
        self._data["encrypt_elapsed"] = dlg.elapsed_seconds

    # --- S2: Seizure / sealing info ---------------------------------------

    def _build_s2(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("seal.s2_title"),
            font=get_font("header"),
        ).pack(anchor="w", pady=(0, 12))

        # --- Case info group (every field is required by the record schema)
        case_group = ttk.LabelFrame(parent, text=t("seal.case_info"), padding=(8, 4))
        case_group.pack(fill="x", pady=(0, 8))

        def _entry(key: str) -> LabeledEntry:
            entry = LabeledEntry(case_group, t(key), required=True)
            entry.pack(fill="x", pady=3)
            return entry

        self._case_number = _entry("seal.case_number")
        self._seizure_date = _entry("seal.seizure_date")
        self._seizure_date.set(datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M"))
        self._seizure_location = _entry("seal.seizure_location")
        self._device_user = _entry("seal.device_user")
        self._storage_type = _entry("seal.storage_type")
        self._media_manufacturer = _entry("seal.media_manufacturer")
        self._media_model = _entry("seal.media_model")
        self._media_serial = _entry("seal.media_serial")

        # --- Seal mode and unlock days (written into the record at S4)
        self._policy_panel = SealPolicyPanel(
            parent, min_days=MIN_UNLOCK_DAYS, max_days=MAX_UNLOCK_DAYS,
            default_days=DEFAULT_UNLOCK_DAYS,
        )
        self._policy_panel.pack(fill="x", pady=(0, 8))

        # --- Investigator info group ---
        inv_group = ttk.LabelFrame(parent, text=t("seal.investigator_info"), padding=(8, 4))
        inv_group.pack(fill="x", pady=(0, 4))

        self._investigator_name = LabeledEntry(inv_group, t("seal.investigator_name"), required=True)
        self._investigator_name.pack(fill="x", pady=4)

        self._investigator_rank = LabeledEntry(inv_group, t("seal.investigator_rank"))
        self._investigator_rank.pack(fill="x", pady=4)

        self._validators.append(self._validate_s2)

    def _s2_entries(self) -> list[LabeledEntry]:
        return [
            self._case_number, self._seizure_date, self._seizure_location,
            self._device_user, self._storage_type, self._media_manufacturer,
            self._media_model, self._media_serial, self._investigator_name,
        ]

    def _validate_s2(self) -> bool:
        invalid: list[LabeledEntry] = []
        for entry in self._s2_entries():
            if entry.is_valid():
                entry.clear_error()
            else:
                entry.highlight_error()
                invalid.append(entry)
        messages: list[str] = []
        seizure_iso = seizure_time_iso(self._seizure_date.get())
        if self._seizure_date.is_valid() and seizure_iso is None:
            self._seizure_date.highlight_error(t("validate.seizure_datetime"))
            invalid.append(self._seizure_date)
            messages.append(t("validate.seizure_datetime"))
        panel_errors = self._policy_panel.validation_errors() or self._strict_policy_errors()
        messages.extend(panel_errors)

        error_count = len(invalid) + len(panel_errors)
        if error_count:
            single = messages[0] if error_count == 1 and messages else None
            self._set_nav_message(
                single or t("validate.fix_errors").format(count=error_count)
            )
            if invalid:
                invalid[0].focus_field()
            else:
                self._policy_panel.focus_first_error()
            return False

        self._set_nav_message("")
        self._store_s2(seizure_iso or "")
        return True

    def _strict_policy_errors(self) -> list[str]:
        """Strict needs a signed policy; refuse it here rather than at S4.

        Asked only when strict is chosen. Without a process yet (S1 not
        run) S4 still refuses strict without a policy.
        """
        if self._policy_panel.mode != MODE_STRICT or self._process is None:
            return []
        if self._process.policy_signer_available():
            return []
        return [t("validate.strict_needs_policy")]

    def _store_s2(self, seizure_iso: str) -> None:
        """Keep the S2 inputs in the shape SealConfig expects."""
        self._data["case_number"] = self._case_number.get()
        self._data["investigator"] = {
            "name": self._investigator_name.get(),
            "rank": self._investigator_rank.get(),
        }
        self._data["seizure"] = {
            "date": seizure_iso,
            "datetime": self._seizure_date.get(),
            "location": self._seizure_location.get(),
            "device_user": self._device_user.get(),
        }
        self._data["media"] = {
            "type": self._storage_type.get(),
            "manufacturer": self._media_manufacturer.get(),
            "model": self._media_model.get(),
            "serial": self._media_serial.get(),
        }
        self._data["seal_mode"] = self._policy_panel.mode
        self._data["unlock_days"] = self._policy_panel.unlock_days()

    # --- S3: Subject (suspect) info ---------------------------------------

    def _build_s3(self, parent: tk.Frame) -> None:
        from tkinter import ttk

        # NOTE: the wizard-level ScrolledFrame now provides scrolling
        # for this step, so no dedicated canvas is needed here.
        tk.Label(
            parent,
            text=t("seal.s3_title"),
            font=get_font("header"),
        ).pack(anchor="w", pady=(0, 12))

        # --- Personal info group ---
        person_group = ttk.LabelFrame(parent, text=t("seal.subject_info"), padding=(8, 4))
        person_group.pack(fill="x", pady=(0, 8))

        self._subject_name = LabeledEntry(person_group, t("seal.subject_name"), required=True)
        self._subject_name.pack(fill="x", pady=4)

        self._subject_email = LabeledEntry(person_group, t("seal.subject_email"), required=True)
        self._subject_email.pack(fill="x", pady=4)

        # Birth date: calendar upper bound is the current year (no future DOB)
        self._subject_birth = DateEntry(
            person_group, t("seal.subject_dob"), required=True, max_year_offset=0
        )
        self._subject_birth.pack(fill="x", pady=4)

        self._subject_phone = LabeledEntry(person_group, t("seal.subject_phone"), required=True)
        self._subject_phone.pack(fill="x", pady=4)

        # --- Security info group ---
        security_group = ttk.LabelFrame(parent, text=t("seal.security_info"), padding=(8, 4))
        security_group.pack(fill="x", pady=(0, 8))

        self._subject_password = LabeledEntry(
            security_group, t("seal.password"), required=True, show="*"
        )
        self._subject_password.pack(fill="x", pady=4)

        self._subject_password_confirm = LabeledEntry(
            security_group, t("seal.password_confirm"), required=True, show="*"
        )
        self._subject_password_confirm.pack(fill="x", pady=4)

        self._signature_pad = EnhancedSignaturePad(
            security_group, label_text=t("seal.signature"), required=True
        )
        self._signature_pad.pack(fill="x", pady=8)

        self._validators.append(self._validate_s3)

    def _validate_s3(self) -> bool:
        fields = [
            self._subject_name,
            self._subject_email,
            self._subject_birth,
            self._subject_phone,
            self._subject_password,
            self._subject_password_confirm,
        ]
        error_count = 0
        focus_target: Optional[Any] = None
        for f in fields:
            if not f.is_valid():
                f.highlight_error()
                error_count += 1
                focus_target = focus_target or f
            else:
                f.clear_error()

        pw = self._subject_password.get()
        pw_confirm = self._subject_password_confirm.get()
        if pw and pw_confirm and pw != pw_confirm:
            self._subject_password_confirm.highlight_error(
                t("validate.password_mismatch")
            )
            error_count += 1
            focus_target = focus_target or self._subject_password_confirm

        if not self._signature_pad.is_valid():
            error_count += 1
            self._signature_pad._status_label.configure(
                text=t("validate.signature_required"),
                fg=get_color("danger_text"),
            )
            logger.warning(
                "S3 signature validation failed: has_signature=%s, confirmed=%s",
                self._signature_pad._has_signature,
                self._signature_pad._confirmed,
            )

        if error_count:
            logger.info("S3 validation failed with %d error(s)", error_count)
            self._set_nav_message(
                t("validate.fix_errors").format(count=error_count)
            )
            if focus_target is not None:
                focus_target.focus_field()
            return False

        self._set_nav_message("")
        self._data["subject"] = {
            "name": self._subject_name.get(),
            "email": self._subject_email.get(),
            "birth": self._subject_birth.get(),
            "phone": self._subject_phone.get(),
            # Protects the subject's signing key (S5); dropped after sealing.
            "password": self._subject_password.get(),
            # The subject signs at S3, so the sealing is attended.
            "participation": t("seal.participation"),
        }
        self._data["signature_lines"] = self._signature_pad.get_lines()

        # Set signer info on the enhanced signature pad
        today_str = datetime.now().strftime("%Y-%m-%d")
        self._signature_pad.set_signer_info(
            self._subject_name.get(), today_str,
        )
        self._data["signature_data"] = self._signature_pad.get_signature_data()

        return True

    # --- S4: Seal record preview ------------------------------------------

    def _build_s4(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("seal.s4_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._s4_summary = SummaryView(parent)
        self._s4_summary.pack(fill="both", expand=True)

        self._validators.append(self._validate_s4)

    def _validate_s4(self) -> bool:
        """S4 is a review of the inputs; S5 builds and signs the record."""
        return True

    @staticmethod
    def _section_title(key: str) -> str:
        """Strip bracket decoration from legacy i18n section keys."""
        return t(key).strip("[] ")

    @staticmethod
    def _file_size_text(meta: Optional[dict[str, Any]]) -> str:
        if not meta:
            return ""
        size = int(meta.get("size", 0))
        return f"{size:,} bytes ({size / (1024 ** 3):.3f} GB)"

    def _policy_preview_rows(self) -> list[tuple]:
        """S4 rows for the seal mode and unlock days chosen at S2."""
        mode = self._data.get("seal_mode", MODE_STANDARD)
        rows: list[tuple] = seal_mode_rows({"seal_mode": mode})
        rows.append((
            t("summary.unlock_days"),
            t("summary.unlock_days_value").format(v=self._data.get("unlock_days", "")),
        ))
        if self._data.get("seal_id"):
            rows.append((t("summary.case_seal_id"), self._data["seal_id"]))
        if mode == MODE_STRICT:
            rows.append(("", t("mode.strict_warning"), "warning"))
        return rows

    def _refresh_s4_preview(self) -> None:
        """Populate the S4 preview cards with collected data."""
        investigator = self._data.get("investigator", {})
        seizure = self._data.get("seizure", {})
        media = self._data.get("media", {})
        subject = self._data.get("subject", {})
        meta = self._data.get("file_metadata")

        file_rows: list[tuple] = [
            (t("summary.source_file"), self._data.get("source_file", "")),
            (t("summary.chunk_size"), f"{self._data.get('chunk_size_gb', '')} GB"),
        ]
        if meta:
            file_rows.extend([
                (t("summary.file_size"), self._file_size_text(meta)),
                (t("summary.sha256"), meta.get("sha256", "")),
                (t("summary.md5"), meta.get("md5", "")),
            ])
        enc_path = self._data.get("enc_path")
        if enc_path:
            file_rows.append((t("summary.enc_file"), enc_path))

        sections = [
            {
                "title": self._section_title("preview.case_info"),
                "rows": [
                    (t("summary.case_number"), self._data.get("case_number", "")),
                    (t("summary.investigator"), investigator.get("name", "")),
                    (t("summary.rank"), investigator.get("rank", "")),
                ],
            },
            {
                "title": self._section_title("preview.seizure_info"),
                "rows": [
                    (t("summary.seizure_datetime"), seizure.get("date", "")),
                    (t("summary.seizure_location"), seizure.get("location", "")),
                    (t("seal.device_user"), seizure.get("device_user", "")),
                ],
            },
            {
                "title": self._section_title("preview.media_info"),
                "rows": [
                    (t("seal.storage_type"), media.get("type", "")),
                    (t("summary.manufacturer"), media.get("manufacturer", "")),
                    (t("summary.model"), media.get("model", "")),
                    (t("summary.serial"), media.get("serial", "")),
                ],
            },
            {
                "title": t("mode.section_title"),
                "rows": self._policy_preview_rows(),
            },
            {
                "title": self._section_title("preview.subject_info"),
                "rows": [
                    (t("summary.subject"), subject.get("name", "")),
                    (t("summary.email"), subject.get("email", "")),
                    (t("summary.dob"), subject.get("birth", "")),
                    (t("summary.phone"), subject.get("phone", "")),
                ],
            },
            {
                "title": self._section_title("preview.target_file_section"),
                "rows": file_rows,
            },
            {
                "title": "",
                "rows": [("", t("preview.confirm_next"))],
            },
        ]
        self._s4_summary.render(sections)

    # --- S5: Digital signature progress -----------------------------------

    def _build_s5(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("seal.s5_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._s5_status = tk.Text(
            parent,
            wrap="word",
            state="disabled",
            font=get_font("caption"),
            bg=get_color("card_bg"),
            fg=get_color("text"),
            relief="solid",
            bd=1,
            highlightthickness=0,
            height=18,
        )
        self._s5_status.pack(fill="both", expand=True, pady=4)

        self._s5_progress_label = tk.Label(
            parent, text=t("seal.s5_waiting"), anchor="w",
            bg=get_color("bg"), fg=get_color("text_secondary"),
            font=get_font("small"),
        )
        self._s5_progress_label.pack(fill="x", pady=4)

        self._validators.append(self._validate_s5)

    def _validate_s5(self) -> bool:
        """S5 passes once the seal is saved; after a failure, Next retries."""
        if self._sealed():
            return True
        if not self._seal_running:
            self._start_background_seal()
        return False

    def _update_s5_status(self, message: str) -> None:
        """Append a status line to the S5 status text."""
        try:
            self._s5_status.configure(state="normal")
            self._s5_status.insert("end", f"  {message}\n")
            self._s5_status.see("end")
            self._s5_status.configure(state="disabled")
        except tk.TclError:
            pass

    def _trigger_s5_signing(self) -> None:
        """Entering S5 starts the seal (S4-S7) unless done or running."""
        if self._sealed() or self._seal_running:
            return
        self._start_background_seal()

    def _seal_request(self) -> dict[str, Any]:
        """The wizard data run_seal_steps needs (no key, no process).

        A deep copy: the worker thread never shares a dict with the wizard.
        """
        return copy.deepcopy(
            {k: self._data[k] for k in _SEAL_REQUEST_KEYS if k in self._data}
        )

    def _start_background_seal(self) -> None:
        """Run S4-S7 of SealProcess on a worker thread (S5 screen)."""
        self._seal_running = True
        self._set_busy(True, t("seal.s5_running"))
        self._s5_progress_label.configure(
            text=t("seal.s5_running"), fg=get_color("text_secondary")
        )
        self._update_s5_status(t("seal.sig_process_start"))
        try:
            start_background_seal(
                self, self._ensure_process(), self._seal_request(),
                on_progress=self._update_s5_status,
                on_success=self._on_seal_success,
                on_error=self._on_seal_error,
                cancel_event=self._async_cancel,
            )
        except Exception as exc:  # the worker could not even start
            self._on_seal_error(exc)

    def _on_seal_success(self, result: SealResult) -> None:
        """Keep the saved seal; from here on it can only be completed.

        Shares 1 and 2 go to the S6 handout panel (saved to files there);
        the wizard keeps only their fingerprints, and ``_seal_result`` keeps
        no share text. The process, which still holds the AES key, is
        released.
        """
        record = json.loads(result.record_json)
        subject = {
            k: v for k, v in self._data.get("subject", {}).items()
            if k != "password"
        }
        mode = record.get("seal_mode", MODE_STANDARD)
        self._share_prints = tuple(fingerprint_of(s) for s in result.key_shares)
        self._handout_panel.load(result.seal_id, result.key_shares[:2], mode)
        self._seal_result = dataclasses.replace(result, key_shares=_NO_SHARES)
        self._process = None
        self._data.update({
            "seal_id": result.seal_id,
            "record_json": result.record_json,
            "record_dict": record,
            "pdf_path": result.pdf_path,
            "unlock_time_iso": result.unlock_time_iso,
            "seal_mode": mode,
            "subject": subject,
            "signature_done": True,
        })
        self._seal_running = False
        self._set_busy(False)
        self._update_s5_status(t("seal.sig_process_done"))
        self._s5_progress_label.configure(
            text=t("seal.s5_complete"), fg=get_color("success_text")
        )
        logger.info(
            "봉인 완료: seal_id=%s mode=%s", result.seal_id, self._data["seal_mode"]
        )

    def _on_seal_error(self, exc: Exception) -> None:
        """Show the failing step; the wizard stays on S5 and Next retries."""
        step = getattr(exc, "step", "S4-S7")
        cause = getattr(exc, "cause", exc)
        logger.warning("봉인 실패 (%s): %s", step, cause)
        self._seal_running = False
        self._set_busy(False)
        self._update_s5_status(t("seal.failed_status").format(step=step, v=cause))
        self._s5_progress_label.configure(
            text=t("seal.failed_retry"), fg=get_color("danger_text")
        )
        messagebox.showerror(
            t("seal.failed_title"),
            t("seal.failed_msg").format(step=step, v=cause),
            parent=self.winfo_toplevel(),
        )
        self._set_nav_message(t("seal.failed_retry"))

    # --- S6: Key split results (unlock time from the signed record) --------

    def _build_s6(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("seal.s6_title"),
            font=get_font("subheader"),
        ).pack(anchor="w", pady=(0, 12))

        self._s6_result = tk.Text(
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
        self._s6_result.pack(fill="both", expand=True, pady=4)

        # Shares 1 and 2 are handed out here, as two separate .share files.
        self._handout_panel = ShareHandoutPanel(
            parent, ask_save_path=self._ask_share_path
        )
        self._handout_panel.pack(fill="x", pady=(4, 0))

        self._validators.append(self._validate_s6)

    def _validate_s6(self) -> bool:
        """S6 -> S7 once the seal is saved and shares 1 and 2 are in files."""
        if self._seal_result is None:
            return False
        if not self._handout_panel.all_saved():
            self._set_nav_message(t("handout.save_both_first"))
            return False
        return True

    def _s6_lines(self) -> list[str]:
        result = self._seal_result
        if result is None or len(self._share_prints) != 4:
            return [t("keysplit.failed")]
        mode = self._data.get("seal_mode", MODE_STANDARD)
        shares = self._share_prints
        lines = [
            keysplit_title(mode),
            "",
            t("keysplit.share_subject").format(v=shares[0]),
            t("keysplit.share_investigator").format(v=shares[1]),
            t("keysplit.share_system").format(v=shares[2]),
            t("keysplit.share_admin").format(v=shares[3]),
            t("keysplit.fingerprint_note"),
            "",
            t("keysplit.unlock_signed").format(v=result.unlock_time_iso),
            t("keysplit.recovery").format(v=recovery_shares_text(mode)),
            "",
            t("keysplit.subject_store"),
            t("keysplit.investigator_store"),
            t("keysplit.system_store"),
        ]
        if mode == MODE_STRICT:
            lines += ["", t("mode.strict_warning")]
        return lines

    def _refresh_s6_result(self) -> None:
        """Show the key split of the saved seal (read from the SealResult)."""
        self._s6_result.configure(state="normal")
        self._s6_result.delete("1.0", "end")
        self._s6_result.insert("1.0", "\n".join(self._s6_lines()))
        self._s6_result.configure(state="disabled")

    # --- S7: Completion summary -------------------------------------------

    def _build_s7(self, parent: tk.Frame) -> None:
        tk.Label(
            parent,
            text=t("seal.s7_title"),
            font=get_font("subheader"),
            bg=get_color("bg"),
            fg=get_color("heading"),
        ).pack(anchor="w", pady=(0, 12))

        self._s7_summary = SummaryView(parent)
        self._s7_summary.pack(fill="both", expand=True, pady=4)

        self._validators.append(self._validate_s7)

    def _validate_s7(self) -> bool:
        """Completion needs a saved seal (no path completes without one)."""
        return self._sealed()

    def _s7_key_rows(self) -> list[tuple]:
        """Mode, unlock time, shares and policy status of the saved seal."""
        record = self._data.get("record_dict") or {}
        mode = self._data.get("seal_mode", MODE_STANDARD)
        signed = "policy" in record
        rows: list[tuple] = seal_mode_rows(record)
        rows.extend([
            (t("summary.unlock_time"), self._data.get("unlock_time_iso", "N/A")),
            (t("summary.key_shares"), key_shares_summary(mode)),
            (
                t("summary.policy"),
                t("summary.policy_signed") if signed else t("summary.policy_absent"),
                "success" if signed else "warning",
            ),
        ])
        rows.extend(share_file_rows(self._handout_panel.saved()))
        return rows

    def _refresh_s7_summary(self) -> None:
        """Populate the final summary cards with time information."""
        from .progress_dialog import _fmt_time

        seal_id = self._data.get("seal_id", "N/A")
        enc_start = self._data.get("encrypt_start_time", "N/A")
        enc_end = self._data.get("encrypt_end_time", "N/A")
        enc_elapsed = self._data.get("encrypt_elapsed", 0)
        file_size_str = self._file_size_text(self._data.get("file_metadata"))

        sections = [
            {
                "title": t("complete.seal_title").strip(),
                "badge": (t("common.complete"), "success"),
                "rows": [
                    (t("summary.seal_id"), seal_id),
                    (t("summary.case_number"), self._data.get("case_number", "")),
                    (t("summary.subject"), self._data.get("subject", {}).get("name", "")),
                    (t("summary.investigator"), self._data.get("investigator", {}).get("name", "")),
                ],
            },
            {
                "title": self._section_title("complete.file_section"),
                "rows": [
                    (t("summary.source_file"), self._data.get("source_file", "")),
                    (t("summary.file_size"), file_size_str),
                    (t("summary.enc_file"), self._data.get("enc_path", "N/A")),
                    (t("summary.signed_pdf"), self._data.get("pdf_path", "N/A")),
                ],
            },
            {
                "title": self._section_title("complete.time_section"),
                "rows": [
                    (t("summary.enc_start"), enc_start),
                    (t("summary.enc_end"), enc_end),
                    (t("summary.elapsed"), _fmt_time(enc_elapsed)),
                ],
            },
            {
                "title": self._section_title("complete.key_section"),
                "rows": self._s7_key_rows(),
            },
            {
                "title": t("summary.notice"),
                "rows": [
                    ("", _clean_multiline(t("complete.seal_saved"))),
                    ("", _clean_multiline(t("complete.key_instruction"))),
                ],
            },
        ]
        self._s7_summary.render(sections)

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
        self._step_label.configure(
            text=t("common.step_of").format(current=step_num, total=self.TOTAL_STEPS)
        )
        # Once sealed (S5 done) there is no way back, and nothing to cancel.
        if index >= 4 and self._sealed():
            self._prev_btn.configure(state="disabled")
        elif index > 0:
            self._prev_btn.configure(state="normal")
        else:
            self._prev_btn.configure(state="disabled")
        self._cancel_btn.configure(
            state="disabled" if self._sealed() or self._busy else "normal"
        )

        if index == self.TOTAL_STEPS - 1:
            self._next_btn.configure(text=t("common.complete"))
        else:
            self._next_btn.configure(text=t("common.next"))

        # Update step indicator
        self._step_indicator.set_active(index)

        # Refresh dynamic content for specific steps
        if index == 3:
            self._refresh_s4_preview()
        elif index == 4:
            self._trigger_s5_signing()
        elif index == 5:
            self._refresh_s6_result()
        elif index == 6:
            self._refresh_s7_summary()

    def _on_step_click(self, step_index: int) -> None:
        """Handle step indicator click to navigate or view past steps."""
        if self._busy:
            return
        actual = self._current_step if self._review_return is None else self._review_return
        if step_index > actual or step_index == self._current_step:
            return
        # After sealing, S1-S4 can only be reviewed read-only.
        if self._sealed() and step_index < 4:
            self._show_step_readonly(step_index)
            return
        if self._review_return is not None:
            self._return_to_actual(step_index)
            return
        self._show_step(step_index)

    def _show_step_readonly(self, index: int) -> None:
        """Show a past step in read-only mode with a "back to current" button.

        The step to return to is kept across nested review visits, and the
        reviewed step's inputs are disabled: after sealing, S1-S4 values can
        no longer take effect (the record is signed and saved).
        """
        if self._review_return is None:
            self._review_return = self._current_step
        actual_step = self._review_return
        self._show_step(index)
        self._disable_inputs(self._steps[index])
        self._next_btn.configure(
            text=t("common.back_to_current"),
            command=lambda: self._return_to_actual(actual_step),
        )
        self._prev_btn.configure(state="disabled")

    def _disable_inputs(self, widget: tk.Misc) -> None:
        """Disable every input widget below ``widget``."""
        for child in widget.winfo_children():
            if isinstance(child, _INPUT_WIDGETS):
                try:
                    child.configure(state="disabled")
                except tk.TclError:
                    pass
            self._disable_inputs(child)

    def _return_to_actual(self, actual_step: int) -> None:
        """Return to the actual current step from readonly view."""
        self._review_return = None
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

    def _on_escape_key(self, _event: Optional[tk.Event]) -> None:  # type: ignore[type-arg]
        if self._busy or self._sealed():
            return
        self._handle_cancel()

    def _go_next(self) -> None:
        """Advance to the next step after validation."""
        if self._busy:
            return
        if self._review_return is not None:
            # Reviewing a past step (also reached by the Return key): go back,
            # never validate the reviewed step.
            self._return_to_actual(self._review_return)
            return
        idx = self._current_step
        validator = self._validators[idx]
        if not validator():
            return

        if idx == self.TOTAL_STEPS - 1:
            # Final step -- complete. The shares were handed out at S6;
            # drop them before the application takes over.
            self._handout_panel.clear()
            if self._on_complete is not None:
                self._on_complete(self._data)
            return

        logger.debug("Advancing from S%d to S%d", idx + 1, idx + 2)
        self._show_step(idx + 1)

    def _go_prev(self) -> None:
        """Return to the previous step."""
        if self._busy:
            return
        if self._current_step > 0:
            self._show_step(self._current_step - 1)

    def _handle_cancel(self) -> None:
        """Confirm cancellation; a saved seal is completed, not cancelled."""
        if self._busy or self._sealed():
            return
        if messagebox.askyesno(
            t("cancel.title"),
            t("seal.cancel_confirm"),
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
