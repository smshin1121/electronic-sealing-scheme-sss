"""Seal process wizard (S1 through S7).

Guides the investigator through the complete sealing workflow:
S1 - File selection and encryption settings
S2 - Seizure / sealing information
S3 - Subject (suspect) information
S4 - Seal record preview and review
S5 - Digital signature progress
S6 - Key splitting results and unlock_time setting
S7 - Completion summary
"""

from __future__ import annotations

import logging
import tkinter as tk
from datetime import datetime, timedelta, timezone
from tkinter import messagebox
from typing import TYPE_CHECKING, Any, Callable, Optional

from .i18n import t
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


def _clean_multiline(text: str) -> str:
    """Strip per-line indentation from an i18n multiline message."""
    return "\n".join(line.strip() for line in text.splitlines()).strip()


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
    ) -> None:
        super().__init__(master)
        self._app = app
        self._on_complete = on_complete
        self._on_cancel = on_cancel
        self._prefill_data = prefill_data
        self._current_step = 0
        self._data: dict[str, Any] = {}
        self._busy = False
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

        # 이미 암호화 완료된 경우 스킵
        if self._data.get("encryption_done"):
            return True

        # S1 검증 통과 → 바로 암호화 수행 (ProgressDialog)
        self._run_encryption()
        return self._data.get("encryption_done", False)

    def _run_encryption(self) -> None:
        """S1 파일 암호화를 ProgressDialog로 수행 (1패스: 해시는 암호화 중 인라인 계산)."""
        import os
        from pathlib import Path
        from .progress_dialog import ProgressDialog

        source = self._data["source_file"]
        output_dir = self._data["output_dir"]
        chunk_gb = self._data["chunk_size_gb"]
        # GCM 안전 마진 때문에 crypto의 MAX_CHUNK_SIZE는 64GiB-16MiB로
        # UI 최대값(64GB)보다 작다 — seal_process와 동일하게 클램프.
        from desktop.crypto import MAX_CHUNK_SIZE
        chunk_bytes = min(chunk_gb * 1024 ** 3, MAX_CHUNK_SIZE)

        # AES 키: 같은 세션 재시도(취소/오류 후 '다음' 재클릭) 시 반드시
        # 기존 키를 재사용한다. 새 키를 만들면 .enc.progress 기반 resume이
        # 이전 키로 암호화된 청크에 새 키 청크를 이어붙여 영구 복호화
        # 불가가 되기 때문 (crypto 계층의 키 지문 가드와 2중 방어).
        aes_key = self._data.get("aes_key")
        if aes_key is None:
            aes_key = os.urandom(32)
            self._data["aes_key"] = aes_key
            self._data["aes_key_hex"] = aes_key.hex()

        enc_filename = Path(source).name + ".enc"
        enc_path = str(Path(output_dir) / enc_filename)
        # 취소/중단 후 위자드가 완료 없이 destroy될 때 부분 산출물을
        # 정리할 수 있도록 경로를 먼저 기록한다.
        self._data["enc_path_pending"] = enc_path

        def task_fn(progress_cb):
            from desktop.crypto import encrypt_file

            # 메타데이터(MD5/SHA-256)는 encrypt_file 내부에서 암호화
            # 읽기와 동시에 1패스로 계산된다 (별도 사전 스캔 없음).
            result = encrypt_file(
                filepath=source,
                aes_key=aes_key,
                output_path=enc_path,
                chunk_size=chunk_bytes,
                progress_cb=progress_cb,
            )
            return result

        def on_complete(result):
            import struct, json
            self._data["enc_path"] = enc_path
            self._data["enc_result"] = result
            # 1패스 인라인 해시 결과를 S4 미리보기/기록지에 사용
            self._data["file_metadata"] = result.metadata

            # .enc 파일에서 메타데이터 읽기
            try:
                with open(enc_path, "rb") as f:
                    f.seek(-4, 2)
                    meta_size = struct.unpack("<I", f.read(4))[0]
                    f.seek(-4 - meta_size, 2)
                    enc_meta = json.loads(f.read(meta_size).decode("utf-8"))
                self._data["enc_meta"] = enc_meta
            except Exception:
                pass

            self._data["encryption_done"] = True

        def on_error(exc):
            # 사용자 취소는 오류가 아니다 — 조용한 상태 메시지만 표시.
            # (.enc/.enc.progress는 같은 세션 재시도 resume을 위해 유지)
            if dlg.was_cancelled:
                self._set_nav_message(t("progress.task_cancelled"), kind="info")
                return
            messagebox.showerror(
                t("encrypt.failed_title"),
                f"{t('encrypt.failed_msg')}:\n{exc}",
                parent=self.winfo_toplevel(),
            )

        dlg = ProgressDialog(
            self.winfo_toplevel(),
            title=t("process.encryption_progress_title"),
            task_fn=task_fn,
            on_complete=on_complete,
            on_error=on_error,
        )
        self._active_dialog = dlg
        try:
            self.winfo_toplevel().wait_window(dlg)
        finally:
            self._active_dialog = None

        # 시간 정보 저장
        self._data["encrypt_start_time"] = dlg.start_time_iso
        self._data["encrypt_end_time"] = dlg.end_time_iso
        self._data["encrypt_elapsed"] = dlg.elapsed_seconds

    # --- S2: Seizure / sealing info ---------------------------------------

    def _build_s2(self, parent: tk.Frame) -> None:
        from tkinter import ttk

        tk.Label(
            parent,
            text=t("seal.s2_title"),
            font=get_font("header"),
        ).pack(anchor="w", pady=(0, 12))

        # --- Case info group ---
        case_group = ttk.LabelFrame(parent, text=t("seal.case_info"), padding=(8, 4))
        case_group.pack(fill="x", pady=(0, 8))

        self._case_number = LabeledEntry(case_group, t("seal.case_number"), required=True)
        self._case_number.pack(fill="x", pady=4)

        self._seizure_date = LabeledEntry(case_group, t("seal.seizure_date"), required=True)
        self._seizure_date.set(datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M"))
        self._seizure_date.pack(fill="x", pady=4)

        self._seizure_location = LabeledEntry(case_group, t("seal.seizure_location"), required=True)
        self._seizure_location.pack(fill="x", pady=4)

        self._media_manufacturer = LabeledEntry(case_group, t("seal.media_manufacturer"))
        self._media_manufacturer.pack(fill="x", pady=2)

        self._media_model = LabeledEntry(case_group, t("seal.media_model"))
        self._media_model.pack(fill="x", pady=2)

        self._media_serial = LabeledEntry(case_group, t("seal.media_serial"))
        self._media_serial.pack(fill="x", pady=2)

        # --- Investigator info group ---
        inv_group = ttk.LabelFrame(parent, text=t("seal.investigator_info"), padding=(8, 4))
        inv_group.pack(fill="x", pady=(0, 4))

        self._investigator_name = LabeledEntry(inv_group, t("seal.investigator_name"), required=True)
        self._investigator_name.pack(fill="x", pady=4)

        self._investigator_rank = LabeledEntry(inv_group, t("seal.investigator_rank"))
        self._investigator_rank.pack(fill="x", pady=4)

        self._validators.append(self._validate_s2)

    def _validate_s2(self) -> bool:
        fields = [
            self._case_number,
            self._seizure_date,
            self._seizure_location,
            self._investigator_name,
        ]
        invalid: list[LabeledEntry] = []
        for f in fields:
            if not f.is_valid():
                f.highlight_error()
                invalid.append(f)
            else:
                f.clear_error()
        if invalid:
            self._set_nav_message(
                t("validate.fix_errors").format(count=len(invalid))
            )
            invalid[0].focus_field()
            return False

        self._set_nav_message("")
        self._data["case_number"] = self._case_number.get()
        self._data["investigator"] = {
            "name": self._investigator_name.get(),
            "rank": self._investigator_rank.get(),
        }
        self._data["seizure"] = {
            "datetime": self._seizure_date.get(),
            "location": self._seizure_location.get(),
        }
        self._data["media"] = {
            "manufacturer": self._media_manufacturer.get(),
            "model": self._media_model.get(),
            "serial": self._media_serial.get(),
        }
        return True

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
            "password": self._subject_password.get(),
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
        """S4 -- 검토 통과 시 seal_id 생성 + record_dict 구성."""
        if not self._data.get("record_dict"):
            existing_seal_id = self._data.get("seal_id")
            self._generate_seal_data()
            # 케이스에서 시작한 경우 기존 seal_id 복원
            if existing_seal_id:
                self._data["seal_id"] = existing_seal_id
                # record_dict 내부의 seal_id도 동기화
                record = self._data.get("record_dict")
                if record:
                    record["seal_id"] = existing_seal_id
        return True

    def _generate_seal_data(self) -> None:
        """S4 통과 시 seal_id와 record_dict를 생성하여 _data에 저장."""
        from datetime import datetime, timezone

        try:
            from desktop.record import create_seal_id, build_seal_record
            seal_id = create_seal_id()
        except ImportError:
            import os
            now = datetime.now(timezone.utc)
            rand_hex = os.urandom(3).hex().upper()
            seal_id = f"S-{now.strftime('%Y%m%d')}-{rand_hex}"

        self._data["seal_id"] = seal_id

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        subject = self._data.get("subject", {})
        investigator = self._data.get("investigator", {})
        seizure = self._data.get("seizure", {})
        media = self._data.get("media", {})

        record_dict = {
            "seal_id": seal_id,
            "case_info": {
                "case_number": self._data.get("case_number", ""),
                "investigator": investigator.get("name", ""),
                "device_user": media.get("device_user", ""),
                "suspect": subject.get("name", ""),
                "storage_type": media.get("type", ""),
                "storage_info": {
                    "manufacturer": media.get("manufacturer", ""),
                    "model": media.get("model", ""),
                    "serial": media.get("serial", ""),
                },
                "seizure_time": seizure.get("datetime", now_iso),
                "seizure_location": seizure.get("location", ""),
            },
            "process_info": {
                "type": "Sealing",
                "start_time": self._data.get("encrypt_start_time", now_iso),
                "end_time": self._data.get("encrypt_end_time", now_iso),
                "file_count": 1,
                "investigator": investigator.get("name", ""),
                "reason": "",
                "participation": t("seal.participation"),
            },
            "file_info": self._build_file_info(),
            "signer_info": {
                "name": subject.get("name", ""),
                "email": subject.get("email", ""),
                "birth_date": subject.get("birth", ""),
                "phone": subject.get("phone", ""),
                "cert_fingerprint": "",
                "signature_image_hash": "",
            },
            "history": {
                "summary": "S1U0R0",
                "events": [{
                    "id": 1,
                    "seal_type": "Sealing",
                    "start_time": now_iso,
                    "end_time": "",
                    "investigator": investigator.get("name", ""),
                }],
            },
        }
        self._data["record_dict"] = record_dict

    def _build_file_info(self) -> dict:
        """암호화 결과가 있으면 실제 메타데이터로, 없으면 빈 값으로 file_info 구성."""
        from pathlib import Path

        meta = self._data.get("file_metadata")
        enc_meta = self._data.get("enc_meta", {})
        enc_path = self._data.get("enc_path", "")

        def _nt(t_val: str) -> str:
            return t_val.replace("+00:00", "Z") if t_val and t_val.endswith("+00:00") else (t_val or "")

        if meta:
            original_files = [{
                "filename": meta.filename,
                "size": meta.size,
                "md5": meta.md5,
                "sha256": meta.sha256,
                "mtime": _nt(meta.mtime),
                "ctime": _nt(meta.ctime),
                "atime": _nt(meta.atime),
            }]
        else:
            original_files = [{
                "filename": self._data.get("source_file", ""),
                "size": 0, "md5": "", "sha256": "",
                "mtime": "", "ctime": "", "atime": "",
            }]

        if enc_meta and enc_path:
            enc_size = Path(enc_path).stat().st_size if Path(enc_path).exists() else 0
            result_files = [{
                "filename": Path(enc_path).name,
                "size": enc_size,
                "encryption_algo": "AES-256-GCM",
                "enc_ended_time": self._data.get("encrypt_end_time", ""),
                "nonces": enc_meta.get("nonces", []),
                "tags": enc_meta.get("tags", []),
                "chunk_lengths": enc_meta.get("chunk_lengths", []),
            }]
        else:
            result_files = []

        return {
            "original_files": original_files,
            "result_files": result_files,
            "hash_match": True,
            "unknown_files": [],
            "derived_files": [],
        }

    @staticmethod
    def _section_title(key: str) -> str:
        """Strip bracket decoration from legacy i18n section keys."""
        return t(key).strip("[] ")

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
            gb = meta.size / (1024 ** 3)
            file_rows.extend([
                (t("summary.file_size"), f"{meta.size:,} bytes ({gb:.3f} GB)"),
                (t("summary.sha256"), meta.sha256),
                (t("summary.md5"), meta.md5),
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
                    (t("summary.seizure_datetime"), seizure.get("datetime", "")),
                    (t("summary.seizure_location"), seizure.get("location", "")),
                ],
            },
            {
                "title": self._section_title("preview.media_info"),
                "rows": [
                    (t("summary.manufacturer"), media.get("manufacturer", "")),
                    (t("summary.model"), media.get("model", "")),
                    (t("summary.serial"), media.get("serial", "")),
                ],
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
        """S5 proceeds after signature processing is triggered."""
        return self._data.get("signature_done", False)

    def _update_s5_status(self, message: str) -> None:
        """Append a status line to the S5 status text."""
        self._s5_status.configure(state="normal")
        self._s5_status.insert("end", f"  {message}\n")
        self._s5_status.see("end")
        self._s5_status.configure(state="disabled")

    def _trigger_s5_signing(self) -> None:
        """S5 화면 진입 시 자동으로 전자서명 프로세스를 백그라운드에서 시작."""
        if self._data.get("signature_done"):
            return  # 이미 완료됨

        import threading

        # Cache toplevel reference on main thread (tk.call is not thread-safe)
        _toplevel = self.winfo_toplevel()

        def _status_cb(msg: str) -> None:
            try:
                _toplevel.after(0, self._update_s5_status, msg)
            except RuntimeError:
                logger.debug("Cannot schedule status update (window destroyed?)")

        def _run_signing() -> None:
            try:
                _status_cb(t("seal.sig_process_start"))

                seal_process = self._data.get("_seal_process")
                if seal_process is None:
                    _status_cb(t("seal.sig_no_process"))
                    _run_simple_signing()
                    return

                result = seal_process.run_s5(status_cb=_status_cb)
                self._data["s5_result"] = result
                _status_cb(t("seal.sig_process_done"))

            except Exception as exc:
                _status_cb(t("seal.sig_error_continue").format(v=exc))
            finally:
                try:
                    _toplevel.after(0, self._mark_s5_done)
                except RuntimeError:
                    # Window may be destroyed; mark done directly
                    self._data["signature_done"] = True

        def _run_simple_signing() -> None:
            """SealProcess 없이 간이 서명 수행 (독립 실행 시)."""
            import json
            import hashlib
            from pathlib import Path

            seal_id = self._data.get("seal_id", "S-00000000-000000")
            output_dir = Path(self._data.get("output_dir", "."))
            output_dir.mkdir(parents=True, exist_ok=True)

            # JSON 저장
            record = self._data.get("record_dict", {})
            json_path = str(output_dir / f"{seal_id}_record.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)
            _status_cb(t("seal.record_json_saved"))

            # PDF placeholder
            pdf_path = str(output_dir / f"{seal_id}_seal_record.pdf")
            try:
                from desktop.record import render_record_pdf
                render_record_pdf(record, "seal_record.html", pdf_path)
                _status_cb(t("seal.pdf_rendered"))
            except Exception as exc:
                _status_cb(t("seal.pdf_fallback").format(v=exc))
                Path(pdf_path).write_text(f"[Placeholder] {seal_id}")

            # 인증서 생성
            try:
                from desktop.signature import (
                    generate_keypair,
                    create_self_signed_cert,
                    save_private_key,
                    save_certificate,
                )
                sig_data = json.dumps(self._data.get("signature_lines", [])).encode()
                sig_hash = hashlib.sha256(sig_data).hexdigest()
                subject = self._data.get("subject", {})
                name = subject.get("name", "Unknown")
                email = subject.get("email", "unknown@example.com")
                pw = subject.get("password")
                if not isinstance(pw, str) or not pw:
                    raise ValueError(
                        "Subject password is required for private-key encryption"
                    )

                private_key, _ = generate_keypair(2048)
                _status_cb(t("seal.rsa_keygen"))

                cert = create_self_signed_cert(private_key, name, email, sig_hash)
                _status_cb(t("seal.x509_cert"))

                cert_path = str(output_dir / f"{seal_id}_cert.pem")
                key_path = str(output_dir / f"{seal_id}_key.pem")
                save_certificate(cert, cert_path)
                save_private_key(private_key, key_path, pw)
                _status_cb(t("seal.cert_saved"))

                self._data["cert_pem_path"] = cert_path
                self._data["key_pem_path"] = key_path
            except Exception as exc:
                _status_cb(t("seal.cert_error").format(v=exc))

            self._data["pdf_path"] = pdf_path
            self._data["record_json_path"] = json_path
            _status_cb(t("seal.sig_process_done"))

        thread = threading.Thread(target=_run_signing, daemon=True)
        thread.start()

    def _mark_s5_done(self) -> None:
        """S5 완료 마킹 — 다음 버튼 활성화."""
        self._data["signature_done"] = True
        self._s5_progress_label.configure(
            text=t("seal.s5_complete"), fg=get_color("success_text")
        )

    # --- S6: Key split results + unlock_time ------------------------------

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

        unlock_frame = tk.Frame(parent)
        unlock_frame.pack(fill="x", pady=8)
        tk.Label(
            unlock_frame,
            text=t("seal.unlock_label"),
            anchor="w",
            width=20,
        ).pack(side="left")
        self._unlock_days_var = tk.IntVar(value=DEFAULT_UNLOCK_DAYS)
        self._unlock_spin = tk.Spinbox(
            unlock_frame,
            from_=MIN_UNLOCK_DAYS,
            to=MAX_UNLOCK_DAYS,
            textvariable=self._unlock_days_var,
            width=6,
        )
        self._unlock_spin.pack(side="left")
        tk.Label(unlock_frame, text=t("seal.unlock_range")).pack(
            side="left", padx=8
        )

        self._validators.append(self._validate_s6)

    def _validate_s6(self) -> bool:
        try:
            days = self._unlock_days_var.get()
            if not (MIN_UNLOCK_DAYS <= days <= MAX_UNLOCK_DAYS):
                raise ValueError
        except (tk.TclError, ValueError):
            self._set_nav_message(
                t("validate.unlock_range").format(
                    min=MIN_UNLOCK_DAYS, max=MAX_UNLOCK_DAYS
                )
            )
            self._unlock_spin.focus_set()
            return False

        self._set_nav_message("")
        now = datetime.now(tz=timezone.utc)
        unlock_time = now + timedelta(days=days)
        self._data["unlock_days"] = days
        self._data["unlock_time_iso"] = unlock_time.isoformat()
        return True

    def _refresh_s6_result(self) -> None:
        """S6 진입 시 키 분할 수행 + 결과 표시."""
        self._s6_result.configure(state="normal")
        self._s6_result.delete("1.0", "end")

        # 키 분할이 아직 안 되어 있으면 수행
        shares = self._data.get("key_shares")
        if not shares or len(shares) != 4:
            shares = self._perform_key_split()

        if shares and len(shares) == 4:
            lines = [
                t("keysplit.complete_title"),
                "",
                t("keysplit.share_subject").format(v=shares[0][:20]),
                t("keysplit.share_investigator").format(v=shares[1][:20]),
                t("keysplit.share_system").format(v=shares[2][:20]),
                t("keysplit.share_admin").format(v=shares[3][:20]),
                "",
                t("keysplit.subject_store"),
                t("keysplit.investigator_store"),
                t("keysplit.system_store"),
            ]
        else:
            lines = [t("keysplit.failed")]

        self._s6_result.insert("1.0", "\n".join(lines))
        self._s6_result.configure(state="disabled")

    def _perform_key_split(self) -> tuple[str, ...] | None:
        """AES 키를 생성하고 SSS(2-of-4)로 분할한다."""
        import os
        try:
            from desktop.crypto import split_key

            # S1에서 실제 암호화된 키가 있으면 사용, 없으면 새로 생성
            aes_key_hex = self._data.get("aes_key_hex")
            if not aes_key_hex:
                aes_key = os.urandom(32)
                aes_key_hex = aes_key.hex()
                self._data["aes_key_hex"] = aes_key_hex

            shares = split_key(aes_key_hex)
            self._data["key_shares"] = shares
            return shares
        except Exception as exc:
            logging.getLogger(__name__).warning("키 분할 실패: %s", exc)
            self._s6_result.insert("end", f"\n{t('common.error')}: {exc}")
            return None

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
        """Final step -- always valid."""
        return True

    def _refresh_s7_summary(self) -> None:
        """Populate the final summary cards with time information."""
        from .progress_dialog import _fmt_time

        seal_id = self._data.get("seal_id", "N/A")
        enc_start = self._data.get("encrypt_start_time", "N/A")
        enc_end = self._data.get("encrypt_end_time", "N/A")
        enc_elapsed = self._data.get("encrypt_elapsed", 0)

        meta = self._data.get("file_metadata")
        file_size_str = ""
        if meta:
            gb = meta.size / (1024 ** 3)
            file_size_str = f"{meta.size:,} bytes ({gb:.3f} GB)"

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
                "rows": [
                    (t("summary.unlock_time"), self._data.get("unlock_time_iso", "N/A")),
                    (t("summary.key_shares"), "4 (SSS 2-of-4)"),
                ],
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
        # S5(digital signature) 이후에는 이전 버튼 비활성화
        if index >= 4 and self._data.get("signature_done"):
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
        current = self._current_step

        # Cannot navigate to future steps
        if step_index > current:
            return

        # Same step — no-op
        if step_index == current:
            return

        # After signature, cannot go back — show readonly
        if self._data.get("signature_done") and step_index < 4:
            self._show_step_readonly(step_index)
            return

        # Normal navigation
        self._show_step(step_index)

    def _show_step_readonly(self, index: int) -> None:
        """Show a past step in read-only mode with a 'back to current' button."""
        actual_step = self._current_step
        self._show_step(index)
        # Override nav buttons for readonly viewing
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
        idx = self._current_step
        validator = self._validators[idx]
        if not validator():
            return

        if idx == self.TOTAL_STEPS - 1:
            # Final step -- complete
            if self._on_complete is not None:
                self._on_complete(self._data)
            return

        logger.debug("Advancing from S%d to S%d", idx + 1, idx + 2)
        self._show_step(idx + 1)

    def _go_prev(self) -> None:
        """Return to the previous step."""
        if self._current_step > 0:
            self._show_step(self._current_step - 1)

    def _handle_cancel(self) -> None:
        """Confirm cancellation with the user."""
        if messagebox.askyesno(
            t("cancel.title"),
            t("seal.cancel_confirm"),
            parent=self.winfo_toplevel(),
        ):
            if self._on_cancel is not None:
                self._on_cancel()

    # ------------------------------------------------------------------
    # Public API for SealProcess to update wizard state
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

    def append_s5_status(self, message: str) -> None:
        """Add a status message to the S5 signature progress view."""
        self._update_s5_status(message)

    def set_s5_complete(self) -> None:
        """Mark S5 as done so the user can proceed."""
        self._data["signature_done"] = True
        self._s5_progress_label.configure(
            text=t("seal.s5_complete"), fg=get_color("success_text")
        )
