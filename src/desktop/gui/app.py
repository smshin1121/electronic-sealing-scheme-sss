"""Main application window for the digital evidence electronic sealing system.

Provides a ttkbootstrap cosmo themed 900x650 window with menu-driven navigation
between the seal, unseal, and reseal process screens.
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox
from typing import Any, Optional

from .i18n import t, get_lang, set_lang, add_listener
from .theme import COLORS, FONTS, SPACING, get_color, get_font, get_spacing, apply_theme
from .toast import ToastManager

logger = logging.getLogger(__name__)


class MainApp:
    """Top-level application controller.

    Manages the root Tk window, menu bar, and switching between
    process screens (seal wizard, unseal, reseal).

    Attributes:
        root: The Tk root window.
        db_path: Path to the SQLite database file.
    """

    WINDOW_WIDTH = 1000
    WINDOW_HEIGHT = 700

    def __init__(self, *, db_path: str = "") -> None:
        self.root = tk.Tk()
        self.root.title(t("app.title"))
        self.root.geometry(f"{self.WINDOW_WIDTH}x{self.WINDOW_HEIGHT}")
        self.root.minsize(800, 600)
        self.root.configure(bg=get_color("bg"))

        # Apply custom design system theme (pure tkinter, no ttkbootstrap override)
        apply_theme(self.root)

        self.db_path = db_path
        self._current_frame: Optional[tk.Frame] = None
        self._current_view: str = "home"  # track current view for refresh

        # Non-modal toast notifications (informational feedback)
        self.toasts = ToastManager()

        self._build_menu()
        self._build_main_frame()
        self._show_home()

        add_listener(self._on_language_change)

    # ------------------------------------------------------------------
    # Menu
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        """Create the application menu bar."""
        self._menubar = tk.Menu(self.root)

        self._process_menu = tk.Menu(self._menubar, tearoff=0)
        self._process_menu.add_command(
            label=t("menu.seal"), command=self._on_seal
        )
        self._process_menu.add_command(
            label=t("menu.unseal"), command=self._on_unseal
        )
        self._process_menu.add_command(
            label=t("menu.reseal"), command=self._on_reseal
        )
        self._process_menu.add_separator()
        self._process_menu.add_command(
            label=t("menu.case_manager"), command=self._on_case_manager
        )
        self._process_menu.add_separator()
        self._process_menu.add_command(
            label=t("menu.exit"), command=self._on_exit
        )
        self._menubar.add_cascade(
            label=t("menu.process"), menu=self._process_menu
        )

        self._help_menu = tk.Menu(self._menubar, tearoff=0)
        self._help_menu.add_command(
            label=t("menu.about"), command=self._on_about
        )
        self._menubar.add_cascade(
            label=t("menu.help"), menu=self._help_menu
        )

        # Language menu
        self._lang_menu = tk.Menu(self._menubar, tearoff=0)
        self._lang_menu.add_command(
            label=t("menu.lang_ko"),
            command=lambda: set_lang("ko"),
        )
        self._lang_menu.add_command(
            label=t("menu.lang_en"),
            command=lambda: set_lang("en"),
        )
        self._menubar.add_cascade(
            label=t("menu.language"), menu=self._lang_menu
        )

        self.root.config(menu=self._menubar)

    # ------------------------------------------------------------------
    # Language change handler
    # ------------------------------------------------------------------

    def _on_language_change(self) -> None:
        """Update all UI text when language changes."""
        # Window title
        self.root.title(t("app.title"))

        # Rebuild menu labels
        self._process_menu.entryconfigure(0, label=t("menu.seal"))
        self._process_menu.entryconfigure(1, label=t("menu.unseal"))
        self._process_menu.entryconfigure(2, label=t("menu.reseal"))
        # index 3 is separator
        self._process_menu.entryconfigure(4, label=t("menu.case_manager"))
        # index 5 is separator
        self._process_menu.entryconfigure(6, label=t("menu.exit"))

        self._menubar.entryconfigure(1, label=t("menu.process"))

        self._help_menu.entryconfigure(0, label=t("menu.about"))
        self._menubar.entryconfigure(2, label=t("menu.help"))

        self._lang_menu.entryconfigure(0, label=t("menu.lang_ko"))
        self._lang_menu.entryconfigure(1, label=t("menu.lang_en"))
        self._menubar.entryconfigure(3, label=t("menu.language"))

        # Refresh current view so the new language applies everywhere.
        # Wizards hold in-progress user input — rebuilding them would lose
        # data, so inform the user the change applies from the next screen.
        if self._current_view == "home":
            self._show_home()
            self.toasts.show(self.root, t("lang.changed"), toast_type="info")
        elif self._current_view == "case_manager":
            self._on_case_manager()
            self.toasts.show(self.root, t("lang.changed"), toast_type="info")
        else:
            self.toasts.show(
                self.root, t("lang.applied_next"), toast_type="info"
            )

    # ------------------------------------------------------------------
    # Main content area
    # ------------------------------------------------------------------

    def _build_main_frame(self) -> None:
        """Create the main content container."""
        self._container = tk.Frame(self.root, bg=get_color("bg"))
        self._container.pack(fill="both", expand=True)

    def _clear_content(self) -> None:
        """Remove the current content frame."""
        if self._current_frame is not None:
            self._current_frame.destroy()
            self._current_frame = None

    def _set_content(self, frame: tk.Frame) -> None:
        """Replace the content area with the given frame.

        NOTE: view handlers must call ``_clear_content()`` BEFORE
        constructing the new view. Wizards capture and override the
        toplevel key bindings in their constructor — destroying the old
        wizard *after* the new one is built would restore the old
        (stale) bindings over the new wizard's ones.
        """
        self._clear_content()
        self._current_frame = frame
        frame.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Home screen
    # ------------------------------------------------------------------

    def _show_home(self) -> None:
        """Display the home dashboard."""
        from .dashboard import Dashboard

        self._current_view = "home"
        # 이전 뷰를 먼저 파괴 — 새 위자드 생성 후 파괴하면 이전
        # 위자드의 <Destroy> 핸들러가 새 바인딩을 덮어쓴다.
        self._clear_content()
        frame = Dashboard(self._container, self)
        self._set_content(frame)

    # ------------------------------------------------------------------
    # Process handlers
    # ------------------------------------------------------------------

    def _on_case_manager(self) -> None:
        """Switch to the case management screen."""
        from .case_manager import CaseManager

        self._current_view = "case_manager"
        # 이전 뷰를 먼저 파괴 — 새 위자드 생성 후 파괴하면 이전
        # 위자드의 <Destroy> 핸들러가 새 바인딩을 덮어쓴다.
        self._clear_content()
        frame = tk.Frame(self._container)
        manager = CaseManager(frame, self, on_back=self._show_home)
        manager.pack(fill="both", expand=True)
        self._set_content(frame)
        logger.info("케이스 관리 화면 진입")

    def _on_seal(self) -> None:
        """Switch to the seal wizard."""
        from .seal_wizard import SealWizard

        self._current_view = "seal"
        # 이전 뷰를 먼저 파괴 — 새 위자드 생성 후 파괴하면 이전
        # 위자드의 <Destroy> 핸들러가 새 바인딩을 덮어쓴다.
        self._clear_content()
        frame = tk.Frame(self._container)
        wizard = SealWizard(
            frame,
            self,
            on_complete=self._on_seal_complete,
            on_cancel=self._on_process_cancel,
        )
        wizard.pack(fill="both", expand=True)
        self._set_content(frame)
        logger.info("봉인 프로세스 시작")

    def _on_unseal(self) -> None:
        """Switch to the unseal wizard."""
        from .unseal_wizard import UnsealWizard

        self._current_view = "unseal"
        # 이전 뷰를 먼저 파괴 — 새 위자드 생성 후 파괴하면 이전
        # 위자드의 <Destroy> 핸들러가 새 바인딩을 덮어쓴다.
        self._clear_content()
        frame = tk.Frame(self._container)
        wizard = UnsealWizard(
            frame,
            self,
            on_complete=self._on_unseal_complete,
            on_cancel=self._on_process_cancel,
        )
        wizard.pack(fill="both", expand=True)
        self._set_content(frame)
        logger.info("봉인해제 프로세스 시작")

    def _on_reseal(self) -> None:
        """Switch to the reseal wizard."""
        from .reseal_wizard import ResealWizard

        self._current_view = "reseal"
        # 이전 뷰를 먼저 파괴 — 새 위자드 생성 후 파괴하면 이전
        # 위자드의 <Destroy> 핸들러가 새 바인딩을 덮어쓴다.
        self._clear_content()
        frame = tk.Frame(self._container)
        wizard = ResealWizard(
            frame,
            self,
            on_complete=self._on_reseal_complete,
            on_cancel=self._on_process_cancel,
        )
        wizard.pack(fill="both", expand=True)
        self._set_content(frame)
        logger.info("재봉인 프로세스 시작")

    def _on_seal_with_case(self, case_data: dict[str, Any]) -> None:
        """Start seal wizard with case info pre-filled."""
        from .seal_wizard import SealWizard

        self._current_view = "seal"
        # 이전 뷰를 먼저 파괴 — 새 위자드 생성 후 파괴하면 이전
        # 위자드의 <Destroy> 핸들러가 새 바인딩을 덮어쓴다.
        self._clear_content()
        frame = tk.Frame(self._container)
        wizard = SealWizard(
            frame,
            self,
            on_complete=self._on_seal_complete,
            on_cancel=self._on_process_cancel,
            prefill_data=case_data,
        )
        wizard.pack(fill="both", expand=True)
        self._set_content(frame)
        logger.info("봉인 프로세스 시작 (케이스 연동): seal_id=%s", case_data.get("seal_id"))

    def _on_unseal_with_case(self, case_data: dict[str, Any]) -> None:
        """Start unseal wizard with case info pre-filled."""
        from .unseal_wizard import UnsealWizard

        self._current_view = "unseal"
        # 이전 뷰를 먼저 파괴 — 새 위자드 생성 후 파괴하면 이전
        # 위자드의 <Destroy> 핸들러가 새 바인딩을 덮어쓴다.
        self._clear_content()
        frame = tk.Frame(self._container)
        wizard = UnsealWizard(
            frame,
            self,
            on_complete=self._on_unseal_complete,
            on_cancel=self._on_process_cancel,
            prefill_data=case_data,
        )
        wizard.pack(fill="both", expand=True)
        self._set_content(frame)
        logger.info("봉인해제 프로세스 시작 (케이스 연동): seal_id=%s", case_data.get("seal_id"))

    def _on_reseal_with_case(self, case_data: dict[str, Any]) -> None:
        """Start reseal wizard with case info pre-filled."""
        from .reseal_wizard import ResealWizard

        self._current_view = "reseal"
        # 이전 뷰를 먼저 파괴 — 새 위자드 생성 후 파괴하면 이전
        # 위자드의 <Destroy> 핸들러가 새 바인딩을 덮어쓴다.
        self._clear_content()
        frame = tk.Frame(self._container)
        wizard = ResealWizard(
            frame,
            self,
            on_complete=self._on_reseal_complete,
            on_cancel=self._on_process_cancel,
            prefill_data=case_data,
        )
        wizard.pack(fill="both", expand=True)
        self._set_content(frame)
        logger.info("재봉인 프로세스 시작 (케이스 연동): seal_id=%s", case_data.get("seal_id"))

    def _ensure_seal_record_exists(self, data: dict[str, Any], seal_id: str) -> None:
        """Ensure a seal_records row exists in DB for the given seal_id.

        When running a standalone seal (not from case manager), no DB row
        exists yet.  This inserts one so that the subsequent UPDATE in
        update_case_meta actually affects a row.
        """
        if not self.db_path or seal_id in ("", "N/A"):
            return
        try:
            from desktop.db.sqlite_store import get_seal_record, save_seal_record
            import json

            existing = get_seal_record(self.db_path, seal_id)
            if existing is None:
                record_json = json.dumps(
                    data.get("record_dict", {}), ensure_ascii=False,
                )
                pdf_path = data.get("pdf_path", "")
                save_seal_record(self.db_path, seal_id, record_json, pdf_path)
                logger.info("독립 프로세스: DB 레코드 INSERT 완료 seal_id=%s", seal_id)
        except Exception as exc:
            logger.warning("seal_record INSERT 실패: %s", exc)

    def _on_seal_complete(self, data: dict[str, Any]) -> None:
        """Handle seal wizard completion."""
        seal_id = data.get("seal_id", "N/A")
        logger.info("봉인 완료: seal_id=%s", seal_id)
        self._ensure_seal_record_exists(data, seal_id)
        self._save_case_meta(data, seal_id, default_status="S1U0R0")
        self._show_home()
        self.toasts.show(
            self.root,
            f"{t('seal_complete.msg')}  (Seal ID: {seal_id})",
            toast_type="success",
            duration=5000,
        )

    def _on_unseal_complete(self, data: dict[str, Any]) -> None:
        """Handle unseal wizard completion."""
        seal_id = data.get("seal_id", "N/A")
        hash_ok = data.get("decrypt_result", {}).get("hash_verified", False)
        logger.info(
            "봉인해제 완료: seal_id=%s, hash_verified=%s", seal_id, hash_ok
        )
        self._ensure_seal_record_exists(data, seal_id)
        self._save_case_meta(data, seal_id, default_status="S1U1R0")
        if hash_ok:
            self._show_home()
            self.toasts.show(
                self.root,
                f"{t('unseal_complete.msg')}  (Seal ID: {seal_id})\n"
                f"{t('hash.verified')}",
                toast_type="success",
                duration=5000,
            )
        else:
            # Hash verification failure is a critical signal — keep it modal
            messagebox.showwarning(
                t("unseal_complete.title"),
                f"{t('unseal_complete.msg')}\n\n"
                f"Seal ID: {seal_id}\n"
                f"{t('hash.failed')}",
            )
            self._show_home()

    def _on_reseal_complete(self, data: dict[str, Any]) -> None:
        """Handle reseal wizard completion."""
        seal_id = data.get("seal_id", "N/A")
        unlock_time = data.get("unlock_time_iso", "N/A")
        logger.info("재봉인 완료: seal_id=%s", seal_id)
        self._ensure_seal_record_exists(data, seal_id)
        self._save_case_meta(data, seal_id, default_status="")
        self._show_home()
        self.toasts.show(
            self.root,
            f"{t('reseal_complete.msg')}  (Seal ID: {seal_id})\n"
            f"unlock_time: {unlock_time}",
            toast_type="success",
            duration=5000,
        )

    def _save_case_meta(
        self, data: dict[str, Any], seal_id: str, *, default_status: str
    ) -> None:
        """Extract and save searchable metadata after a process completes."""
        if not self.db_path or seal_id in ("", "N/A"):
            return

        # Extract metadata from wizard data or record_dict.  The seal
        # wizard stores the record at data["record_dict"]; the unseal /
        # reseal wizards store it under data["record_result"]["record_dict"]
        # (the U6/R6 step result) — support both so status is derived
        # from the accumulated history summary (e.g. S1U1R1).
        record = (
            data.get("record_dict")
            or data.get("record_result", {}).get("record_dict")
            or {}
        )
        case_info = record.get("case_info", {})

        case_number = (
            data.get("case_number", "")
            or case_info.get("case_number", "")
            or record.get("case_number", "")
        )
        suspect_name = (
            data.get("subject", {}).get("name", "")
            or case_info.get("suspect", "")
        )
        investigator_name = (
            data.get("investigator", {}).get("name", "")
            or case_info.get("investigator", "")
            or record.get("investigator", {}).get("name", "")
        )

        # Derive status from history if available
        history = record.get("history", {})
        if isinstance(history, dict):
            status = history.get("summary", default_status)
        elif isinstance(history, list):
            s = sum(1 for e in history if e.get("event") in ("seal", "Sealing"))
            u = sum(1 for e in history if e.get("event") in ("unseal", "Unsealing"))
            r = sum(1 for e in history if e.get("event") in ("reseal", "Resealing"))
            status = f"S{s}U{u}R{r}"
        else:
            status = default_status

        # Prepare record_json and pdf_path for update
        import json as _json
        record_json_str = (
            _json.dumps(record, ensure_ascii=False) if record else ""
        )
        pdf_path = (
            data.get("pdf_path", "")
            or data.get("record_result", {}).get("pdf_path", "")
        )

        try:
            from desktop.db import update_case_meta
            update_case_meta(
                self.db_path,
                seal_id,
                case_number=case_number,
                suspect_name=suspect_name,
                investigator=investigator_name,
                status=status or default_status,
                record_json=record_json_str,
                pdf_path=pdf_path,
            )
        except Exception as exc:
            logger.warning("케이스 메타 저장 실패: %s", exc)

    def _on_process_cancel(self) -> None:
        """Return to the home screen when a process is cancelled."""
        self._show_home()

    # ------------------------------------------------------------------
    # Application lifecycle
    # ------------------------------------------------------------------

    def _on_exit(self) -> None:
        """Prompt for confirmation before exiting."""
        if messagebox.askyesno(t("exit.title"), t("exit.confirm")):
            self.root.destroy()

    def _on_about(self) -> None:
        """Show the about dialog."""
        messagebox.showinfo(t("about.title"), t("about.desc"))

    def run(self) -> None:
        """Start the Tk main event loop."""
        self.root.mainloop()
