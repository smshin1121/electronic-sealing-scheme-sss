"""Regression tests for GUI cancellation and verification behavior.

Covers:
3. Cancellation classification — a cancel signal wrapped by another
   exception (e.g. EncryptionError) must still surface as cancellation.
4. U3/U4 pre-verification exceptions must yield all_matched=False with
   a verification_error, never a silent pass.
5. <Return> on a focused button invokes it (class binding installed by
   apply_theme) and stops propagation to wizard navigation.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture()
def root():
    """Create and teardown a Tk root window."""
    r = tk.Tk()
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


# ---------------------------------------------------------------------------
# Fix 3: cancel classification in ProgressDialog
# ---------------------------------------------------------------------------

class TestResolveTaskError:
    def test_wrapped_exception_with_cancel_flag_is_cancellation(self) -> None:
        from desktop.gui.progress_dialog import (
            _CancelledError,
            resolve_task_error,
        )

        # Crypto layer wraps the cancel signal in EncryptionError —
        # the cancel event decides, not the exception type.
        wrapped = RuntimeError("Encryption failed: user cancelled")
        result = resolve_task_error(wrapped, cancelled=True)
        assert isinstance(result, _CancelledError)

    def test_direct_cancelled_error_stays_cancellation(self) -> None:
        from desktop.gui.progress_dialog import (
            _CancelledError,
            resolve_task_error,
        )

        result = resolve_task_error(_CancelledError("stop"), cancelled=False)
        assert isinstance(result, _CancelledError)

    def test_real_error_without_cancel_is_preserved(self) -> None:
        from desktop.gui.progress_dialog import (
            _CancelledError,
            resolve_task_error,
        )

        original = ValueError("real failure")
        result = resolve_task_error(original, cancelled=False)
        assert result is original
        assert not isinstance(result, _CancelledError)


# ---------------------------------------------------------------------------
# Fix 4: U3/U4 verification exceptions must not report success
# ---------------------------------------------------------------------------

class TestPresealValidation:
    def _base_data(self, tmp_path: Path) -> dict:
        return {
            "enc_filepath": str(tmp_path / "missing.enc"),
            "seal_record_path": str(tmp_path / "missing_record.json"),
            "aes_key_hex": "ab" * 32,
            "output_dir": str(tmp_path),
            "reason": "test",
            "investigator": "tester",
            "subject_participated": False,
        }

    def test_exception_reports_mismatch_with_error(
        self, tmp_path: Path
    ) -> None:
        from desktop.gui.unseal_wizard import compute_preseal_validation

        data = self._base_data(tmp_path)  # files do not exist → error
        result = compute_preseal_validation(str(tmp_path / "t.db"), data)

        assert result["all_matched"] is False
        assert result["verification_error"]
        assert result["verification_items"] == []

    def test_corrupt_seal_record_reports_error(self, tmp_path: Path) -> None:
        from desktop.gui.unseal_wizard import compute_preseal_validation

        data = self._base_data(tmp_path)
        # enc file exists but the seal record is corrupt JSON.
        Path(data["enc_filepath"]).write_bytes(b"\x00" * 64)
        Path(data["seal_record_path"]).write_text(
            "{ not valid json", encoding="utf-8"
        )

        result = compute_preseal_validation(str(tmp_path / "t.db"), data)

        assert result["all_matched"] is False
        assert result["verification_error"]


# ---------------------------------------------------------------------------
# Fix 5: <Return> invokes the focused button
# ---------------------------------------------------------------------------

class TestButtonReturnBinding:
    def test_apply_theme_installs_class_bindings(self, root: tk.Tk) -> None:
        from desktop.gui.theme import apply_theme

        apply_theme(root)
        assert root.bind_class("Button", "<Return>")
        assert root.bind_class("TButton", "<Return>")

    def test_return_invokes_enabled_button(self, root: tk.Tk) -> None:
        from desktop.gui.theme import _invoke_focused_button

        clicks: list[int] = []
        btn = tk.Button(root, command=lambda: clicks.append(1))
        event = SimpleNamespace(widget=btn)

        outcome = _invoke_focused_button(event)  # type: ignore[arg-type]

        assert clicks == [1]
        # "break" stops the toplevel <Return> wizard-navigation binding.
        assert outcome == "break"

    def test_return_skips_disabled_button(self, root: tk.Tk) -> None:
        from desktop.gui.theme import _invoke_focused_button

        clicks: list[int] = []
        btn = tk.Button(root, command=lambda: clicks.append(1))
        btn.configure(state="disabled")
        event = SimpleNamespace(widget=btn)

        outcome = _invoke_focused_button(event)  # type: ignore[arg-type]

        assert clicks == []
        assert outcome == "break"

    def test_return_guard_still_blocks_global_navigation(
        self, root: tk.Tk
    ) -> None:
        """The navigation guard keeps treating buttons as unsafe so the
        class binding (not global navigation) handles Enter."""
        from desktop.gui.widgets import is_return_navigation_safe

        assert is_return_navigation_safe(tk.Button(root)) is False
