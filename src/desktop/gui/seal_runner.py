"""Background sealing for the seal wizard (S4-S7 at the S5 screen).

Runs :func:`desktop.seal_steps.run_seal_steps` on a worker thread and
delivers every callback on the Tk thread: progress messages go through a
queue that the Tk thread drains, and the result or the failure arrives
through :func:`desktop.gui.progress_dialog.run_async`. The worker never
touches a widget.
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from typing import Any, Callable, Mapping

from desktop.seal_process import SealResult
from desktop.seal_steps import SEAL_STEP_MESSAGES, SealStepError, run_seal_steps

from .i18n import t
from .progress_dialog import run_async

logger = logging.getLogger(__name__)

# Status messages of SealProcess mapped to i18n keys; an unknown message
# (for example one carrying an exception text) is shown as it is.
_PROGRESS_KEYS: dict[str, str] = {
    SEAL_STEP_MESSAGES["S4"]: "seal.run_s4",
    SEAL_STEP_MESSAGES["S5"]: "seal.run_s5",
    SEAL_STEP_MESSAGES["S6"]: "seal.run_s6",
    SEAL_STEP_MESSAGES["S7"]: "seal.run_s7",
    "Generating signing credentials": "seal.s5_msg_credentials",
    "Local TSA ready": "seal.s5_msg_tsa_ready",
    "RSA-2048 key generated": "seal.rsa_keygen",
    "X.509 certificate generated": "seal.x509_cert",
    "Certificate and key saved": "seal.cert_saved",
    "Writing record JSON": "seal.s5_msg_record_json",
    "Rendering record PDF": "seal.s5_msg_rendering",
    "Record PDF rendered": "seal.pdf_rendered",
    "Applying PAdES signature": "seal.s5_msg_signing",
    "PDF signed successfully": "seal.s5_msg_signed",
    "Requesting RFC3161 timestamp": "seal.s5_msg_tsa_request",
    "RFC3161 timestamp verified": "seal.s5_msg_tsa_verified",
    "S5 complete": "seal.s5_msg_done",
}

POLL_MS = 100


def progress_text(message: str) -> str:
    """Localized text of a SealProcess status message."""
    key = _PROGRESS_KEYS.get(message)
    return t(key) if key else message


def start_background_seal(
    widget: tk.Misc,
    process: Any,
    request: Mapping[str, Any],
    *,
    on_progress: Callable[[str], None],
    on_success: Callable[[SealResult], None],
    on_error: Callable[[Exception], None],
    cancel_event: threading.Event,
    poll_ms: int = POLL_MS,
) -> None:
    """Seal in the background; every callback runs on the Tk thread.

    Args:
        widget: Widget whose ``after`` loop delivers the callbacks; they are
            dropped once it is destroyed or ``cancel_event`` is set.
        process: The SealProcess whose S1 has completed.
        request: Wizard data for :func:`run_seal_steps` (no key material).
        on_progress: Receives each localized progress line, in order.
        on_success: Receives the saved seal.
        on_error: Receives the :class:`SealStepError` of the failed step.
        cancel_event: Set when the wizard is destroyed.
        poll_ms: Delivery interval.
    """
    messages: "queue.SimpleQueue[str]" = queue.SimpleQueue()
    finished = threading.Event()

    def _drain() -> None:
        while True:
            try:
                message = messages.get_nowait()
            except queue.Empty:
                return
            on_progress(progress_text(message))

    def _poll() -> None:
        if cancel_event.is_set():
            return
        try:
            if not widget.winfo_exists():
                return
        except tk.TclError:
            return
        _drain()
        if not finished.is_set():
            widget.after(poll_ms, _poll)

    def _task() -> SealResult:
        try:
            result = run_seal_steps(
                process, request, on_step=lambda _s, msg: messages.put(msg)
            )
        except SealStepError as exc:
            if cancel_event.is_set():
                logger.warning(
                    "Sealing failed at %s after the wizard was closed: %s",
                    exc.step, exc.cause,
                )
            raise
        finally:
            finished.set()
        if cancel_event.is_set():
            # Nobody will show it: say where the saved seal is.
            logger.warning(
                "Seal %s was saved after the wizard was closed (%s)",
                result.seal_id, result.pdf_path,
            )
        return result

    def _ok(result: SealResult) -> None:
        _drain()
        on_success(result)

    def _err(exc: Exception) -> None:
        _drain()
        on_error(exc)

    run_async(widget, _task, _ok, _err, poll_ms=poll_ms, cancel_event=cancel_event)
    widget.after(poll_ms, _poll)
