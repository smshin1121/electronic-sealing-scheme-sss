"""Progress dialog for long-running encryption/decryption operations.

Displays a progress bar, byte/chunk counter, elapsed/remaining time,
and cancel button.  All heavy work runs on a background thread;
UI updates happen on the main thread via ``root.after()``.

Also provides :func:`run_async`, a lightweight helper to run a
callable on a worker thread and deliver the result back on the
Tk main loop — used by the wizards to keep verification/comparison
and record (PDF) generation off the main thread.
"""

from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Optional

from .i18n import t
from .theme import get_color, get_font

# Progress totals at or above this value are assumed to be byte counts
# (the crypto layer reports byte-level progress every 8 MiB buffer).
_BYTE_DISPLAY_THRESHOLD = 4 * 1024 * 1024


def _fmt_size(num_bytes: float) -> str:
    """Format a byte count as a human readable string."""
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def run_async(
    widget: tk.Misc,
    task_fn: Callable[[], Any],
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    poll_ms: int = 100,
    cancel_event: Optional[threading.Event] = None,
) -> None:
    """Run *task_fn* on a daemon thread; deliver callbacks on the Tk thread.

    Callbacks are skipped silently if *widget* has been destroyed by the
    time the task finishes, or if *cancel_event* has been set (the
    worker result is discarded). The worker itself cannot be forcibly
    interrupted — long side-effect tasks (e.g. PDF generation) run to
    completion, but their results are dropped once cancelled.
    """
    holder: dict[str, Any] = {}
    done = threading.Event()

    def _worker() -> None:
        try:
            holder["result"] = task_fn()
        except Exception as exc:  # noqa: BLE001 — delivered to on_error
            holder["error"] = exc
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True).start()

    def _poll() -> None:
        if cancel_event is not None and cancel_event.is_set():
            return
        try:
            if not widget.winfo_exists():
                return
        except tk.TclError:
            return
        if not done.is_set():
            widget.after(poll_ms, _poll)
            return
        error = holder.get("error")
        if error is not None:
            if on_error is not None:
                on_error(error)
        elif on_success is not None:
            on_success(holder.get("result"))

    widget.after(poll_ms, _poll)


class ProgressDialog(tk.Toplevel):
    """Modal dialog showing progress of a background task with time tracking.

    Usage::

        def my_task(progress_cb):
            for i in range(10):
                do_work(i)
                progress_cb(i + 1, 10)

        dlg = ProgressDialog(root, title="암호화 진행", task_fn=my_task)
        root.wait_window(dlg)
        print(dlg.elapsed_seconds, dlg.start_time_iso, dlg.end_time_iso)
    """

    POLL_INTERVAL_MS = 100

    def __init__(
        self,
        master: tk.Widget,
        *,
        title: str = "",
        task_fn: Callable[[Callable[[int, int], None]], object],
        on_complete: Optional[Callable[[object], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        super().__init__(master)
        self.title(title or t("progress.title"))
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.grab_set()

        self._task_fn = task_fn
        self._on_complete = on_complete
        self._on_error = on_error

        self._cancelled = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._current_chunk = 0
        self._total_chunks = 0
        self._lock = threading.Lock()
        self._task_result: object = None
        self._task_done = threading.Event()
        self.result_error: Optional[Exception] = None
        self._stage_text: str = ""

        # Time tracking
        self._start_time: float = 0.0
        self._end_time: float = 0.0
        self.start_time_iso: str = ""
        self.end_time_iso: str = ""
        self.elapsed_seconds: float = 0.0

        self._build_ui()
        self._center_window()
        self._start_task()

    def _build_ui(self) -> None:
        frame = tk.Frame(self, padx=20, pady=16, bg=get_color("card_bg"))
        frame.pack(fill="both", expand=True)

        self._status_label = tk.Label(
            frame,
            text=t("progress.preparing"),
            anchor="w",
            font=get_font("small"),
            fg=get_color("text"),
            bg=get_color("card_bg"),
        )
        self._status_label.pack(fill="x", pady=(0, 6))

        self._progress_var = tk.DoubleVar(value=0.0)
        self._progress_bar = ttk.Progressbar(
            frame, variable=self._progress_var,
            maximum=100.0, length=450, mode="determinate",
        )
        self._progress_bar.pack(fill="x", pady=(0, 6))

        # Quantity + percentage row
        info_frame = tk.Frame(frame, bg=get_color("card_bg"))
        info_frame.pack(fill="x", pady=(0, 4))
        self._chunk_label = tk.Label(
            info_frame,
            text=t("progress.chunk_label").format(current=0, total=0),
            anchor="w",
            fg=get_color("text"),
            bg=get_color("card_bg"),
            font=get_font("small"),
        )
        self._chunk_label.pack(side="left")
        self._pct_label = tk.Label(
            info_frame,
            text="0.0%",
            anchor="e",
            fg=get_color("text"),
            bg=get_color("card_bg"),
            font=get_font("small"),
        )
        self._pct_label.pack(side="right")

        # Time row
        time_frame = tk.Frame(frame, bg=get_color("card_bg"))
        time_frame.pack(fill="x", pady=(0, 4))
        self._elapsed_label = tk.Label(
            time_frame,
            text=t("progress.elapsed_label").format(time="00:00:00"),
            anchor="w",
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
            font=get_font("small"),
        )
        self._elapsed_label.pack(side="left")
        self._remaining_label = tk.Label(
            time_frame,
            text=t("progress.remaining_calc"),
            anchor="e",
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
            font=get_font("small"),
        )
        self._remaining_label.pack(side="right")

        # Speed row
        self._speed_label = tk.Label(
            frame,
            text="",
            anchor="w",
            fg=get_color("text_secondary"),
            bg=get_color("card_bg"),
            font=get_font("caption"),
        )
        self._speed_label.pack(fill="x", pady=(0, 8))

        self._cancel_btn = tk.Button(
            frame,
            text=t("progress.cancel"),
            width=12,
            command=self._on_cancel,
            fg=get_color("danger"),
            bg=get_color("card_bg"),
            activebackground=get_color("error_bg"),
            activeforeground=get_color("danger"),
            relief="solid",
            bd=1,
            font=get_font("small"),
        )
        self._cancel_btn.pack()

    def _center_window(self) -> None:
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        parent = self.master
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        x = px + (pw - w) // 2
        y = py + (ph - h) // 2
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_stage(self, text: str) -> None:
        """Set a stage description shown in the status label.

        Thread-safe; useful for multi-phase tasks (e.g. "암호화 중" →
        "기록지 생성 중").  While a stage is set, the generic
        "처리 중..." status text is suppressed.
        """
        self._stage_text = text

        def _apply() -> None:
            try:
                self._status_label.configure(text=text)
            except tk.TclError:
                pass

        try:
            self.after(0, _apply)
        except (tk.TclError, RuntimeError):
            pass

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _progress_callback(self, current: int, total: int) -> None:
        """Thread-safe progress update called from the background task."""
        if self._cancelled.is_set():
            raise _CancelledError(t("progress.user_cancelled"))
        with self._lock:
            self._current_chunk = current
            self._total_chunks = total

    def _start_task(self) -> None:
        from datetime import datetime, timezone
        self._start_time = time.monotonic()
        self.start_time_iso = datetime.now(timezone.utc).astimezone().isoformat()
        self._thread = threading.Thread(target=self._run_task, daemon=True)
        self._thread.start()
        # Schedule (not call) the first poll: a synchronous call here could
        # destroy the dialog inside __init__ when the task finishes fast,
        # making the caller's wait_window(dlg) raise "bad window path name".
        self.after(self.POLL_INTERVAL_MS, self._poll_progress)

    def _run_task(self) -> None:
        try:
            result = self._task_fn(self._progress_callback)
            self._task_result = result
        except Exception as exc:  # noqa: BLE001 — classified below
            # 취소 신호(_CancelledError)가 작업 계층에서 다른 예외로
            # 래핑될 수 있다(예: EncryptionError). 취소 이벤트가 켜져
            # 있으면 어떤 예외든 취소로 분류해 "암호화 실패" 오표시를
            # 막는다.
            self.result_error = resolve_task_error(
                exc, self._cancelled.is_set()
            )
        finally:
            self._end_time = time.monotonic()
            from datetime import datetime, timezone
            self.end_time_iso = datetime.now(timezone.utc).astimezone().isoformat()
            self.elapsed_seconds = self._end_time - self._start_time
            self._task_done.set()

    def _format_quantity(self, current: int, total: int) -> str:
        """Format the progress quantity row (bytes vs. abstract units)."""
        if total >= _BYTE_DISPLAY_THRESHOLD:
            return t("progress.bytes_label").format(
                current=_fmt_size(current), total=_fmt_size(total)
            )
        return t("progress.chunk_label").format(current=current, total=total)

    def _format_speed(self, current: int, total: int, elapsed: float) -> str:
        if elapsed <= 0:
            return ""
        if total >= _BYTE_DISPLAY_THRESHOLD:
            mb_per_sec = (current / elapsed) / (1024.0 * 1024.0)
            return t("progress.speed_mb").format(rate=mb_per_sec)
        return t("progress.speed_label").format(rate=current / elapsed)

    def _poll_progress(self) -> None:
        if self._task_done.is_set():
            self._finish()
            return

        with self._lock:
            current = self._current_chunk
            total = self._total_chunks

        elapsed = time.monotonic() - self._start_time

        if total > 0 and current > 0:
            pct = (current / total) * 100.0
            self._progress_var.set(pct)
            self._chunk_label.configure(text=self._format_quantity(current, total))
            self._pct_label.configure(text=f"{pct:.1f}%")
            if not self._stage_text:
                self._status_label.configure(text=t("progress.status"))

            # Estimated remaining time (byte-level callbacks make this
            # responsive from the first 8 MiB buffer onward)
            rate = elapsed / current
            remaining = rate * (total - current)
            self._elapsed_label.configure(
                text=t("progress.elapsed_label").format(time=_fmt_time(elapsed))
            )
            self._remaining_label.configure(
                text=t("progress.remaining_label").format(time=_fmt_time(remaining))
            )
            self._speed_label.configure(
                text=self._format_speed(current, total, elapsed)
            )
        else:
            self._elapsed_label.configure(
                text=t("progress.elapsed_label").format(time=_fmt_time(elapsed))
            )
            if not self._stage_text:
                self._status_label.configure(text=t("progress.preparing"))

        self.after(self.POLL_INTERVAL_MS, self._poll_progress)

    def _finish(self) -> None:
        elapsed = self.elapsed_seconds
        if self.result_error is not None:
            self._status_label.configure(
                text=t("progress.error").format(time=_fmt_time(elapsed))
            )
            if self._on_error is not None:
                self._on_error(self.result_error)
        else:
            self._progress_var.set(100.0)
            self._pct_label.configure(text="100.0%")
            self._status_label.configure(
                text=t("progress.complete").format(time=_fmt_time(elapsed))
            )
            self._remaining_label.configure(text=t("progress.remaining_zero"))
            if self._on_complete is not None:
                self._on_complete(self._task_result)
        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self._cancelled.set()
        self._cancel_btn.configure(state="disabled")
        self._status_label.configure(text=t("progress.cancelling"))

    def cancel_and_join(self, timeout: float = 5.0) -> bool:
        """Signal cancellation and wait for the worker thread to exit.

        Used by the wizards before deleting partial output files, so
        the deletion never races a worker that still holds the file
        open (Windows sharing violation).

        Args:
            timeout: Maximum seconds to wait for the worker thread.

        Returns:
            True if the worker has exited (or never started), False if
            it is still running after the timeout.
        """
        self._cancelled.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)
        return thread is None or not thread.is_alive()

    @property
    def was_cancelled(self) -> bool:
        return self._cancelled.is_set()


def _fmt_time(seconds: float) -> str:
    """Format seconds as HH:MM:SS or MM:SS using i18n."""
    s = int(seconds)
    if s < 0:
        return t("time.zero")
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h > 0:
        return t("time.fmt_hms").format(h=h, m=m, s=sec)
    if m > 0:
        return t("time.fmt_ms").format(m=m, s=sec)
    return t("time.fmt_s").format(s=sec)


class _CancelledError(Exception):
    """Internal exception to signal task cancellation."""


def resolve_task_error(error: Exception, cancelled: bool) -> Exception:
    """Classify a background-task exception as cancellation or failure.

    The cancel signal raised inside the progress callback may be wrapped
    by intermediate layers (e.g. ``EncryptionError`` from the crypto
    module), so the original exception type alone is not reliable.
    Whenever the cancel event was set, the outcome is a cancellation.

    Args:
        error: The exception raised by the task function.
        cancelled: Whether the dialog's cancel event was set.

    Returns:
        A ``_CancelledError`` for cancellations, otherwise *error* as-is.
    """
    if cancelled or isinstance(error, _CancelledError):
        return _CancelledError(t("progress.task_cancelled"))
    return error
