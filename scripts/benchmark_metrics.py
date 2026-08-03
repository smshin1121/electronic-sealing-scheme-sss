"""Resource monitoring, confidence intervals, and baseline I/O passes.

Provides per-run peak RSS and CPU-time capture, Student-t 95% confidence
intervals, and plain-copy/read-only baselines for the performance harness.
"""
from __future__ import annotations

import math
import shutil
import statistics
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

MB = 1024**2
GB = 1024**3
BASELINE_BUFFER_SIZE = 8 * MB  # matches the crypto layer's streaming buffer

BASELINE_KINDS = ("copy", "read")
BASELINE_LABELS = {"copy": "Plain file copy", "read": "Read-only scan"}

# Two-sided 95% Student-t critical values indexed by degrees of freedom.
_T_95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}
_T_95_LARGE = 1.960


def t_critical_95(sample_count: int) -> float:
    df = sample_count - 1
    if df < 1:
        return 0.0
    return _T_95.get(df, _T_95_LARGE)


def ci95_half_width(values: list[float]) -> float:
    """Half-width of the two-sided 95% CI of the mean (Student-t)."""
    if len(values) < 2:
        return 0.0
    return t_critical_95(len(values)) * statistics.stdev(values) / math.sqrt(len(values))


class ResourceMonitor:
    """Captures wall time, process CPU time, and sampled peak RSS for a phase.

    Usage::

        with ResourceMonitor() as monitor:
            do_work()
        monitor.wall_seconds / monitor.cpu_share / monitor.peak_rss_mb
    """

    def __init__(self, interval_seconds: float = 0.05) -> None:
        self._interval = interval_seconds
        self._process = psutil.Process()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._peak_rss = 0
        self._cpu_start: Any = None
        self._wall_start = 0.0
        self.wall_seconds = 0.0
        self.cpu_seconds = 0.0
        self.cpu_share = 0.0
        self.peak_rss_mb = 0.0

    def _sample_loop(self) -> None:
        while not self._stop.is_set():
            try:
                rss = self._process.memory_info().rss
                if rss > self._peak_rss:
                    self._peak_rss = rss
            except psutil.Error:
                pass
            self._stop.wait(self._interval)

    def __enter__(self) -> "ResourceMonitor":
        self._peak_rss = self._process.memory_info().rss
        self._cpu_start = self._process.cpu_times()
        self._stop.clear()
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._wall_start = time.perf_counter()
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.wall_seconds = time.perf_counter() - self._wall_start
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        cpu_end = self._process.cpu_times()
        self.cpu_seconds = (cpu_end.user - self._cpu_start.user) + (
            cpu_end.system - self._cpu_start.system
        )
        self.cpu_share = (
            self.cpu_seconds / self.wall_seconds if self.wall_seconds > 0 else 0.0
        )
        self.peak_rss_mb = self._peak_rss / MB


@dataclass
class BaselineResult:
    case_label: str
    kind: str  # one of BASELINE_KINDS
    file_size_bytes: int
    file_size_gb: float
    run_index: int
    seconds: float
    mb_s: float
    cpu_seconds: float
    cpu_share: float
    peak_rss_mb: float


def run_baseline_pass(kind: str, source: Path, scratch_dir: Path) -> ResourceMonitor:
    """Runs one baseline pass over `source` and returns its resource profile.

    "copy": streamed read+write with the crypto-layer buffer size (I/O ceiling
    for the full read-process-write pattern). "read": streamed read-only scan
    (read-bandwidth ceiling). Copy output is deleted before returning.
    """
    if kind not in BASELINE_KINDS:
        raise ValueError(f"Unknown baseline kind: {kind}")

    if kind == "copy":
        dest = scratch_dir / f"{source.stem}.baseline_copy"
        try:
            with ResourceMonitor() as monitor:
                with open(source, "rb") as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst, BASELINE_BUFFER_SIZE)
        finally:
            if dest.exists():
                dest.unlink()
        return monitor

    with ResourceMonitor() as monitor:
        with open(source, "rb") as src:
            while src.read(BASELINE_BUFFER_SIZE):
                pass
    return monitor


def build_baseline_summary_rows(
    results: list[BaselineResult],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[BaselineResult]] = {}
    for row in results:
        grouped.setdefault((row.case_label, row.kind), []).append(row)

    summary_rows: list[dict[str, Any]] = []
    for (case_label, kind), group in sorted(grouped.items()):
        speeds = [item.mb_s for item in group]
        summary_rows.append(
            {
                "case_label": case_label,
                "kind": kind,
                "file_size_gb": group[0].file_size_gb,
                "repeats": len(group),
                "mb_s_mean": round(statistics.mean(speeds), 2),
                "mb_s_ci95": round(ci95_half_width(speeds), 2),
                "seconds_mean": round(
                    statistics.mean(item.seconds for item in group), 2
                ),
                "cpu_share_mean": round(
                    statistics.mean(item.cpu_share for item in group), 3
                ),
                "peak_rss_mb_max": round(max(item.peak_rss_mb for item in group), 1),
            }
        )
    return summary_rows
