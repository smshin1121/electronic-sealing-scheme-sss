"""Generate the main-text throughput figure from recorded benchmark artifacts.

Reads ``summary.csv`` and ``baseline_summary.csv`` from a benchmark output
directory (see run_performance_benchmark.py) and emits a vector PDF for
``\\includegraphics`` in the manuscript. Companion to the ``--emit-only``
table emission: measurement data is never re-typed by hand.

matplotlib is a documentation-side dependency only; the sealing prototype
itself does not require it.

Usage:
    python scripts/generate_performance_figure.py \
        --artifacts-dir artifacts/performance/revision_full \
        --output Latex/generated/performance_throughput.pdf
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402  (backend must be set first)

PRIMARY_CHUNK_GB = "1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_series(artifacts_dir: Path) -> dict:
    with open(artifacts_dir / "summary.csv", encoding="utf-8") as handle:
        crypto = [
            row
            for row in csv.DictReader(handle)
            if row["chunk_size_gb"] == PRIMARY_CHUNK_GB
        ]
    crypto.sort(key=lambda row: float(row["file_size_gb"]))
    with open(artifacts_dir / "baseline_summary.csv", encoding="utf-8") as handle:
        baseline = list(csv.DictReader(handle))

    def baseline_series(kind: str) -> tuple[list, list, list]:
        rows = sorted(
            (row for row in baseline if row["kind"] == kind),
            key=lambda row: float(row["file_size_gb"]),
        )
        return (
            [float(row["file_size_gb"]) for row in rows],
            [float(row["mb_s_mean"]) for row in rows],
            [float(row["mb_s_ci95"]) for row in rows],
        )

    return {
        "sizes": [float(row["file_size_gb"]) for row in crypto],
        "enc": [float(row["encryption_mb_s_mean"]) for row in crypto],
        "enc_ci": [float(row["encryption_mb_s_ci95"]) for row in crypto],
        "dec": [float(row["decryption_mb_s_mean"]) for row in crypto],
        "dec_ci": [float(row["decryption_mb_s_ci95"]) for row in crypto],
        "copy": baseline_series("copy"),
        "read": baseline_series("read"),
    }


def render(series: dict, output: Path) -> None:
    # Wide (two-column span) proportions: the manuscript places this as a
    # figure* — the only float pattern that placed reliably under cas-dc.
    fig, ax = plt.subplots(figsize=(7.0, 2.3))
    plt.rcParams.update({"font.size": 8})
    read_x, read_m, read_c = series["read"]
    copy_x, copy_m, copy_c = series["copy"]
    ax.errorbar(
        read_x, read_m, yerr=read_c, fmt="^--", color="#a0a0a0",
        label="Read-only scan", capsize=2, lw=0.9, ms=3.5,
    )
    ax.errorbar(
        copy_x, copy_m, yerr=copy_c, fmt="s--", color="#505050",
        label="Plain file copy", capsize=2, lw=0.9, ms=3.5,
    )
    ax.errorbar(
        series["sizes"], series["enc"], yerr=series["enc_ci"], fmt="o-",
        color="#1f4e9c", label="AES-GCM sealing (enc.)", capsize=2,
        lw=1.2, ms=3.5,
    )
    ax.errorbar(
        series["sizes"], series["dec"], yerr=series["dec_ci"], fmt="d-",
        color="#c23b22", label="AES-GCM unsealing (dec.)", capsize=2,
        lw=1.2, ms=3.5,
    )
    ax.set_xscale("log")
    ax.set_xticks(series["sizes"])
    ax.set_xticklabels([str(int(s)) for s in series["sizes"]], fontsize=8)
    ax.tick_params(axis="y", labelsize=8)
    ax.minorticks_off()
    ax.set_xlabel("Input size (GiB)", fontsize=8)
    ax.set_ylabel("Throughput (MiB/s)", fontsize=8)
    ax.set_ylim(0, 1000)
    ax.grid(True, alpha=0.25, lw=0.4)
    ax.legend(fontsize=7.5, loc="lower left", ncol=2, framealpha=0.9)
    fig.tight_layout(pad=0.4)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def main() -> int:
    args = parse_args()
    series = load_series(args.artifacts_dir.resolve())
    render(series, args.output.resolve())
    print(f"figure written: {args.output}")
    return 0


if __name__ == "__main__":
    return_code = main()
    raise SystemExit(return_code)
