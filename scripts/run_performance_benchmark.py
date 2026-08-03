from __future__ import annotations

import argparse
import csv
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
SCRIPTS_ROOT = Path(__file__).resolve().parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from desktop.crypto import decrypt_file, encrypt_file
from desktop.crypto.aes_gcm_encrypt import MAX_CHUNK_SIZE

from benchmark_metrics import (
    BASELINE_KINDS,
    BASELINE_LABELS,
    BaselineResult,
    ResourceMonitor,
    build_baseline_summary_rows,
    ci95_half_width,
    run_baseline_pass,
)

GB = 1024**3
MB = 1024**2
BUFFER_SIZE = 64 * 1024 * 1024
DEFAULT_SIZES_GB = [10, 20, 50, 100, 200, 450]
DEFAULT_CHUNK_SIZES_GB = [64]


@dataclass
class BenchmarkCase:
    label: str
    source_path: Path | None
    size_bytes: int
    generator_size_gb: int | None = None


@dataclass
class RunResult:
    case_label: str
    file_size_bytes: int
    file_size_gb: float
    chunk_size_gb: int
    run_index: int
    encryption_seconds: float
    encryption_mb_s: float
    decryption_seconds: float
    decryption_mb_s: float
    hash_verified: bool
    aes_ni: str
    # Resource profile (0.0 for rows recorded before the revision upgrade).
    enc_cpu_seconds: float = 0.0
    enc_cpu_share: float = 0.0
    enc_peak_rss_mb: float = 0.0
    dec_cpu_seconds: float = 0.0
    dec_cpu_share: float = 0.0
    dec_peak_rss_mb: float = 0.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Automate repeated AES-GCM encryption/decryption benchmarking, "
            "environment capture, and LaTeX/CSV/JSON artifact generation."
        )
    )
    parser.add_argument(
        "--sizes-gb",
        nargs="+",
        type=int,
        default=DEFAULT_SIZES_GB,
        help="Synthetic plaintext sizes in GiB when no input files are provided.",
    )
    parser.add_argument(
        "--chunk-sizes-gb",
        nargs="+",
        type=int,
        default=DEFAULT_CHUNK_SIZES_GB,
        help="GCM segment sizes in GiB to benchmark.",
    )
    parser.add_argument(
        "--repeats", type=int, default=5, help="Repeated runs per test condition."
    )
    parser.add_argument(
        "--data-mode",
        choices=["urandom", "zero"],
        default="urandom",
        help="Synthetic file generation mode.",
    )
    parser.add_argument(
        "--input-files",
        nargs="*",
        default=[],
        help="Existing forensic image files to benchmark directly.",
    )
    parser.add_argument(
        "--input-globs",
        nargs="*",
        default=[],
        help="Glob patterns for existing forensic images, e.g. 'datasets/CFReDS/**/*.dd'.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "artifacts" / "performance" / datetime.now(
            timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ"),
    )
    parser.add_argument(
        "--latex-dir",
        type=Path,
        default=REPO_ROOT / "latex" / "generated",
        help="Destination for auto-generated LaTeX tables.",
    )
    parser.add_argument(
        "--primary-chunk-gb",
        type=int,
        default=None,
        help="Chunk size used for the manuscript-ready LaTeX performance table.",
    )
    parser.add_argument(
        "--baselines",
        nargs="*",
        choices=list(BASELINE_KINDS),
        default=[],
        help=(
            "Baseline I/O passes to run per case: 'copy' (streamed read+write "
            "ceiling) and/or 'read' (read-bandwidth ceiling)."
        ),
    )
    parser.add_argument(
        "--baseline-repeats",
        type=int,
        default=5,
        help="Repeated runs per baseline kind and case.",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep intermediate encrypted/decrypted files.",
    )
    parser.add_argument(
        "--cooldown-seconds",
        type=float,
        default=0.0,
        help="Optional sleep interval between runs.",
    )
    parser.add_argument(
        "--emit-only",
        action="store_true",
        help=(
            "Regenerate the LaTeX outputs from the artifacts already present "
            "in --output-dir without running any measurement."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.emit_only:
        return emit_outputs_only(args)
    validate_args(args)

    output_dir = args.output_dir.resolve()
    latex_dir = args.latex_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    latex_dir.mkdir(parents=True, exist_ok=True)

    system_info = collect_system_info(output_dir)
    save_json(output_dir / "environment.json", system_info)

    cases = collect_cases(args)
    raw_json_path = output_dir / "raw_runs.json"
    raw_csv_path = output_dir / "raw_runs.csv"
    summary_json_path = output_dir / "summary.json"
    summary_csv_path = output_dir / "summary.csv"
    primary_chunk_gb = args.primary_chunk_gb or args.chunk_sizes_gb[0]
    if primary_chunk_gb not in args.chunk_sizes_gb:
        raise SystemExit(
            f"--primary-chunk-gb {primary_chunk_gb} is not present in --chunk-sizes-gb"
        )

    raw_results = load_existing_results(raw_json_path)
    baseline_json_path = output_dir / "baseline_runs.json"
    baseline_results = load_existing_baselines(baseline_json_path)
    runs_root = output_dir / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)

    for case in cases:
        check_disk_headroom(output_dir, case.size_bytes)
        current_plaintext = prepare_initial_plaintext(case, runs_root, args.data_mode)

        run_case_baselines(
            case,
            current_plaintext,
            runs_root,
            args,
            baseline_results,
            output_dir,
        )

        for chunk_size_gb in args.chunk_sizes_gb:
            target_plaintext = runs_root / f"{sanitize_label(case.label)}.bin"
            current_plaintext = ensure_plaintext_name(current_plaintext, target_plaintext)

            for run_index in range(1, args.repeats + 1):
                if has_completed_run(
                    raw_results, case.label, case.size_bytes, chunk_size_gb, run_index
                ):
                    continue

                run_dir = runs_root / (
                    f"{sanitize_label(case.label)}_chunk{chunk_size_gb}GB_run{run_index}"
                )
                run_dir.mkdir(parents=True, exist_ok=True)

                enc_path = run_dir / f"{current_plaintext.stem}.enc"
                dec_dir = run_dir / "decrypted"
                dec_dir.mkdir(parents=True, exist_ok=True)
                aes_key = os.urandom(32)

                enc_monitor = timed_encrypt(
                    current_plaintext, aes_key, enc_path, chunk_size_gb
                )
                enc_elapsed = enc_monitor.wall_seconds

                if not args.keep_artifacts and current_plaintext.exists():
                    current_plaintext.unlink()

                dec_monitor, dec_output_path, hash_verified = timed_decrypt(
                    enc_path, aes_key, dec_dir
                )
                dec_elapsed = dec_monitor.wall_seconds
                if not hash_verified:
                    raise RuntimeError(
                        f"Hash verification failed for case '{case.label}', "
                        f"run {run_index}, chunk {chunk_size_gb} GB"
                    )

                raw_results.append(
                    RunResult(
                        case_label=case.label,
                        file_size_bytes=case.size_bytes,
                        file_size_gb=round(case.size_bytes / GB, 3),
                        chunk_size_gb=chunk_size_gb,
                        run_index=run_index,
                        encryption_seconds=enc_elapsed,
                        encryption_mb_s=(case.size_bytes / MB) / enc_elapsed,
                        decryption_seconds=dec_elapsed,
                        decryption_mb_s=(case.size_bytes / MB) / dec_elapsed,
                        hash_verified=hash_verified,
                        aes_ni=system_info["cpu"]["aes_ni"],
                        enc_cpu_seconds=round(enc_monitor.cpu_seconds, 3),
                        enc_cpu_share=round(enc_monitor.cpu_share, 4),
                        enc_peak_rss_mb=round(enc_monitor.peak_rss_mb, 1),
                        dec_cpu_seconds=round(dec_monitor.cpu_seconds, 3),
                        dec_cpu_share=round(dec_monitor.cpu_share, 4),
                        dec_peak_rss_mb=round(dec_monitor.peak_rss_mb, 1),
                    )
                )
                persist_progress(
                    raw_results,
                    raw_json_path=raw_json_path,
                    raw_csv_path=raw_csv_path,
                    summary_json_path=summary_json_path,
                    summary_csv_path=summary_csv_path,
                )

                if not args.keep_artifacts and enc_path.exists():
                    enc_path.unlink()

                current_plaintext = dec_output_path
                if args.cooldown_seconds > 0:
                    time.sleep(args.cooldown_seconds)

            current_plaintext = ensure_plaintext_name(current_plaintext, target_plaintext)

        if not args.keep_artifacts and current_plaintext.exists():
            current_plaintext.unlink()

    raw_rows = [asdict(row) for row in raw_results]
    summary_rows = build_summary_rows(raw_results)
    baseline_summary_rows = build_baseline_summary_rows(baseline_results)

    save_json(output_dir / "benchmark_config.json", build_config_payload(args, cases))
    save_json(raw_json_path, raw_rows)
    save_json(summary_json_path, summary_rows)
    save_csv(raw_csv_path, raw_rows)
    save_csv(summary_csv_path, summary_rows)
    if baseline_results:
        persist_baselines(baseline_results, output_dir)
        save_json(output_dir / "baseline_summary.json", baseline_summary_rows)
        save_csv(output_dir / "baseline_summary.csv", baseline_summary_rows)
    write_markdown_report(
        output_dir / "report.md",
        args,
        system_info,
        summary_rows,
        baseline_summary_rows,
    )
    write_latex_tables(
        latex_dir,
        system_info,
        summary_rows,
        primary_chunk_gb,
        cases,
        baseline_summary_rows,
    )

    print(f"Benchmark completed: {output_dir}")
    print(f"LaTeX output written to: {latex_dir}")
    return 0


def emit_outputs_only(args: argparse.Namespace) -> int:
    """Rebuild the generated LaTeX from recorded artifacts, measuring nothing.

    Reads environment.json, benchmark_config.json, raw_runs.json, and
    baseline_runs.json from --output-dir. The measurement artifacts and the
    markdown report are left untouched.
    """
    output_dir = args.output_dir.resolve()
    latex_dir = args.latex_dir.resolve()
    env_path = output_dir / "environment.json"
    config_path = output_dir / "benchmark_config.json"
    if not env_path.exists() or not config_path.exists():
        raise SystemExit(
            "--emit-only requires environment.json and benchmark_config.json "
            f"in {output_dir}"
        )
    system_info = json.loads(env_path.read_text(encoding="utf-8"))
    config = json.loads(config_path.read_text(encoding="utf-8"))
    cases = [
        BenchmarkCase(
            label=row["label"],
            source_path=Path(row["source_path"]) if row.get("source_path") else None,
            size_bytes=row["size_bytes"],
        )
        for row in config.get("cases", [])
    ]
    raw_results = load_existing_results(output_dir / "raw_runs.json")
    if not raw_results:
        raise SystemExit(f"--emit-only found no completed runs in {output_dir}")
    baseline_results = load_existing_baselines(output_dir / "baseline_runs.json")

    chunk_sizes = sorted({row.chunk_size_gb for row in raw_results})
    primary_chunk_gb = args.primary_chunk_gb or min(chunk_sizes)
    if primary_chunk_gb not in chunk_sizes:
        raise SystemExit(
            f"--primary-chunk-gb {primary_chunk_gb} is not present in the "
            f"recorded runs {chunk_sizes}"
        )

    summary_rows = build_summary_rows(raw_results)
    baseline_summary_rows = build_baseline_summary_rows(baseline_results)
    latex_dir.mkdir(parents=True, exist_ok=True)
    write_latex_tables(
        latex_dir,
        system_info,
        summary_rows,
        primary_chunk_gb,
        cases,
        baseline_summary_rows,
    )
    print(f"Emit-only: LaTeX output written to {latex_dir}")
    return 0


def load_existing_results(raw_json_path: Path) -> list[RunResult]:
    if not raw_json_path.exists():
        return []
    rows = json.loads(raw_json_path.read_text(encoding="utf-8"))
    return [RunResult(**row) for row in rows]


def load_existing_baselines(baseline_json_path: Path) -> list[BaselineResult]:
    if not baseline_json_path.exists():
        return []
    rows = json.loads(baseline_json_path.read_text(encoding="utf-8"))
    return [BaselineResult(**row) for row in rows]


def has_completed_baseline(
    baseline_results: list[BaselineResult],
    case_label: str,
    kind: str,
    run_index: int,
) -> bool:
    return any(
        row.case_label == case_label
        and row.kind == kind
        and row.run_index == run_index
        for row in baseline_results
    )


def persist_baselines(
    baseline_results: list[BaselineResult], output_dir: Path
) -> None:
    rows = [asdict(row) for row in baseline_results]
    save_json(output_dir / "baseline_runs.json", rows)
    save_csv(output_dir / "baseline_runs.csv", rows)


def run_case_baselines(
    case: BenchmarkCase,
    plaintext_path: Path,
    runs_root: Path,
    args: argparse.Namespace,
    baseline_results: list[BaselineResult],
    output_dir: Path,
) -> None:
    """Runs the requested baseline passes for one case, with resume support."""
    for kind in args.baselines:
        for run_index in range(1, args.baseline_repeats + 1):
            if has_completed_baseline(
                baseline_results, case.label, kind, run_index
            ):
                continue
            monitor = run_baseline_pass(kind, plaintext_path, runs_root)
            baseline_results.append(
                BaselineResult(
                    case_label=case.label,
                    kind=kind,
                    file_size_bytes=case.size_bytes,
                    file_size_gb=round(case.size_bytes / GB, 3),
                    run_index=run_index,
                    seconds=monitor.wall_seconds,
                    mb_s=(case.size_bytes / MB) / monitor.wall_seconds,
                    cpu_seconds=round(monitor.cpu_seconds, 3),
                    cpu_share=round(monitor.cpu_share, 4),
                    peak_rss_mb=round(monitor.peak_rss_mb, 1),
                )
            )
            persist_baselines(baseline_results, output_dir)
            if args.cooldown_seconds > 0:
                time.sleep(args.cooldown_seconds)


def has_completed_run(
    raw_results: list[RunResult],
    case_label: str,
    size_bytes: int,
    chunk_size_gb: int,
    run_index: int,
) -> bool:
    return any(
        row.case_label == case_label
        and row.file_size_bytes == size_bytes
        and row.chunk_size_gb == chunk_size_gb
        and row.run_index == run_index
        for row in raw_results
    )


def persist_progress(
    raw_results: list[RunResult],
    *,
    raw_json_path: Path,
    raw_csv_path: Path,
    summary_json_path: Path,
    summary_csv_path: Path,
) -> None:
    raw_rows = [asdict(row) for row in raw_results]
    summary_rows = build_summary_rows(raw_results)
    save_json(raw_json_path, raw_rows)
    save_json(summary_json_path, summary_rows)
    save_csv(raw_csv_path, raw_rows)
    save_csv(summary_csv_path, summary_rows)


def validate_args(args: argparse.Namespace) -> None:
    if args.repeats < 1:
        raise SystemExit("--repeats must be at least 1")
    if any(size < 1 for size in args.sizes_gb):
        raise SystemExit("--sizes-gb values must be at least 1")
    if any(chunk < 1 or chunk > 64 for chunk in args.chunk_sizes_gb):
        raise SystemExit("--chunk-sizes-gb values must be between 1 and 64")


def collect_cases(args: argparse.Namespace) -> list[BenchmarkCase]:
    file_paths: list[Path] = []
    for item in args.input_files:
        path = Path(item).resolve()
        if not path.is_file():
            raise SystemExit(f"Input file not found: {path}")
        file_paths.append(path)

    for pattern in args.input_globs:
        for match in REPO_ROOT.glob(pattern):
            if match.is_file():
                file_paths.append(match.resolve())

    unique_paths = sorted(set(file_paths))
    if unique_paths:
        return [
            BenchmarkCase(
                label=path.name,
                source_path=path,
                size_bytes=path.stat().st_size,
            )
            for path in unique_paths
        ]

    return [
        BenchmarkCase(
            label=f"{size_gb}GB_synthetic",
            source_path=None,
            size_bytes=size_gb * GB,
            generator_size_gb=size_gb,
        )
        for size_gb in args.sizes_gb
    ]


def build_config_payload(
    args: argparse.Namespace, cases: list[BenchmarkCase]
) -> dict[str, Any]:
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "repeats": args.repeats,
        "chunk_sizes_gb": args.chunk_sizes_gb,
        "data_mode": args.data_mode,
        "keep_artifacts": args.keep_artifacts,
        "cooldown_seconds": args.cooldown_seconds,
        "cases": [
            {
                "label": case.label,
                "size_bytes": case.size_bytes,
                "source_path": str(case.source_path) if case.source_path else None,
            }
            for case in cases
        ],
    }


def collect_system_info(output_dir: Path) -> dict[str, Any]:
    mem = psutil.virtual_memory()
    disk = shutil.disk_usage(output_dir.anchor or str(output_dir))
    os_info = collect_os_info()
    cpu = collect_cpu_info()
    storage = collect_storage_info()
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "os": os_info,
        "cpu": {
            "brand_raw": cpu.get("brand_raw", "unknown"),
            "arch": cpu.get("arch", "unknown"),
            "bits": cpu.get("bits", "unknown"),
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "hz_advertised": cpu.get("hz_advertised", "unknown"),
            "aes_ni": cpu.get("aes_ni", "unknown"),
        },
        "memory": {
            "total_bytes": mem.total,
            "total_gb": round(mem.total / GB, 2),
            "summary": collect_memory_summary(mem.total),
        },
        "storage": {
            "drive": output_dir.anchor,
            "free_bytes": disk.free,
            "total_bytes": disk.total,
            "model": storage.get("model", "unknown"),
            "media_type": storage.get("media_type", "unknown"),
            "size_bytes": storage.get("size_bytes"),
        },
        "python": sys.version,
    }


def collect_os_info() -> dict[str, Any]:
    if os.name != "nt":
        return {"label": os.name}
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                (
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                    "$os = Get-CimInstance Win32_OperatingSystem | "
                    "Select-Object -First 1 Caption,Version,BuildNumber,OSArchitecture; "
                    "$os | ConvertTo-Json -Compress"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        payload = json.loads(completed.stdout.strip())
        caption = str(payload.get("Caption", "Windows")).strip()
        architecture = str(payload.get("OSArchitecture", "")).strip()
        version = str(payload.get("Version", "")).strip()
        build = str(payload.get("BuildNumber", "")).strip()
        bits = f" ({architecture})" if architecture else ""
        version_bits = f", Version {version}" if version else ""
        build_bits = f", Build {build}" if build else ""
        return {"label": f"{caption}{bits}{version_bits}{build_bits}"}
    except Exception:
        return {"label": "Windows"}


def collect_cpu_info() -> dict[str, Any]:
    payload = {
        "brand_raw": os.environ.get("PROCESSOR_IDENTIFIER", "unknown"),
        "arch": os.environ.get("PROCESSOR_ARCHITECTURE", "unknown"),
        "bits": 64 if sys.maxsize > 2**32 else 32,
        "hz_advertised": "unknown",
        "aes_ni": "unknown",
    }
    if os.name != "nt":
        payload["brand_raw"] = os.uname().machine if hasattr(os, "uname") else payload["brand_raw"]
        return payload
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                (
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                    "$cpu = Get-CimInstance Win32_Processor | "
                    "Select-Object -First 1 Name,MaxClockSpeed; "
                    "$cpu | ConvertTo-Json -Compress"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        cpu = json.loads(completed.stdout.strip())
        payload["brand_raw"] = cpu.get("Name", "unknown")
        max_clock = cpu.get("MaxClockSpeed")
        if max_clock:
            payload["hz_advertised"] = f"{int(max_clock) / 1000:.2f} GHz"
    except Exception:
        pass
    return payload


def collect_memory_summary(total_bytes: int) -> str:
    total_gb = int(math.ceil(total_bytes / GB))
    if os.name != "nt":
        return f"{total_gb} GB"
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                (
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                    "$mods = Get-CimInstance Win32_PhysicalMemory | "
                    "Select-Object Capacity,Speed; "
                    "$mods | ConvertTo-Json -Compress"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        payload = json.loads(completed.stdout.strip())
        modules = payload if isinstance(payload, list) else [payload]
        count = len(modules)
        speed = modules[0].get("Speed") if modules else None
        module_gb = (
            int(round((modules[0].get("Capacity") or 0) / GB)) if modules else None
        )
        parts = [f"{total_gb} GB"]
        if speed:
            parts.append(f"DDR5-{speed}")
        if count and module_gb:
            parts.append(f"({count} x {module_gb} GB)")
        return " ".join(parts)
    except Exception:
        return f"{total_gb} GB"


def collect_storage_info() -> dict[str, Any]:
    if os.name != "nt":
        return {}
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                (
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                    "$d = Get-PhysicalDisk | Where-Object { $_.MediaType -ne 'Unspecified' } | "
                    "Sort-Object Size -Descending | Select-Object -First 1 FriendlyName,MediaType,Size; "
                    "if (-not $d) { "
                    "$d = Get-CimInstance Win32_DiskDrive | Sort-Object Size -Descending | "
                    "Select-Object -First 1 Model,MediaType,Size | "
                    "ForEach-Object { [pscustomobject]@{ FriendlyName = $_.Model; MediaType = $_.MediaType; Size = $_.Size } } "
                    "} "
                    "$d | ConvertTo-Json -Compress"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        payload = json.loads(completed.stdout.strip())
        return {
            "model": payload.get("FriendlyName"),
            "media_type": payload.get("MediaType"),
            "size_bytes": payload.get("Size"),
        }
    except Exception:
        return {}


def check_disk_headroom(output_dir: Path, file_size_bytes: int) -> None:
    free_bytes = shutil.disk_usage(output_dir.anchor or str(output_dir)).free
    required = file_size_bytes * 2 + (5 * GB)
    if free_bytes < required:
        raise SystemExit(
            f"Insufficient free disk space. Need about {required / GB:.1f} GB, "
            f"have {free_bytes / GB:.1f} GB."
        )


def prepare_initial_plaintext(
    case: BenchmarkCase, runs_root: Path, data_mode: str
) -> Path:
    target_path = runs_root / f"{sanitize_label(case.label)}.bin"
    if case.source_path:
        shutil.copy2(case.source_path, target_path)
        return target_path

    create_plaintext_file(target_path, case.size_bytes, data_mode)
    return target_path


def create_plaintext_file(path: Path, size_bytes: int, data_mode: str) -> None:
    if path.exists() and path.stat().st_size == size_bytes:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    zero_chunk = b"\x00" * BUFFER_SIZE
    remaining = size_bytes
    with open(path, "wb") as handle:
        while remaining > 0:
            block_size = min(BUFFER_SIZE, remaining)
            if data_mode == "urandom":
                handle.write(os.urandom(block_size))
            else:
                handle.write(zero_chunk[:block_size])
            remaining -= block_size


def timed_encrypt(
    plaintext_path: Path, aes_key: bytes, enc_path: Path, chunk_size_gb: int
) -> ResourceMonitor:
    # Nominal 64 GB segments are clamped to the crypto layer's GCM-safe
    # maximum (64 GiB - 16 MiB); see _MAX_CHUNK_SIZE in aes_gcm_encrypt.
    chunk_size = min(chunk_size_gb * GB, MAX_CHUNK_SIZE)
    with ResourceMonitor() as monitor:
        encrypt_file(
            filepath=str(plaintext_path),
            aes_key=aes_key,
            output_path=str(enc_path),
            chunk_size=chunk_size,
        )
    return monitor


def timed_decrypt(
    enc_path: Path, aes_key: bytes, dec_dir: Path
) -> tuple[ResourceMonitor, Path, bool]:
    dec_dir.mkdir(parents=True, exist_ok=True)
    with ResourceMonitor() as monitor:
        result = decrypt_file(str(enc_path), aes_key, str(dec_dir))
    return monitor, Path(result.output_filepath), bool(result.hash_verified)


def ensure_plaintext_name(current_path: Path, target_path: Path) -> Path:
    if current_path == target_path:
        return current_path
    if target_path.exists():
        target_path.unlink()
    current_path.replace(target_path)
    return target_path


def build_summary_rows(results: list[RunResult]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int], list[RunResult]] = {}
    for row in results:
        grouped.setdefault((row.case_label, row.chunk_size_gb), []).append(row)

    summary_rows: list[dict[str, Any]] = []
    for (case_label, chunk_size_gb), group in sorted(grouped.items()):
        summary_rows.append(
            {
                "case_label": case_label,
                "chunk_size_gb": chunk_size_gb,
                "file_size_gb": round(group[0].file_size_bytes / GB, 3),
                "repeats": len(group),
                "encryption_seconds_mean": round(
                    statistics.mean(item.encryption_seconds for item in group), 2
                ),
                "encryption_seconds_std": round(
                    safe_std([item.encryption_seconds for item in group]), 2
                ),
                "encryption_mb_s_mean": round(
                    statistics.mean(item.encryption_mb_s for item in group), 2
                ),
                "encryption_mb_s_std": round(
                    safe_std([item.encryption_mb_s for item in group]), 2
                ),
                "decryption_seconds_mean": round(
                    statistics.mean(item.decryption_seconds for item in group), 2
                ),
                "decryption_seconds_std": round(
                    safe_std([item.decryption_seconds for item in group]), 2
                ),
                "decryption_mb_s_mean": round(
                    statistics.mean(item.decryption_mb_s for item in group), 2
                ),
                "decryption_mb_s_std": round(
                    safe_std([item.decryption_mb_s for item in group]), 2
                ),
                "encryption_seconds_ci95": round(
                    ci95_half_width([item.encryption_seconds for item in group]), 2
                ),
                "encryption_mb_s_ci95": round(
                    ci95_half_width([item.encryption_mb_s for item in group]), 2
                ),
                "decryption_seconds_ci95": round(
                    ci95_half_width([item.decryption_seconds for item in group]), 2
                ),
                "decryption_mb_s_ci95": round(
                    ci95_half_width([item.decryption_mb_s for item in group]), 2
                ),
                "enc_cpu_share_mean": round(
                    statistics.mean(item.enc_cpu_share for item in group), 3
                ),
                "dec_cpu_share_mean": round(
                    statistics.mean(item.dec_cpu_share for item in group), 3
                ),
                "enc_peak_rss_mb_max": round(
                    max(item.enc_peak_rss_mb for item in group), 1
                ),
                "dec_peak_rss_mb_max": round(
                    max(item.dec_peak_rss_mb for item in group), 1
                ),
                "all_hash_verified": all(item.hash_verified for item in group),
            }
        )
    return summary_rows


def safe_std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def write_markdown_report(
    path: Path,
    args: argparse.Namespace,
    system_info: dict[str, Any],
    summary_rows: list[dict[str, Any]],
    baseline_summary_rows: list[dict[str, Any]] | None = None,
) -> None:
    lines = [
        "# Automated Performance Benchmark Report",
        "",
        f"- Captured at: `{system_info['captured_at_utc']}`",
        f"- Repeats per condition: `{args.repeats}`",
        f"- Chunk sizes (GiB): `{', '.join(map(str, args.chunk_sizes_gb))}`",
        f"- AES-NI: `{system_info['cpu']['aes_ni']}`",
        f"- CPU: `{system_info['cpu']['brand_raw']}`",
        f"- RAM: `{system_info['memory']['total_gb']} GB`",
        f"- Storage: `{system_info['storage']['model']}` ({system_info['storage']['media_type']})",
        "",
        "| Case | Size (GiB) | Chunk (GiB) | Enc Time Mean +/- CI95 (s) | Enc Speed Mean +/- CI95 (MiB/s) | Dec Time Mean +/- CI95 (s) | Dec Speed Mean +/- CI95 (MiB/s) | Enc CPU Share | Dec CPU Share | Enc Peak RSS (MiB) | Dec Peak RSS (MiB) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            "| {case_label} | {file_size_gb:.3f} | {chunk_size_gb} | "
            "{encryption_seconds_mean:.2f} +/- {encryption_seconds_ci95:.2f} | "
            "{encryption_mb_s_mean:.2f} +/- {encryption_mb_s_ci95:.2f} | "
            "{decryption_seconds_mean:.2f} +/- {decryption_seconds_ci95:.2f} | "
            "{decryption_mb_s_mean:.2f} +/- {decryption_mb_s_ci95:.2f} | "
            "{enc_cpu_share_mean:.3f} | {dec_cpu_share_mean:.3f} | "
            "{enc_peak_rss_mb_max:.1f} | {dec_peak_rss_mb_max:.1f} |".format(**row)
        )
    if baseline_summary_rows:
        lines.extend(
            [
                "",
                "## Baseline I/O Passes",
                "",
                "| Case | Kind | Speed Mean +/- CI95 (MiB/s) | CPU Share | Peak RSS (MiB) |",
                "|---|---|---:|---:|---:|",
            ]
        )
        for row in baseline_summary_rows:
            lines.append(
                "| {case_label} | {kind} | {mb_s_mean:.2f} +/- {mb_s_ci95:.2f} | "
                "{cpu_share_mean:.3f} | {peak_rss_mb_max:.1f} |".format(**row)
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_latex_tables(
    latex_dir: Path,
    system_info: dict[str, Any],
    summary_rows: list[dict[str, Any]],
    primary_chunk_gb: int,
    cases: list[BenchmarkCase],
    baseline_summary_rows: list[dict[str, Any]] | None = None,
) -> None:
    snippets = [
        build_env_table_tex(system_info),
        build_primary_performance_table_tex(summary_rows, primary_chunk_gb, cases),
        build_segment_sensitivity_tex(summary_rows),
        build_baseline_table_tex(baseline_summary_rows or [], summary_rows),
    ]
    (latex_dir / "benchmark_tables.tex").write_text(
        "\n\n".join(snippets) + "\n", encoding="utf-8"
    )
    (latex_dir / "benchmark_results_text.tex").write_text(
        build_results_text_tex(
            summary_rows, primary_chunk_gb, cases, baseline_summary_rows or []
        ),
        encoding="utf-8",
    )


def build_env_table_tex(system_info: dict[str, Any]) -> str:
    os_label = system_info.get("os", {}).get(
        "label", "Windows" if os.name == "nt" else os.name
    )
    return rf"""\renewcommand{{\InsertTableEnvSpecs}}{{%
\begin{{table}}[t]
\centering
\caption{{System Environment Specifications}}
\label{{tab:env_specs}}
\renewcommand{{\arraystretch}}{{1.2}}
\footnotesize
\begin{{tabularx}}{{\linewidth}}{{l|>{{\raggedright\arraybackslash}}X}}
\hline
\textbf{{Category}} & \textbf{{Specification}} \\ \hline
OS & {latex_escape(os_label)} \\ \hline
CPU & {latex_escape(system_info['cpu']['brand_raw'])} \\ \hline
RAM & {latex_escape(system_info['memory'].get('summary', format_memory_line(system_info['memory']['total_gb'])))} \\ \hline
Storage & {latex_escape(format_storage_line(system_info['storage']))} \\ \hline
\end{{tabularx}}
\end{{table}}
}}"""


def build_primary_performance_table_tex(
    summary_rows: list[dict[str, Any]],
    primary_chunk_gb: int,
    cases: list[BenchmarkCase],
) -> str:
    rows = [row for row in summary_rows if row["chunk_size_gb"] == primary_chunk_gb]
    synthetic_only = all(case.source_path is None for case in cases)

    if synthetic_only:
        rows.sort(key=lambda row: row["file_size_gb"])
        first_col_header = r"\textbf{File Size}"
        first_col_units = r"\textbf{(GiB)}"
        first_cells = [str(int(row["file_size_gb"])) for row in rows]
    else:
        rows.sort(key=lambda row: (row["file_size_gb"], row["case_label"]))
        first_col_header = r"\textbf{Dataset}"
        first_col_units = ""
        first_cells = [latex_escape(row["case_label"]) for row in rows]

    body_lines = []
    for row, first_cell in zip(rows, first_cells):
        body_lines.append(
            "    {first} & {enc_t:.2f} $\\pm$ {enc_ts:.2f} & {enc_s:.2f} $\\pm$ {enc_ss:.2f} "
            "& {dec_t:.2f} $\\pm$ {dec_ts:.2f} & {dec_s:.2f} $\\pm$ {dec_ss:.2f} \\\\".format(
                first=first_cell,
                enc_t=row["encryption_seconds_mean"],
                enc_ts=row["encryption_seconds_ci95"],
                enc_s=row["encryption_mb_s_mean"],
                enc_ss=row["encryption_mb_s_ci95"],
                dec_t=row["decryption_seconds_mean"],
                dec_ts=row["decryption_seconds_ci95"],
                dec_s=row["decryption_mb_s_mean"],
                dec_ss=row["decryption_mb_s_ci95"],
            )
        )
    body_text = "\n".join(body_lines)
    repeats = max((row["repeats"] for row in rows), default=0)
    # Revision-round marking (CR-08): the enclosing \InsertTablePerformance
    # macro (tables.tex) wraps the whole tabular in a blue scope — a \color
    # emitted inside the first cell would not survive tabular cell grouping.
    return rf"""\renewcommand{{\BenchmarkPerformanceCaptionSuffix}}{{{primary_chunk_gb} GiB segment, mean $\pm$ 95\% CI, $n={repeats}$}}
\renewcommand{{\BenchmarkPerformanceHeader}}{{{first_col_header}}}
\renewcommand{{\BenchmarkPerformanceUnits}}{{{first_col_units}}}
\renewcommand{{\InsertTablePerformanceRows}}{{%
{body_text}
}}"""


def build_segment_sensitivity_tex(summary_rows: list[dict[str, Any]]) -> str:
    chunk_sizes = sorted({row["chunk_size_gb"] for row in summary_rows})
    if len(chunk_sizes) < 2:
        return "% No segment-sensitivity table generated (single chunk size only)."

    target_case = max(summary_rows, key=lambda row: row["file_size_gb"])["case_label"]
    rows = [row for row in summary_rows if row["case_label"] == target_case]
    rows.sort(key=lambda row: row["chunk_size_gb"])
    # Caption avoids internal case labels (same CR nit as the baseline table);
    # keep in sync with the hand-fixed caption shipped in the 8/2 run.
    target_gb = max(row["file_size_gb"] for row in rows)
    body_lines = [
        "    {chunk} & {enc:.2f} $\\pm$ {encs:.2f} & {dec:.2f} $\\pm$ {decs:.2f} "
        "& {rss:.0f} \\\\".format(
            chunk=row["chunk_size_gb"],
            enc=row["encryption_mb_s_mean"],
            encs=row["encryption_mb_s_ci95"],
            dec=row["decryption_mb_s_mean"],
            decs=row["decryption_mb_s_ci95"],
            rss=max(row["enc_peak_rss_mb_max"], row["dec_peak_rss_mb_max"]),
        )
        for row in rows
    ]
    body_text = "\n".join(body_lines)
    return rf"""\newcommand{{\InsertTableSegmentSensitivity}}{{%
\begin{{table}}[t]
\centering
\caption{{Segment-Size Sensitivity for the {target_gb:.0f}~GiB Input (mean $\pm$ 95\% CI)}}
\label{{tab:segment_sensitivity}}
\renewcommand{{\arraystretch}}{{1.15}}
\footnotesize
\begin{{tabularx}}{{\linewidth}}{{c|c|c|c}}
\hline
\textbf{{Chunk Size (GiB)}} & \textbf{{Enc. Speed (MiB/s)}} & \textbf{{Dec. Speed (MiB/s)}} & \textbf{{Peak RSS (MiB)}} \\ \hline
{body_text}
\hline
\end{{tabularx}}
\end{{table}}
}}"""


def build_baseline_table_tex(
    baseline_summary_rows: list[dict[str, Any]],
    summary_rows: list[dict[str, Any]],
) -> str:
    if not baseline_summary_rows:
        # CR-13: never leave the macro undefined — emit a visible sentinel.
        return (
            "\\newcommand{\\InsertTableBaselineComparison}{"
            "\\textbf{[ERROR: no baseline passes in this benchmark run]}}"
        )

    target_case = max(
        baseline_summary_rows, key=lambda row: row["file_size_gb"]
    )["case_label"]
    baseline_rows = [
        row for row in baseline_summary_rows if row["case_label"] == target_case
    ]
    baseline_rows.sort(key=lambda row: row["kind"])

    body_lines = [
        "    {label} & {speed:.2f} $\\pm$ {ci:.2f} & {cpu:.0f}\\% \\\\".format(
            label=latex_escape(BASELINE_LABELS.get(row["kind"], row["kind"])),
            speed=row["mb_s_mean"],
            ci=row["mb_s_ci95"],
            cpu=row["cpu_share_mean"] * 100,
        )
        for row in baseline_rows
    ]
    crypto_rows = [
        row for row in summary_rows if row["case_label"] == target_case
    ]
    if crypto_rows:
        best = min(crypto_rows, key=lambda row: row["chunk_size_gb"])
        body_lines.append(
            "    AES-GCM sealing (enc.) & {speed:.2f} $\\pm$ {ci:.2f} & {cpu:.0f}\\% \\\\".format(
                speed=best["encryption_mb_s_mean"],
                ci=best["encryption_mb_s_ci95"],
                cpu=best["enc_cpu_share_mean"] * 100,
            )
        )
        body_lines.append(
            "    AES-GCM unsealing (dec.) & {speed:.2f} $\\pm$ {ci:.2f} & {cpu:.0f}\\% \\\\".format(
                speed=best["decryption_mb_s_mean"],
                ci=best["decryption_mb_s_ci95"],
                cpu=best["dec_cpu_share_mean"] * 100,
            )
        )
    body_text = "\n".join(body_lines)
    # New table this revision round (CR-08): render fully blue; caption
    # avoids internal case labels (CR nit: "200GB_synthetic" -> prose).
    target_gb = max(row["file_size_gb"] for row in baseline_rows)
    baseline_n = max((row.get("repeats", 0) for row in baseline_rows), default=0)
    sealing_n = max((row.get("repeats", 0) for row in crypto_rows), default=0)
    n_suffix = ""
    if baseline_n and sealing_n:
        n_suffix = rf"; baselines $n={baseline_n}$, sealing $n={sealing_n}$"
    return rf"""\newcommand{{\InsertTableBaselineComparison}}{{%
\begin{{table}}[t]
\color{{blue}}
\centering
\caption{{Throughput vs.\ Storage I/O Ceiling for the {target_gb:.0f}~GiB input (mean $\pm$ 95\% CI{n_suffix})}}
\label{{tab:baseline_comparison}}
\renewcommand{{\arraystretch}}{{1.15}}
\footnotesize
\begin{{tabularx}}{{\linewidth}}{{>{{\raggedright\arraybackslash}}X|c|c}}
\hline
\textbf{{Operation}} & \textbf{{Speed (MiB/s)}} & \textbf{{CPU Share}} \\ \hline
{body_text}
\hline
\end{{tabularx}}
\end{{table}}
}}"""


def build_results_text_tex(
    summary_rows: list[dict[str, Any]],
    primary_chunk_gb: int,
    cases: list[BenchmarkCase],
    baseline_summary_rows: list[dict[str, Any]] | None = None,
) -> str:
    rows = [row for row in summary_rows if row["chunk_size_gb"] == primary_chunk_gb]
    if not rows:
        return "% No generated benchmark text available.\n"

    enc_avg = statistics.mean(row["encryption_mb_s_mean"] for row in rows)
    dec_avg = statistics.mean(row["decryption_mb_s_mean"] for row in rows)
    enc_cpu = statistics.mean(row["enc_cpu_share_mean"] for row in rows)
    dec_cpu = statistics.mean(row["dec_cpu_share_mean"] for row in rows)
    repeats = max(row["repeats"] for row in rows)
    min_size = min(row["file_size_gb"] for row in rows)
    max_size = max(row["file_size_gb"] for row in rows)
    synthetic_only = all(case.source_path is None for case in cases)

    if synthetic_only:
        scope_text = (
            f"The automated benchmark repeated each synthetic input size from "
            f"{min_size:.0f} GiB to {max_size:.0f} GiB {repeats} times under a "
            f"{primary_chunk_gb} GiB segment configuration; results are reported "
            f"as means with 95\\% confidence intervals."
        )
    else:
        scope_text = (
            f"The automated benchmark repeated each selected forensic image "
            f"{repeats} times under a {primary_chunk_gb} GiB segment "
            f"configuration; results are reported as means with 95\\% "
            f"confidence intervals."
        )

    sentences = [
        scope_text,
        (
            f"As shown in Table~\\ref{{tab:performance}}, the mean encryption "
            f"throughput was {enc_avg:.2f} MiB/s and the mean decryption "
            f"throughput was {dec_avg:.2f} MiB/s on the evaluated platform."
        ),
        (
            f"Process CPU time accounted for {enc_cpu * 100:.0f}\\% of "
            f"encryption wall-clock time and {dec_cpu * 100:.0f}\\% of "
            f"decryption wall-clock time averaged across input sizes, "
            f"indicating a "
            f"{'predominantly I/O-bound' if max(enc_cpu, dec_cpu) < 0.5 else 'substantially CPU-bound'} "
            f"workload under the streaming pipeline; the size-dependent "
            f"regime split is analyzed below."
        ),
    ]

    if baseline_summary_rows:
        largest_label = max(
            baseline_summary_rows, key=lambda row: row["file_size_gb"]
        )["case_label"]
        by_kind = {
            row["kind"]: row
            for row in baseline_summary_rows
            if row["case_label"] == largest_label
        }
        copy_row = by_kind.get("copy")
        read_row = by_kind.get("read")
        if copy_row and read_row:
            sentences.append(
                f"For the largest input, a plain streamed file copy reached "
                f"{copy_row['mb_s_mean']:.2f} MiB/s and a read-only scan "
                f"{read_row['mb_s_mean']:.2f} MiB/s "
                f"(Table~\\ref{{tab:baseline_comparison}}), bounding the "
                f"attainable throughput of any read-process-write pipeline on "
                f"this storage device."
            )

    sentences.append(
        "Measurements were collected by an automated benchmarking pipeline "
        "that writes directly into the manuscript source, eliminating hand "
        "transcription."
    )
    # CR-08: the regenerated paragraph is revised content — mark it blue.
    return "\\revb{" + " ".join(sentences) + "}\n"


def save_json(path: Path, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def save_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def format_memory_line(total_gb: float) -> str:
    return f"{int(math.ceil(total_gb))} GB"


def format_storage_line(storage: dict[str, Any]) -> str:
    model = storage.get("model") or "unknown"
    media_type = storage.get("media_type") or "unknown"
    size_bytes = storage.get("size_bytes")
    prefix = ""
    if isinstance(size_bytes, (int, float)) and size_bytes > 0:
        if size_bytes >= 1000**4:
            prefix = f"{round(size_bytes / (1000**4))} TB "
        else:
            prefix = f"{round(size_bytes / (1000**3))} GB "
    if media_type and media_type != "unknown":
        return f"{prefix}{model} ({media_type})".strip()
    return f"{prefix}{model}".strip()


def sanitize_label(label: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in label)
    return safe[:120]


def latex_escape(value: Any) -> str:
    text = str(value if value is not None else "unknown")
    for old, new in (
        ("\\", r"\textbackslash{}"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("$", r"\$"),
        ("#", r"\#"),
        ("_", r"\_"),
        ("{", r"\{"),
        ("}", r"\}"),
        ("~", r"\textasciitilde{}"),
        ("^", r"\textasciicircum{}"),
    ):
        text = text.replace(old, new)
    return text


if __name__ == "__main__":
    raise SystemExit(main())
