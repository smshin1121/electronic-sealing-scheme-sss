from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_EXE = sys.executable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plan, run, and merge staged benchmark batches for constrained storage "
            "environments."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan")
    plan.add_argument("--manifest", type=Path, required=True)
    plan.add_argument("--max-batch-gb", type=float, default=120.0)
    plan.add_argument("--chunk-sizes-gb", nargs="+", type=int, default=[64])
    plan.add_argument("--repeats", type=int, default=5)
    plan.add_argument("--primary-chunk-gb", type=int, default=64)
    plan.add_argument("--sizes-gb", nargs="*", type=int, default=[])
    plan.add_argument("--input-files", nargs="*", default=[])
    plan.add_argument("--input-globs", nargs="*", default=[])
    plan.add_argument("--data-mode", choices=["urandom", "zero"], default="urandom")
    plan.add_argument("--baselines", nargs="*", choices=["copy", "read"], default=[])
    plan.add_argument("--baseline-repeats", type=int, default=5)
    plan.add_argument("--latex-dir", type=Path, default=REPO_ROOT / "Latex" / "generated")
    plan.add_argument("--runs-root", type=Path, default=REPO_ROOT / "artifacts" / "performance")

    run = sub.add_parser("run-batch")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--batch", type=int, required=True)

    merge = sub.add_parser("merge")
    merge.add_argument("--manifest", type=Path, required=True)
    merge.add_argument("--output-dir", type=Path, required=True)
    merge.add_argument("--latex-dir", type=Path, default=REPO_ROOT / "Latex" / "generated")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "plan":
        return command_plan(args)
    if args.command == "run-batch":
        return command_run_batch(args)
    if args.command == "merge":
        return command_merge(args)
    raise SystemExit(f"Unknown command: {args.command}")


def command_plan(args: argparse.Namespace) -> int:
    cases = []
    for size in args.sizes_gb:
        cases.append(
            {
                "label": f"{size}GB_synthetic",
                "type": "synthetic",
                "size_gb": size,
                "source_path": None,
            }
        )

    for item in args.input_files:
        path = Path(item).resolve()
        if not path.is_file():
            raise SystemExit(f"Input file not found: {path}")
        cases.append(
            {
                "label": path.name,
                "type": "file",
                "size_gb": round(path.stat().st_size / (1024**3), 3),
                "source_path": str(path),
            }
        )

    for pattern in args.input_globs:
        for path in sorted(REPO_ROOT.glob(pattern)):
            if path.is_file():
                cases.append(
                    {
                        "label": path.name,
                        "type": "file",
                        "size_gb": round(path.stat().st_size / (1024**3), 3),
                        "source_path": str(path.resolve()),
                    }
                )

    dedup = {}
    for case in cases:
        dedup[(case["label"], case["source_path"], case["size_gb"])] = case
    cases = list(dedup.values())
    cases.sort(key=lambda item: (item["size_gb"], item["label"]))

    batches = []
    current = []
    current_total = 0.0
    for case in cases:
        case_size = max(case["size_gb"], 0.001)
        if current and current_total + case_size > args.max_batch_gb:
            batches.append(current)
            current = []
            current_total = 0.0
        current.append(case)
        current_total += case_size
    if current:
        batches.append(current)

    manifest = {
        "created_at": str(Path.cwd()),
        "chunk_sizes_gb": args.chunk_sizes_gb,
        "repeats": args.repeats,
        "primary_chunk_gb": args.primary_chunk_gb,
        "data_mode": args.data_mode,
        "baselines": args.baselines,
        "baseline_repeats": args.baseline_repeats,
        "latex_dir": str(args.latex_dir.resolve()),
        "runs_root": str(args.runs_root.resolve()),
        "max_batch_gb": args.max_batch_gb,
        "batches": [],
    }

    for idx, batch in enumerate(batches, 1):
        output_dir = args.runs_root.resolve() / f"batch_{idx:02d}"
        manifest["batches"].append(
            {
                "batch_index": idx,
                "output_dir": str(output_dir),
                "cases": batch,
            }
        )

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Manifest written: {args.manifest}")
    print(f"Batches planned: {len(manifest['batches'])}")
    return 0


def command_run_batch(args: argparse.Namespace) -> int:
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    batch = next(
        (item for item in manifest["batches"] if item["batch_index"] == args.batch),
        None,
    )
    if batch is None:
        raise SystemExit(f"Batch {args.batch} not found in manifest.")

    command = [
        PYTHON_EXE,
        str(REPO_ROOT / "scripts" / "run_performance_benchmark.py"),
        "--chunk-sizes-gb",
        *map(str, manifest["chunk_sizes_gb"]),
        "--repeats",
        str(manifest["repeats"]),
        "--output-dir",
        batch["output_dir"],
        "--latex-dir",
        manifest["latex_dir"],
        "--data-mode",
        manifest["data_mode"],
        "--primary-chunk-gb",
        str(manifest["primary_chunk_gb"]),
    ]

    baselines = manifest.get("baselines", [])
    if baselines:
        command.extend(["--baselines", *baselines])
        command.extend(
            ["--baseline-repeats", str(manifest.get("baseline_repeats", 5))]
        )

    input_files = [case["source_path"] for case in batch["cases"] if case["source_path"]]
    synthetic_sizes = [str(int(case["size_gb"])) for case in batch["cases"] if case["source_path"] is None]
    if input_files:
        command.extend(["--input-files", *input_files])
    if synthetic_sizes:
        command.extend(["--sizes-gb", *synthetic_sizes])

    return subprocess.run(command, check=False).returncode


def command_merge(args: argparse.Namespace) -> int:
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    input_dirs = [batch["output_dir"] for batch in manifest["batches"]]
    command = [
        PYTHON_EXE,
        str(REPO_ROOT / "scripts" / "merge_benchmark_results.py"),
        *input_dirs,
        "--output-dir",
        str(args.output_dir.resolve()),
        "--latex-dir",
        str(args.latex_dir.resolve()),
        "--primary-chunk-gb",
        str(manifest["primary_chunk_gb"]),
    ]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
