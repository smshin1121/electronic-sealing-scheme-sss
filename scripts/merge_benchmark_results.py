from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.benchmark_metrics import (
    BaselineResult,
    build_baseline_summary_rows,
)
from scripts.run_performance_benchmark import (
    BenchmarkCase,
    RunResult,
    build_summary_rows,
    save_csv,
    save_json,
    write_latex_tables,
    write_markdown_report,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Merge multiple staged benchmark runs into one consolidated "
            "summary and manuscript-ready LaTeX output."
        )
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Benchmark output directories to merge.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for merged report and summary files.",
    )
    parser.add_argument(
        "--latex-dir",
        type=Path,
        default=REPO_ROOT / "Latex" / "generated",
        help="Destination for merged LaTeX tables.",
    )
    parser.add_argument(
        "--primary-chunk-gb",
        type=int,
        default=64,
        help="Chunk size used for the manuscript-ready LaTeX performance table.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    latex_dir = args.latex_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    latex_dir.mkdir(parents=True, exist_ok=True)

    merged_raw_rows: list[dict[str, Any]] = []
    merged_baseline_rows: list[dict[str, Any]] = []
    merged_cases: dict[str, BenchmarkCase] = {}
    merged_sources: list[str] = []
    base_environment: dict[str, Any] | None = None
    chunk_sizes: set[int] = set()

    for item in args.inputs:
        bench_dir = Path(item).resolve()
        raw_path = bench_dir / "raw_runs.json"
        env_path = bench_dir / "environment.json"
        config_path = bench_dir / "benchmark_config.json"

        if not raw_path.is_file():
            raise SystemExit(f"Missing raw_runs.json: {raw_path}")
        if not env_path.is_file():
            raise SystemExit(f"Missing environment.json: {env_path}")
        if not config_path.is_file():
            raise SystemExit(f"Missing benchmark_config.json: {config_path}")

        raw_rows = json.loads(raw_path.read_text(encoding="utf-8"))
        config = json.loads(config_path.read_text(encoding="utf-8"))
        env = json.loads(env_path.read_text(encoding="utf-8"))

        if base_environment is None:
            base_environment = env

        merged_raw_rows.extend(raw_rows)
        merged_sources.append(str(bench_dir))
        chunk_sizes.update(config.get("chunk_sizes_gb", []))

        baseline_path = bench_dir / "baseline_runs.json"
        if baseline_path.is_file():
            merged_baseline_rows.extend(
                json.loads(baseline_path.read_text(encoding="utf-8"))
            )

        for case in config.get("cases", []):
            label = case["label"]
            merged_cases[label] = BenchmarkCase(
                label=label,
                source_path=Path(case["source_path"]) if case.get("source_path") else None,
                size_bytes=case["size_bytes"],
            )

    if base_environment is None:
        raise SystemExit("No benchmark inputs were merged.")

    run_results = [RunResult(**row) for row in merged_raw_rows]
    summary_rows = build_summary_rows(run_results)
    baseline_results = [BaselineResult(**row) for row in merged_baseline_rows]
    baseline_summary_rows = build_baseline_summary_rows(baseline_results)

    merged_config = {
        "merged_sources": merged_sources,
        "primary_chunk_gb": args.primary_chunk_gb,
        "chunk_sizes_gb": sorted(chunk_sizes),
        "case_count": len(merged_cases),
        "run_count": len(run_results),
    }

    save_json(output_dir / "benchmark_config.json", merged_config)
    save_json(output_dir / "environment.json", base_environment)
    save_json(output_dir / "raw_runs.json", merged_raw_rows)
    save_json(output_dir / "summary.json", summary_rows)
    save_csv(output_dir / "raw_runs.csv", merged_raw_rows)
    save_csv(output_dir / "summary.csv", summary_rows)
    if merged_baseline_rows:
        save_json(output_dir / "baseline_runs.json", merged_baseline_rows)
        save_csv(output_dir / "baseline_runs.csv", merged_baseline_rows)
        save_json(output_dir / "baseline_summary.json", baseline_summary_rows)
        save_csv(output_dir / "baseline_summary.csv", baseline_summary_rows)

    report_args = argparse.Namespace(
        repeats="merged",
        chunk_sizes_gb=sorted(chunk_sizes),
    )
    write_markdown_report(
        output_dir / "report.md",
        report_args,
        base_environment,
        summary_rows,
        baseline_summary_rows,
    )
    write_latex_tables(
        latex_dir,
        base_environment,
        summary_rows,
        args.primary_chunk_gb,
        list(merged_cases.values()),
        baseline_summary_rows,
    )

    print(f"Merged benchmark written to: {output_dir}")
    print(f"Merged LaTeX written to: {latex_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
