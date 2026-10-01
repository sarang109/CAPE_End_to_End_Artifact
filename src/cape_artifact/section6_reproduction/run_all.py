"""Run all five section 6.2-6.6 reproduction benchmarks and save results.

Usage: python -m cape_artifact.section6_reproduction.run_all
"""
from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

from . import dfmr_benchmark, factorial_workload, performance_state, planning_benchmark, structural_checks


def main() -> None:
    output_dir = Path(__file__).resolve().parents[3] / "results" / "section6_reproduction"
    output_dir.mkdir(parents=True, exist_ok=True)

    started = time.time()
    results = {}

    t0 = time.time()
    results["factorial_workload_6_2_6_3"] = factorial_workload.run(output_dir)
    results["factorial_workload_6_2_6_3"]["elapsed_seconds"] = round(time.time() - t0, 3)

    t0 = time.time()
    results["planning_benchmark_6_4a"] = planning_benchmark.run(output_dir)
    results["planning_benchmark_6_4a"]["elapsed_seconds"] = round(time.time() - t0, 3)

    t0 = time.time()
    results["structural_checks_6_4b_7_8"] = structural_checks.run(output_dir)
    results["structural_checks_6_4b_7_8"]["elapsed_seconds"] = round(time.time() - t0, 3)

    t0 = time.time()
    results["performance_state_6_5"] = performance_state.run(output_dir)
    results["performance_state_6_5"]["elapsed_seconds"] = round(time.time() - t0, 3)

    t0 = time.time()
    dfmr_result = dfmr_benchmark.run(output_dir)
    results["dfmr_benchmark_6_6"] = {"rows": dfmr_result["rows"], "elapsed_seconds": round(time.time() - t0, 3)}

    environment = {
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "total_elapsed_seconds": round(time.time() - started, 3),
    }
    (output_dir / "run_all_environment.json").write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
    (output_dir / "run_all_index.json").write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")

    print(json.dumps({"environment": environment, "results": results}, indent=2, default=str))


if __name__ == "__main__":
    main()
