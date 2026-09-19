"""Dense provenance-domain scalability stress test, extending `scalability_benchmark.py`.

A reviewer pass on `scalability_benchmark.py` noted that its own configured
50-domain instances only touch ~18.5 active domains at the median, since
`_gen_instance` samples at most 3 domains per candidate observation --
realistic for this artifact's evidence topologies, but it "does not
demonstrate performance for dense graphs, large f, or hundreds of active
domains." This benchmark answers that specifically: candidates here can
touch up to `MAX_DOMAINS_PER_CANDIDATE = 25` domains each (not <=3), domain
counts run up to 500 (not 50), and fault budgets run up to 20 (not 3) --
deliberately dense enough to actually engage `HYPOTHESIS_LIMIT`, which
`scalability_benchmark.py`'s own sweep never reaches at any of its
(domain count, fault budget, candidate count) cells.

This is new, supplementary, additive work. It does not import
`scalability_benchmark.py`'s private `_gen_instance` (a fresh, denser
generator is defined here instead) and does not modify, rerun, or
overwrite any of `scalability_benchmark.py`'s four output files
(`scalability_timing.csv`, `scalability_dfmr_timing.csv`,
`scalability_correctness.csv`, `scalability_summary.json`) or
`planning_benchmark.py`'s results.
"""
from __future__ import annotations

import csv
import json
import random
import statistics
import time
from math import comb
from pathlib import Path

from ..algorithms import cwr_plan
from ..models import Observation

DOMAIN_COUNTS = (50, 100, 200, 500)
FAULT_BUDGETS = (1, 5, 10, 20)
CANDIDATE_COUNTS = (10, 20, 40)
MAX_DOMAINS_PER_CANDIDATE = 25
SEEDS_PER_CELL = 10
HYPOTHESIS_LIMIT = 20_000  # same advisory threshold as scalability_benchmark.py


def _domains(n: int) -> tuple[str, ...]:
    return tuple(f"D{i:04d}" for i in range(n))


def _gen_dense_instance(rng: random.Random, domains: tuple[str, ...], n_candidates: int):
    """Denser than `scalability_benchmark.py`'s `_gen_instance`: each
    candidate touches up to `MAX_DOMAINS_PER_CANDIDATE` domains (not <=3),
    so the union of touched ("active") domains across all candidates is a
    much larger fraction of the configured graph."""
    k_max = min(MAX_DOMAINS_PER_CANDIDATE, len(domains))
    residual_deps = frozenset(rng.sample(domains, k=min(5, len(domains))))
    residual = [Observation("residual-0", "sku", 1, True, residual_deps, 0)]
    candidates = []
    for i in range(n_candidates):
        k = rng.randint(1, k_max)
        deps = frozenset(rng.sample(domains, k=k))
        cost = rng.randint(1, 9)
        candidates.append(Observation(f"cand-{i}", "sku", 1, True, deps, cost))
    return residual, candidates


def _active_domain_count(residual, candidates) -> int:
    return len({d for obs in (*residual, *candidates) for d in obs.dependencies})


def _estimate_hypothesis_count(residual, candidates, fault_budget: int) -> int:
    touched = {d for obs in (*residual, *candidates) for d in obs.dependencies}
    m = len(touched)
    return sum(comb(m, k) for k in range(min(fault_budget, m) + 1))


def run_dense_sweep() -> list[dict]:
    rows = []
    for domain_count in DOMAIN_COUNTS:
        domains = _domains(domain_count)
        for fault_budget in FAULT_BUDGETS:
            for n_candidates in CANDIDATE_COUNTS:
                for seed_idx in range(SEEDS_PER_CELL):
                    seed = 940_000_000 + domain_count * 1_000 + fault_budget * 100 + n_candidates * 10 + seed_idx
                    rng = random.Random(seed)
                    residual, candidates = _gen_dense_instance(rng, domains, n_candidates)
                    active_domains = _active_domain_count(residual, candidates)
                    est_hypotheses = _estimate_hypothesis_count(residual, candidates, fault_budget)

                    row = {
                        "seed": seed,
                        "domain_count": domain_count,
                        "active_domain_count": active_domains,
                        "fault_budget": fault_budget,
                        "n_candidates": n_candidates,
                        "estimated_hypotheses": est_hypotheses,
                    }
                    if est_hypotheses > HYPOTHESIS_LIMIT:
                        row.update(
                            {"skipped_resource_limit": 1, "cwr_feasible": "", "cwr_cost": "", "cwr_time_ms": "",
                             "fallback_verdict": "STEP_UP"}
                        )
                        rows.append(row)
                        continue

                    t0 = time.perf_counter()
                    cwr_result = cwr_plan(residual, candidates, fault_budget)
                    cwr_time_ms = (time.perf_counter() - t0) * 1000
                    row.update(
                        {"skipped_resource_limit": 0, "cwr_feasible": int(cwr_result is not None),
                         "cwr_cost": cwr_result[0] if cwr_result is not None else "",
                         "cwr_time_ms": round(cwr_time_ms, 4), "fallback_verdict": ""}
                    )
                    rows.append(row)
    return rows


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(pct * len(ordered)))
    return ordered[idx]


def run(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = run_dense_sweep()
    _write_csv(output_dir / "dense_scalability_timing.csv", rows)

    solved = [r for r in rows if not r["skipped_resource_limit"]]
    skipped = [r for r in rows if r["skipped_resource_limit"]]
    active_counts = [r["active_domain_count"] for r in rows]
    by_domain_count: dict[int, list[float]] = {}
    for r in solved:
        by_domain_count.setdefault(r["domain_count"], []).append(r["cwr_time_ms"])
    timing_by_domain_count = {
        str(d): {
            "n": len(times),
            "mean_ms": round(statistics.mean(times), 4),
            "median_ms": round(statistics.median(times), 4),
            "p95_ms": round(_percentile(times, 0.95), 4),
            "max_ms": round(max(times), 4),
        }
        for d, times in sorted(by_domain_count.items())
    }

    summary = {
        "scope": (
            "Denser extension of scalability_benchmark.py: candidates touch up "
            f"to {MAX_DOMAINS_PER_CANDIDATE} domains each (vs <=3), domain "
            f"counts up to {max(DOMAIN_COUNTS)} (vs 50), fault budgets up to "
            f"{max(FAULT_BUDGETS)} (vs 3). Does not modify or rerun "
            "scalability_benchmark.py or planning_benchmark.py."
        ),
        "total_instances": len(rows),
        "solved_instances": len(solved),
        "skipped_resource_limit_instances": len(skipped),
        "hypothesis_limit": HYPOTHESIS_LIMIT,
        "active_domain_count_median": statistics.median(active_counts),
        "active_domain_count_max": max(active_counts),
        "timing_by_domain_count_ms": timing_by_domain_count,
    }
    (output_dir / "dense_scalability_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    result = run(Path(__file__).resolve().parents[3] / "results" / "section6_reproduction")
    print(json.dumps(result, indent=2))
