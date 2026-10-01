"""Section 6.4 (first half) / 7.2: CWR exact planning vs. exhaustive, greedy,
sequential, and full acquisition on synthetic all-positive repair instances.
"""
from __future__ import annotations

import csv
import itertools
import json
import random
import statistics
import time
from pathlib import Path

from ..algorithms import cover_number, cwr_plan, residual_hypotheses
from ..models import Observation

DOMAINS = tuple("ABCDEF")
FAULT_BUDGETS = (1, 2)
CANDIDATE_COUNTS = (6, 9)
SEEDS_PER_CELL = 150


def _gen_instance(rng: random.Random, fault_budget: int, n_candidates: int, has_residual: bool):
    residual = []
    if has_residual:
        deps = frozenset(rng.sample(DOMAINS, k=rng.randint(1, 3)))
        residual.append(Observation("residual-0", "sku", 1, True, deps, 0))
    candidates = []
    for i in range(n_candidates):
        deps = frozenset(rng.sample(DOMAINS, k=rng.randint(1, 3)))
        cost = rng.randint(1, 9)
        candidates.append(Observation(f"cand-{i}", "sku", 1, True, deps, cost))
    return residual, candidates


def _exhaustive_plan(residual, candidates, fault_budget):
    best = None
    for size in range(len(candidates) + 1):
        for combo in itertools.combinations(candidates, size):
            if cover_number([*residual, *combo]) > fault_budget:
                cost = sum(c.cost for c in combo)
                if best is None or cost < best:
                    best = cost
    return best


def _greedy_plan(residual, candidates, fault_budget):
    chosen_cost = 0
    current = list(residual)
    pool = list(candidates)
    while True:
        hyps = residual_hypotheses(current, pool, fault_budget)
        if not hyps:
            return chosen_cost
        if not pool:
            return None
        best = None
        for obs in pool:
            eliminated = sum(1 for h in hyps if not h.intersection(obs.dependencies))
            if eliminated == 0:
                continue
            score = eliminated / obs.cost
            if best is None or score > best[0] or (score == best[0] and obs.cost < best[1].cost):
                best = (score, obs)
        if best is None:
            return None
        chosen_obs = best[1]
        chosen_cost += chosen_obs.cost
        current.append(chosen_obs)
        pool = [o for o in pool if o.source_id != chosen_obs.source_id]


def _sequential_plan(residual, candidates, fault_budget):
    current = list(residual)
    cost = 0
    for obs in candidates:
        if cover_number([o for o in current if o.allowed]) > fault_budget:
            break
        current.append(obs)
        cost += obs.cost
    return cost if cover_number([o for o in current if o.allowed]) > fault_budget else None


def _full_plan(residual, candidates, fault_budget):
    combined = [*residual, *candidates]
    if cover_number([o for o in combined if o.allowed]) > fault_budget:
        return sum(c.cost for c in candidates)
    return None


def run(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    cwr_times_us = []
    for fault_budget in FAULT_BUDGETS:
        for n_candidates in CANDIDATE_COUNTS:
            for seed_idx in range(SEEDS_PER_CELL):
                seed = 700_000 + fault_budget * 100_000 + n_candidates * 1_000 + seed_idx
                rng = random.Random(seed)
                has_residual = seed_idx % 2 == 0
                residual, candidates = _gen_instance(rng, fault_budget, n_candidates, has_residual)

                t0 = time.perf_counter()
                cwr_result = cwr_plan(residual, candidates, fault_budget)
                cwr_times_us.append((time.perf_counter() - t0) * 1_000_000)
                cwr_cost = cwr_result[0] if cwr_result is not None else None

                exhaustive_cost = _exhaustive_plan(residual, candidates, fault_budget)
                greedy_cost = _greedy_plan(residual, candidates, fault_budget)
                sequential_cost = _sequential_plan(residual, candidates, fault_budget)
                full_cost = _full_plan(residual, candidates, fault_budget)

                rows.append(
                    {
                        "seed": seed,
                        "fault_budget": fault_budget,
                        "n_candidates": n_candidates,
                        "has_residual": int(has_residual),
                        "feasible": int(exhaustive_cost is not None),
                        "cwr_cost": cwr_cost,
                        "exhaustive_cost": exhaustive_cost,
                        "greedy_cost": greedy_cost,
                        "sequential_cost": sequential_cost,
                        "full_cost": full_cost,
                        "cwr_matches_exhaustive": int(cwr_cost == exhaustive_cost),
                    }
                )

    feasible_rows = [r for r in rows if r["feasible"]]
    n_feasible = len(feasible_rows)
    n_total = len(rows)
    agreement = sum(r["cwr_matches_exhaustive"] for r in rows)
    greedy_suboptimal = sum(1 for r in feasible_rows if r["greedy_cost"] is not None and r["greedy_cost"] > r["cwr_cost"])

    planner_totals = {
        "full": sum(r["full_cost"] for r in feasible_rows if r["full_cost"] is not None),
        "sequential": sum(r["sequential_cost"] for r in feasible_rows if r["sequential_cost"] is not None),
        "greedy": sum(r["greedy_cost"] for r in feasible_rows if r["greedy_cost"] is not None),
        "cwr": sum(r["cwr_cost"] for r in feasible_rows if r["cwr_cost"] is not None),
    }
    planner_means = {k: round(v / n_feasible, 3) for k, v in planner_totals.items()} if n_feasible else {}

    cwr_times_us.sort()
    p95_idx = min(len(cwr_times_us) - 1, int(0.95 * len(cwr_times_us)))
    timing = {
        "median_us": round(statistics.median(cwr_times_us), 3),
        "p95_us": round(cwr_times_us[p95_idx], 3),
    }

    summary = {
        "total_instances": n_total,
        "feasible_instances": n_feasible,
        "infeasible_instances": n_total - n_feasible,
        "cwr_exhaustive_agreement": agreement,
        "cwr_exhaustive_agreement_pct": round(100 * agreement / n_total, 2),
        "greedy_suboptimal_count": greedy_suboptimal,
        "planner_total_cost": planner_totals,
        "planner_mean_cost": planner_means,
        "cwr_timing_us": timing,
    }

    with (output_dir / "planning_instances.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output_dir / "planning_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    result = run(Path(__file__).resolve().parents[3] / "results" / "section6_reproduction")
    print(json.dumps(result, indent=2))
