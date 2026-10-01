"""Section 6.6 / 7.3: 1,000-world DFMR finite-world stress benchmark against
Full, Sequential, and CWR.
"""
from __future__ import annotations

import csv
import json
import random
import statistics
from pathlib import Path

from ..algorithms import bilateral_decision, cwr_plan, dfmr_choose_next
from ..models import ALLOW, DENY, STEP_UP, Observation

DOMAINS5 = ("A", "B", "C", "D", "E")
FAULT_BUDGET = 1
N_WORLDS = 1000
SEEDS = tuple(range(2026091700, 2026091700 + N_WORLDS))
FLIP_PROBABILITY = 0.85
CORRUPTION_PROBABILITY = 0.6


def build_world(seed: int):
    rng = random.Random(seed)
    shared_root = "A"
    solo_roots = ("B", "C", "D", "E")
    specs = []
    for i in range(4):
        specs.append({"id": f"shared-{i}", "deps": frozenset({shared_root}), "cost": rng.randint(1, 3)})
    for i, root in enumerate(solo_roots):
        specs.append({"id": f"solo-{i}", "deps": frozenset({root}), "cost": rng.randint(3, 8)})
    dual_domains = frozenset(rng.sample(DOMAINS5, 2))
    specs.append({"id": "dual-0", "deps": dual_domains, "cost": rng.randint(3, 8)})

    truth_allowed = rng.random() < 0.5
    corrupted = frozenset({rng.choice(DOMAINS5)}) if rng.random() < CORRUPTION_PROBABILITY else frozenset()

    def reported_value(spec) -> bool:
        if corrupted & spec["deps"] and rng.random() < FLIP_PROBABILITY:
            return not truth_allowed
        return truth_allowed

    current_spec = specs[0]
    current_obs = Observation(current_spec["id"], "sku", 1, reported_value(current_spec), current_spec["deps"], current_spec["cost"])
    candidates = [(spec, reported_value(spec)) for spec in specs[1:]]
    return truth_allowed, current_obs, candidates


def run_full(current_obs, candidates):
    observations = [current_obs] + [Observation(spec["id"], "sku", 1, value, spec["deps"], spec["cost"]) for spec, value in candidates]
    verdict = bilateral_decision(observations, FAULT_BUDGET)
    cost = sum(o.cost for o in observations)
    return verdict, cost, len(candidates)


def run_sequential(current_obs, candidates):
    observations = [current_obs]
    remaining = sorted(candidates, key=lambda pair: pair[0]["cost"])
    cost = 0
    queries = 0
    verdict = bilateral_decision(observations, FAULT_BUDGET)
    for spec, value in remaining:
        if verdict != STEP_UP:
            break
        observations.append(Observation(spec["id"], "sku", 1, value, spec["deps"], spec["cost"]))
        cost += spec["cost"]
        queries += 1
        verdict = bilateral_decision(observations, FAULT_BUDGET)
    return verdict, cost, queries


def run_cwr(current_obs, candidates):
    """CWR only repairs positive support (Section 5.5); a negative current
    observation contributes nothing and negative refreshes are dropped."""
    observations = [current_obs] if current_obs.allowed else []
    remaining = {spec["id"]: (spec, value) for spec, value in candidates}
    cost = 0
    queries = 0

    while remaining:
        unchanged_positive = [o for o in observations if o.allowed]
        candidate_obs = [Observation(sid, "sku", 1, True, spec["deps"], spec["cost"]) for sid, (spec, _) in remaining.items()]
        plan = cwr_plan(unchanged_positive, candidate_obs, FAULT_BUDGET)
        if plan is None:
            break
        _, plan_ids = plan
        progressed = False
        for sid in plan_ids:
            spec, value = remaining.pop(sid)
            observations.append(Observation(sid, "sku", 1, value, spec["deps"], spec["cost"]))
            cost += spec["cost"]
            queries += 1
            progressed = True
            if not value:
                break
        if not progressed:
            break
        if bilateral_decision(observations, FAULT_BUDGET) == ALLOW:
            break

    positives_only = [o for o in observations if o.allowed]
    final = ALLOW if bilateral_decision(positives_only, FAULT_BUDGET) == ALLOW else STEP_UP
    return final, cost, queries


def run_dfmr(current_obs, candidates):
    observations = [current_obs]
    remaining = {spec["id"]: (spec, value) for spec, value in candidates}
    cost = 0
    queries = 0
    verdict = bilateral_decision(observations, FAULT_BUDGET)
    while verdict == STEP_UP and remaining:
        candidate_obs = [Observation(sid, "sku", 1, True, spec["deps"], spec["cost"]) for sid, (spec, _) in remaining.items()]
        next_id = dfmr_choose_next(observations, candidate_obs, FAULT_BUDGET)
        if next_id is None:
            break
        spec, value = remaining.pop(next_id)
        observations.append(Observation(next_id, "sku", 1, value, spec["deps"], spec["cost"]))
        cost += spec["cost"]
        queries += 1
        verdict = bilateral_decision(observations, FAULT_BUDGET)
    return verdict, cost, queries


def run(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for seed in SEEDS:
        truth_allowed, current_obs, candidates = build_world(seed)
        expected = ALLOW if truth_allowed else DENY
        for method_name, method in (("FULL", run_full), ("SEQUENTIAL", run_sequential), ("CWR", run_cwr), ("DFMR", run_dfmr)):
            verdict, cost, queries = method(current_obs, candidates)
            rows.append(
                {
                    "seed": seed,
                    "truth": "ALLOW" if truth_allowed else "DENY",
                    "method": method_name,
                    "verdict": verdict,
                    "correct": int(verdict == expected),
                    "cost": cost,
                    "queries": queries,
                }
            )

    with (output_dir / "dfmr_benchmark_runs.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    summary = []
    for method_name in ("FULL", "SEQUENTIAL", "CWR", "DFMR"):
        for subset_name, subset_filter in (
            ("ALL", lambda r: True),
            ("ALLOW", lambda r: r["truth"] == "ALLOW"),
            ("DENY", lambda r: r["truth"] == "DENY"),
        ):
            group = [r for r in rows if r["method"] == method_name and subset_filter(r)]
            if not group:
                continue
            costs = sorted(r["cost"] for r in group)
            p95_idx = min(len(costs) - 1, int(0.95 * len(costs)))
            summary.append(
                {
                    "method": method_name,
                    "subset": subset_name,
                    "n": len(group),
                    "correct_pct": round(100 * sum(r["correct"] for r in group) / len(group), 2),
                    "step_up_pct": round(100 * sum(1 for r in group if r["verdict"] == STEP_UP) / len(group), 2),
                    "mean_cost": round(statistics.fmean(r["cost"] for r in group), 3),
                    "p95_cost": costs[p95_idx],
                    "mean_queries": round(statistics.fmean(r["queries"] for r in group), 3),
                }
            )
    (output_dir / "dfmr_benchmark_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return {"rows": len(rows), "summary": summary}


if __name__ == "__main__":
    result = run(Path(__file__).resolve().parents[3] / "results" / "section6_reproduction")
    print(json.dumps(result["summary"], indent=2))
