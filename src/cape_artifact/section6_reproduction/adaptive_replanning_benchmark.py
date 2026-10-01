"""CWR's realized adaptive-replanning cost vs. its own single-shot theorem.

`cwr_plan`'s minimum-cost guarantee (`algorithms.py`) is stated over a
single planning call: *given* a set of candidates that will report positive
if queried, this is the minimum cost that certifies the predicate. The
manuscript's gateway (`gateway.py` lines ~121-151) uses it *adaptively*:
plan, query the plan's sources, and if any comes back negative or
unavailable, replan over the remaining candidates and try again. A reviewer
pass noted that the theorem's proof covers the single-shot case, not the
realized cost of this full adaptive loop when early guesses turn out wrong
-- each wrong guess wastes that source's query cost before a new, smaller
plan is computed.

This benchmark measures that gap directly, reusing `cwr_plan` unmodified.
For each generated instance, every candidate has a hidden ground-truth
outcome (whether it would actually report positive if queried, and whether
it's available at all); the adaptive loop below is a fresh implementation
of `gateway.py`'s own replanning logic (not importing gateway.py, to avoid
any coupling to its `EvidenceNetwork`/`Cart` machinery) run against that
ground truth, and its **realized total query cost** (including any wasted
queries against candidates that turned out negative) is compared to
`cwr_plan`'s own **theoretical single-shot minimum** computed with full
foreknowledge of which candidates are truly positive -- an honest *lower
bound* on any strategy's cost (since real evidence isn't guaranteed
positive), not a claim that this is the optimal adaptive cost; computing a
true offline-adaptive-optimal is a separate, harder problem this benchmark
does not attempt.

Three adversary strengths generate the ground truth:

- `benign`: every candidate is truly positive and available -- sanity
  check, realized cost should exactly equal the theoretical minimum.
- `random`: each candidate is truly positive with probability `P_POSITIVE`,
  independently.
- `adversarial`: the cheapest candidates (the ones CWR's dominance-pruned
  planner would prefer to try first) are deliberately made falsely
  negative, up to `ADVERSARIAL_FRACTION` of all candidates -- the worst
  case for wasted-query overhead, since it forces CWR to exhaust its
  preferred cheap picks before succeeding.

This is new, supplementary, additive work; it does not modify `gateway.py`,
`payee_gateway.py`, `algorithms.py`, or any of their already-published
results.
"""
from __future__ import annotations

import csv
import json
import random
import statistics
from pathlib import Path

from ..algorithms import cwr_plan, positive_certificate
from ..models import Observation

DOMAIN_COUNTS = (6, 10, 15)
FAULT_BUDGETS = (1, 2)
CANDIDATE_COUNTS = (6, 9, 12)
SEEDS_PER_CELL = 20
P_POSITIVE = 0.7
ADVERSARIAL_FRACTION = 0.6
ADVERSARY_LEVELS = ("benign", "random", "adversarial")


def _domains(n: int) -> tuple[str, ...]:
    return tuple(f"D{i:03d}" for i in range(n))


def _gen_instance(rng: random.Random, domains: tuple[str, ...], n_candidates: int):
    candidates = []
    for i in range(n_candidates):
        k = rng.randint(1, min(3, len(domains)))
        deps = frozenset(rng.sample(domains, k=k))
        cost = rng.randint(1, 9)
        candidates.append(Observation(f"cand-{i}", "sku", 1, True, deps, cost))
    return candidates


def _assign_ground_truth(rng: random.Random, candidates: list[Observation], adversary: str) -> dict[str, bool]:
    if adversary == "benign":
        return {c.source_id: True for c in candidates}
    if adversary == "random":
        return {c.source_id: rng.random() < P_POSITIVE for c in candidates}
    if adversary == "adversarial":
        by_cost = sorted(candidates, key=lambda c: (c.cost, c.source_id))
        n_false = int(len(candidates) * ADVERSARIAL_FRACTION)
        falsified = {c.source_id for c in by_cost[:n_false]}
        return {c.source_id: c.source_id not in falsified for c in candidates}
    raise ValueError(f"unknown adversary: {adversary!r}")


def _theoretical_minimum(candidates: list[Observation], ground_truth: dict[str, bool], fault_budget: int) -> int | None:
    truly_positive = [c for c in candidates if ground_truth[c.source_id]]
    result = cwr_plan([], truly_positive, fault_budget)
    return result[0] if result is not None else None


def _run_adaptive(candidates: list[Observation], ground_truth: dict[str, bool], fault_budget: int) -> dict:
    by_id = {c.source_id: c for c in candidates}
    current_positive: list[Observation] = []
    stale_ids = [c.source_id for c in candidates]
    realized_cost = 0
    queried_count = 0
    wasted_queries = 0
    rounds = 0

    while not positive_certificate(current_positive, fault_budget):
        rounds += 1
        metadata = [
            Observation(sid, "sku", 1, True, by_id[sid].dependencies, by_id[sid].cost) for sid in stale_ids
        ]
        plan = cwr_plan(current_positive, metadata, fault_budget)
        if not plan or not plan[1]:
            return {"verdict": "STEP_UP", "realized_cost": realized_cost, "queried_count": queried_count,
                    "wasted_queries": wasted_queries, "rounds": rounds}
        replanned = False
        for sid in plan[1]:
            queried_count += 1
            realized_cost += by_id[sid].cost
            stale_ids.remove(sid)
            if ground_truth[sid]:
                current_positive.append(by_id[sid])
            else:
                wasted_queries += 1
                replanned = True
                break
        if replanned:
            continue
    return {"verdict": "ALLOW", "realized_cost": realized_cost, "queried_count": queried_count,
            "wasted_queries": wasted_queries, "rounds": rounds}


def run_benchmark() -> list[dict]:
    rows = []
    for domain_count in DOMAIN_COUNTS:
        domains = _domains(domain_count)
        for fault_budget in FAULT_BUDGETS:
            for n_candidates in CANDIDATE_COUNTS:
                for adversary in ADVERSARY_LEVELS:
                    for seed_idx in range(SEEDS_PER_CELL):
                        seed = (
                            950_000_000 + domain_count * 100_000 + fault_budget * 10_000
                            + n_candidates * 100 + ADVERSARY_LEVELS.index(adversary) * 10 + seed_idx
                        )
                        rng = random.Random(seed)
                        candidates = _gen_instance(rng, domains, n_candidates)
                        ground_truth = _assign_ground_truth(rng, candidates, adversary)
                        theoretical_min = _theoretical_minimum(candidates, ground_truth, fault_budget)
                        adaptive = _run_adaptive(candidates, ground_truth, fault_budget)

                        feasible = theoretical_min is not None
                        overhead_ratio = (
                            adaptive["realized_cost"] / theoretical_min
                            if feasible and theoretical_min > 0 and adaptive["verdict"] == "ALLOW"
                            else ""
                        )
                        rows.append(
                            {
                                "seed": seed, "domain_count": domain_count, "fault_budget": fault_budget,
                                "n_candidates": n_candidates, "adversary": adversary,
                                "feasible": int(feasible), "theoretical_min_cost": theoretical_min if feasible else "",
                                "realized_cost": adaptive["realized_cost"], "verdict": adaptive["verdict"],
                                "queried_count": adaptive["queried_count"], "wasted_queries": adaptive["wasted_queries"],
                                "rounds": adaptive["rounds"], "overhead_ratio": overhead_ratio,
                            }
                        )
    return rows


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = run_benchmark()
    _write_csv(output_dir / "adaptive_replanning_runs.csv", rows)

    summary = {"scope": (
        "Realized CWR adaptive-replanning cost vs. its own single-shot "
        "theoretical minimum (an honest lower bound, not a claim of "
        "optimal-adaptive cost). Does not modify gateway.py, "
        "payee_gateway.py, algorithms.py, or their results."
    )}
    for adversary in ADVERSARY_LEVELS:
        group = [r for r in rows if r["adversary"] == adversary]
        allowed = [r for r in group if r["verdict"] == "ALLOW" and r["overhead_ratio"] != ""]
        step_up = [r for r in group if r["verdict"] == "STEP_UP"]
        ratios = [r["overhead_ratio"] for r in allowed]
        summary[adversary] = {
            "total_instances": len(group),
            "resolved_to_allow": len(allowed),
            "step_up_count": len(step_up),
            "mean_overhead_ratio": round(statistics.mean(ratios), 4) if ratios else None,
            "median_overhead_ratio": round(statistics.median(ratios), 4) if ratios else None,
            "max_overhead_ratio": round(max(ratios), 4) if ratios else None,
            "mean_wasted_queries": round(statistics.mean(r["wasted_queries"] for r in group), 4),
        }
    (output_dir / "adaptive_replanning_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    result = run(Path(__file__).resolve().parents[3] / "results" / "section6_reproduction")
    print(json.dumps(result, indent=2))
