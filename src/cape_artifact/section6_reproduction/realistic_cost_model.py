"""A documented, explicitly SIMULATED realistic cost/latency model, applied
post-hoc to the existing deterministic results.

A reviewer pass noted the manuscript's cost model is dimensionless and
purely additive (`query_cost = sum(source.cost)`, confirmed in
`gateway.py` line ~199) and does not capture parallel queries,
network-tail latency, per-source failure probability, or retries. This
module does not change that cost model or re-run the experiment; it reads
the **existing, unmodified** `results/end_to_end_runs.csv` (columns
`defense`, `queries`, `query_cost` -- no per-round batch detail is
recorded there, so the parallelism assumption below is the finest grain
available without re-instrumenting `gateway.py`) and layers a clearly
labeled *simulation* on top, writing a new derived-metrics file.

Every parameter below is an illustrative assumption, not a measurement
from a real deployment or provider SLA:

- `LATENCY_MEDIAN_MS` / `LATENCY_SIGMA`: a lognormal per-source network
  round-trip latency (median 150 ms, shaped for a realistic long tail).
- `FAILURE_PROBABILITY`: 2% chance a given call needs one retry.
- `RETRY_LATENCY_MULTIPLIER`: a retried call's latency is doubled
  (backoff), matching the retry convention already used for real,
  billed calls elsewhere in this artifact (`frontier_benchmark.retry_with_backoff`).

Parallelism assumption (the actual new modeling choice, everything else
is standard latency simulation): `CWR`, `FULL`, `MAJORITY`, and `TTL`'s
"refresh every source" style queries are modeled as one parallel batch
(realized latency = the slowest of the batch, not the sum) since a real
implementation could reasonably issue them concurrently; `DFMR`'s
one-source-at-a-time adaptive queries are modeled as strictly sequential,
since each query's outcome determines whether/what to query next.
`AP2_ONLY` never queries anything (0 latency, unchanged from the abstract
model).
"""
from __future__ import annotations

import csv
import json
import random
import statistics
from pathlib import Path

LATENCY_MEDIAN_MS = 150.0
LATENCY_SIGMA = 0.6
FAILURE_PROBABILITY = 0.02
RETRY_LATENCY_MULTIPLIER = 2.0

PARALLEL_DEFENSES = {"CWR", "FULL", "MAJORITY", "TTL"}
SEQUENTIAL_DEFENSES = {"DFMR"}
NO_QUERY_DEFENSES = {"AP2_ONLY"}


def _sample_latency_ms(rng: random.Random) -> float:
    latency = rng.lognormvariate(_log_median(), LATENCY_SIGMA)
    if rng.random() < FAILURE_PROBABILITY:
        latency *= RETRY_LATENCY_MULTIPLIER
    return latency


def _log_median() -> float:
    import math

    return math.log(LATENCY_MEDIAN_MS)


def simulate_realistic_latency_ms(defense: str, n_queries: int, rng: random.Random) -> float:
    if n_queries <= 0 or defense in NO_QUERY_DEFENSES:
        return 0.0
    draws = [_sample_latency_ms(rng) for _ in range(n_queries)]
    if defense in SEQUENTIAL_DEFENSES:
        return sum(draws)
    # Parallel-batch defenses (including any not explicitly listed, as a
    # conservative default -- treating an unknown defense as sequential
    # would silently overstate its simulated cost).
    return max(draws)


def run(input_csv: Path, output_dir: Path, seed: int = 20260919) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    with input_csv.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))

    derived_rows = []
    for row in rows:
        defense = row["defense"]
        n_queries = int(row["queries"])
        realistic_latency_ms = simulate_realistic_latency_ms(defense, n_queries, rng)
        derived_rows.append(
            {
                "repetition": row["repetition"],
                "scenario": row["scenario"],
                "defense": defense,
                "queries": n_queries,
                "abstract_query_cost": row["query_cost"],
                "abstract_latency_ms": row["latency_ms"],
                "simulated_realistic_latency_ms": round(realistic_latency_ms, 4),
            }
        )

    _write_csv(output_dir / "realistic_cost_model_runs.csv", derived_rows)

    by_defense: dict[str, list[float]] = {}
    for row in derived_rows:
        by_defense.setdefault(row["defense"], []).append(row["simulated_realistic_latency_ms"])
    summary = {
        "assumptions": {
            "latency_median_ms": LATENCY_MEDIAN_MS,
            "latency_sigma": LATENCY_SIGMA,
            "failure_probability": FAILURE_PROBABILITY,
            "retry_latency_multiplier": RETRY_LATENCY_MULTIPLIER,
            "parallel_defenses": sorted(PARALLEL_DEFENSES),
            "sequential_defenses": sorted(SEQUENTIAL_DEFENSES),
            "note": "Illustrative simulation, not measured from a real deployment.",
        },
        "by_defense_simulated_latency_ms": {
            defense: {
                "n": len(values),
                "mean": round(statistics.mean(values), 4),
                "median": round(statistics.median(values), 4),
                "max": round(max(values), 4),
            }
            for defense, values in sorted(by_defense.items())
        },
    }
    (output_dir / "realistic_cost_model_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    results_dir = Path(__file__).resolve().parents[3] / "results"
    result = run(results_dir / "end_to_end_runs.csv", results_dir / "section6_reproduction")
    print(json.dumps(result, indent=2))
