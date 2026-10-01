"""A documented, explicitly SIMULATED human-confirmation cost model for
STEP_UP, applied post-hoc to the existing deterministic results.

A reviewer pass noted the manuscript never measures the cost of `STEP_UP`
itself: how often human confirmation succeeds, or how long it takes. No
real user study exists in this artifact to draw on, so -- per explicit
agreement -- this module builds a clearly labeled *simulation* instead of
presenting invented numbers as measured data. It reads the **existing,
unmodified** `results/end_to_end_runs.csv`, isolates its `STEP_UP` rows,
and applies a documented, illustrative human-confirmation latency and
success-probability model, writing a new derived-metrics file. It does not
modify the source CSV, `gateway.py`, or any other already-published result.

Every parameter is a stated illustrative assumption, not a measurement:

- `CONFIRMATION_LATENCY_MEDIAN_S` / `_SIGMA`: a lognormal human-response
  time (median 45 seconds, shaped for a realistic long tail -- someone
  glancing at a push notification versus someone who has to be tracked
  down), loosely modeled on general human-response-time literature, not
  any measurement of this system's actual users.
- `CONFIRMATION_SUCCESS_PROBABILITY`: 0.92, i.e. an assumed 8% of step-ups
  are never resolved (declined, ignored, or timed out) -- again
  illustrative, not measured.
"""
from __future__ import annotations

import csv
import json
import random
import statistics
from pathlib import Path

CONFIRMATION_LATENCY_MEDIAN_S = 45.0
CONFIRMATION_LATENCY_SIGMA = 0.8
CONFIRMATION_SUCCESS_PROBABILITY = 0.92


def _log_median_s() -> float:
    import math

    return math.log(CONFIRMATION_LATENCY_MEDIAN_S)


def simulate_confirmation(rng: random.Random) -> tuple[float, bool]:
    latency_s = rng.lognormvariate(_log_median_s(), CONFIRMATION_LATENCY_SIGMA)
    resolved = rng.random() < CONFIRMATION_SUCCESS_PROBABILITY
    return latency_s, resolved


def run(input_csv: Path, output_dir: Path, seed: int = 20260919) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    with input_csv.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))

    step_up_rows = [r for r in rows if r["verdict"] == "STEP_UP"]
    derived_rows = []
    for row in step_up_rows:
        latency_s, resolved = simulate_confirmation(rng)
        derived_rows.append(
            {
                "repetition": row["repetition"],
                "scenario": row["scenario"],
                "defense": row["defense"],
                "attack": row["attack"],
                "assumption_status": row["assumption_status"],
                "simulated_confirmation_latency_s": round(latency_s, 4),
                "simulated_confirmation_resolved": int(resolved),
            }
        )

    _write_csv(output_dir / "step_up_cost_model_runs.csv", derived_rows)

    by_defense: dict[str, list[dict]] = {}
    for row in derived_rows:
        by_defense.setdefault(row["defense"], []).append(row)
    summary = {
        "assumptions": {
            "confirmation_latency_median_s": CONFIRMATION_LATENCY_MEDIAN_S,
            "confirmation_latency_sigma": CONFIRMATION_LATENCY_SIGMA,
            "confirmation_success_probability": CONFIRMATION_SUCCESS_PROBABILITY,
            "note": "Illustrative simulation; no real human-confirmation study exists in this artifact.",
        },
        "total_step_up_rows": len(step_up_rows),
        "by_defense": {
            defense: {
                "n": len(group),
                "mean_latency_s": round(statistics.mean(r["simulated_confirmation_latency_s"] for r in group), 4),
                "median_latency_s": round(statistics.median(r["simulated_confirmation_latency_s"] for r in group), 4),
                "resolved_count": sum(r["simulated_confirmation_resolved"] for r in group),
                "resolved_rate_pct": round(
                    100 * sum(r["simulated_confirmation_resolved"] for r in group) / len(group), 2
                ),
            }
            for defense, group in sorted(by_defense.items())
        },
    }
    (output_dir / "step_up_cost_model_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
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
