"""Section 6.5 / 7.6 / 7.7 / 7.9: drift-sweep fetch counts, local decision
latency, and the SQLite durable-state / idempotent-retry experiment.
"""
from __future__ import annotations

import csv
import itertools
import json
import os
import random
import sqlite3
import statistics
import tempfile
import threading
import time
from pathlib import Path

from ..models import Observation

FAULT_BUDGET = 1
SOURCE_COUNTS = (6, 12, 24)
DRIFT_FRACTIONS = (0.0, 1 / 6, 2 / 6, 3 / 6, 4 / 6, 5 / 6, 1.0)
LATENCY_FRACTIONS = (0.0, 0.5, 1.0)
ORDER_SEEDS = tuple(range(40260916, 40260936))
STRONG_VARIANTS = ("FULL", "AFFECTED", "RESIDUAL", "CWR")


def _independent_sources(n: int) -> list[dict]:
    return [
        {"id": f"src-{i}", "deps": frozenset({f"root-{i}"}), "cost": 1 + (i % 4)}
        for i in range(n)
    ]


def _obs(src: dict, value: bool, version: int) -> Observation:
    return Observation(src["id"], "sku", version, value, src["deps"], src["cost"])


def _cover_ok(obs_list: list[Observation]) -> bool:
    """Equivalent to ``cover_number(positives) > FAULT_BUDGET`` but only
    searches hitting sets up to size FAULT_BUDGET, so it stays cheap even
    with dozens of disjoint domains (``cover_number`` itself searches every
    size up to the full domain count and is combinatorially unsuitable for
    that regime)."""
    positive_deps = [o.dependencies for o in obs_list if o.allowed]
    if not positive_deps:
        return False
    domains = sorted(set().union(*positive_deps))
    for size in range(FAULT_BUDGET + 1):
        for combo in itertools.combinations(domains, size):
            c = set(combo)
            if all(c & deps for deps in positive_deps):
                return False
    return True


def _run_variant(variant: str, sources: list[dict], changed: set[int]) -> tuple[int, float]:
    """Return (fetch_count, decision_time_seconds) for a benign no-race drift world."""
    from ..algorithms import cwr_plan

    t0 = time.perf_counter()
    if variant == "FULL":
        obs = [_obs(s, True, 2 if i in changed else 1) for i, s in enumerate(sources)]
        fetches = len(sources)
        _cover_ok(obs)
    elif variant == "AFFECTED":
        obs = []
        fetches = 0
        for i, s in enumerate(sources):
            if i in changed:
                obs.append(_obs(s, True, 2))
                fetches += 1
            else:
                obs.append(_obs(s, True, 1))
        _cover_ok(obs)
    elif variant == "RESIDUAL":
        obs = [_obs(s, True, 1) for i, s in enumerate(sources) if i not in changed]
        fetches = 0
        for i in sorted(changed):
            if _cover_ok(obs):
                break
            obs.append(_obs(sources[i], True, 2))
            fetches += 1
        _cover_ok(obs)
    elif variant == "CWR":
        current = [_obs(s, True, 1) for i, s in enumerate(sources) if i not in changed]
        fetches = 0
        remaining = sorted(changed)
        while not _cover_ok(current) and remaining:
            unchanged_positive = [o for o in current if o.allowed]
            candidates = [Observation(sources[i]["id"], "sku", 2, True, sources[i]["deps"], sources[i]["cost"]) for i in remaining]
            plan = cwr_plan(unchanged_positive, candidates, FAULT_BUDGET)
            if plan is None:
                break
            _, plan_ids = plan
            for sid in plan_ids:
                i = next(idx for idx in remaining if sources[idx]["id"] == sid)
                current.append(_obs(sources[i], True, 2))
                fetches += 1
                remaining.remove(i)
        _cover_ok(current)
    else:
        raise ValueError(variant)
    elapsed = time.perf_counter() - t0
    return fetches, elapsed


def drift_sweep(output_dir: Path) -> dict:
    rows = []
    for n in SOURCE_COUNTS:
        for fraction in DRIFT_FRACTIONS:
            n_changed = round(fraction * n)
            for seed in ORDER_SEEDS:
                rng = random.Random(seed)
                sources = _independent_sources(n)
                order = list(range(n))
                rng.shuffle(order)
                changed = set(order[:n_changed])
                for variant in STRONG_VARIANTS:
                    fetches, _ = _run_variant(variant, sources, changed)
                    rows.append(
                        {
                            "n_sources": n,
                            "fraction_changed": round(fraction, 4),
                            "n_changed": n_changed,
                            "seed": seed,
                            "variant": variant,
                            "fetches": fetches,
                        }
                    )
    with (output_dir / "drift_sweep.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return {"calls": len(rows)}


def latency_sweep(output_dir: Path) -> dict:
    rows = []
    cells: dict[tuple[int, float, str], list[float]] = {}
    for n in SOURCE_COUNTS:
        for fraction in LATENCY_FRACTIONS:
            n_changed = round(fraction * n)
            for variant in STRONG_VARIANTS:
                planned = []
                for call_idx in range(240):
                    seed = 50_000_000 + n * 10_000 + int(fraction * 100) * 100 + call_idx
                    planned.append(seed)
                rng = random.Random(1_000_000 + n + int(fraction * 100))
                rng.shuffle(planned)
                timings = []
                for call_idx, seed in enumerate(planned):
                    order_rng = random.Random(seed)
                    sources = _independent_sources(n)
                    order = list(range(n))
                    order_rng.shuffle(order)
                    changed = set(order[:n_changed])
                    _, elapsed = _run_variant(variant, sources, changed)
                    if call_idx >= 40:
                        timings.append(elapsed * 1000.0)
                cells[(n, fraction, variant)] = timings
                for t_ms in timings:
                    rows.append({"n_sources": n, "fraction_changed": fraction, "variant": variant, "latency_ms": round(t_ms, 6)})

    with (output_dir / "latency_sweep.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    table7 = {}
    for variant in STRONG_VARIANTS:
        table7[variant] = {}
        for fraction, label in zip(LATENCY_FRACTIONS, ("0_changed", "12_changed", "24_changed")):
            timings = cells[(24, fraction, variant)]
            table7[variant][label] = round(statistics.median(timings), 3)
    return {"calls": len(rows), "table7_median_ms_at_24_sources": table7}


def _budget_trial(n_ops: int, unit_amount: int, budget: int, n_workers: int) -> tuple[int, int, int]:
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init = sqlite3.connect(db_path)
    init.execute("CREATE TABLE ledger(total INTEGER)")
    init.execute("INSERT INTO ledger VALUES (0)")
    init.commit()
    init.close()

    approved = 0
    rejected = 0
    lock = threading.Lock()

    def worker(op_ids: list[int]) -> None:
        nonlocal approved, rejected
        conn = sqlite3.connect(db_path, timeout=30)
        for _ in op_ids:
            while True:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    total = conn.execute("SELECT total FROM ledger").fetchone()[0]
                    if total + unit_amount <= budget:
                        conn.execute("UPDATE ledger SET total = total + ?", (unit_amount,))
                        conn.commit()
                        with lock:
                            approved += 1
                    else:
                        conn.rollback()
                        with lock:
                            rejected += 1
                    break
                except sqlite3.OperationalError:
                    conn.rollback()
                    continue
        conn.close()

    ops = list(range(n_ops))
    chunks = [ops[i::n_workers] for i in range(n_workers)]
    threads = [threading.Thread(target=worker, args=(chunk,)) for chunk in chunks]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = sqlite3.connect(db_path)
    final_total = final.execute("SELECT total FROM ledger").fetchone()[0]
    final.close()
    os.remove(db_path)
    return approved, rejected, final_total


def _idempotent_retry_trial(release_on_uncertain: bool) -> tuple[bool, int]:
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE ops(op_id TEXT PRIMARY KEY, amount INTEGER, status TEXT)")
    conn.execute("INSERT INTO ops VALUES ('op-1', 100, 'RESERVED')")
    conn.commit()
    conn.close()

    conn = sqlite3.connect(db_path)
    if release_on_uncertain:
        conn.execute("UPDATE ops SET status = 'RELEASED' WHERE op_id = 'op-1'")
        conn.commit()

    row = conn.execute("SELECT status FROM ops WHERE op_id = 'op-1'").fetchone()
    if row is not None and row[0] == "RESERVED":
        extra_payment = False
    else:
        conn.execute("INSERT INTO ops VALUES ('op-2', 100, 'CAPTURED')")
        conn.commit()
        extra_payment = True

    total_committed = conn.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM ops WHERE status IN ('RESERVED', 'CAPTURED')"
    ).fetchone()[0]
    conn.close()
    os.remove(db_path)
    return extra_payment, total_committed


def durable_state_experiment(output_dir: Path) -> dict:
    budget_rows = []
    for n_workers in (2, 8, 32):
        for trial in range(10):
            approved, rejected, final_total = _budget_trial(100, 20, 500, n_workers)
            budget_rows.append(
                {"n_workers": n_workers, "trial": trial, "approved": approved, "rejected": rejected, "final_total": final_total}
            )

    idempotency_rows = []
    for trial in range(10):
        extra_payment, total = _idempotent_retry_trial(release_on_uncertain=False)
        idempotency_rows.append({"group": "retain_uncertain_reservation", "trial": trial, "extra_payment": int(extra_payment), "total_committed": total})
    for trial in range(10):
        extra_payment, total = _idempotent_retry_trial(release_on_uncertain=True)
        idempotency_rows.append({"group": "release_uncertain_reservation", "trial": trial, "extra_payment": int(extra_payment), "total_committed": total})

    with (output_dir / "durable_state_budget.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(budget_rows[0]))
        writer.writeheader()
        writer.writerows(budget_rows)
    with (output_dir / "durable_state_idempotency.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(idempotency_rows[0]))
        writer.writeheader()
        writer.writerows(idempotency_rows)

    return {
        "budget_trials": len(budget_rows),
        "all_approved_25": all(r["approved"] == 25 for r in budget_rows),
        "all_budget_respected": all(r["final_total"] <= 500 for r in budget_rows),
        "retain_group_no_extra_payment": all(
            r["extra_payment"] == 0 for r in idempotency_rows if r["group"] == "retain_uncertain_reservation"
        ),
        "release_group_all_extra_payment": all(
            r["extra_payment"] == 1 for r in idempotency_rows if r["group"] == "release_uncertain_reservation"
        ),
    }


def run(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    drift = drift_sweep(output_dir)
    latency = latency_sweep(output_dir)
    durable = durable_state_experiment(output_dir)
    summary = {"drift_sweep": drift, "latency_sweep": latency, "durable_state": durable}
    (output_dir / "performance_state_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    result = run(Path(__file__).resolve().parents[3] / "results" / "section6_reproduction")
    print(json.dumps(result, indent=2))
