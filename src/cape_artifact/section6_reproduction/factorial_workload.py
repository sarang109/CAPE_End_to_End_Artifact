"""Section 6.2/6.3: matched authorization variants over a factorial evidence workload.

Reproduces the shape of Table 2 and Fig. 1: four provenance layouts, eight
event cases, twenty source orders, eight defense variants, fault budget f=1.
"""
from __future__ import annotations

import csv
import json
import random
import statistics
from dataclasses import dataclass
from pathlib import Path

from ..algorithms import cover_number, cwr_plan
from ..models import Observation

N_SOURCES = 6
FAULT_BUDGET = 1
LAYOUTS = ("independent", "pairs", "funnel", "single")
VARIANTS = ("QUOTE", "MAJORITY", "STATIC", "TTL", "FULL", "AFFECTED", "RESIDUAL", "CWR")
SEEDS = tuple(range(20260916, 20260936))
EVENT_CASES = (
    "benign_unchanged",
    "benign_2_changed",
    "benign_6_changed",
    "benign_unavailable_2",
    "attack_poisoned_root",
    "attack_flip_within_ttl",
    "attack_flip_beyond_ttl",
    "attack_race_after_read",
)


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    root: str
    signer: str
    cost: int

    @property
    def dependencies(self) -> frozenset:
        return frozenset({self.root, self.signer})


def _layout_roots(layout: str) -> list[str]:
    if layout == "independent":
        return [f"root-{i}" for i in range(N_SOURCES)]
    if layout == "pairs":
        return [f"root-{i // 2}" for i in range(N_SOURCES)]
    if layout == "funnel":
        return ["root-funnel" if i < 4 else f"root-solo-{i}" for i in range(N_SOURCES)]
    if layout == "single":
        return ["root-single"] * N_SOURCES
    raise ValueError(layout)


def _poisoned_group(layout: str) -> set[int]:
    return {
        "independent": {0},
        "pairs": {0, 1},
        "funnel": {0, 1, 2, 3},
        "single": set(range(N_SOURCES)),
    }[layout]


def build_sources(layout: str) -> list[SourceSpec]:
    roots = _layout_roots(layout)
    return [SourceSpec(f"s{i}", roots[i], f"signer-{i}", cost=1 + (i % 4)) for i in range(N_SOURCES)]


def resolve_world(layout: str, case_key: str, seed: int) -> dict:
    sources = build_sources(layout)
    rng = random.Random(seed)
    order = list(range(N_SOURCES))
    rng.shuffle(order)
    poisoned = _poisoned_group(layout)

    initial_value = {i: True for i in range(N_SOURCES)}
    read_value = {i: True for i in range(N_SOURCES)}
    read_version = {i: 1 for i in range(N_SOURCES)}
    dispatch_value = {i: True for i in range(N_SOURCES)}
    dispatch_version = {i: 1 for i in range(N_SOURCES)}
    available = {i: True for i in range(N_SOURCES)}
    changed: set[int] = set()
    truth_at_dispatch = True
    ttl_age = 1.0

    if case_key == "benign_unchanged":
        pass
    elif case_key == "benign_2_changed":
        for i in order[:2]:
            read_version[i] = dispatch_version[i] = 2
            changed.add(i)
    elif case_key == "benign_6_changed":
        for i in range(N_SOURCES):
            read_version[i] = dispatch_version[i] = 2
            changed.add(i)
    elif case_key == "benign_unavailable_2":
        for i in order[:2]:
            available[i] = False
    elif case_key == "attack_poisoned_root":
        truth_at_dispatch = False
        for i in range(N_SOURCES):
            if i not in poisoned:
                initial_value[i] = read_value[i] = dispatch_value[i] = False
    elif case_key in ("attack_flip_within_ttl", "attack_flip_beyond_ttl"):
        truth_at_dispatch = False
        ttl_age = 60.0 if case_key == "attack_flip_beyond_ttl" else 1.0
        for i in range(N_SOURCES):
            if i not in poisoned:
                read_value[i] = dispatch_value[i] = False
                read_version[i] = dispatch_version[i] = 2
                changed.add(i)
    elif case_key == "attack_race_after_read":
        truth_at_dispatch = False
        for i in range(N_SOURCES):
            dispatch_value[i] = False
            dispatch_version[i] = 2
    else:
        raise ValueError(case_key)

    return dict(
        sources=sources,
        order=order,
        initial_value=initial_value,
        read_value=read_value,
        read_version=read_version,
        dispatch_value=dispatch_value,
        dispatch_version=dispatch_version,
        available=available,
        changed=changed,
        truth_at_dispatch=truth_at_dispatch,
        ttl_age=ttl_age,
        attack=case_key.startswith("attack_"),
    )


def _obs(spec: SourceSpec, value: bool, version: int) -> Observation:
    return Observation(spec.source_id, "sku-x", version, value, spec.dependencies, spec.cost)


def _positive_cert(obs_list: list[Observation]) -> bool:
    positives = [o for o in obs_list if o.allowed]
    return cover_number(positives) > FAULT_BUDGET


def _atomic_recheck(world: dict, obs_by_index: dict[int, Observation]) -> tuple[dict[int, Observation], int, int]:
    race = any(world["dispatch_version"][i] != world["read_version"][i] for i in obs_by_index)
    if not race:
        return obs_by_index, 0, 0
    sources = world["sources"]
    refreshed = {
        i: _obs(sources[i], world["dispatch_value"][i], world["dispatch_version"][i])
        for i in range(len(sources))
        if world["available"][i]
    }
    cost = sum(o.cost for o in refreshed.values())
    return refreshed, len(refreshed), cost


def eval_quote(world: dict) -> tuple[str, bool, int, int]:
    return "ALLOW", True, 0, 0


def eval_majority(world: dict) -> tuple[str, bool, int, int]:
    sources = world["sources"]
    obs = [
        _obs(sources[i], world["read_value"][i], world["read_version"][i])
        for i in range(len(sources))
        if world["available"][i]
    ]
    fetches, cost = len(obs), sum(o.cost for o in obs)
    positives = sum(1 for o in obs if o.allowed)
    allow = positives * 2 > len(obs)
    return ("ALLOW" if allow else "DENY"), allow, fetches, cost


def eval_static(world: dict) -> tuple[str, bool, int, int]:
    sources = world["sources"]
    obs = [_obs(sources[i], world["initial_value"][i], 1) for i in range(len(sources))]
    allow = _positive_cert(obs)
    return ("ALLOW" if allow else "STEP_UP"), allow, 0, 0


def eval_ttl(world: dict) -> tuple[str, bool, int, int]:
    sources = world["sources"]
    if world["ttl_age"] >= 30.0:
        obs = [
            _obs(sources[i], world["read_value"][i], world["read_version"][i])
            for i in range(len(sources))
            if world["available"][i]
        ]
        fetches, cost = len(obs), sum(o.cost for o in obs)
    else:
        obs = [_obs(sources[i], world["initial_value"][i], 1) for i in range(len(sources))]
        fetches, cost = 0, 0
    allow = _positive_cert(obs)
    return ("ALLOW" if allow else "STEP_UP"), allow, fetches, cost


def eval_full(world: dict) -> tuple[str, bool, int, int]:
    sources = world["sources"]
    obs_by_index = {
        i: _obs(sources[i], world["read_value"][i], world["read_version"][i])
        for i in range(len(sources))
        if world["available"][i]
    }
    fetches, cost = len(obs_by_index), sum(o.cost for o in obs_by_index.values())
    allow = _positive_cert(list(obs_by_index.values()))
    if allow:
        obs_by_index, ef, ec = _atomic_recheck(world, obs_by_index)
        fetches += ef
        cost += ec
        allow = _positive_cert(list(obs_by_index.values()))
    return ("ALLOW" if allow else "STEP_UP"), allow, fetches, cost


def eval_affected(world: dict) -> tuple[str, bool, int, int]:
    sources = world["sources"]
    obs_by_index: dict[int, Observation] = {}
    fetches = cost = 0
    for i in range(len(sources)):
        if not world["available"][i]:
            continue
        if i in world["changed"]:
            obs_by_index[i] = _obs(sources[i], world["read_value"][i], world["read_version"][i])
            fetches += 1
            cost += sources[i].cost
        else:
            obs_by_index[i] = _obs(sources[i], world["initial_value"][i], 1)
    allow = _positive_cert(list(obs_by_index.values()))
    if allow:
        obs_by_index, ef, ec = _atomic_recheck(world, obs_by_index)
        fetches += ef
        cost += ec
        allow = _positive_cert(list(obs_by_index.values()))
    return ("ALLOW" if allow else "STEP_UP"), allow, fetches, cost


def eval_residual(world: dict) -> tuple[str, bool, int, int]:
    sources = world["sources"]
    obs_by_index: dict[int, Observation] = {}
    for i in range(len(sources)):
        if world["available"][i] and i not in world["changed"]:
            obs_by_index[i] = _obs(sources[i], world["initial_value"][i], 1)
    fetches = cost = 0

    def cert_ok() -> bool:
        return _positive_cert(list(obs_by_index.values()))

    if not cert_ok():
        for i in world["order"]:
            if i not in world["changed"] or not world["available"][i]:
                continue
            obs_by_index[i] = _obs(sources[i], world["read_value"][i], world["read_version"][i])
            fetches += 1
            cost += sources[i].cost
            if cert_ok():
                break
    allow = cert_ok()
    if allow:
        obs_by_index, ef, ec = _atomic_recheck(world, obs_by_index)
        fetches += ef
        cost += ec
        allow = cert_ok()
    return ("ALLOW" if allow else "STEP_UP"), allow, fetches, cost


def eval_cwr(world: dict) -> tuple[str, bool, int, int]:
    sources = world["sources"]
    obs_by_index: dict[int, Observation] = {}
    for i in range(len(sources)):
        if world["available"][i] and i not in world["changed"]:
            obs_by_index[i] = _obs(sources[i], world["initial_value"][i], 1)
    fetches = cost = 0
    remaining = {i for i in world["changed"] if world["available"][i]}

    def cert_ok() -> bool:
        return _positive_cert(list(obs_by_index.values()))

    while not cert_ok() and remaining:
        unchanged_positive = [o for o in obs_by_index.values() if o.allowed]
        candidates = [
            Observation(sources[i].source_id, "sku-x", world["read_version"][i], True, sources[i].dependencies, sources[i].cost)
            for i in sorted(remaining)
        ]
        plan = cwr_plan(unchanged_positive, candidates, FAULT_BUDGET)
        if plan is None:
            break
        _, plan_ids = plan
        for sid in plan_ids:
            i = next(idx for idx in remaining if sources[idx].source_id == sid)
            obs_by_index[i] = _obs(sources[i], world["read_value"][i], world["read_version"][i])
            fetches += 1
            cost += sources[i].cost
            remaining.discard(i)
            if not obs_by_index[i].allowed:
                break
        if cert_ok():
            break
    allow = cert_ok()
    if allow:
        obs_by_index, ef, ec = _atomic_recheck(world, obs_by_index)
        fetches += ef
        cost += ec
        allow = cert_ok()
    return ("ALLOW" if allow else "STEP_UP"), allow, fetches, cost


EVALUATORS = {
    "QUOTE": eval_quote,
    "MAJORITY": eval_majority,
    "STATIC": eval_static,
    "TTL": eval_ttl,
    "FULL": eval_full,
    "AFFECTED": eval_affected,
    "RESIDUAL": eval_residual,
    "CWR": eval_cwr,
}


def run(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for layout in LAYOUTS:
        for case_key in EVENT_CASES:
            for seed in SEEDS:
                world = resolve_world(layout, case_key, seed)
                for variant in VARIANTS:
                    verdict, payment_effect, fetches, cost = EVALUATORS[variant](world)
                    unsafe = payment_effect and not world["truth_at_dispatch"]
                    benign_completed = (not world["attack"]) and payment_effect and world["truth_at_dispatch"]
                    rows.append(
                        {
                            "layout": layout,
                            "event_case": case_key,
                            "seed": seed,
                            "variant": variant,
                            "attack": int(world["attack"]),
                            "truth_at_dispatch": int(world["truth_at_dispatch"]),
                            "verdict": verdict,
                            "payment_effect": int(payment_effect),
                            "unauthorized_payment": int(unsafe),
                            "benign_completed": int(benign_completed),
                            "fetches": fetches,
                            "cost": cost,
                        }
                    )

    summary = []
    for variant in VARIANTS:
        group = [r for r in rows if r["variant"] == variant]
        attack_rows = [r for r in group if r["attack"]]
        benign_rows = [r for r in group if not r["attack"]]
        summary.append(
            {
                "variant": variant,
                "attack_executions": len(attack_rows),
                "unsafe_of_attack": sum(r["unauthorized_payment"] for r in attack_rows),
                "benign_executions": len(benign_rows),
                "benign_completed": sum(r["benign_completed"] for r in benign_rows),
                "total_fetches": sum(r["fetches"] for r in group),
                "total_cost": sum(r["cost"] for r in group),
                "mean_fetches": round(statistics.fmean(r["fetches"] for r in group), 3),
            }
        )

    with (output_dir / "factorial_workload_runs.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (output_dir / "factorial_workload_summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    (output_dir / "factorial_workload_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return {"rows": len(rows), "summary": summary}


if __name__ == "__main__":
    result = run(Path(__file__).resolve().parents[3] / "results" / "section6_reproduction")
    print(json.dumps(result["summary"], indent=2))
