from __future__ import annotations

import argparse
import csv
import json
import math
import platform
import statistics
import sys
from collections import defaultdict
from dataclasses import replace
from pathlib import Path

from .ap2_flow import AP2Bundle, AP2Harness
from .evidence import EvidenceNetwork
from .gateway import Gateway
from .models import CacheEntry, Cart, Policy
from .sandbox import PaymentSandbox
from .scenarios import SOURCE_LAYOUT, scenario_catalog


DEFENSES = ("AP2_ONLY", "MAJORITY", "TTL", "FULL", "CWR", "DFMR")


def policy_fixture() -> Policy:
    return Policy(
        allowed_categories=frozenset({"electronics"}),
        forbidden_categories=frozenset({"stored_value"}),
        max_amount_cents=20_000,
        allowed_merchants=frozenset({"merchant-good"}),
        allowed_currencies=frozenset({"USD"}),
    )


def _configure_execution(network: EvidenceNetwork, scenario) -> None:
    if scenario.force_refresh:
        for cfg in network.sources.values():
            cfg.version += 1
    if scenario.stale_change:
        for cfg in network.sources.values():
            cfg.truth_allowed = scenario.execution_truth_allowed
            cfg.version += 1
    for cfg in network.sources.values():
        if cfg.dependencies.intersection(scenario.compromised_domains):
            cfg.compromised = True
        if cfg.source_id in scenario.compromised_sources:
            cfg.compromised = True
        if cfg.source_id in scenario.unavailable_sources:
            cfg.available = False
    if scenario.tamper_signature_source:
        network.sources[scenario.tamper_signature_source].tamper_signature = True


def _tamper_bundle(bundle: AP2Bundle, attack: str | None) -> AP2Bundle:
    if attack is None:
        return bundle
    if attack == "nonce":
        return replace(bundle, nonce=bundle.nonce + "-replay")
    if attack == "audience":
        return replace(bundle, audience=bundle.audience + "-confused")
    if attack == "transaction":
        return replace(bundle, transaction_id=bundle.transaction_id + "-swap")
    if attack == "token":
        tail = "A" if bundle.token[-1] != "A" else "B"
        return replace(bundle, token=bundle.token[:-1] + tail)
    raise ValueError(f"unknown AP2 tamper: {attack}")


def wilson_interval(successes: int, total: int, z: float = 1.959964) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def _exact_mcnemar_p(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(min(b, c) + 1)) / (2**n)
    return min(1.0, 2 * tail)


def run_experiment(repetitions: int, output_dir: Path) -> tuple[list[dict], list[dict]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    policy = policy_fixture()
    rows: list[dict] = []
    ap2 = AP2Harness()
    scenarios = scenario_catalog()
    with EvidenceNetwork(SOURCE_LAYOUT) as network, PaymentSandbox() as payment:
        gateway = Gateway(network, payment, ap2, policy, fault_budget=1)
        for repetition in range(repetitions):
            for scenario_index, scenario in enumerate(scenarios):
                sku = f"sku-{scenario.name}"
                for defense in DEFENSES:
                    payment.reset()
                    network.reset(scenario.initial_truth_allowed)
                    for source_id, dependencies in scenario.dependency_overrides:
                        network.sources[source_id].dependencies = dependencies
                    cache: dict[str, CacheEntry] = {}
                    for sid in sorted(network.sources):
                        obs = network.fetch(sid, sku)
                        if obs:
                            cache[sid] = CacheEntry(obs, age_seconds=1.0)
                    _configure_execution(network, scenario)
                    cart = Cart(
                        operation_id=f"op-{repetition:03d}-{scenario_index:02d}-{defense.lower()}",
                        sku=sku,
                        merchant_id=scenario.merchant_id,
                        merchant_name=scenario.merchant_id,
                        amount_cents=scenario.amount_cents,
                        currency=scenario.currency,
                        claimed_category=scenario.claimed_category,
                        title=scenario.title,
                        external_content=scenario.external_content,
                    )
                    bundle = _tamper_bundle(ap2.issue(cart, policy), scenario.ap2_tamper)

                    def race_hook() -> None:
                        if scenario.version_race:
                            for cfg in network.sources.values():
                                cfg.truth_allowed = False
                                cfg.version += 1

                    decision = gateway.authorize(defense, cart, bundle, cache, race_hook=race_hook)
                    truth_at_dispatch = False if scenario.version_race else scenario.execution_truth_allowed
                    unauthorized = decision.payment_effect and not truth_at_dispatch
                    benign_completed = not scenario.attack and truth_at_dispatch and decision.payment_effect
                    rows.append(
                        {
                            "repetition": repetition,
                            "scenario": scenario.name,
                            "family": scenario.family,
                            "attack": int(scenario.attack),
                            "assumption_status": scenario.assumption_status,
                            "defense": defense,
                            "truth_at_dispatch": int(truth_at_dispatch),
                            "verdict": decision.verdict,
                            "payment_effect": int(decision.payment_effect),
                            "unauthorized_payment": int(unauthorized),
                            "benign_completed": int(benign_completed),
                            "queries": len(decision.queried_sources),
                            "query_cost": decision.query_cost,
                            "latency_ms": round(decision.latency_ms, 6),
                            "reason": decision.reason,
                            "ap2_verified": int(decision.ap2_verified),
                        }
                    )

    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["defense"]].append(row)
    summary: list[dict] = []
    for defense in DEFENSES:
        group = groups[defense]
        within = [r for r in group if r["attack"] and r["assumption_status"] == "within_model"]
        breaks = [r for r in group if r["attack"] and r["assumption_status"] != "within_model"]
        benign = [r for r in group if not r["attack"]]
        unsafe = sum(r["unauthorized_payment"] for r in within)
        scenario_outcomes = {
            r["scenario"]: max(
                x["unauthorized_payment"]
                for x in within if x["scenario"] == r["scenario"]
            )
            for r in within
        }
        low, high = wilson_interval(unsafe, len(within))
        latencies = sorted(float(r["latency_ms"]) for r in group)
        p95_index = min(len(latencies) - 1, math.ceil(0.95 * len(latencies)) - 1)
        summary.append(
            {
                "defense": defense,
                "executions": len(group),
                "within_model_attacks": len(within),
                "unique_within_model_scenarios": len(scenario_outcomes),
                "unsafe_unique_scenarios": sum(scenario_outcomes.values()),
                "unauthorized_within_model": unsafe,
                "unauthorized_rate_pct": round(100 * unsafe / len(within), 2),
                "unauthorized_95ci_low_pct": round(100 * low, 2),
                "unauthorized_95ci_high_pct": round(100 * high, 2),
                "assumption_break_attacks": len(breaks),
                "unauthorized_assumption_breaks": sum(r["unauthorized_payment"] for r in breaks),
                "benign_executions": len(benign),
                "benign_completions": sum(r["benign_completed"] for r in benign),
                "step_up": sum(r["verdict"] == "STEP_UP" for r in group),
                "mean_queries": round(statistics.fmean(r["queries"] for r in group), 3),
                "mean_query_cost": round(statistics.fmean(r["query_cost"] for r in group), 3),
                "median_latency_ms": round(statistics.median(latencies), 3),
                "p95_latency_ms": round(latencies[p95_index], 3),
            }
        )

    paired = _paired_comparisons(rows)
    manifest = [
        {
            "scenario": s.name,
            "family": s.family,
            "attack": int(s.attack),
            "assumption_status": s.assumption_status,
            "expected_truth_at_dispatch": int(False if s.version_race else s.execution_truth_allowed),
        }
        for s in scenarios
    ]
    _write_csv(output_dir / "end_to_end_runs.csv", rows)
    _write_csv(output_dir / "end_to_end_summary.csv", summary)
    _write_csv(output_dir / "paired_comparisons.csv", paired)
    _write_csv(output_dir / "scenario_manifest.csv", manifest)
    (output_dir / "end_to_end_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    environment = {
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "repetitions": repetitions,
        "scenario_count": len(scenarios),
        "defenses": list(DEFENSES),
        "fault_budget": 1,
        "ap2_commit": "e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
        "paid_api_calls": 0,
        "network_after_install": "loopback only",
    }
    (output_dir / "environment.json").write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
    return rows, summary


def _paired_comparisons(rows: list[dict]) -> list[dict]:
    within = [r for r in rows if r["attack"] and r["assumption_status"] == "within_model"]
    by_key = {(r["scenario"], r["defense"]): r for r in within}
    output = []
    for defense in DEFENSES:
        if defense == "DFMR":
            continue
        b = c = 0
        for scenario in {r["scenario"] for r in within}:
            left = by_key[(scenario, defense)]["unauthorized_payment"]
            right = by_key[(scenario, "DFMR")]["unauthorized_payment"]
            b += int(left and not right)
            c += int(right and not left)
        output.append(
            {
                "comparison": f"{defense}_vs_DFMR",
                "defense_only_unsafe": b,
                "dfmr_only_unsafe": c,
                "discordant_pairs": b + c,
                "exact_mcnemar_p": _exact_mcnemar_p(b, c),
            }
        )
    return output


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[2] / "results")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    _, summary = run_experiment(args.repetitions, args.output_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
