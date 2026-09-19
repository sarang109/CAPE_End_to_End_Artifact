"""Deterministic, zero-API-cost comparison of CAPE's defenses against the
new practical baselines (`baselines.py`) over the three-way payee corpus
(`payee_scenarios.py`).

This is new, supplementary work answering two reviewer gaps at once: (1)
the missing static-allowlist / policy-engine / CaMeL-inspired comparison
baselines, and (2) the "looks like a payee-allowlist test" concern, by
exercising a `NOVEL_UNREGISTERED` category the attacker/legitimate split
never covered. It reuses `payee_gateway.route_payee_check` and
`baselines.route_baseline_check` unmodified and writes only new files
under `results/external_validation/`; it does not touch any
already-published result.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from collections import defaultdict
from pathlib import Path

from . import baselines, payee_gateway, payee_scenarios
from .models import ALLOW

ALL_DEFENSES: tuple[str, ...] = payee_gateway.DEFENSES + baselines.DEFENSES
CORRUPTED_DOMAIN = "bank-directory-root"


def _route(defense: str, *, recipient_is_legit: bool, is_known_attacker: bool,
           corrupted_domain: str | None, forged_value: bool):
    if defense in payee_gateway.DEFENSES:
        return payee_gateway.route_payee_check(
            defense, recipient_is_legit=recipient_is_legit,
            corrupted_domain=corrupted_domain, forged_value=forged_value,
        )
    return baselines.route_baseline_check(
        defense, recipient_is_legit=recipient_is_legit, corrupted_domain=corrupted_domain,
        forged_value=forged_value, is_known_attacker=is_known_attacker,
    )


def run_comparison(output_dir: Path) -> tuple[list[dict], list[dict]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    scenarios = payee_scenarios.all_scenarios()
    rows: list[dict] = []
    for scenario in scenarios:
        # Uncorrupted evidence, and (for non-legitimate recipients) the
        # attacker-controls-the-shared-root case, forging the opposite of
        # the truth -- the manuscript's own corruption model.
        corruption_cases: list[tuple[str | None, bool]] = [(None, True)]
        corruption_cases.append((CORRUPTED_DOMAIN, not scenario.recipient_is_legit))
        for corrupted_domain, forged_value in corruption_cases:
            for defense in ALL_DEFENSES:
                result = _route(
                    defense, recipient_is_legit=scenario.recipient_is_legit,
                    is_known_attacker=scenario.category == payee_scenarios.KNOWN_ATTACKER,
                    corrupted_domain=corrupted_domain, forged_value=forged_value,
                )
                unauthorized_payment = result.unauthorized and not scenario.recipient_is_legit
                wrongly_blocked_benign = (result.verdict != ALLOW) and scenario.recipient_is_legit
                rows.append(
                    {
                        "recipient": scenario.recipient,
                        "category": scenario.category,
                        "recipient_is_legit": int(scenario.recipient_is_legit),
                        "corrupted": int(corrupted_domain is not None),
                        "defense": defense,
                        "verdict": result.verdict,
                        "queried_sources": result.queried_sources,
                        "query_cost": result.query_cost,
                        "unauthorized_payment": int(unauthorized_payment),
                        "wrongly_blocked_benign": int(wrongly_blocked_benign),
                    }
                )

    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["defense"]].append(row)
    summary: list[dict] = []
    for defense in ALL_DEFENSES:
        group = groups[defense]
        corrupted_attack = [r for r in group if r["corrupted"] and not r["recipient_is_legit"]]
        corrupted_benign = [r for r in group if r["corrupted"] and r["recipient_is_legit"]]
        uncorrupted = [r for r in group if not r["corrupted"]]
        novel_unregistered = [r for r in group if r["category"] == payee_scenarios.NOVEL_UNREGISTERED]
        summary.append(
            {
                "defense": defense,
                "is_cape_defense": int(defense in payee_gateway.DEFENSES),
                "executions": len(group),
                "corrupted_attack_cases": len(corrupted_attack),
                "unauthorized_under_corruption": sum(r["unauthorized_payment"] for r in corrupted_attack),
                "corrupted_benign_cases": len(corrupted_benign),
                "wrongly_blocked_benign_under_corruption": sum(
                    r["wrongly_blocked_benign"] for r in corrupted_benign
                ),
                "uncorrupted_cases": len(uncorrupted),
                "uncorrupted_unauthorized": sum(r["unauthorized_payment"] for r in uncorrupted),
                "novel_unregistered_cases": len(novel_unregistered),
                "novel_unregistered_unauthorized": sum(r["unauthorized_payment"] for r in novel_unregistered),
                "mean_query_cost": round(sum(r["query_cost"] for r in group) / len(group), 3),
            }
        )

    _write_csv(output_dir / "baseline_comparison_runs.csv", rows)
    _write_csv(output_dir / "baseline_comparison_summary.csv", summary)
    environment = {
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "defenses": list(ALL_DEFENSES),
        "cape_defenses": list(payee_gateway.DEFENSES),
        "baseline_defenses": list(baselines.DEFENSES),
        "scenario_count": len(scenarios),
        "scenario_categories": {
            payee_scenarios.KNOWN_LEGITIMATE: list(payee_scenarios.KNOWN_LEGITIMATE_PAYEES),
            payee_scenarios.KNOWN_ATTACKER: list(payee_scenarios.KNOWN_ATTACKER_PAYEES),
            payee_scenarios.NOVEL_UNREGISTERED: list(payee_scenarios.NOVEL_UNREGISTERED_PAYEES),
        },
        "fault_budget": payee_gateway.FAULT_BUDGET,
        "paid_api_calls": 0,
    }
    (output_dir / "baseline_comparison_environment.json").write_text(
        json.dumps(environment, indent=2) + "\n", encoding="utf-8"
    )
    return rows, summary


def _write_csv(path: Path, rows: list[dict]) -> None:
    import csv

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path(__file__).resolve().parents[2] / "results" / "external_validation",
    )
    args = parser.parse_args()
    _, summary = run_comparison(args.output_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
