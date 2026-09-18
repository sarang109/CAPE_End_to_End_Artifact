"""Section 6.4 (second half) / 7.8: exhaustive finite verification of the
certificate and zero-refresh rules, plus the four assumption-violation
counterexamples (hidden root, silent version change, excess corruption,
missing dispatch binding).
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path

from ..algorithms import positive_certificate, residual_hypotheses
from ..models import Observation

DOMAINS3 = ("A", "B", "C")
N_ITEMS = 4
FAULT_BUDGET = 1


def _nonempty_subsets(domains: tuple[str, ...]) -> list[frozenset]:
    out = []
    for size in range(1, len(domains) + 1):
        for combo in itertools.combinations(domains, size):
            out.append(frozenset(combo))
    return out


def enumerate_certificate_configs() -> dict:
    dep_options = _nonempty_subsets(DOMAINS3)
    corruption_sets = [frozenset()] + [frozenset({d}) for d in DOMAINS3]

    total_combinations = 0
    accepted_states = 0
    accepted_false_predicates = 0

    for deps_combo in itertools.product(dep_options, repeat=N_ITEMS):
        for truth in (True, False):
            for corruption in corruption_sets:
                affected = [i for i in range(N_ITEMS) if corruption & deps_combo[i]]
                for outputs in itertools.product((False, True), repeat=len(affected)):
                    reported = [truth] * N_ITEMS
                    for idx, value in zip(affected, outputs):
                        reported[idx] = value
                    total_combinations += 1
                    obs = [
                        Observation(f"e{i}", "sku", 1, reported[i], deps_combo[i], 1)
                        for i in range(N_ITEMS)
                    ]
                    accepted = positive_certificate(obs, FAULT_BUDGET)
                    if accepted:
                        accepted_states += 1
                        if not truth:
                            accepted_false_predicates += 1

    return {
        "total_combinations": total_combinations,
        "accepted_states": accepted_states,
        "accepted_false_predicates": accepted_false_predicates,
    }


def _independent_alternative_world_exists(deps_combo: tuple[frozenset, ...], u_indices: tuple[int, ...]) -> bool:
    domains = sorted(set().union(*deps_combo)) if deps_combo else []
    for size in range(FAULT_BUDGET + 1):
        for corruption in itertools.combinations(domains, size):
            c_set = set(corruption)
            if all(c_set & deps_combo[i] for i in u_indices):
                return True
    return False


def enumerate_zero_refresh_subsets() -> dict:
    dep_options = _nonempty_subsets(DOMAINS3)
    total_subsets = 0
    agreements = 0
    for deps_combo in itertools.product(dep_options, repeat=N_ITEMS):
        for size in range(N_ITEMS + 1):
            for u_indices in itertools.combinations(range(N_ITEMS), size):
                total_subsets += 1
                independent_result = _independent_alternative_world_exists(deps_combo, u_indices)
                u_obs = [Observation(f"e{i}", "sku", 1, True, deps_combo[i], 1) for i in u_indices]
                library_result = bool(residual_hypotheses(u_obs, [], FAULT_BUDGET))
                if independent_result == library_result:
                    agreements += 1
    return {"total_residual_subsets": total_subsets, "agreements": agreements}


def assumption_violation_table() -> list[dict]:
    rows = []

    # 1. Hidden common root: registry claims two independent domains, but both
    # sources secretly share an undisclosed root the registry never records.
    disclosed = [
        Observation("s0", "sku", 1, True, frozenset({"root-x"}), 1),
        Observation("s1", "sku", 1, True, frozenset({"root-y"}), 1),
    ]
    full_unsafe = positive_certificate(disclosed, FAULT_BUDGET) and True  # both actually hidden-corrupted -> false predicate
    cwr_unsafe = full_unsafe  # both refresh from the same undisclosed source either way
    rows.append({"fault": "hidden_common_root", "full_unsafe": int(full_unsafe), "cwr_unsafe": int(cwr_unsafe)})

    # 2. Silent version change: the predicate flips to false for two
    # disjoint-domain sources whose cached positive certificate was
    # sufficient (cover number 2 > f = 1), but neither source advances its
    # version, violating the freshness contract in Section 3.3. Full
    # re-queries every source regardless of the version tag and observes the
    # new negative values; CWR/Affected/Residual trust the (lying) unchanged
    # version tag and keep serving the stale cached positives.
    stale_cache = [
        Observation("s0", "sku", 1, True, frozenset({"root-p"}), 1),
        Observation("s1", "sku", 1, True, frozenset({"root-q"}), 1),
    ]
    live_negative_same_version = [
        Observation("s0", "sku", 1, False, frozenset({"root-p"}), 1),
        Observation("s1", "sku", 1, False, frozenset({"root-q"}), 1),
    ]
    full_unsafe = positive_certificate(live_negative_same_version, FAULT_BUDGET)
    cwr_unsafe = positive_certificate(stale_cache, FAULT_BUDGET)
    rows.append({"fault": "silent_version_change", "full_unsafe": int(full_unsafe), "cwr_unsafe": int(cwr_unsafe)})

    # 3. Two roots corrupted while f = 1: exceeds the declared adversary budget.
    two_corrupted = [
        Observation("s0", "sku", 1, True, frozenset({"root-a"}), 1),
        Observation("s1", "sku", 1, True, frozenset({"root-b"}), 1),
    ]
    accepted = positive_certificate(two_corrupted, FAULT_BUDGET)
    rows.append({"fault": "two_roots_corrupted_f1", "full_unsafe": int(accepted), "cwr_unsafe": int(accepted)})

    # 4. No dispatch binding: certificate is checked, then the truth flips
    # before the (unbound) dispatch call, which neither variant re-verifies.
    checked_positive = [
        Observation("s0", "sku", 1, True, frozenset({"root-a"}), 1),
        Observation("s1", "sku", 1, True, frozenset({"root-b"}), 1),
        Observation("s2", "sku", 1, True, frozenset({"root-c"}), 1),
    ]
    certified_at_check_time = positive_certificate(checked_positive, FAULT_BUDGET)
    dispatched_without_recheck = certified_at_check_time  # dispatch fires on the stale certificate
    truth_at_dispatch_is_false = True
    unsafe = dispatched_without_recheck and truth_at_dispatch_is_false
    rows.append({"fault": "no_dispatch_binding", "full_unsafe": int(unsafe), "cwr_unsafe": int(unsafe)})

    return rows


def run(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    certificate = enumerate_certificate_configs()
    zero_refresh = enumerate_zero_refresh_subsets()
    assumption_table = assumption_violation_table()

    summary = {
        "certificate_enumeration": certificate,
        "zero_refresh_enumeration": zero_refresh,
        "assumption_violation_table": assumption_table,
    }
    (output_dir / "structural_checks_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    result = run(Path(__file__).resolve().parents[3] / "results" / "section6_reproduction")
    print(json.dumps(result, indent=2))
