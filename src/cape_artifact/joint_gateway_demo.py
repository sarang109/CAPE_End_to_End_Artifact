"""Proof-of-concept: combining CAPE's existing shopping-category and
payee-verification evidence topologies into one joint decision.

`gateway.py`'s shopping-category evidence network and `payee_gateway.py`'s
`PAYEE_SOURCES` are currently disjoint -- confirmed by reading both, no
source in either topology is actually shared with the other. To
demonstrate `joint_algorithms.py`'s actual benefit (a source relevant to
more than one predicate has its cost counted once, not once per
predicate), this demo posits **one new, explicitly illustrative** shared
source -- a hypothetical combined merchant-and-payee compliance directory
-- alongside the real, unmodified `payee_gateway.PAYEE_SOURCES` and a
small, same-shape illustrative category evidence set (3 shared-root + 2
independent sources, matching the topology convention `payee_gateway.py`
and the AP2 testbed already use). This demonstrates the capability; it is
not a claim that this shared source exists in the artifact's current real
evidence topologies.
"""
from __future__ import annotations

from .algorithms import cwr_plan
from .joint_algorithms import JointCandidate, joint_cwr_plan
from .models import Observation
from .payee_gateway import PAYEE_SOURCES

CATEGORY_SOURCES: tuple[tuple[str, frozenset, int], ...] = (
    ("cat-registry-a", frozenset({"catalog-root"}), 1),
    ("cat-registry-b", frozenset({"catalog-root"}), 1),
    ("cat-registry-c", frozenset({"catalog-root"}), 1),
    ("cat-independent-1", frozenset({"cat-independent-root-1"}), 2),
    ("cat-independent-2", frozenset({"cat-independent-root-2"}), 2),
)

# Illustrative only -- see module docstring. Priced cheaper than a second
# independent-root source (2) so the joint planner actually has a reason
# to route through it instead of treating category/payee as separate;
# see JOINT_GATEWAY_DEMO_README.md for the arithmetic.
SHARED_SOURCE: tuple[str, frozenset, int] = (
    "merchant-payee-directory", frozenset({"catalog-root", "bank-directory-root"}), 1,
)


def build_candidates() -> tuple[JointCandidate, ...]:
    candidates = []
    for sid, deps, cost in CATEGORY_SOURCES:
        candidates.append(JointCandidate(sid, "sku", 1, deps, cost, frozenset({"category"})))
    for sid, deps, cost in PAYEE_SOURCES:
        candidates.append(JointCandidate(sid, "sku", 1, deps, cost, frozenset({"payee"})))
    sid, deps, cost = SHARED_SOURCE
    candidates.append(JointCandidate(sid, "sku", 1, deps, cost, frozenset({"category", "payee"})))
    return tuple(candidates)


def _as_observations(candidates: tuple[JointCandidate, ...], predicate: str) -> list[Observation]:
    return [
        Observation(c.source_id, c.sku, c.version, True, c.dependencies, c.cost)
        for c in candidates
        if predicate in c.relevant_predicates
    ]


def demo(fault_budget: int = 1) -> dict:
    candidates = build_candidates()
    joint_result = joint_cwr_plan({}, candidates, fault_budget, ("category", "payee"))

    category_only = cwr_plan([], _as_observations(candidates, "category"), fault_budget)
    payee_only = cwr_plan([], _as_observations(candidates, "payee"), fault_budget)

    joint_cost = joint_result[0] if joint_result is not None else None
    independent_cost = (
        category_only[0] + payee_only[0]
        if category_only is not None and payee_only is not None
        else None
    )
    savings = (
        independent_cost - joint_cost
        if joint_cost is not None and independent_cost is not None
        else None
    )

    return {
        "fault_budget": fault_budget,
        "joint_plan_cost": joint_cost,
        "joint_plan_sources": joint_result[1] if joint_result is not None else None,
        "category_only_cost": category_only[0] if category_only is not None else None,
        "payee_only_cost": payee_only[0] if payee_only is not None else None,
        "independent_sum_cost": independent_cost,
        "savings_from_joint_planning": savings,
        "shared_source_cost": SHARED_SOURCE[2],
    }


if __name__ == "__main__":
    import json

    print(json.dumps(demo(), indent=2))
