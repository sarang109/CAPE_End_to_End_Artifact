"""Multi-predicate joint evidence planning: generalizing CWR and DFMR from
one boolean predicate to several simultaneous ones.

A reviewer pass noted that real commerce policies often combine several
conditions at once (category, merchant, geography, recurring-payment
status, ...), while every predicate in the manuscript is evaluated one at
a time. Simply running `cwr_plan`/`dfmr_choose_next` once per predicate and
ANDing the verdicts is *already possible with the existing, unmodified
code* -- it is not a new capability, just composition. This module builds
the capability that composition cannot express: when a single source's
evidence is *relevant to more than one predicate at once* (e.g. one
merchant-and-payee directory lookup speaks to both "is this category
allowed" and "is this payee verified"), a joint planner can let that one
query count toward more than one predicate's certificate, for one cost --
strictly cheaper, in general, than planning each predicate independently
and summing the results.

`JointCandidate` extends the idea of `models.Observation` with
`relevant_predicates: FrozenSet[str]`: which predicates asking this source
is useful for. A source not relevant to a predicate contributes nothing to
that predicate's coverage -- it is not treated as trivially satisfying it
just because its dependencies happen not to intersect that predicate's
hypotheses; that would silently misrepresent a source that was never asked
about a predicate as one that certified it.

`joint_cwr_plan` reuses `algorithms.residual_hypotheses` unmodified (once
per predicate) and `algorithms._min_cost_exact_cover` unmodified (once,
over a combined hypothesis space with a per-predicate bit offset) -- the
same proven-correct primitives `cwr_plan` itself uses, not reimplemented
logic. `joint_dfmr_choose_next` mirrors `dfmr_choose_next`'s minimax
recursion exactly, generalized to a per-predicate state dict and
`joint_bilateral_decision` as its termination check.

This module does not modify `algorithms.py`, `gateway.py`, or
`payee_gateway.py`; it only adds new functions/dataclasses.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from math import inf
from typing import FrozenSet, Sequence

from .algorithms import (
    _min_cost_exact_cover,
    bilateral_decision,
    corruption_cost_for_truth,
    positive_certificate,
    residual_hypotheses,
)
from .models import ALLOW, DENY, STEP_UP, Observation


@dataclass(frozen=True)
class JointCandidate:
    source_id: str
    sku: str
    version: int
    dependencies: FrozenSet[str]
    cost: int
    relevant_predicates: FrozenSet[str]


def joint_positive_certificate(
    current: dict[str, Sequence[Observation]], fault_budget: int, predicates: Sequence[str]
) -> bool:
    """True iff every predicate's own positive certificate holds."""
    return all(positive_certificate(current.get(p, []), fault_budget) for p in predicates)


def joint_bilateral_decision(
    current: dict[str, Sequence[Observation]], fault_budget: int, predicates: Sequence[str]
) -> str:
    """ALLOW iff every predicate's own `bilateral_decision` is ALLOW; DENY
    if any predicate is DENY-certified (a single failing predicate should
    block the joint decision, not be outvoted by the others); otherwise
    STEP_UP."""
    results = [bilateral_decision(current.get(p, []), fault_budget) for p in predicates]
    if any(r == DENY for r in results):
        return DENY
    if all(r == ALLOW for r in results):
        return ALLOW
    return STEP_UP


def joint_cwr_plan(
    unchanged_positive: dict[str, Sequence[Observation]],
    candidates: Sequence[JointCandidate],
    fault_budget: int,
    predicates: Sequence[str],
) -> tuple[int, tuple[str, ...]] | None:
    """Exact minimum-cost plan certifying every predicate in `predicates`
    simultaneously. Strictly cheaper than (or equal to) running `cwr_plan`
    once per predicate and unioning the plans whenever any candidate is
    relevant to more than one predicate, because such a candidate's cost
    is only paid once here.
    """
    offsets: dict[str, int] = {}
    per_predicate_hypotheses: dict[str, tuple] = {}
    total_bits = 0
    for p in predicates:
        relevant = [
            Observation(c.source_id, c.sku, c.version, True, c.dependencies, c.cost)
            for c in candidates
            if p in c.relevant_predicates
        ]
        hyps = residual_hypotheses(unchanged_positive.get(p, []), relevant, fault_budget)
        per_predicate_hypotheses[p] = hyps
        offsets[p] = total_bits
        total_bits += len(hyps)

    if total_bits == 0:
        return 0, ()

    items: list[tuple[str, int, int]] = []
    for c in sorted(candidates, key=lambda x: x.source_id):
        mask = 0
        for p in predicates:
            if p not in c.relevant_predicates:
                continue
            offset = offsets[p]
            for i, hypothesis in enumerate(per_predicate_hypotheses[p]):
                if not hypothesis.intersection(c.dependencies):
                    mask |= 1 << (offset + i)
        if mask:
            items.append((c.source_id, c.cost, mask))

    return _min_cost_exact_cover(items, total_bits)


def _joint_state_consistent(
    state: dict[str, Sequence[Observation]], fault_budget: int, predicates: Sequence[str]
) -> bool:
    return all(
        corruption_cost_for_truth(state.get(p, []), True) <= fault_budget
        or corruption_cost_for_truth(state.get(p, []), False) <= fault_budget
        for p in predicates
    )


def joint_dfmr_choose_next(
    current: dict[str, Sequence[Observation]],
    candidates: Sequence[JointCandidate],
    fault_budget: int,
    predicates: Sequence[str],
) -> str | None:
    """Multi-predicate generalization of `dfmr_choose_next`: the same exact
    finite minimax policy, terminating via `joint_bilateral_decision`
    instead of `bilateral_decision`, over a per-predicate observation state.
    A queried candidate's outcome is applied uniformly to every predicate
    it is relevant to (one physical query, one outcome, shared across the
    predicates it speaks to)."""
    ordered = tuple(sorted(candidates, key=lambda x: x.source_id))
    by_id = {c.source_id: c for c in ordered}
    base_current = {p: tuple(current.get(p, [])) for p in predicates}

    def reconstruct(state_key: tuple[tuple[str, bool], ...]) -> dict[str, list[Observation]]:
        state: dict[str, list[Observation]] = {p: list(base_current.get(p, ())) for p in predicates}
        for sid, allowed in state_key:
            meta = by_id[sid]
            obs = Observation(sid, meta.sku, meta.version, allowed, meta.dependencies, meta.cost)
            for p in meta.relevant_predicates:
                if p in state:
                    state[p].append(obs)
        return state

    @lru_cache(maxsize=None)
    def value(
        state_key: tuple[tuple[str, bool], ...], remaining_ids: tuple[str, ...]
    ) -> tuple[float, str | None]:
        state = reconstruct(state_key)
        if joint_bilateral_decision(state, fault_budget, predicates) != STEP_UP:
            return 0, None
        if not remaining_ids:
            return inf, None
        best: tuple[float, str | None] = (inf, None)
        for sid in remaining_ids:
            meta = by_id[sid]
            branch_values: list[float] = []
            for outcome in (False, True):
                next_key = tuple(sorted((*state_key, (sid, outcome))))
                next_state = reconstruct(next_key)
                if not _joint_state_consistent(next_state, fault_budget, predicates):
                    continue
                tail, _ = value(next_key, tuple(x for x in remaining_ids if x != sid))
                branch_values.append(tail)
            if not branch_values:
                continue
            worst = meta.cost + max(branch_values)
            if worst < best[0] or (worst == best[0] and (best[1] is None or sid < best[1])):
                best = (worst, sid)
        return best

    _, source_id = value((), tuple(c.source_id for c in ordered))
    return source_id
