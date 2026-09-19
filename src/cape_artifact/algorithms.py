from __future__ import annotations

from functools import lru_cache
from itertools import combinations
from math import inf
from typing import Iterable, Sequence

from .models import ALLOW, DENY, STEP_UP, Observation


def _powerset_up_to(domains: Sequence[str], limit: int):
    for size in range(limit + 1):
        for combo in combinations(domains, size):
            yield frozenset(combo)


def _all_domains(observations: Iterable[Observation]) -> tuple[str, ...]:
    return tuple(sorted({d for obs in observations for d in obs.dependencies}))


def cover_number(observations: Sequence[Observation]) -> int:
    """Return the minimum provenance-domain hitting-set size.

    The empty observation set has cover number zero. Only signature-valid
    observations should be passed by callers.
    """
    if not observations:
        return 0
    domains = _all_domains(observations)
    for size in range(len(domains) + 1):
        for candidate in combinations(domains, size):
            c = frozenset(candidate)
            if all(c.intersection(obs.dependencies) for obs in observations):
                return size
    return inf


def corruption_cost_for_truth(
    observations: Sequence[Observation], truth_allowed: bool
) -> int:
    disagreeing = [obs for obs in observations if obs.allowed != truth_allowed]
    return cover_number(disagreeing)


def bilateral_decision(observations: Sequence[Observation], fault_budget: int) -> str:
    rho_allow = corruption_cost_for_truth(observations, True)
    rho_deny = corruption_cost_for_truth(observations, False)
    allow_cert = rho_deny > fault_budget
    deny_cert = rho_allow > fault_budget
    if allow_cert and not deny_cert:
        return ALLOW
    if deny_cert and not allow_cert:
        return DENY
    return STEP_UP


def positive_certificate(observations: Sequence[Observation], fault_budget: int) -> bool:
    positives = [obs for obs in observations if obs.allowed]
    return cover_number(positives) > fault_budget


def residual_hypotheses(
    unchanged_positive: Sequence[Observation],
    candidates: Sequence[Observation],
    fault_budget: int,
) -> tuple[frozenset[str], ...]:
    domains = sorted(
        {d for obs in (*unchanged_positive, *candidates) for d in obs.dependencies}
    )
    return tuple(
        c
        for c in _powerset_up_to(domains, fault_budget)
        if all(c.intersection(obs.dependencies) for obs in unchanged_positive)
    )


def _min_cost_exact_cover(
    items: list[tuple[str, int, int]], n_hypotheses: int
) -> tuple[int, tuple[str, ...]] | None:
    """Exact minimum-cost set cover over an `n_hypotheses`-bit hypothesis
    space, given `items` as `(id, cost, bitmask_of_covered_hypotheses)`
    triples. Shared by `cwr_plan` (single predicate) and
    `joint_algorithms.joint_cwr_plan` (multiple simultaneous predicates,
    over a combined, per-predicate-offset hypothesis space) so both reuse
    the identical, dominance-pruned, memoized bitmask DP rather than
    duplicating it.
    """
    if n_hypotheses == 0:
        return 0, ()

    # Safe dominance pruning with stable tie-breaking.
    pruned: list[tuple[str, int, int]] = []
    for item in items:
        sid, cost, mask = item
        dominated = False
        for osid, ocost, omask in items:
            if sid == osid:
                continue
            superset = (omask | mask) == omask
            strictly_better = ocost < cost or (ocost == cost and osid < sid)
            if superset and strictly_better:
                dominated = True
                break
        if not dominated:
            pruned.append(item)
    items = pruned

    full_mask = (1 << n_hypotheses) - 1

    @lru_cache(maxsize=None)
    def solve(remaining: int) -> tuple[float, tuple[str, ...]]:
        if remaining == 0:
            return 0, ()
        uncovered = (remaining & -remaining).bit_length() - 1
        best = (inf, ())
        for sid, cost, mask in items:
            if not (mask & (1 << uncovered)):
                continue
            next_remaining = remaining & ~mask
            tail_cost, tail = solve(next_remaining)
            candidate = (cost + tail_cost, tuple(sorted((sid, *tail))))
            if candidate < best:
                best = candidate
        return best

    cost, plan = solve(full_mask)
    if cost == inf:
        return None
    return int(cost), plan


def cwr_plan(
    unchanged_positive: Sequence[Observation],
    candidates: Sequence[Observation],
    fault_budget: int,
) -> tuple[int, tuple[str, ...]] | None:
    """Exact minimum-cost all-positive repair plan."""
    hypotheses = residual_hypotheses(unchanged_positive, candidates, fault_budget)
    if not hypotheses:
        return 0, ()

    items: list[tuple[str, int, int]] = []
    for obs in sorted(candidates, key=lambda x: x.source_id):
        mask = 0
        for i, hypothesis in enumerate(hypotheses):
            if not hypothesis.intersection(obs.dependencies):
                mask |= 1 << i
        if mask:
            items.append((obs.source_id, obs.cost, mask))

    return _min_cost_exact_cover(items, len(hypotheses))


def _state_consistent(observations: Sequence[Observation], fault_budget: int) -> bool:
    return (
        corruption_cost_for_truth(observations, True) <= fault_budget
        or corruption_cost_for_truth(observations, False) <= fault_budget
    )


def dfmr_choose_next(
    current: Sequence[Observation],
    candidates: Sequence[Observation],
    fault_budget: int,
) -> str | None:
    """Return the first query in the exact finite minimax policy.

    Candidate objects provide source metadata and cost; their `allowed` field is
    ignored during planning. Both Boolean outcomes are considered when feasible.
    """
    ordered = tuple(sorted(candidates, key=lambda x: x.source_id))
    by_id = {obs.source_id: obs for obs in ordered}

    def key_for(obs: Sequence[Observation]) -> tuple[tuple[str, bool], ...]:
        return tuple(sorted((o.source_id, o.allowed) for o in obs))

    @lru_cache(maxsize=None)
    def value(
        state_key: tuple[tuple[str, bool], ...], remaining_ids: tuple[str, ...]
    ) -> tuple[float, str | None]:
        state = [
            Observation(
                source_id=sid,
                sku=by_id[sid].sku,
                version=by_id[sid].version,
                allowed=allowed,
                dependencies=by_id[sid].dependencies,
                cost=by_id[sid].cost,
            )
            if sid in by_id
            else next(o for o in current if o.source_id == sid)
            for sid, allowed in state_key
        ]
        if bilateral_decision(state, fault_budget) != STEP_UP:
            return 0, None
        if not remaining_ids:
            return inf, None
        best: tuple[float, str | None] = (inf, None)
        for sid in remaining_ids:
            meta = by_id[sid]
            branch_values: list[float] = []
            for outcome in (False, True):
                obs = Observation(
                    source_id=sid,
                    sku=meta.sku,
                    version=meta.version,
                    allowed=outcome,
                    dependencies=meta.dependencies,
                    cost=meta.cost,
                )
                next_state = [*state, obs]
                if not _state_consistent(next_state, fault_budget):
                    continue
                tail, _ = value(
                    key_for(next_state), tuple(x for x in remaining_ids if x != sid)
                )
                branch_values.append(tail)
            if not branch_values:
                continue
            worst = meta.cost + max(branch_values)
            if worst < best[0] or (
                worst == best[0] and (best[1] is None or sid < best[1])
            ):
                best = (worst, sid)
        return best

    # The cache needs metadata for current observations as well.
    for obs in current:
        by_id.setdefault(obs.source_id, obs)
    _, source_id = value(key_for(current), tuple(obs.source_id for obs in ordered))
    return source_id


def dfmr_choose_next_bounded(
    current: Sequence[Observation],
    candidates: Sequence[Observation],
    fault_budget: int,
    limit: int = 9,
) -> str | None:
    """Resource-bounded `dfmr_choose_next`, safe to call from a real request path.

    `dfmr_choose_next`'s exact minimax recurrence branches over every
    remaining candidate and is measured (`section6_reproduction/
    scalability_benchmark.py`, `DFMR_STATE_LIMIT`) to cost roughly an order
    of magnitude more per +2 candidates, reaching ~0.1-1s/instance at 9
    candidates. That benchmark's own resource-limit fallback -- give up and
    let the caller fall back to `STEP_UP` rather than run the recurrence --
    previously existed only in the benchmark wrapper, not in the actual
    request path (`gateway.py` / `payee_gateway.py`). This function is that
    same guard, callable from production code: above `limit` candidates it
    returns `None` immediately, the same "no further query recommended"
    signal `dfmr_choose_next` already returns when it can't find one, so
    every existing caller's STEP_UP-on-`None` handling applies unchanged.
    Below the limit it delegates to `dfmr_choose_next` verbatim.
    """
    if len(candidates) > limit:
        return None
    return dfmr_choose_next(current, candidates, fault_budget)
