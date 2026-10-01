"""Payee-identity predicate gateway, reused by the AgentDojo external-validation bridge.

The manuscript's gateway (`gateway.py`) evaluates one protected predicate --
"is the selected product's category allowed" -- against a five-source
shopping-catalog evidence network (Section 6.7). Section 3.1 names two other
predicate families the same architecture is meant to generalize to,
including "a payee may need to match an approved merchant." This module
implements that second predicate -- "is the payment recipient a verified,
registered payee" -- using the *same* unmodified algorithms
(`cover_number`, `positive_certificate`, `bilateral_decision`, `cwr_plan`,
`dfmr_choose_next`) from `algorithms.py`, so that the AgentDojo bridge in
`agentdojo_validation.py` can route a real, externally sourced payment
proposal (a tool call an LLM agent actually issued against AgentDojo's
banking environment) through CAPE's provenance-aware defenses without
inventing a new predicate model or touching the existing shopping `Gateway`
class, its tests, or any of its already-published results.

Evidence topology (fault budget f=1, mirroring the AP2 testbed's 5-source,
3-shared-root layout in Section 6.7): three payee-verification sources
derived from one shared bank/counterparty-directory root, plus two
independent out-of-band confirmation sources (SMS, email) each on their own
root. An attacker who can redirect a compromised agent's payment (as in the
AgentDojo banking injection tasks this module is paired with) is modeled as
also controlling the shared directory root -- the same "one compromised
root outvotes independent witnesses" scenario the manuscript uses
throughout -- while the two independent sources continue to report the
recipient's true legitimacy.

TTL is not modeled here: TTL's distinguishing mechanic in the manuscript is
a fixed-age cache that is reused until it expires, which presumes a
sequence of decisions over time. AgentDojo's banking tasks are each a
single, fresh authorization decision, so there is no cache-age dimension
for TTL to act on; including it would either collapse to FULL or to a
result determined entirely by an arbitrary "is this the first decision"
convention. It is omitted rather than reported as a degenerate case.
"""
from __future__ import annotations

from dataclasses import dataclass

from .algorithms import bilateral_decision, cwr_plan, dfmr_choose_next_bounded, positive_certificate
from .models import ALLOW, DENY, STEP_UP, Observation

FAULT_BUDGET = 1

# (source_id, dependency_domains, acquisition_cost)
_SHARED_ROOT_SOURCES: tuple[tuple[str, frozenset[str], int], ...] = (
    ("bank-registry-a", frozenset({"bank-directory-root"}), 1),
    ("bank-registry-b", frozenset({"bank-directory-root"}), 1),
    ("bank-registry-c", frozenset({"bank-directory-root"}), 1),
)
_INDEPENDENT_SOURCES: tuple[tuple[str, frozenset[str], int], ...] = (
    ("sms-confirmation", frozenset({"telco-root"}), 2),
    ("email-confirmation", frozenset({"mail-root"}), 2),
)
PAYEE_SOURCES = _SHARED_ROOT_SOURCES + _INDEPENDENT_SOURCES

DEFENSES = ("AP2_ONLY", "MAJORITY", "FULL", "CWR", "DFMR")


@dataclass(frozen=True)
class PayeeCheckResult:
    verdict: str
    queried_sources: int
    query_cost: int

    @property
    def unauthorized(self) -> bool:
        """True iff this defense would release payment to an illegitimate payee.

        Matches the manuscript's convention (Section 6.1/6.7): only ALLOW
        (a recorded, dispatchable authorization) counts as a payment
        effect. STEP_UP is a safe non-completion, not an unsafe
        authorization, even though it also does not complete the payment.
        """
        return self.verdict == ALLOW


def _source_observation(source_id: str, deps: frozenset[str], cost: int, *, recipient_is_legit: bool,
                         corrupted_domain: str | None, forged_value: bool) -> Observation:
    is_corrupted = corrupted_domain is not None and corrupted_domain in deps
    allowed = forged_value if is_corrupted else recipient_is_legit
    return Observation(source_id=source_id, sku="payee-check", version=1, allowed=allowed, dependencies=deps, cost=cost)


def route_payee_check(
    defense: str,
    *,
    recipient_is_legit: bool,
    corrupted_domain: str | None = None,
    forged_value: bool = True,
) -> PayeeCheckResult:
    """Evaluate whether `defense` would authorize payment to this recipient.

    `corrupted_domain` names the one provenance domain (at most, since
    `FAULT_BUDGET == 1`) an attacker is modeled as controlling; pass `None`
    for an uncorrupted (benign) evidence state. `forged_value` is what a
    corrupted source reports (default `True`: the attacker's shared-root
    foothold makes an illegitimate recipient look legitimate, the
    dangerous case this predicate exists to catch).
    """
    sources = [
        _source_observation(sid, deps, cost, recipient_is_legit=recipient_is_legit,
                             corrupted_domain=corrupted_domain, forged_value=forged_value)
        for sid, deps, cost in PAYEE_SOURCES
    ]
    by_id = {obs.source_id: obs for obs in sources}
    shared_root = sources[: len(_SHARED_ROOT_SOURCES)]
    independent = sources[len(_SHARED_ROOT_SOURCES):]

    if defense == "AP2_ONLY":
        # Trusts the agent's proposed recipient outright, with no independent
        # payee-provenance check -- the same boundary role AP2_ONLY plays in
        # the shopping gateway (Section 6.2/6.7).
        return PayeeCheckResult(ALLOW, queried_sources=0, query_cost=0)

    if defense == "MAJORITY":
        positives = sum(obs.allowed for obs in sources)
        verdict = ALLOW if positives > len(sources) / 2 else DENY
        return PayeeCheckResult(verdict, queried_sources=len(sources), query_cost=sum(o.cost for o in sources))

    if defense == "FULL":
        verdict = bilateral_decision(sources, FAULT_BUDGET)
        return PayeeCheckResult(verdict, queried_sources=len(sources), query_cost=sum(o.cost for o in sources))

    if defense == "CWR":
        current_positive = [obs for obs in shared_root if obs.allowed]
        stale = list(independent)
        queried: list[str] = []
        while stale and not positive_certificate(current_positive, FAULT_BUDGET):
            planning_metadata = [
                Observation(o.source_id, o.sku, o.version, True, o.dependencies, o.cost) for o in stale
            ]
            plan = cwr_plan(current_positive, planning_metadata, FAULT_BUDGET)
            if not plan or not plan[1]:
                break
            replanned = False
            for sid in plan[1]:
                obs = by_id[sid]
                queried.append(sid)
                stale = [s for s in stale if s.source_id != sid]
                if obs.allowed:
                    current_positive.append(obs)
                else:
                    replanned = True
                    break
            if replanned:
                continue
        verdict = ALLOW if positive_certificate(current_positive, FAULT_BUDGET) else STEP_UP
        cost = sum(o.cost for o in shared_root) + sum(by_id[sid].cost for sid in queried)
        return PayeeCheckResult(verdict, queried_sources=len(shared_root) + len(queried), query_cost=cost)

    if defense == "DFMR":
        current = list(shared_root)
        stale = list(independent)
        queried = []
        verdict = bilateral_decision(current, FAULT_BUDGET)
        while stale and verdict == STEP_UP:
            planning_metadata = [
                Observation(o.source_id, o.sku, o.version, False, o.dependencies, o.cost) for o in stale
            ]
            sid = dfmr_choose_next_bounded(current, planning_metadata, FAULT_BUDGET)
            if sid is None:
                break
            obs = by_id[sid]
            queried.append(sid)
            stale = [s for s in stale if s.source_id != sid]
            current.append(obs)
            verdict = bilateral_decision(current, FAULT_BUDGET)
        cost = sum(o.cost for o in shared_root) + sum(by_id[sid].cost for sid in queried)
        return PayeeCheckResult(verdict, queried_sources=len(shared_root) + len(queried), query_cost=cost)

    raise ValueError(f"unknown defense: {defense!r}")
