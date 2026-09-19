"""Practical comparison baselines for the payee-verification predicate.

A reviewer pass on the manuscript's AgentDojo external validation
(`agentdojo_validation.py` / `payee_gateway.py`) asked for the strongest
practical baselines, naming three specifically: a static payee allowlist
with version invalidation, a production-style policy engine, and an
external enforcement architecture such as CaMeL ("Defeating Prompt
Injections by Design", Debenedetti et al., 2025). This module implements
all three against the *same* evidence topology and the *same* unmodified
primitives (`bilateral_decision`, `Observation`, `ALLOW`/`DENY`/`STEP_UP`)
that `payee_gateway.py` uses, so their results are directly comparable to
`AP2_ONLY` / `MAJORITY` / `FULL` / `CWR` / `DFMR` without inventing a
second evidence model.

None of these three baselines change `payee_gateway.py`, `algorithms.py`,
or their existing `DEFENSES` tuple; this module only adds new, separate
defense labels (`STATIC_ALLOWLIST`, `POLICY_ENGINE`, `CAMEL_INSPIRED`).

Each baseline is deliberately implemented to fail the same way a real
deployment of that design would fail, rather than being strengthened to
look better than it is:

- `STATIC_ALLOWLIST` and `POLICY_ENGINE` both trust a single pinned
  snapshot of one shared-root source (`bank-registry-a`). If that shared
  root is the corrupted domain, a version-current snapshot is still
  trusted outright -- they fail exactly like `AP2_ONLY` / `MAJORITY` do
  under the manuscript's own corrupted-shared-root scenario. Version
  invalidation only protects against a *stale* snapshot, not a
  *corrupted* one; that distinction is the point of including them.
- `CAMEL_INSPIRED` reimplements only CaMeL's central mechanism -- a value
  sourced from untrusted "data" provenance must be corroborated by an
  independently-rooted "control" channel before it can be used in a
  control position (here, as the payment recipient) -- using
  `bilateral_decision` over the two independent, differently-rooted
  sources (SMS + email) and never consulting the shared registry at all.
  This is *not* a reimplementation of CaMeL's custom interpreter, capability
  system, or dual-LLM architecture; it is a faithful reduction of its
  provenance-separation idea to this artifact's evidence model, and is
  labeled as such throughout so it is not confused with the published
  system.
"""
from __future__ import annotations

from .algorithms import bilateral_decision
from .models import ALLOW, DENY, STEP_UP
from .payee_gateway import (
    FAULT_BUDGET,
    _INDEPENDENT_SOURCES,
    _SHARED_ROOT_SOURCES,
    PayeeCheckResult,
    _source_observation,
)

DEFENSES = ("STATIC_ALLOWLIST", "POLICY_ENGINE", "CAMEL_INSPIRED")

# The single shared-root source each single-source baseline is pinned to.
_PINNED_SOURCE_ID, _PINNED_DEPS, _PINNED_COST = _SHARED_ROOT_SOURCES[0]


def _pinned_snapshot_observation(*, recipient_is_legit: bool, corrupted_domain: str | None,
                                  forged_value: bool):
    return _source_observation(
        _PINNED_SOURCE_ID, _PINNED_DEPS, _PINNED_COST,
        recipient_is_legit=recipient_is_legit, corrupted_domain=corrupted_domain,
        forged_value=forged_value,
    )


def _static_allowlist(*, recipient_is_legit: bool, corrupted_domain: str | None,
                       forged_value: bool, registry_version: int, pinned_version: int) -> PayeeCheckResult:
    """Trust one pinned-version registry snapshot; invalidate only on staleness."""
    if pinned_version != registry_version:
        # The snapshot is out of date -- refuse to authorize from stale data.
        return PayeeCheckResult(STEP_UP, queried_sources=0, query_cost=0)
    obs = _pinned_snapshot_observation(
        recipient_is_legit=recipient_is_legit, corrupted_domain=corrupted_domain,
        forged_value=forged_value,
    )
    verdict = ALLOW if obs.allowed else DENY
    return PayeeCheckResult(verdict, queried_sources=1, query_cost=obs.cost)


def _policy_engine(*, recipient_is_legit: bool, corrupted_domain: str | None, forged_value: bool,
                    is_known_attacker: bool, registry_version: int, ruleset_version: int) -> PayeeCheckResult:
    """A declarative blocklist-then-registry rule engine, version-pinned.

    Mirrors a realistic production policy engine: an explicit blocklist
    rule fires first (free, no query needed), and anything not on the
    blocklist falls through to a single registry lookup. Like
    `STATIC_ALLOWLIST`, this inherits the registry's corruption -- the
    blocklist only ever contains recipients already known to be bad, so a
    *newly* corrupted registry entry that isn't on the blocklist yet is
    authorized exactly like `AP2_ONLY`.
    """
    if ruleset_version != registry_version:
        return PayeeCheckResult(STEP_UP, queried_sources=0, query_cost=0)
    if is_known_attacker:
        return PayeeCheckResult(DENY, queried_sources=0, query_cost=0)
    obs = _pinned_snapshot_observation(
        recipient_is_legit=recipient_is_legit, corrupted_domain=corrupted_domain,
        forged_value=forged_value,
    )
    verdict = ALLOW if obs.allowed else DENY
    return PayeeCheckResult(verdict, queried_sources=1, query_cost=obs.cost)


def _camel_inspired(*, recipient_is_legit: bool, corrupted_domain: str | None,
                     forged_value: bool) -> PayeeCheckResult:
    """Corroborate via independent, differently-rooted sources only; never consult the shared registry."""
    independent = [
        _source_observation(sid, deps, cost, recipient_is_legit=recipient_is_legit,
                             corrupted_domain=corrupted_domain, forged_value=forged_value)
        for sid, deps, cost in _INDEPENDENT_SOURCES
    ]
    verdict = bilateral_decision(independent, FAULT_BUDGET)
    return PayeeCheckResult(verdict, queried_sources=len(independent),
                             query_cost=sum(o.cost for o in independent))


def route_baseline_check(
    defense: str,
    *,
    recipient_is_legit: bool,
    corrupted_domain: str | None = None,
    forged_value: bool = True,
    is_known_attacker: bool = False,
    registry_version: int = 1,
    pinned_version: int = 1,
    ruleset_version: int = 1,
) -> PayeeCheckResult:
    """Evaluate whether `defense` would authorize payment to this recipient.

    Same calling convention as `payee_gateway.route_payee_check`, extended
    with the version/staleness and blocklist parameters these baselines
    need. Unused parameters are ignored by defenses that don't need them.
    """
    if defense == "STATIC_ALLOWLIST":
        return _static_allowlist(
            recipient_is_legit=recipient_is_legit, corrupted_domain=corrupted_domain,
            forged_value=forged_value, registry_version=registry_version,
            pinned_version=pinned_version,
        )

    if defense == "POLICY_ENGINE":
        return _policy_engine(
            recipient_is_legit=recipient_is_legit, corrupted_domain=corrupted_domain,
            forged_value=forged_value, is_known_attacker=is_known_attacker,
            registry_version=registry_version, ruleset_version=ruleset_version,
        )

    if defense == "CAMEL_INSPIRED":
        return _camel_inspired(
            recipient_is_legit=recipient_is_legit, corrupted_domain=corrupted_domain,
            forged_value=forged_value,
        )

    raise ValueError(f"unknown defense: {defense!r}")
