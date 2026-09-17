from __future__ import annotations

import time
from dataclasses import replace

from .algorithms import (
    bilateral_decision,
    cwr_plan,
    dfmr_choose_next,
    positive_certificate,
)
from .ap2_flow import AP2Bundle, AP2Harness
from .evidence import EvidenceNetwork
from .models import ALLOW, DENY, STEP_UP, CacheEntry, Cart, Decision, Observation, Policy
from .sandbox import PaymentSandbox, cart_digest


class Gateway:
    def __init__(
        self,
        network: EvidenceNetwork,
        payment: PaymentSandbox,
        ap2: AP2Harness,
        policy: Policy,
        fault_budget: int = 1,
    ):
        self.network = network
        self.payment = payment
        self.ap2 = ap2
        self.policy = policy
        self.fault_budget = fault_budget

    def _fetch(self, source_id: str, sku: str, queried: list[str]) -> Observation | None:
        queried.append(source_id)
        return self.network.fetch(source_id, sku)

    def _hard_checks(self, cart: Cart, bundle: AP2Bundle) -> tuple[bool, str]:
        try:
            violations = self.ap2.verify(bundle)
        except Exception as exc:
            return False, f"AP2 verification error: {type(exc).__name__}"
        if violations:
            return False, "AP2 constraint violation: " + "; ".join(violations)
        if cart.amount_cents > self.policy.max_amount_cents:
            return False, "amount exceeds local policy"
        if cart.merchant_id not in self.policy.allowed_merchants:
            return False, "merchant outside local policy"
        if cart.currency not in self.policy.allowed_currencies:
            return False, "currency outside local policy"
        return True, "verified"

    def authorize(
        self,
        defense: str,
        cart: Cart,
        bundle: AP2Bundle,
        cache: dict[str, CacheEntry],
        race_hook=None,
    ) -> Decision:
        started = time.perf_counter_ns()
        queried: list[str] = []
        hard_ok, hard_reason = self._hard_checks(cart, bundle)
        if not hard_ok:
            return self._finish(Decision(DENY, hard_reason, ap2_verified=False), started)

        observations: list[Observation] = []
        verdict = STEP_UP
        reason = "insufficient evidence"

        if defense == "AP2_ONLY":
            verdict = (
                ALLOW
                if cart.claimed_category in self.policy.allowed_categories
                and cart.claimed_category not in self.policy.forbidden_categories
                else DENY
            )
            reason = "trusted agent semantic field"

        elif defense == "MAJORITY":
            for sid in sorted(self.network.sources):
                obs = self._fetch(sid, cart.sku, queried)
                if obs:
                    observations.append(obs)
            positives = sum(obs.allowed for obs in observations)
            verdict = ALLOW if positives > len(observations) / 2 else DENY
            reason = "provenance-blind signed majority"

        elif defense == "TTL":
            expired = any(entry.age_seconds > 30 for entry in cache.values())
            if expired:
                for sid in sorted(self.network.sources):
                    obs = self._fetch(sid, cart.sku, queried)
                    if obs:
                        observations.append(obs)
            else:
                observations = [entry.observation for entry in cache.values()]
            verdict = bilateral_decision(observations, self.fault_budget)
            reason = "fixed-window evidence reuse"

        elif defense == "FULL":
            for sid in sorted(self.network.sources):
                obs = self._fetch(sid, cart.sku, queried)
                if obs:
                    observations.append(obs)
            verdict = bilateral_decision(observations, self.fault_budget)
            reason = "full provenance-aware refresh"

        elif defense == "CWR":
            current_positive: list[Observation] = []
            stale_ids: list[str] = []
            for sid in sorted(self.network.sources):
                entry = cache.get(sid)
                if (
                    entry
                    and entry.observation.version == self.network.registry.version(sid)
                    and entry.observation.allowed
                ):
                    current_positive.append(entry.observation)
                else:
                    stale_ids.append(sid)
            while not positive_certificate(current_positive, self.fault_budget):
                metadata = [
                    Observation(
                        source_id=sid,
                        sku=cart.sku,
                        version=self.network.registry.version(sid),
                        allowed=True,
                        dependencies=self.network.registry.dependencies(sid),
                        cost=self.network.registry.cost(sid),
                    )
                    for sid in stale_ids
                ]
                plan = cwr_plan(current_positive, metadata, self.fault_budget)
                if not plan:
                    break
                _, source_plan = plan
                if not source_plan:
                    break
                replan = False
                for sid in source_plan:
                    obs = self._fetch(sid, cart.sku, queried)
                    stale_ids.remove(sid)
                    if obs and obs.allowed:
                        current_positive.append(obs)
                    else:
                        replan = True
                        break
                if not replan and positive_certificate(
                    current_positive, self.fault_budget
                ):
                    break
            verdict = (
                ALLOW
                if positive_certificate(current_positive, self.fault_budget)
                else STEP_UP
            )
            observations = current_positive
            reason = "minimum-cost positive witness repair"

        elif defense == "DFMR":
            current: list[Observation] = []
            stale_ids: list[str] = []
            for sid in sorted(self.network.sources):
                entry = cache.get(sid)
                if entry and entry.observation.version == self.network.registry.version(sid):
                    current.append(entry.observation)
                else:
                    stale_ids.append(sid)
            verdict = bilateral_decision(current, self.fault_budget)
            while verdict == STEP_UP and stale_ids:
                metadata = [
                    Observation(
                        source_id=sid,
                        sku=cart.sku,
                        version=self.network.registry.version(sid),
                        allowed=False,
                        dependencies=self.network.registry.dependencies(sid),
                        cost=self.network.registry.cost(sid),
                    )
                    for sid in stale_ids
                ]
                sid = dfmr_choose_next(current, metadata, self.fault_budget)
                if sid is None:
                    break
                obs = self._fetch(sid, cart.sku, queried)
                stale_ids.remove(sid)
                if obs:
                    current.append(obs)
                verdict = bilateral_decision(current, self.fault_budget)
            observations = current
            reason = "decision-flip margin repair"
        else:
            raise ValueError(f"unknown defense: {defense}")

        decision = Decision(
            verdict=verdict,
            reason=reason,
            queried_sources=queried,
            query_cost=sum(self.network.registry.cost(sid) for sid in queried),
            ap2_verified=True,
        )
        if verdict != ALLOW:
            return self._finish(decision, started)

        supporting_versions = {
            obs.source_id: obs.version for obs in observations if obs.allowed
        }
        expected_digest = cart_digest(cart)
        if race_hook:
            race_hook()

        # AP2_ONLY and TTL are negative controls for semantic version binding.
        if defense not in {"AP2_ONLY", "TTL"}:
            for sid, version in supporting_versions.items():
                if self.network.registry.version(sid) != version:
                    decision.verdict = STEP_UP
                    decision.reason = "version conflict at bound dispatch"
                    return self._finish(decision, started)

        decision.payment_effect = self.payment.dispatch(cart, expected_digest)
        if not decision.payment_effect:
            decision.verdict = STEP_UP
            decision.reason = "dispatch binding failed"
        return self._finish(decision, started)

    @staticmethod
    def _finish(decision: Decision, started_ns: int) -> Decision:
        decision.latency_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
        return decision
