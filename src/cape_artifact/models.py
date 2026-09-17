from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


ALLOW = "ALLOW"
DENY = "DENY"
STEP_UP = "STEP_UP"


@dataclass(frozen=True)
class Policy:
    allowed_categories: FrozenSet[str]
    forbidden_categories: FrozenSet[str]
    max_amount_cents: int
    allowed_merchants: FrozenSet[str]
    allowed_currencies: FrozenSet[str]


@dataclass(frozen=True)
class Cart:
    operation_id: str
    sku: str
    merchant_id: str
    merchant_name: str
    amount_cents: int
    currency: str
    claimed_category: str
    title: str
    external_content: str = ""


@dataclass(frozen=True)
class Observation:
    source_id: str
    sku: str
    version: int
    allowed: bool
    dependencies: FrozenSet[str]
    cost: int
    signature_valid: bool = True


@dataclass
class CacheEntry:
    observation: Observation
    age_seconds: float


@dataclass
class Decision:
    verdict: str
    reason: str
    queried_sources: list[str] = field(default_factory=list)
    query_cost: int = 0
    payment_effect: bool = False
    ap2_verified: bool = False
    latency_ms: float = 0.0


@dataclass(frozen=True)
class Scenario:
    name: str
    family: str
    attack: bool
    initial_truth_allowed: bool
    execution_truth_allowed: bool
    compromised_domains: FrozenSet[str] = frozenset()
    compromised_sources: FrozenSet[str] = frozenset()
    unavailable_sources: FrozenSet[str] = frozenset()
    dependency_overrides: tuple[tuple[str, FrozenSet[str]], ...] = ()
    stale_change: bool = False
    version_race: bool = False
    force_refresh: bool = False
    tamper_signature_source: str | None = None
    ap2_tamper: str | None = None
    assumption_status: str = "within_model"
    amount_cents: int = 10_000
    currency: str = "USD"
    merchant_id: str = "merchant-good"
    claimed_category: str = "electronics"
    title: str = "Noise-cancelling headphones"
    external_content: str = ""
