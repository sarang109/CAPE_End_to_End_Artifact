import itertools
import random
import unittest

from cape_artifact.algorithms import cover_number, cwr_plan
from cape_artifact.joint_algorithms import (
    JointCandidate,
    joint_bilateral_decision,
    joint_cwr_plan,
    joint_dfmr_choose_next,
    joint_positive_certificate,
)
from cape_artifact.models import ALLOW, DENY, STEP_UP, Observation


def jc(sid, deps, cost, predicates):
    return JointCandidate(sid, "sku", 1, frozenset(deps), cost, frozenset(predicates))


def obs(sid, value, deps, cost=1):
    return Observation(sid, "sku", 1, value, frozenset(deps), cost)


class JointPlanningSavesOverIndependentPlanning(unittest.TestCase):
    def test_a_shared_candidate_is_only_paid_for_once(self):
        # Two predicates, each needing f=1 tolerance over its own domain
        # pair, but one candidate is relevant to BOTH and covers both
        # domain pairs at once.
        candidates = [
            jc("shared", {"cat-a", "pay-a"}, 5, {"category", "payee"}),
            jc("cat-only", {"cat-b"}, 3, {"category"}),
            jc("pay-only", {"pay-b"}, 4, {"payee"}),
        ]
        joint = joint_cwr_plan({}, candidates, 1, ("category", "payee"))
        self.assertIsNotNone(joint)
        joint_cost, _ = joint

        # "shared"'s real dependencies ({cat-a, pay-a}) must be used in
        # full even when computing each predicate's plan independently --
        # a physical source's corruption-domain footprint doesn't shrink
        # just because only one predicate is being asked about.
        cat_only_candidates = [obs("shared", True, {"cat-a", "pay-a"}, 5), obs("cat-only", True, {"cat-b"}, 3)]
        pay_only_candidates = [obs("shared", True, {"cat-a", "pay-a"}, 5), obs("pay-only", True, {"pay-b"}, 4)]
        cat_plan = cwr_plan([], cat_only_candidates, 1)
        pay_plan = cwr_plan([], pay_only_candidates, 1)
        independent_cost = cat_plan[0] + pay_plan[0]

        # Independently, "shared" is planned (and its cost paid) in BOTH
        # single-predicate plans; jointly it is paid for once, saving
        # exactly its own cost.
        self.assertEqual(independent_cost - joint_cost, 5)
        self.assertEqual(joint_cost, cat_plan[0] + pay_plan[0] - 5)

    def test_irrelevant_candidate_does_not_trivially_satisfy_a_predicate(self):
        # A candidate relevant ONLY to "payee" must not be treated as
        # covering "category" just because its dependencies don't
        # intersect category's hypotheses.
        candidates = [jc("payee-only", {"pay-a"}, 1, {"payee"})]
        result = joint_cwr_plan({}, candidates, 1, ("category", "payee"))
        # category has a residual hypothesis (empty dependency set never
        # certifies) that no candidate here can cover -> infeasible.
        self.assertIsNone(result)


class JointDecisionTests(unittest.TestCase):
    def test_allow_requires_every_predicate_to_allow(self):
        current = {
            "category": [obs("a", True, {"x"}), obs("b", True, {"y"})],
            "payee": [obs("c", True, {"z"}), obs("d", True, {"w"})],
        }
        self.assertEqual(joint_bilateral_decision(current, 1, ("category", "payee")), ALLOW)
        self.assertTrue(joint_positive_certificate(current, 1, ("category", "payee")))

    def test_any_predicate_deny_certified_denies_the_joint_decision(self):
        current = {
            "category": [obs("a", False, {"x"}), obs("b", False, {"y"})],
            "payee": [obs("c", True, {"z"}), obs("d", True, {"w"})],
        }
        self.assertEqual(joint_bilateral_decision(current, 1, ("category", "payee")), DENY)

    def test_insufficient_evidence_on_either_predicate_steps_up(self):
        current = {
            "category": [obs("a", True, {"x"}), obs("b", True, {"x"})],  # copied positive, doesn't certify
            "payee": [obs("c", True, {"z"}), obs("d", True, {"w"})],
        }
        self.assertEqual(joint_bilateral_decision(current, 1, ("category", "payee")), STEP_UP)


class JointDfmrTests(unittest.TestCase):
    def test_prefers_the_shared_source_when_one_query_can_resolve_both_predicates(self):
        # At fault_budget=0, a single positive observation already
        # certifies a predicate (cover_number 1 > f=0), so querying the
        # shared source first can resolve BOTH predicates from one query;
        # cat-alt/pay-alt can each only ever resolve their own predicate.
        candidates = [
            jc("shared", {"cat-a", "pay-a"}, 2, {"category", "payee"}),
            jc("cat-alt", {"cat-b"}, 10, {"category"}),
            jc("pay-alt", {"pay-b"}, 10, {"payee"}),
        ]
        next_id = joint_dfmr_choose_next({}, candidates, 0, ("category", "payee"))
        self.assertEqual(next_id, "shared")

    def test_ties_when_every_source_is_independently_necessary(self):
        # At fault_budget=1, every one of these three candidates is
        # ultimately required regardless of query order (each predicate
        # needs its own two relevant candidates for f=1 tolerance), so
        # DFMR has no cost preference among them and falls back to the
        # same alphabetical tie-break `dfmr_choose_next` already uses.
        candidates = [
            jc("shared", {"cat-a", "pay-a"}, 2, {"category", "payee"}),
            jc("cat-alt", {"cat-b"}, 10, {"category"}),
            jc("pay-alt", {"pay-b"}, 10, {"payee"}),
        ]
        next_id = joint_dfmr_choose_next({}, candidates, 1, ("category", "payee"))
        self.assertEqual(next_id, "cat-alt")


class JointExhaustiveCrossCheckTests(unittest.TestCase):
    """Brute-force cross-check, mirroring
    section6_reproduction/scalability_benchmark.py's `_exhaustive_plan`
    pattern, generalized to multiple predicates."""

    def _exhaustive(self, candidates, fault_budget, predicates):
        best = None
        for size in range(len(candidates) + 1):
            for combo in itertools.combinations(candidates, size):
                state = {p: [] for p in predicates}
                for c in combo:
                    o = Observation(c.source_id, c.sku, c.version, True, c.dependencies, c.cost)
                    for p in c.relevant_predicates:
                        if p in state:
                            state[p].append(o)
                if all(cover_number(state[p]) > fault_budget for p in predicates):
                    cost = sum(c.cost for c in combo)
                    if best is None or cost < best:
                        best = cost
        return best

    def test_matches_exhaustive_search_across_random_instances(self):
        domains = tuple(f"D{i}" for i in range(6))
        predicate_sets = (("category", "payee"), ("category", "payee", "geo"))
        mismatches = 0
        total = 0
        for predicates in predicate_sets:
            for seed in range(60):
                rng = random.Random(1_000_000 + seed)
                n_candidates = rng.randint(2, 5)
                candidates = []
                for i in range(n_candidates):
                    k = rng.randint(1, 3)
                    deps = frozenset(rng.sample(domains, k=k))
                    cost = rng.randint(1, 9)
                    n_relevant = rng.randint(1, len(predicates))
                    relevant = frozenset(rng.sample(predicates, k=n_relevant))
                    candidates.append(JointCandidate(f"c{i}", "sku", 1, deps, cost, relevant))
                fault_budget = rng.choice((1, 2))

                joint_result = joint_cwr_plan({}, candidates, fault_budget, predicates)
                joint_cost = joint_result[0] if joint_result is not None else None
                exhaustive_cost = self._exhaustive(candidates, fault_budget, predicates)

                total += 1
                if joint_cost != exhaustive_cost:
                    mismatches += 1
        self.assertEqual(mismatches, 0, f"{mismatches}/{total} instances disagreed with exhaustive search")


if __name__ == "__main__":
    unittest.main()
