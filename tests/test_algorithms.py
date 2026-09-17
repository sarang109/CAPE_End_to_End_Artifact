import unittest

from cape_artifact.algorithms import (
    bilateral_decision,
    cwr_plan,
    dfmr_choose_next,
    positive_certificate,
)
from cape_artifact.models import ALLOW, DENY, STEP_UP, Observation


def obs(sid, value, deps, cost=1):
    return Observation(sid, "sku", 1, value, frozenset(deps), cost)


class AlgorithmTests(unittest.TestCase):
    def test_two_independent_positives_certify_f_one(self):
        evidence = [obs("a", True, {"x"}), obs("b", True, {"y"})]
        self.assertTrue(positive_certificate(evidence, 1))
        self.assertEqual(bilateral_decision(evidence, 1), ALLOW)

    def test_copied_positives_do_not_certify(self):
        evidence = [obs("a", True, {"x"}), obs("b", True, {"x"})]
        self.assertFalse(positive_certificate(evidence, 1))
        self.assertEqual(bilateral_decision(evidence, 1), STEP_UP)

    def test_negative_evidence_certifies_deny_symmetrically(self):
        evidence = [obs("a", False, {"x"}), obs("b", False, {"y"})]
        self.assertEqual(bilateral_decision(evidence, 1), DENY)

    def test_cwr_finds_minimum_cost_repair(self):
        current = [obs("u", True, {"a", "b"})]
        candidates = [
            obs("e1", True, {"a", "c"}, 4),
            obs("e2", True, {"b", "d"}, 1),
            obs("e3", True, {"c", "d"}, 6),
        ]
        self.assertEqual(cwr_plan(current, candidates, 1), (5, ("e1", "e2")))

    def test_dfmr_prefers_independent_source_over_cheaper_copy(self):
        current = [obs("cached", True, {"shared"}, 0)]
        candidates = [
            obs("copy", True, {"shared"}, 1),
            obs("independent-1", True, {"independent-1"}, 3),
            obs("independent-2", True, {"independent-2"}, 4),
        ]
        self.assertEqual(dfmr_choose_next(current, candidates, 1), "independent-1")


if __name__ == "__main__":
    unittest.main()
