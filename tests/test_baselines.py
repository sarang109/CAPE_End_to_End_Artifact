import unittest

from cape_artifact.baselines import route_baseline_check
from cape_artifact.models import ALLOW, DENY, STEP_UP

CORRUPTED_ROOT = "bank-directory-root"


class StaticAllowlistTests(unittest.TestCase):
    def test_allows_legitimate_recipient_on_current_snapshot(self):
        result = route_baseline_check("STATIC_ALLOWLIST", recipient_is_legit=True)
        self.assertEqual(result.verdict, ALLOW)

    def test_denies_illegitimate_recipient_on_current_snapshot(self):
        result = route_baseline_check("STATIC_ALLOWLIST", recipient_is_legit=False)
        self.assertEqual(result.verdict, DENY)

    def test_stale_snapshot_steps_up_instead_of_trusting_it(self):
        result = route_baseline_check(
            "STATIC_ALLOWLIST", recipient_is_legit=True, registry_version=2, pinned_version=1,
        )
        self.assertEqual(result.verdict, STEP_UP)

    def test_corrupted_shared_root_still_fools_a_current_snapshot(self):
        # Honest failure mode: version freshness does not imply corruption
        # tolerance. A current-version snapshot of a corrupted registry is
        # still trusted outright, same as AP2_ONLY/MAJORITY.
        result = route_baseline_check(
            "STATIC_ALLOWLIST", recipient_is_legit=False,
            corrupted_domain=CORRUPTED_ROOT, forged_value=True,
        )
        self.assertEqual(result.verdict, ALLOW)


class PolicyEngineTests(unittest.TestCase):
    def test_blocklist_rule_denies_known_attacker_for_free(self):
        result = route_baseline_check(
            "POLICY_ENGINE", recipient_is_legit=False, is_known_attacker=True,
        )
        self.assertEqual(result.verdict, DENY)
        self.assertEqual(result.query_cost, 0)

    def test_falls_through_to_registry_for_unblocked_recipient(self):
        result = route_baseline_check("POLICY_ENGINE", recipient_is_legit=True, is_known_attacker=False)
        self.assertEqual(result.verdict, ALLOW)

    def test_stale_ruleset_steps_up(self):
        result = route_baseline_check(
            "POLICY_ENGINE", recipient_is_legit=True, registry_version=2, ruleset_version=1,
        )
        self.assertEqual(result.verdict, STEP_UP)

    def test_newly_corrupted_recipient_not_yet_on_blocklist_is_still_authorized(self):
        # Honest failure mode: the blocklist only protects recipients
        # already known to be bad; a fresh corruption not yet on it is
        # authorized exactly like AP2_ONLY.
        result = route_baseline_check(
            "POLICY_ENGINE", recipient_is_legit=False, is_known_attacker=False,
            corrupted_domain=CORRUPTED_ROOT, forged_value=True,
        )
        self.assertEqual(result.verdict, ALLOW)


class CamelInspiredTests(unittest.TestCase):
    def test_allows_legitimate_recipient_via_independent_corroboration(self):
        result = route_baseline_check("CAMEL_INSPIRED", recipient_is_legit=True)
        self.assertEqual(result.verdict, ALLOW)
        self.assertEqual(result.queried_sources, 2)

    def test_denies_illegitimate_recipient_via_independent_corroboration(self):
        result = route_baseline_check("CAMEL_INSPIRED", recipient_is_legit=False)
        self.assertEqual(result.verdict, DENY)

    def test_ignores_shared_root_corruption_entirely(self):
        # It never queries the shared registry, so corrupting it has no
        # effect on the verdict -- the point of not trusting that data.
        corrupted = route_baseline_check(
            "CAMEL_INSPIRED", recipient_is_legit=True,
            corrupted_domain=CORRUPTED_ROOT, forged_value=False,
        )
        uncorrupted = route_baseline_check("CAMEL_INSPIRED", recipient_is_legit=True)
        self.assertEqual(corrupted.verdict, uncorrupted.verdict)
        self.assertEqual(corrupted.verdict, ALLOW)


class UnknownDefenseTests(unittest.TestCase):
    def test_unknown_defense_raises(self):
        with self.assertRaises(ValueError):
            route_baseline_check("NOT_A_DEFENSE", recipient_is_legit=True)


if __name__ == "__main__":
    unittest.main()
