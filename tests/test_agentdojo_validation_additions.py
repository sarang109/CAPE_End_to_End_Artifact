import unittest

from cape_artifact.agentdojo_validation import ATTACKER_IBAN, route_money_calls_diverse
from cape_artifact.baseline_comparison import ALL_DEFENSES
from cape_artifact.payee_scenarios import KNOWN_ATTACKER, KNOWN_LEGITIMATE, NOVEL_UNREGISTERED

# This module exercises only the new, pure (no network, no API key)
# additions to agentdojo_validation.py. The pipeline-construction functions
# (`build_pipeline`, `build_defended_pipeline`, ...) require a real
# OpenAI/Google client and are validated by actually running the real
# benchmark, matching how this module was validated before these additions
# (it had no unit tests at all, by the same reasoning).


class RouteMoneyCallsDiverseTests(unittest.TestCase):
    def test_covers_all_eight_defenses_per_call(self):
        rows = route_money_calls_diverse([{"function": "send_money", "recipient": ATTACKER_IBAN}])
        self.assertEqual(len(rows), len(ALL_DEFENSES))
        self.assertEqual({r["defense"] for r in rows}, set(ALL_DEFENSES))

    def test_classifies_the_real_attacker_iban_as_known_attacker(self):
        rows = route_money_calls_diverse([{"function": "send_money", "recipient": ATTACKER_IBAN}])
        self.assertTrue(all(r["category"] == KNOWN_ATTACKER for r in rows))
        self.assertTrue(all(r["recipient_is_legit"] == 0 for r in rows))

    def test_classifies_a_real_transaction_history_recipient_as_known_legitimate(self):
        rows = route_money_calls_diverse(
            [{"function": "send_money", "recipient": "US122000000121212121212"}]
        )
        self.assertTrue(all(r["category"] == KNOWN_LEGITIMATE for r in rows))
        self.assertTrue(all(r["recipient_is_legit"] == 1 for r in rows))

    def test_classifies_an_unfamiliar_recipient_as_novel_unregistered_not_legit(self):
        # The case the "payee-allowlist test" critique targets: a recipient
        # that is neither the attacker's IBAN nor a known-legitimate one.
        rows = route_money_calls_diverse(
            [{"function": "send_money", "recipient": "DE44500105175407324931"}]
        )
        self.assertTrue(all(r["category"] == NOVEL_UNREGISTERED for r in rows))
        self.assertTrue(all(r["recipient_is_legit"] == 0 for r in rows))

    def test_cwr_and_dfmr_never_authorize_a_novel_unregistered_recipient(self):
        rows = route_money_calls_diverse(
            [{"function": "send_money", "recipient": "DE44500105175407324931"}]
        )
        for row in rows:
            if row["defense"] in ("CWR", "DFMR"):
                self.assertEqual(row["unauthorized_payment"], 0)


if __name__ == "__main__":
    unittest.main()
