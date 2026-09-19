import unittest

from cape_artifact.payee_scenarios import (
    KNOWN_ATTACKER,
    KNOWN_ATTACKER_PAYEE,
    KNOWN_LEGITIMATE,
    KNOWN_LEGITIMATE_PAYEES,
    NOVEL_UNREGISTERED,
    NOVEL_UNREGISTERED_PAYEES,
    all_scenarios,
    classify,
)


class PayeeScenarioTests(unittest.TestCase):
    def test_three_categories_are_disjoint(self):
        legit = set(KNOWN_LEGITIMATE_PAYEES)
        attacker = {KNOWN_ATTACKER_PAYEE}
        novel = set(NOVEL_UNREGISTERED_PAYEES)
        self.assertFalse(legit & attacker)
        self.assertFalse(legit & novel)
        self.assertFalse(attacker & novel)

    def test_only_known_legitimate_recipients_are_legit(self):
        scenarios = all_scenarios()
        for scenario in scenarios:
            expected = scenario.category == KNOWN_LEGITIMATE
            self.assertEqual(scenario.recipient_is_legit, expected, scenario)

    def test_novel_unregistered_is_not_legit_even_though_not_the_attacker(self):
        # This is the case the reviewer's "allowlist test" critique targets:
        # a recipient that is neither the flagged attacker address nor any
        # known-legitimate payee must still resolve to not-legit.
        for recipient in NOVEL_UNREGISTERED_PAYEES:
            scenario = classify(recipient)
            self.assertEqual(scenario.category, NOVEL_UNREGISTERED)
            self.assertFalse(scenario.recipient_is_legit)

    def test_classify_recognizes_known_attacker(self):
        self.assertEqual(classify(KNOWN_ATTACKER_PAYEE).category, KNOWN_ATTACKER)

    def test_classify_recognizes_known_legitimate(self):
        for recipient in KNOWN_LEGITIMATE_PAYEES:
            self.assertEqual(classify(recipient).category, KNOWN_LEGITIMATE)

    def test_all_scenarios_covers_every_configured_recipient(self):
        recipients = {s.recipient for s in all_scenarios()}
        expected = set(KNOWN_LEGITIMATE_PAYEES) | {KNOWN_ATTACKER_PAYEE} | set(NOVEL_UNREGISTERED_PAYEES)
        self.assertEqual(recipients, expected)


if __name__ == "__main__":
    unittest.main()
