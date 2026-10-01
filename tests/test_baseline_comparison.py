import shutil
import tempfile
import unittest
from pathlib import Path

from cape_artifact import payee_gateway, payee_scenarios
from cape_artifact.baseline_comparison import ALL_DEFENSES, run_comparison


class BaselineComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_all_eight_defenses_are_covered(self):
        self.assertEqual(len(ALL_DEFENSES), 8)
        self.assertEqual(len(set(ALL_DEFENSES)), 8)

    def test_writes_three_new_files_and_nothing_else(self):
        run_comparison(self.tmp)
        produced = {p.name for p in self.tmp.iterdir()}
        self.assertEqual(
            produced,
            {
                "baseline_comparison_runs.csv",
                "baseline_comparison_summary.csv",
                "baseline_comparison_environment.json",
            },
        )

    def test_cwr_and_dfmr_never_authorize_a_corrupted_novel_unregistered_payment(self):
        rows, _ = run_comparison(self.tmp)
        novel_attack_rows = [
            r for r in rows
            if r["category"] == payee_scenarios.NOVEL_UNREGISTERED
            and r["corrupted"] == 1
            and r["defense"] in ("CWR", "DFMR")
        ]
        self.assertTrue(novel_attack_rows)
        self.assertTrue(all(r["unauthorized_payment"] == 0 for r in novel_attack_rows))

    def test_ap2_only_and_static_allowlist_are_fooled_by_a_corrupted_shared_root(self):
        rows, _ = run_comparison(self.tmp)
        fooled = [
            r for r in rows
            if r["category"] != payee_scenarios.KNOWN_LEGITIMATE
            and r["corrupted"] == 1
            and r["defense"] in ("AP2_ONLY", "STATIC_ALLOWLIST")
        ]
        self.assertTrue(fooled)
        self.assertTrue(all(r["unauthorized_payment"] == 1 for r in fooled))

    def test_camel_inspired_is_unaffected_by_shared_root_corruption(self):
        rows, _ = run_comparison(self.tmp)
        camel_rows = [r for r in rows if r["defense"] == "CAMEL_INSPIRED"]
        by_recipient_corruption = {(r["recipient"], r["corrupted"]): r["verdict"] for r in camel_rows}
        for recipient in payee_scenarios.KNOWN_ATTACKER_PAYEES + payee_scenarios.NOVEL_UNREGISTERED_PAYEES:
            self.assertEqual(
                by_recipient_corruption[(recipient, 0)],
                by_recipient_corruption[(recipient, 1)],
            )


if __name__ == "__main__":
    unittest.main()
