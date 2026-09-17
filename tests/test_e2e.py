import tempfile
import unittest
from pathlib import Path

from cape_artifact.experiment import run_experiment


class EndToEndTests(unittest.TestCase):
    def test_strong_variants_prevent_unauthorized_payment(self):
        with tempfile.TemporaryDirectory() as temp:
            rows, _ = run_experiment(1, Path(temp))
        for defense in ("FULL", "CWR", "DFMR"):
            unsafe = [
                row
                for row in rows
                if row["defense"] == defense and row["unauthorized_payment"]
                and row["assumption_status"] == "within_model"
            ]
            self.assertEqual(unsafe, [], defense)

    def test_assumption_breaks_are_exposed_not_hidden(self):
        with tempfile.TemporaryDirectory() as temp:
            rows, _ = run_experiment(1, Path(temp))
        self.assertTrue(
            any(
                row["defense"] in {"FULL", "CWR", "DFMR"}
                and row["assumption_status"] != "within_model"
                and row["unauthorized_payment"]
                for row in rows
            )
        )

    def test_ap2_binding_attacks_are_denied_before_payment(self):
        with tempfile.TemporaryDirectory() as temp:
            rows, _ = run_experiment(1, Path(temp))
        binding_rows = [
            row for row in rows
            if row["family"] == "mandate_binding"
        ]
        self.assertTrue(binding_rows)
        self.assertFalse(any(row["payment_effect"] for row in binding_rows))

    def test_negative_controls_expose_semantic_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            rows, _ = run_experiment(1, Path(temp))
        self.assertTrue(
            any(
                row["defense"] == "AP2_ONLY" and row["unauthorized_payment"]
                for row in rows
            )
        )
        self.assertTrue(
            any(
                row["defense"] == "MAJORITY"
                and row["family"] == "shared_provenance"
                and row["unauthorized_payment"]
                for row in rows
            )
        )


if __name__ == "__main__":
    unittest.main()
