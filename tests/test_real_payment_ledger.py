import shutil
import tempfile
import unittest
from pathlib import Path

from cape_artifact.real_payment_ledger import IdempotencyConflict, RealPaymentLedger


class RealPaymentLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db_path = self.tmp / "ledger.db"

    def test_new_operation_is_created(self):
        with RealPaymentLedger(self.db_path) as ledger:
            created, entry = ledger.record("op-1", "digest-a", "pi_123", "succeeded")
            self.assertTrue(created)
            self.assertEqual(entry.operation_id, "op-1")
            self.assertEqual(ledger.count(), 1)

    def test_same_operation_and_digest_is_idempotent(self):
        with RealPaymentLedger(self.db_path) as ledger:
            ledger.record("op-1", "digest-a", "pi_123", "succeeded")
            created, entry = ledger.record("op-1", "digest-a", "pi_123", "succeeded")
            self.assertFalse(created)
            self.assertEqual(entry.stripe_payment_intent_id, "pi_123")
            self.assertEqual(ledger.count(), 1)

    def test_same_operation_with_different_digest_conflicts(self):
        with RealPaymentLedger(self.db_path) as ledger:
            ledger.record("op-1", "digest-a", "pi_123", "succeeded")
            with self.assertRaises(IdempotencyConflict):
                ledger.record("op-1", "digest-b", "pi_456", "succeeded")

    def test_persists_across_reopening_the_same_file(self):
        with RealPaymentLedger(self.db_path) as ledger:
            ledger.record("op-1", "digest-a", "pi_123", "succeeded")
        with RealPaymentLedger(self.db_path) as reopened:
            self.assertEqual(reopened.count(), 1)
            entries = reopened.all_entries()
            self.assertEqual(entries[0].operation_id, "op-1")


if __name__ == "__main__":
    unittest.main()
