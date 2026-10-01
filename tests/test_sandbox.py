import unittest

from cape_artifact.models import Cart
from cape_artifact.sandbox import PaymentSandbox, cart_digest


def cart(amount=10_000):
    return Cart(
        operation_id="stable-operation", sku="sku", merchant_id="merchant-good",
        merchant_name="merchant-good", amount_cents=amount, currency="USD",
        claimed_category="electronics", title="Headphones",
    )


class PaymentSandboxTests(unittest.TestCase):
    def test_same_operation_and_digest_is_idempotent(self):
        original = cart()
        with PaymentSandbox() as payment:
            self.assertTrue(payment.dispatch(original, cart_digest(original)))
            self.assertTrue(payment.dispatch(original, cart_digest(original)))
            self.assertEqual(payment.effect_count, 1)

    def test_same_operation_with_mutated_cart_is_rejected(self):
        original = cart()
        mutated = cart(amount=19_000)
        with PaymentSandbox() as payment:
            self.assertTrue(payment.dispatch(original, cart_digest(original)))
            self.assertFalse(payment.dispatch(mutated, cart_digest(mutated)))
            self.assertEqual(payment.effect_count, 1)


if __name__ == "__main__":
    unittest.main()
