import unittest

from cape_artifact.stripe_adapter import construct_signed_test_event, verify_webhook_signature


class WebhookSignatureTests(unittest.TestCase):
    def test_correctly_signed_event_verifies(self):
        payload, sig_header = construct_signed_test_event({"id": "evt_1", "type": "payment_intent.succeeded"}, "whsec_test")
        self.assertTrue(verify_webhook_signature(payload, sig_header, "whsec_test"))

    def test_wrong_secret_fails_verification(self):
        payload, sig_header = construct_signed_test_event({"id": "evt_1"}, "whsec_test")
        self.assertFalse(verify_webhook_signature(payload, sig_header, "whsec_other"))

    def test_tampered_payload_fails_verification(self):
        payload, sig_header = construct_signed_test_event({"id": "evt_1"}, "whsec_test")
        tampered = payload.replace(b"evt_1", b"evt_2")
        self.assertFalse(verify_webhook_signature(tampered, sig_header, "whsec_test"))

    def test_expired_timestamp_fails_verification(self):
        payload, sig_header = construct_signed_test_event({"id": "evt_1"}, "whsec_test", timestamp=1)
        self.assertFalse(verify_webhook_signature(payload, sig_header, "whsec_test"))

    def test_malformed_header_fails_verification(self):
        self.assertFalse(verify_webhook_signature(b"{}", "not-a-valid-header", "whsec_test"))


if __name__ == "__main__":
    unittest.main()
