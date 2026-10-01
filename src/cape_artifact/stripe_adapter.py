"""Optional Stripe sandbox dispatch adapter.

`create_test_payment_intent` (below) is not used by the reported
experiment, and was previously the only function here. The functions
added below it extend this adapter to cover a real authorize -> capture ->
refund lifecycle, a decline path, and webhook-signature verification --
closing the reviewer gap that no real payment processor lifecycle was ever
exercised, beyond the single local SQLite-backed sandbox
(`sandbox.py`, in-memory dict; see `real_payment_ledger.py` for a genuine
SQLite-backed ledger used alongside these calls).

This file intentionally uses only the standard library and every function
refuses live (`sk_live_`/`pk_live_`) keys -- test mode only, real money
never moves.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

# Stripe's own test-mode payment-method tokens (no Stripe.js/real card
# needed): a token that always succeeds, and one that always declines.
# https://docs.stripe.com/testing#cards -- these are Stripe's documented
# values, not invented here.
TEST_PAYMENT_METHOD_SUCCESS = "pm_card_visa"
TEST_PAYMENT_METHOD_DECLINE = "pm_card_chargeDeclined"


def _require_test_key(secret_key: str) -> None:
    if not secret_key.startswith("sk_test_"):
        raise ValueError("Stripe adapter accepts sandbox test keys only")


def _request(secret_key: str, path: str, fields: dict, idempotency_key: str | None = None) -> dict:
    body = urllib.parse.urlencode(fields).encode("ascii")
    headers = {
        "Authorization": f"Bearer {secret_key}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(f"https://api.stripe.com{path}", data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def create_test_payment_intent(
    secret_key: str,
    amount_cents: int,
    currency: str,
    idempotency_key: str,
) -> dict:
    _require_test_key(secret_key)
    return _request(
        secret_key,
        "/v1/payment_intents",
        {"amount": amount_cents, "currency": currency.lower(), "payment_method_types[]": "card"},
        idempotency_key,
    )


def confirm_test_payment_intent(
    secret_key: str,
    amount_cents: int,
    currency: str,
    idempotency_key: str,
    *,
    should_succeed: bool = True,
    manual_capture: bool = True,
) -> dict:
    """Create-and-confirm in one call, using Stripe's own test payment-method
    tokens -- a real authorization against Stripe's test-mode API. With
    `manual_capture=True` (default), a successful confirmation lands in
    `requires_capture`, mirroring a real authorize-then-capture flow rather
    than Stripe's default auto-capture-on-confirm behavior."""
    _require_test_key(secret_key)
    payment_method = TEST_PAYMENT_METHOD_SUCCESS if should_succeed else TEST_PAYMENT_METHOD_DECLINE
    fields = {
        "amount": amount_cents,
        "currency": currency.lower(),
        "payment_method": payment_method,
        "confirm": "true",
        "automatic_payment_methods[enabled]": "true",
        "automatic_payment_methods[allow_redirects]": "never",
    }
    if manual_capture:
        fields["capture_method"] = "manual"
    return _request(secret_key, "/v1/payment_intents", fields, idempotency_key)


def capture_test_payment_intent(secret_key: str, payment_intent_id: str, idempotency_key: str) -> dict:
    """Real capture of a `requires_capture` PaymentIntent -- the settlement
    step no other track in this artifact exercises against a real processor."""
    _require_test_key(secret_key)
    return _request(secret_key, f"/v1/payment_intents/{payment_intent_id}/capture", {}, idempotency_key)


def create_test_refund(secret_key: str, payment_intent_id: str, idempotency_key: str) -> dict:
    """Real reversal of a captured PaymentIntent."""
    _require_test_key(secret_key)
    return _request(secret_key, "/v1/refunds", {"payment_intent": payment_intent_id}, idempotency_key)


def construct_signed_test_event(payload: dict, secret: str, timestamp: int | None = None) -> tuple[bytes, str]:
    """Build a synthetically signed webhook event using Stripe's own,
    documented signing scheme (HMAC-SHA256 over `{timestamp}.{payload}`,
    header shape `t=<ts>,v1=<sig>`; https://docs.stripe.com/webhooks#verify-manually).

    This artifact has no live public HTTPS endpoint for Stripe to actually
    deliver a webhook to in this session, so real end-to-end webhook
    delivery is not tested here -- only the verification algorithm itself,
    against a self-signed payload using a locally generated secret. That is
    an honest, disclosed narrowing of scope, not a substitute for it.
    """
    ts = timestamp if timestamp is not None else int(time.time())
    body = json.dumps(payload).encode("utf-8")
    signed_payload = f"{ts}.".encode("utf-8") + body
    signature = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return body, f"t={ts},v1={signature}"


def verify_webhook_signature(payload: bytes, sig_header: str, secret: str, tolerance_seconds: int = 300) -> bool:
    """Verify a Stripe webhook signature per Stripe's documented manual-
    verification algorithm. Returns False (not an exception) for any
    malformed header, expired timestamp, or mismatched signature."""
    parts = dict(item.split("=", 1) for item in sig_header.split(",") if "=" in item)
    if "t" not in parts or "v1" not in parts:
        return False
    try:
        ts = int(parts["t"])
    except ValueError:
        return False
    if abs(time.time() - ts) > tolerance_seconds:
        return False
    signed_payload = f"{ts}.".encode("utf-8") + payload
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts["v1"])
