# Real Stripe test-mode payment lifecycle (new, additive)

New, supplementary work. Does not modify `sandbox.py`, the AP2 path, or any
already-published result -- it adds `stripe_lifecycle_runs.csv`,
`stripe_lifecycle_summary.json`, and a real, file-backed SQLite database
`stripe_ledger.db`.

## Why

A reviewer pass noted no real payment processor was ever tested: the AP2
path's settlement is `sandbox.py`'s in-memory `PaymentSandbox`. This
experiment exercises a real processor's test-mode API end-to-end --
authorize, capture, refund, a decline path, idempotency, and webhook
signature verification -- using `src/cape_artifact/stripe_adapter.py`
(extended with `confirm_test_payment_intent`, `capture_test_payment_intent`,
`create_test_refund`, and webhook-signature helpers; the original
`create_test_payment_intent` is unchanged) against Stripe's real
`https://api.stripe.com` test-mode endpoints, and a genuine
`sqlite3`-backed ledger (`src/cape_artifact/real_payment_ledger.py`) instead
of an in-memory structure.

Requires a real `sk_test_...` key as the `STRIPE_SECRET_KEY` environment
variable (never written to a file). Reproduce with:

```bash
STRIPE_SECRET_KEY=sk_test_... .venv/Scripts/python.exe run_stripe_lifecycle.py --i-accept-stripe-test-calls
```

## Results

Every step succeeded against Stripe's real test-mode API on the first run:
create-and-confirm with a real test payment method landed in
`requires_capture` (real authorization); capture returned `succeeded` (real
settlement); refund returned `succeeded` (real reversal); confirming with
Stripe's own always-declining test payment method correctly surfaced
`error.code = "card_declined"`, `decline_code = "generic_decline"`. The
SQLite ledger correctly replayed an identical (operation_id, cart_digest)
pair as idempotent (no duplicate row) and correctly raised
`IdempotencyConflict` for the same operation_id with a different digest.
Webhook-signature verification correctly accepted a genuine signature and
correctly rejected a tampered payload. Every response's `livemode` field
was `false` (0 violations) -- confirmed test-mode only, no real money moved
at any point.

## Limitations (disclosed, not tested this session)

- **True webhook delivery to a live endpoint.** No public HTTPS endpoint is
  available in this environment for Stripe to actually deliver a webhook
  to. Only the signature-*verification algorithm* is tested, against a
  self-signed synthetic event -- a real, meaningful test of the
  verification logic, but not of live delivery.
- **24-hour idempotency-key expiration.** Cannot be observed within a
  single session; only immediate same-key/same-params and
  same-key/different-params behavior is tested.

## Files

- `stripe_lifecycle_runs.csv`: one row per real Stripe API call (create,
  capture, refund, decline), its resulting status/error/decline code, and
  its `livemode` flag.
- `stripe_lifecycle_summary.json`: pass/fail summary of every check above.
- `stripe_ledger.db`: the real SQLite database recording every call, with
  the same idempotency semantics as `sandbox.py`'s existing in-memory
  ledger, now persisted and independently queryable.
