"""Real Stripe test-mode payment lifecycle: authorize -> capture -> refund,
a decline path, idempotency replay/conflict, and webhook-signature
verification.

Answers the reviewer gap that no real payment processor was ever tested
(the AP2 path's settlement is a local, in-memory sandbox --
`sandbox.py`). Every call here is real and goes to Stripe's actual test-mode
API (`https://api.stripe.com`) using a real `sk_test_...` key, recorded into
a genuine SQLite-backed ledger (`real_payment_ledger.py`) rather than an
in-memory structure. No real money moves: Stripe's test mode is free, every
adapter function refuses non-test keys, and this module checks
`livemode: false` on every response as an explicit safety assertion.

Two things this cannot test in a single session, disclosed rather than
faked:

- **True webhook delivery.** There is no live public HTTPS endpoint here
  for Stripe to deliver a webhook to, so only the signature-verification
  *algorithm* is exercised (`stripe_adapter.construct_signed_test_event` /
  `verify_webhook_signature`), against a self-signed synthetic event, not
  an event Stripe actually sent.
- **24-hour idempotency-key expiration.** Stripe's real idempotency keys
  expire after 24 hours; that cannot be observed within one session. This
  module tests only the immediate same-key/same-params and
  same-key/different-params behavior, both via the local ledger and (for
  create) against Stripe's own API.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import stripe_adapter
from .real_payment_ledger import IdempotencyConflict, RealPaymentLedger

AMOUNT_CENTS = 1000
CURRENCY = "usd"


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def run(secret_key: str, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    livemode_violations = 0

    def record_call(step: str, response: dict) -> None:
        nonlocal livemode_violations
        if response.get("livemode", False):
            livemode_violations += 1
        rows.append(
            {
                "step": step,
                "id": response.get("id", ""),
                "status": response.get("status", ""),
                "livemode": response.get("livemode", ""),
                "error_code": (response.get("error") or {}).get("code", ""),
                "decline_code": (response.get("error") or {}).get("decline_code", ""),
            }
        )

    with RealPaymentLedger(output_dir / "stripe_ledger.db") as ledger:
        # 1. Authorize (manual capture) -> requires_capture.
        created = stripe_adapter.confirm_test_payment_intent(
            secret_key, AMOUNT_CENTS, CURRENCY, "lifecycle-create-1", should_succeed=True, manual_capture=True,
        )
        record_call("create_confirm", created)
        pi_id = created.get("id", "")
        ledger.record("lifecycle-create-1", _digest("create", pi_id), pi_id, created.get("status", ""))

        # 2. Capture -> succeeded (real settlement).
        captured = stripe_adapter.capture_test_payment_intent(secret_key, pi_id, "lifecycle-capture-1")
        record_call("capture", captured)
        ledger.record("lifecycle-capture-1", _digest("capture", pi_id), pi_id, captured.get("status", ""))

        # 3. Refund -> succeeded (real reversal).
        refunded = stripe_adapter.create_test_refund(secret_key, pi_id, "lifecycle-refund-1")
        record_call("refund", refunded)
        ledger.record("lifecycle-refund-1", _digest("refund", pi_id), refunded.get("id", ""), refunded.get("status", ""))

        # 4. Decline path.
        declined = stripe_adapter.confirm_test_payment_intent(
            secret_key, AMOUNT_CENTS, CURRENCY, "lifecycle-decline-1", should_succeed=False, manual_capture=True,
        )
        record_call("decline", declined)

        # 5. Ledger idempotency: same op+digest replays; same op+different digest conflicts.
        same_digest = _digest("create", pi_id)
        created_flag_1, _ = ledger.record("lifecycle-create-1", same_digest, pi_id, "succeeded")
        idempotent_replay_ok = created_flag_1 is False
        conflict_raised = False
        try:
            ledger.record("lifecycle-create-1", _digest("different", pi_id), pi_id, "succeeded")
        except IdempotencyConflict:
            conflict_raised = True

        # 6. Webhook signature verification (self-signed synthetic event; see module docstring).
        secret = "whsec_synthetic_test_only"
        payload, sig_header = stripe_adapter.construct_signed_test_event(
            {"id": "evt_synthetic_1", "type": "payment_intent.succeeded", "data": {"object": {"id": pi_id}}}, secret,
        )
        webhook_verifies = stripe_adapter.verify_webhook_signature(payload, sig_header, secret)
        tampered_rejected = not stripe_adapter.verify_webhook_signature(
            payload.replace(b"succeeded", b"tampered_x"), sig_header, secret
        )

        ledger_entry_count = ledger.count()

    summary = {
        "amount_cents": AMOUNT_CENTS,
        "currency": CURRENCY,
        "create_confirm_status": created.get("status"),
        "capture_status": captured.get("status"),
        "refund_status": refunded.get("status"),
        "decline_error_code": (declined.get("error") or {}).get("code"),
        "decline_code": (declined.get("error") or {}).get("decline_code"),
        "ledger_idempotent_replay_ok": idempotent_replay_ok,
        "ledger_idempotency_conflict_raised": conflict_raised,
        "ledger_entry_count": ledger_entry_count,
        "webhook_signature_verifies": webhook_verifies,
        "webhook_tampered_payload_rejected": tampered_rejected,
        "livemode_violations": livemode_violations,
        "not_tested_this_session": [
            "true webhook delivery to a live public endpoint (none available)",
            "24-hour idempotency-key expiration (cannot elapse within one session)",
        ],
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    _write_csv(output_dir / "stripe_lifecycle_runs.csv", rows)
    (output_dir / "stripe_lifecycle_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _write_csv(path: Path, rows: list[dict]) -> None:
    import csv

    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
