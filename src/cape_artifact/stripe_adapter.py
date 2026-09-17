"""Optional Stripe sandbox dispatch adapter.

This file is not used by the reported experiment. It intentionally uses only
the standard library and refuses live keys.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request


def create_test_payment_intent(
    secret_key: str,
    amount_cents: int,
    currency: str,
    idempotency_key: str,
) -> dict:
    if not secret_key.startswith("sk_test_"):
        raise ValueError("Stripe adapter accepts sandbox test keys only")
    body = urllib.parse.urlencode(
        {
            "amount": amount_cents,
            "currency": currency.lower(),
            "payment_method_types[]": "card",
        }
    ).encode("ascii")
    request = urllib.request.Request(
        "https://api.stripe.com/v1/payment_intents",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {secret_key}",
            "Idempotency-Key": idempotency_key,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())
