from __future__ import annotations

import json
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.generated.open_payment_mandate import (
    AllowedPayees,
    AmountRange,
    OpenPaymentMandate,
)
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain

from .models import Cart, Policy


def _jwk_with_kid(raw_key, kid: str) -> JWK:
    material = json.loads(JWK.from_pyca(raw_key).export())
    material["kid"] = kid
    return JWK(**material)


@dataclass(frozen=True)
class AP2Bundle:
    token: str
    transaction_id: str
    audience: str
    nonce: str


class AP2Harness:
    """Small official-SDK harness; no Gemini or external service is involved."""

    def __init__(self):
        self.issuer_jwk = _jwk_with_kid(
            ec.generate_private_key(ec.SECP256R1()), "cape-issuer"
        )
        self.agent_jwk = _jwk_with_kid(
            ec.generate_private_key(ec.SECP256R1()), "cape-agent"
        )
        self.client = MandateClient()

    def issue(self, cart: Cart, policy: Policy) -> AP2Bundle:
        now = int(time.time())
        if len(policy.allowed_currencies) != 1:
            raise ValueError("the AP2 harness requires exactly one allowed currency")
        policy_currency = next(iter(policy.allowed_currencies))
        merchant = Merchant(id=cart.merchant_id, name=cart.merchant_name)
        allowed = [Merchant(id=m, name=m) for m in sorted(policy.allowed_merchants)]
        open_token = self.client.create(
            payloads=[
                OpenPaymentMandate(
                    constraints=[
                        AmountRange(
                            currency=policy_currency,
                            min=0,
                            max=policy.max_amount_cents,
                        ),
                        AllowedPayees(allowed=allowed),
                    ],
                    cnf={"jwk": json.loads(self.agent_jwk.export_public())},
                    iat=now,
                    exp=now + 3600,
                )
            ],
            issuer_key=self.issuer_jwk,
        )
        audience = "cape-payment-sandbox"
        nonce = cart.operation_id
        closed = self.client.present(
            holder_key=self.agent_jwk,
            mandate_token=open_token,
            payloads=[
                PaymentMandate(
                    transaction_id=cart.operation_id,
                    payee=merchant,
                    payment_amount=Amount(
                        amount=cart.amount_cents, currency=cart.currency
                    ),
                    payment_instrument=PaymentInstrument(
                        type="card", id="test-instrument", description="Research fixture"
                    ),
                    iat=now,
                    exp=now + 3600,
                )
            ],
            nonce=nonce,
            aud=audience,
        )
        return AP2Bundle(closed, cart.operation_id, audience, nonce)

    def verify(self, bundle: AP2Bundle) -> list[str]:
        payloads = self.client.verify(
            token=bundle.token,
            key_or_provider=lambda _token: self.issuer_jwk,
            expected_aud=bundle.audience,
            expected_nonce=bundle.nonce,
        )
        chain = PaymentMandateChain.parse(payloads)
        return chain.verify(expected_transaction_id=bundle.transaction_id)
