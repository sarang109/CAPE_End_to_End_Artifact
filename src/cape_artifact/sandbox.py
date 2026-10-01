from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .evidence import canonical_json
from .models import Cart


def cart_digest(cart: Cart) -> str:
    payload = {
        "operation_id": cart.operation_id,
        "sku": cart.sku,
        "merchant_id": cart.merchant_id,
        "amount_cents": cart.amount_cents,
        "currency": cart.currency,
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


class _PaymentHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/payments":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        operation_id = request.get("operation_id")
        digest = request.get("cart_digest")
        if not operation_id or not digest:
            self.send_error(400)
            return
        state = self.server.state  # type: ignore[attr-defined]
        with state["lock"]:
            prior = state["effects"].get(operation_id)
            if prior is not None and prior != digest:
                self.send_error(409, "idempotency conflict")
                return
            created = prior is None
            state["effects"][operation_id] = digest
        body = canonical_json({"status": "succeeded", "created": created})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class PaymentSandbox:
    def __init__(self):
        self.state = {"effects": {}, "lock": threading.Lock()}

    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _PaymentHandler)
        self.server.state = self.state  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/payments"
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def reset(self):
        with self.state["lock"]:
            self.state["effects"].clear()

    def dispatch(self, cart: Cart, expected_digest: str) -> bool:
        if cart_digest(cart) != expected_digest:
            return False
        body = canonical_json(
            {"operation_id": cart.operation_id, "cart_digest": expected_digest}
        )
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return json.loads(response.read()).get("status") == "succeeded"
        except urllib.error.HTTPError:
            return False

    @property
    def effect_count(self) -> int:
        with self.state["lock"]:
            return len(self.state["effects"])
