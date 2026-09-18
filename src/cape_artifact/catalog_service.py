"""Real local HTTP service exposing the synthetic product catalog.

Mirrors the evidence providers and payment sandbox elsewhere in this
artifact: the shopping agent's view of the merchant catalog is a genuine
network call to a service bound to an ephemeral loopback port, not an
in-process Python data structure. This is deliberately the "merchant data"
side of the threat model — a disguised stored-value product is served
under its cover title and claimed category exactly as an attacker-
controlled merchant catalog would present it. The true category is never
exposed by this service; independent verification of the true category is
the job of `evidence.py` and `gateway.py`, matching the same separation
`evidence.py`'s workload generator already keeps from its scoring code
("the optimizer never reads the hidden truth field").
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .catalog import ALLOWED_PRODUCTS, DISGUISED_STORED_VALUE_PRODUCTS, MERCHANT


def _listing(sku: str, title: str, category: str, price_usd: int) -> dict:
    return {"sku": sku, "title": title, "category": category, "price_usd": price_usd, "merchant": MERCHANT}


def catalog_listings() -> dict[str, dict]:
    """The merchant-facing catalog: legitimate products under their real
    category, disguised stored-value products under their cover category.
    """
    listings: dict[str, dict] = {}
    for product in ALLOWED_PRODUCTS:
        listings[product.sku] = _listing(product.sku, product.title, product.category, product.price_usd)
    for disguise in DISGUISED_STORED_VALUE_PRODUCTS:
        listings[disguise.sku] = _listing(
            disguise.sku, disguise.cover_title, disguise.cover_category, disguise.price_usd
        )
    return listings


class _CatalogHandler(BaseHTTPRequestHandler):
    server_version = "CAPE-Catalog/1.0"

    def do_GET(self):
        listings: dict[str, dict] = self.server.listings  # type: ignore[attr-defined]
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/products":
            body = json.dumps({"products": list(listings.values())}).encode("utf-8")
        elif parsed.path.startswith("/products/"):
            sku = parsed.path.removeprefix("/products/")
            if sku not in listings:
                self.send_error(404, "unknown sku")
                return
            body = json.dumps(listings[sku]).encode("utf-8")
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class CatalogService:
    """Context manager binding the catalog HTTP service to 127.0.0.1:0."""

    def __init__(self):
        self._listings = catalog_listings()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.url: str = ""

    def __enter__(self) -> "CatalogService":
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _CatalogHandler)
        self._server.listings = self._listings  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"http://127.0.0.1:{self._server.server_port}"
        return self

    def __exit__(self, *_args) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def list_products(self, timeout: float = 2.0) -> list[dict]:
        with urllib.request.urlopen(f"{self.url}/products", timeout=timeout) as response:
            return json.loads(response.read())["products"]

    def get_product(self, sku: str, timeout: float = 2.0) -> dict | None:
        try:
            with urllib.request.urlopen(f"{self.url}/products/{sku}", timeout=timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise


__all__ = ["CatalogService", "catalog_listings"]
