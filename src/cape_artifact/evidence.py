from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import Observation


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass
class SourceConfig:
    source_id: str
    dependencies: frozenset[str]
    cost: int
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    version: int = 1
    truth_allowed: bool = True
    compromised: bool = False
    available: bool = True
    tamper_signature: bool = False


class Registry:
    def __init__(self, sources: dict[str, SourceConfig]):
        self.sources = sources

    def version(self, source_id: str) -> int:
        return self.sources[source_id].version

    def dependencies(self, source_id: str) -> frozenset[str]:
        return self.sources[source_id].dependencies

    def cost(self, source_id: str) -> int:
        return self.sources[source_id].cost

    def public_key(self, source_id: str) -> Ed25519PublicKey:
        return self.sources[source_id].public_key


class _EvidenceHandler(BaseHTTPRequestHandler):
    server_version = "CAPE-Evidence/1.0"

    def do_GET(self):
        cfg: SourceConfig = self.server.source_config  # type: ignore[attr-defined]
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/attest":
            self.send_error(404)
            return
        if not cfg.available:
            self.send_error(503, "source unavailable")
            return
        sku = urllib.parse.parse_qs(parsed.query).get("sku", [""])[0]
        if not sku:
            self.send_error(400, "missing sku")
            return
        payload = {
            "source_id": cfg.source_id,
            "sku": sku,
            "version": cfg.version,
            "allowed": True if cfg.compromised else cfg.truth_allowed,
        }
        signature = cfg.private_key.sign(canonical_json(payload))
        if cfg.tamper_signature:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        body = canonical_json({"payload": payload, "signature": b64(signature)})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class EvidenceNetwork:
    def __init__(self, source_layout: list[tuple[str, frozenset[str], int]]):
        self._base_dependencies = {
            source_id: dependencies for source_id, dependencies, _ in source_layout
        }
        self.sources: dict[str, SourceConfig] = {}
        self.servers: dict[str, ThreadingHTTPServer] = {}
        self.threads: list[threading.Thread] = []
        self.urls: dict[str, str] = {}
        for source_id, dependencies, cost in source_layout:
            private = Ed25519PrivateKey.generate()
            self.sources[source_id] = SourceConfig(
                source_id=source_id,
                dependencies=dependencies,
                cost=cost,
                private_key=private,
                public_key=private.public_key(),
            )
        self.registry = Registry(self.sources)

    def __enter__(self):
        for source_id, cfg in self.sources.items():
            server = ThreadingHTTPServer(("127.0.0.1", 0), _EvidenceHandler)
            server.source_config = cfg  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.servers[source_id] = server
            self.threads.append(thread)
            self.urls[source_id] = f"http://127.0.0.1:{server.server_port}"
        return self

    def __exit__(self, *_args):
        for server in self.servers.values():
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def reset(self, truth_allowed: bool):
        for cfg in self.sources.values():
            cfg.dependencies = self._base_dependencies[cfg.source_id]
            cfg.version = 1
            cfg.truth_allowed = truth_allowed
            cfg.compromised = False
            cfg.available = True
            cfg.tamper_signature = False

    def fetch(self, source_id: str, sku: str, timeout: float = 2.0) -> Observation | None:
        try:
            with urllib.request.urlopen(
                f"{self.urls[source_id]}/attest?{urllib.parse.urlencode({'sku': sku})}",
                timeout=timeout,
            ) as response:
                body = json.loads(response.read())
        except Exception:
            return None
        payload = body.get("payload", {})
        if payload.get("source_id") != source_id or payload.get("sku") != sku:
            return None
        if payload.get("version") != self.registry.version(source_id):
            return None
        signature_valid = True
        try:
            self.registry.public_key(source_id).verify(
                b64decode(body.get("signature", "")), canonical_json(payload)
            )
        except (InvalidSignature, ValueError, TypeError):
            signature_valid = False
        if not signature_valid:
            return None
        return Observation(
            source_id=source_id,
            sku=sku,
            version=int(payload["version"]),
            allowed=bool(payload["allowed"]),
            dependencies=self.registry.dependencies(source_id),
            cost=self.registry.cost(source_id),
            signature_valid=True,
        )

    def configuration_digest(self) -> str:
        material = {
            sid: {
                "dependencies": sorted(cfg.dependencies),
                "cost": cfg.cost,
            }
            for sid, cfg in sorted(self.sources.items())
        }
        return hashlib.sha256(canonical_json(material)).hexdigest()
