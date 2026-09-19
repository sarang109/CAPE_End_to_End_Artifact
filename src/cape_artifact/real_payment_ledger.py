"""A genuine, file-backed SQLite ledger for the real Stripe test-mode
experiment (`run_stripe_lifecycle.py`).

The manuscript's existing local payment sandbox (`sandbox.py`,
`PaymentSandbox`) is an in-memory Python dict behind a loopback HTTP
server -- confirmed by reading it directly, despite looser README
language describing "a local SQLite processor." Rather than change that
existing, published-result-critical class, this is a new, separate
component: a real `sqlite3`-backed database file recording every Stripe
call this artifact makes, with the same idempotency semantics
`sandbox.py` already has (same operation_id + same cart digest ->
idempotent replay; same operation_id + different digest -> conflict), now
backed by a persistent, queryable database rather than memory.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


class IdempotencyConflict(Exception):
    """Raised when the same operation_id is reused with a different cart digest."""


@dataclass(frozen=True)
class LedgerEntry:
    operation_id: str
    cart_digest: str
    stripe_payment_intent_id: str | None
    status: str
    created_at: str


class RealPaymentLedger:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payments (
                operation_id TEXT PRIMARY KEY,
                cart_digest TEXT NOT NULL,
                stripe_payment_intent_id TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def record(
        self, operation_id: str, cart_digest: str, stripe_payment_intent_id: str | None, status: str
    ) -> tuple[bool, LedgerEntry]:
        """Record a payment operation. Returns `(created, entry)`: `created`
        is `False` for an idempotent replay of an identical prior operation
        (the stored entry is returned unchanged), `True` for a genuinely new
        row. Raises `IdempotencyConflict` if `operation_id` was already used
        with a different `cart_digest` -- the same case `sandbox.py` returns
        HTTP 409 for, here surfaced as a real exception over a real table.
        """
        cur = self.conn.execute(
            "SELECT cart_digest, stripe_payment_intent_id, status, created_at FROM payments WHERE operation_id = ?",
            (operation_id,),
        )
        row = cur.fetchone()
        if row is not None:
            prior_digest, prior_intent_id, prior_status, prior_created_at = row
            if prior_digest != cart_digest:
                raise IdempotencyConflict(
                    f"operation_id {operation_id!r} was already recorded with a different cart digest"
                )
            return False, LedgerEntry(operation_id, prior_digest, prior_intent_id, prior_status, prior_created_at)

        created_at = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO payments (operation_id, cart_digest, stripe_payment_intent_id, status, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (operation_id, cart_digest, stripe_payment_intent_id, status, created_at),
        )
        self.conn.commit()
        return True, LedgerEntry(operation_id, cart_digest, stripe_payment_intent_id, status, created_at)

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0]

    def all_entries(self) -> list[LedgerEntry]:
        rows = self.conn.execute(
            "SELECT operation_id, cart_digest, stripe_payment_intent_id, status, created_at FROM payments "
            "ORDER BY created_at"
        ).fetchall()
        return [LedgerEntry(*row) for row in rows]

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "RealPaymentLedger":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
