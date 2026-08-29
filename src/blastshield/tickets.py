"""Change tickets: the enforcement mechanism behind "dry-run first".

A ticket is issued only by a successful, policy-clean dry run. `db_apply`
refuses to execute anything without a valid ticket, and the ticket is bound
to the SHA-256 of the exact change payload — so an agent cannot dry-run a
harmless statement and then apply a different one. Tickets expire, and each
ticket is single-use (consumption is tracked per change_id).

The ticket is a compact, self-verifying token:

    base64url(json payload) + "." + hex(HMAC-SHA256(secret, payload))

Nothing about it requires a database round trip to verify.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass


class TicketError(Exception):
    """Raised for any invalid, expired, mismatched or reused ticket."""


@dataclass(frozen=True)
class TicketPayload:
    change_id: str
    database: str
    change_hash: str
    issued_at: float
    expires_at: float


def hash_change(canonical_change: str) -> str:
    return hashlib.sha256(canonical_change.encode("utf-8")).hexdigest()


class TicketIssuer:
    def __init__(self, secret: str, ttl_seconds: int) -> None:
        self._secret = secret.encode("utf-8")
        self._ttl = ttl_seconds
        self._consumed: set[str] = set()

    # -- issue ---------------------------------------------------------------
    def issue(self, database: str, canonical_change: str) -> tuple[str, TicketPayload]:
        now = time.time()
        payload = TicketPayload(
            change_id=str(uuid.uuid4()),
            database=database,
            change_hash=hash_change(canonical_change),
            issued_at=now,
            expires_at=now + self._ttl,
        )
        body = json.dumps(payload.__dict__, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        token = base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + sig
        return token, payload

    # -- verify ---------------------------------------------------------------
    def verify(self, token: str, database: str, canonical_change: str) -> TicketPayload:
        try:
            body_b64, sig = token.rsplit(".", 1)
            padded = body_b64 + "=" * (-len(body_b64) % 4)
            body = base64.urlsafe_b64decode(padded)
        except (ValueError, TypeError) as exc:
            raise TicketError(
                "Malformed ticket. Run db_dry_run first and pass its 'ticket' value unchanged."
            ) from exc

        expected = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise TicketError(
                "Ticket signature is invalid. It was not issued by this server (or the "
                "server restarted with an ephemeral secret — set BLAST_TICKET_SECRET)."
            )

        data = json.loads(body)
        payload = TicketPayload(**data)

        if payload.database != database:
            raise TicketError(
                f"Ticket was issued for '{payload.database}' but apply targets '{database}'."
            )
        if payload.change_hash != hash_change(canonical_change):
            raise TicketError(
                "Ticket does not match this change. The statement/operation you are applying "
                "differs from the one that was dry-run. Dry-run the exact change you intend "
                "to apply."
            )
        if time.time() > payload.expires_at:
            raise TicketError("Ticket expired. Run db_dry_run again to get a fresh one.")
        if payload.change_id in self._consumed:
            raise TicketError(
                "Ticket already used. Each ticket authorizes exactly one apply; run "
                "db_dry_run again if you intend to run this change again."
            )
        return payload

    def consume(self, change_id: str) -> None:
        self._consumed.add(change_id)
