"""Tamper-evident audit log (NIST SP 800-171 3.3.1, 3.3.2, 3.3.8).

Every authorization decision, including denials and authentication failures, becomes one event.
Events form a SHA-256 hash chain: each event's hash covers the previous hash and the event's
canonical JSON, so editing, deleting or reordering any stored event breaks ``verify()`` from that
point on. Events are also emitted as structured log lines for Cloud Logging, where a locked log
bucket provides an independent retained copy.

Events carry identifiers and markings only, never CUI content, filenames or metadata values.
Audit writes are fail-closed: if the event cannot be written, the request fails.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from typing import Any

from sqlalchemy import insert, select, update

from strongbox.auth.principal import Principal
from strongbox.storage import schema
from strongbox.storage.database import Database, utcnow

GENESIS = "0" * 64
log = logging.getLogger("strongbox.audit")


def _canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), default=str).encode()


def _chain(prev_hash: str, event: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode() + _canonical(event)).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    checked: int
    first_invalid_seq: int | None = None
    head_seq: int = 0


_HASHED = (
    "seq",
    "ts",
    "request_id",
    "actor",
    "actor_kind",
    "on_behalf_of",
    "action",
    "resource_type",
    "resource_id",
    "marking",
    "decision",
    "reason",
    "details",
)


class AuditLog:
    def __init__(self, db: Database) -> None:
        self._db = db
        self._lock = threading.Lock()

    def record(
        self,
        *,
        principal: Principal | None,
        action: str,
        resource_type: str,
        resource_id: str | None,
        decision: str,
        reason: str,
        marking: str | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
        anonymous_subject: str = "anonymous",
    ) -> int:
        if principal is None:
            actor, kind, obo = anonymous_subject, "anonymous", None
        elif principal.actor:
            actor, kind, obo = principal.actor, principal.kind.value, principal.subject
        else:
            actor, kind, obo = principal.subject, principal.kind.value, None

        with self._lock, self._db.engine.begin() as conn:
            head = conn.execute(
                select(schema.audit_head).where(schema.audit_head.c.id == 1).with_for_update()
            ).one()
            event: dict[str, Any] = {
                "seq": int(head.seq) + 1,
                "ts": utcnow().isoformat(timespec="microseconds"),
                "request_id": request_id,
                "actor": actor,
                "actor_kind": kind,
                "on_behalf_of": obo,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "marking": marking,
                "decision": decision,
                "reason": reason[:512],
                "details": details or {},
            }
            digest = _chain(head.hash, event)
            conn.execute(insert(schema.audit_events).values(**event, prev_hash=head.hash, hash=digest))
            conn.execute(
                update(schema.audit_head)
                .where(schema.audit_head.c.id == 1)
                .values(seq=event["seq"], hash=digest)
            )
        log.info(json.dumps({"audit": True, **event, "hash": digest}, default=str))
        return int(event["seq"])

    def verify(self, *, batch: int = 1000) -> VerifyResult:
        prev = GENESIS
        checked = 0
        last_seq = 0
        with self._db.engine.connect() as conn:
            head = conn.execute(select(schema.audit_head).where(schema.audit_head.c.id == 1)).one()
            while True:
                rows = conn.execute(
                    select(schema.audit_events)
                    .where(schema.audit_events.c.seq > last_seq)
                    .order_by(schema.audit_events.c.seq)
                    .limit(batch)
                ).all()
                if not rows:
                    break
                for row in rows:
                    data = row._mapping
                    event = {k: data[k] for k in _HASHED}
                    if (
                        int(data["seq"]) != last_seq + 1
                        or data["prev_hash"] != prev
                        or _chain(prev, event) != data["hash"]
                    ):
                        return VerifyResult(False, checked, int(data["seq"]), int(head.seq))
                    prev = data["hash"]
                    last_seq = int(data["seq"])
                    checked += 1
        if last_seq != int(head.seq) or prev != head.hash:
            return VerifyResult(False, checked, last_seq + 1, int(head.seq))
        return VerifyResult(True, checked, None, int(head.seq))

    def list(self, *, after_seq: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        with self._db.engine.connect() as conn:
            rows = conn.execute(
                select(schema.audit_events)
                .where(schema.audit_events.c.seq > after_seq)
                .order_by(schema.audit_events.c.seq)
                .limit(max(1, min(limit, 1000)))
            ).all()
        return [dict(r._mapping) for r in rows]
