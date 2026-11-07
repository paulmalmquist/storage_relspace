"""Single choke point that pairs every policy decision with an audit event."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from strongbox.audit import AuditLog
from strongbox.auth.policy import Action, Decision, PolicyEngine
from strongbox.auth.principal import Principal
from strongbox.errors import AccessDenied, NotFound
from strongbox.markings import Marking


@dataclass(frozen=True, slots=True)
class Ctx:
    """Who is asking, plus the request id that ties audit events to logs and traces."""

    principal: Principal
    request_id: str | None = None


class Guard:
    def __init__(self, policy: PolicyEngine, audit: AuditLog, *, conceal_denied: bool) -> None:
        self.policy = policy
        self.audit = audit
        self._conceal = conceal_denied

    def check(
        self,
        ctx: Ctx,
        action: Action,
        *,
        resource_type: str,
        resource_id: str | None,
        marking: Marking | None,
        details: dict[str, Any] | None = None,
        audit_allow: bool = True,
        concealable: bool = True,
    ) -> Decision:
        decision = self.policy.evaluate(ctx.principal, action, marking)
        if decision.allowed and not audit_allow:
            return decision
        self.audit.record(
            principal=ctx.principal,
            action=action.value,
            resource_type=resource_type,
            resource_id=resource_id,
            decision=decision.label,
            reason=decision.reason,
            marking=marking.banner if marking else None,
            request_id=ctx.request_id,
            details=details,
        )
        if decision.allowed or decision.withheld:
            return decision
        if decision.conceal and concealable and self._conceal:
            raise NotFound(f"{resource_type} not found")
        raise AccessDenied(decision.reason)

    def peek(self, ctx: Ctx, action: Action, marking: Marking | None) -> Decision:
        """Evaluate without auditing (used to filter list results; the list itself is audited)."""
        return self.policy.evaluate(ctx.principal, action, marking)

    def note(
        self,
        ctx: Ctx,
        action: Action | str,
        *,
        resource_type: str,
        resource_id: str | None,
        decision: str,
        reason: str,
        marking: Marking | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.audit.record(
            principal=ctx.principal,
            action=action.value if isinstance(action, Action) else action,
            resource_type=resource_type,
            resource_id=resource_id,
            decision=decision,
            reason=reason,
            marking=marking.banner if marking else None,
            request_id=ctx.request_id,
            details=details,
        )
