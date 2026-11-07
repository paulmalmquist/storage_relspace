"""Identity, health, principal administration and audit endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response

from strongbox.api.deps import authenticate, get_container, get_ctx
from strongbox.api.schemas import AuditList, AuditVerify, PrincipalIn, WhoAmI
from strongbox.auth.policy import Action
from strongbox.auth.principal import Principal, PrincipalSpec
from strongbox.errors import AccessDenied, ValidationFailed
from strongbox.services.container import Container
from strongbox.services.guard import Ctx

router = APIRouter()


@router.get("/healthz", tags=["system"], include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["system"], include_in_schema=False)
def readyz(response: Response, c: Container = Depends(get_container)) -> dict[str, str]:
    try:
        c.db.ping()
    except Exception:  # noqa: BLE001
        response.status_code = 503
        return {"status": "unavailable"}
    return {"status": "ok"}


@router.get("/v1/whoami", response_model=WhoAmI, tags=["identity"])
def whoami(principal: Principal = Depends(authenticate)) -> dict[str, Any]:
    return principal.to_public_dict()


@router.get("/v1/principals", tags=["admin"])
def list_principals(ctx: Ctx = Depends(get_ctx), c: Container = Depends(get_container)) -> dict[str, Any]:
    c.guard.check(ctx, Action.PRINCIPAL_ADMIN, resource_type="principal", resource_id=None, marking=None)
    return {"items": c.principals.list()}


@router.put("/v1/principals/{subject}", tags=["admin"])
def put_principal(
    subject: str, body: PrincipalIn, ctx: Ctx = Depends(get_ctx), c: Container = Depends(get_container)
) -> dict[str, Any]:
    c.guard.check(
        ctx,
        Action.PRINCIPAL_ADMIN,
        resource_type="principal",
        resource_id=subject,
        marking=None,
        details={
            "cui_categories": sorted(body.cui_categories),
            "us_person": body.us_person,
            "scopes": sorted(body.scopes),
        },
    )
    if subject == ctx.principal.subject or subject == ctx.principal.actor:
        raise AccessDenied("administrators cannot modify their own principal (separation of duties)")
    spec = PrincipalSpec(subject=subject, **body.model_dump())
    try:
        c.principals.put(spec)
    except ValueError as exc:
        raise ValidationFailed(str(exc)) from exc
    return {"subject": subject, "updated": True}


@router.get("/v1/audit/events", response_model=AuditList, tags=["audit"])
def audit_events(
    after_seq: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
) -> dict[str, Any]:
    c.guard.check(ctx, Action.AUDIT_READ, resource_type="audit", resource_id=None, marking=None)
    return {"items": c.audit.list(after_seq=after_seq, limit=limit)}


@router.get("/v1/audit/verify", response_model=AuditVerify, tags=["audit"])
def audit_verify(ctx: Ctx = Depends(get_ctx), c: Container = Depends(get_container)) -> dict[str, Any]:
    c.guard.check(ctx, Action.AUDIT_READ, resource_type="audit", resource_id=None, marking=None)
    r = c.audit.verify()
    return {
        "ok": r.ok,
        "checked": r.checked,
        "head_seq": r.head_seq,
        "first_invalid_seq": r.first_invalid_seq,
    }
