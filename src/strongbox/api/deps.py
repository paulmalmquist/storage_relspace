"""Request-scoped dependencies: container lookup, authentication, delegation."""

from __future__ import annotations

from fastapi import Depends, Request

from strongbox.auth.principal import Principal, PrincipalKind
from strongbox.errors import AccessDenied, Unauthenticated
from strongbox.services.container import Container
from strongbox.services.guard import Ctx

ON_BEHALF_OF = "x-on-behalf-of"


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _fail(c: Container, request: Request, reason: str, subject: str = "anonymous") -> Unauthenticated:
    c.audit.record(
        principal=None,
        action="auth.authenticate",
        resource_type="session",
        resource_id=None,
        decision="deny",
        reason=reason,
        request_id=_request_id(request),
        anonymous_subject=subject[:255],
    )
    return Unauthenticated(reason)


def authenticate(request: Request, c: Container = Depends(get_container)) -> Principal:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _fail(c, request, "missing bearer token")
    try:
        verified = c.verifier.verify(token.strip())
    except Unauthenticated as exc:
        raise _fail(c, request, exc.detail) from exc
    principal = c.principals.get(verified.subject)
    if principal is None:
        raise _fail(c, request, "unknown or disabled principal", verified.subject)

    obo = request.headers.get(ON_BEHALF_OF)
    if obo:
        if not principal.has_scope("delegate"):
            c.audit.record(
                principal=principal,
                action="auth.delegate",
                resource_type="session",
                resource_id=None,
                decision="deny",
                reason="caller lacks the delegate scope",
                request_id=_request_id(request),
            )
            raise AccessDenied("caller may not act on behalf of other principals")
        try:
            delegator_token = c.delegation_verifier.verify(obo.strip())
        except Unauthenticated as exc:
            raise _fail(c, request, f"invalid on-behalf-of token: {exc.detail}", principal.subject) from exc
        delegator = c.principals.get(delegator_token.subject)
        if delegator is None:
            raise _fail(c, request, "unknown or disabled on-behalf-of principal", delegator_token.subject)
        if delegator.kind is PrincipalKind.AGENT:
            raise AccessDenied("agents cannot delegate to other agents")
        principal = delegator.delegated_to(principal)
    request.state.principal = principal
    return principal


def get_ctx(request: Request, principal: Principal = Depends(authenticate)) -> Ctx:
    return Ctx(principal=principal, request_id=_request_id(request))
