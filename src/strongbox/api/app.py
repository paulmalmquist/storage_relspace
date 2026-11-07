"""FastAPI application factory. Run with: uvicorn --factory strongbox.api.app:create_app"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from strongbox import __version__
from strongbox.api.middleware import RequestContextMiddleware
from strongbox.api.routes import admin, blobs, records
from strongbox.config import Settings, get_settings
from strongbox.errors import StrongboxError
from strongbox.services.container import Container

log = logging.getLogger("strongbox.api")

DESCRIPTION = """
Inter-service API for CUI-grade blob and structured data storage.

* Authenticate with `Authorization: Bearer <OIDC ID token>` (Google-signed for Cloud Run/GKE workloads).
* Agents and services acting for a user also send `X-On-Behalf-Of: <user token>`; access is the
  intersection of both principals.
* Every CUI response carries `X-Strongbox-Marking` with its banner; propagate it downstream.
* Errors are `application/problem+json` with a stable `code`.
"""


def _problem(request: Request, status: int, code: str, title: str, detail: str) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        headers=headers,
        content={
            "type": "about:blank",
            "title": title,
            "status": status,
            "code": code,
            "detail": detail,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


def create_app(container: Container | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or (container.settings if container else get_settings())
    container = container or Container.build(settings)
    docs = settings.expose_docs
    app = FastAPI(
        title="Strongbox",
        version=__version__,
        description=DESCRIPTION,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.container = container
    app.add_middleware(RequestContextMiddleware)

    @app.exception_handler(StrongboxError)
    async def _domain_error(request: Request, exc: StrongboxError) -> JSONResponse:
        if exc.status >= 500:
            log.error(
                "request %s failed: %s %s", getattr(request.state, "request_id", "-"), exc.code, exc.detail
            )
        return _problem(request, exc.status, exc.code, type(exc).__name__, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        parts = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]]
        return _problem(request, 422, "validation_failed", "ValidationFailed", "; ".join(parts))

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error in request %s", getattr(request.state, "request_id", "-"))
        return _problem(request, 500, "internal_error", "InternalError", "internal error")

    app.include_router(admin.router)
    app.include_router(blobs.router)
    app.include_router(records.router)
    return app
