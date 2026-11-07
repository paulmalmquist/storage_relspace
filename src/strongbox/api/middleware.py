"""Pure-ASGI middleware (safe for streaming bodies): request ids and security headers."""

from __future__ import annotations

import re
import uuid

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_RID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
_DOC_PATHS = ("/docs", "/openapi.json")


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        rid = incoming if _RID_RE.match(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        is_docs = scope.get("path", "").startswith(_DOC_PATHS)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["x-request-id"] = rid
                headers["cache-control"] = "no-store"
                headers["x-content-type-options"] = "nosniff"
                headers["referrer-policy"] = "no-referrer"
                headers["strict-transport-security"] = "max-age=63072000; includeSubDomains"
                if not is_docs:
                    headers["content-security-policy"] = "default-src 'none'; frame-ancestors 'none'"
            await send(message)

        await self.app(scope, receive, send_wrapper)
