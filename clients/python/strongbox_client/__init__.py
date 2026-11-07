"""Async Python client for the Strongbox API, for Python services, Spark/Airflow jobs and notebooks.

    from strongbox_client import StrongboxClient, GoogleIdTokenSource

    async with StrongboxClient(API_URL, GoogleIdTokenSource("strongbox-api"), serverless_auth=True) as sb:
        blob = await sb.put_blob(b"...", marking="CUI//SP-EXPT", filename="weld-map.csv")
        data, marking = await sb.read_blob(blob["id"])

Create calls carry an Idempotency-Key automatically, so transient-failure retries never duplicate data.
"""

from __future__ import annotations

import asyncio
import base64
import json
import random
import time
import uuid
from collections.abc import AsyncIterable, AsyncIterator, Callable
from typing import Any
from urllib.parse import quote

import httpx

RETRY_STATUSES = frozenset({502, 503, 504})


class StrongboxAPIError(Exception):
    def __init__(self, status: int, code: str, detail: str, request_id: str | None = None) -> None:
        super().__init__(f"{status} {code}: {detail}")
        self.status = status
        self.code = code
        self.detail = detail
        self.request_id = request_id


class TokenSource:
    """Anything that returns a bearer token; called before every request so tokens can refresh."""

    def __call__(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class StaticToken(TokenSource):
    def __init__(self, token: str) -> None:
        self._token = token

    def __call__(self) -> str:
        return self._token


class GoogleIdTokenSource(TokenSource):
    """Fetches Google-signed ID tokens for `audience` from the runtime's service account (metadata server
    on Cloud Run/GKE, or ADC locally) and refreshes them a minute before expiry."""

    def __init__(self, audience: str) -> None:
        self._audience = audience
        self._token: str | None = None
        self._exp = 0.0

    def __call__(self) -> str:
        if self._token is None or time.time() > self._exp - 60:
            import google.auth.transport.requests
            import google.oauth2.id_token
            import jwt

            self._token = google.oauth2.id_token.fetch_id_token(  # type: ignore[no-untyped-call,unused-ignore]
                google.auth.transport.requests.Request(), self._audience
            )
            self._exp = float(jwt.decode(self._token, options={"verify_signature": False})["exp"])
        if self._token is None:
            raise RuntimeError("could not obtain a Google ID token")
        return self._token


TokenLike = str | Callable[[], str]


def _as_source(token: TokenLike | None) -> Callable[[], str] | None:
    if token is None:
        return None
    return StaticToken(token) if isinstance(token, str) else token


class StrongboxClient:
    def __init__(
        self,
        base_url: str,
        token: TokenLike,
        *,
        on_behalf_of: TokenLike | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        serverless_auth: bool = False,
        _http: httpx.AsyncClient | None = None,
    ) -> None:
        self._token = _as_source(token)
        self._obo = _as_source(on_behalf_of)
        self._owns_http = _http is None
        self._http = _http or httpx.AsyncClient(
            base_url=base_url.rstrip("/"), transport=transport, timeout=timeout
        )
        self._retries = max_retries
        self._base_url = base_url
        # Cloud Run IAM reads X-Serverless-Authorization when present, leaving Authorization for Strongbox.
        self._serverless = serverless_auth

    def on_behalf_of(self, token: TokenLike | None) -> StrongboxClient:
        """A view of this client that adds X-On-Behalf-Of, sharing the connection pool."""
        return StrongboxClient(
            self._base_url,
            self._token or "",
            on_behalf_of=token,
            max_retries=self._retries,
            serverless_auth=self._serverless,
            _http=self._http,
        )

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> StrongboxClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ---- transport ----------------------------------------------------------------------
    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {"X-Request-ID": uuid.uuid4().hex}
        if self._token:
            bearer = f"Bearer {self._token()}"
            h["Authorization"] = bearer
            if self._serverless:
                h["X-Serverless-Authorization"] = bearer
        if self._obo:
            h["X-On-Behalf-Of"] = self._obo()
        if extra:
            h.update(extra)
        return h

    async def _request(
        self,
        method: str,
        path: str,
        *,
        retry: bool = True,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self._http.request(method, path, headers=self._headers(headers), **kwargs)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError):
                if not retry or attempt > self._retries:
                    raise
            else:
                if resp.status_code not in RETRY_STATUSES or not retry or attempt > self._retries:
                    if resp.status_code >= 400:
                        _raise(resp)
                    return resp
            await asyncio.sleep(min(8.0, 0.25 * 2**attempt) * (0.5 + random.random()))  # noqa: S311  # nosec B311

    # ---- identity -----------------------------------------------------------------------
    async def whoami(self) -> dict[str, Any]:
        return (await self._request("GET", "/v1/whoami")).json()  # type: ignore[no-any-return]

    # ---- blobs --------------------------------------------------------------------------
    async def put_blob(
        self,
        data: bytes | AsyncIterable[bytes],
        *,
        marking: str,
        content_type: str = "application/octet-stream",
        filename: str | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        headers = {
            "X-Strongbox-Marking": marking,
            "Content-Type": content_type,
            "Idempotency-Key": idempotency_key or uuid.uuid4().hex,
        }
        if filename:
            headers["X-Strongbox-Filename"] = quote(filename, safe="")
        if metadata:
            headers["X-Strongbox-Metadata"] = base64.urlsafe_b64encode(json.dumps(metadata).encode()).decode()
        retry = isinstance(data, bytes | bytearray)  # streams cannot be replayed
        resp = await self._request("POST", "/v1/blobs", retry=retry, headers=headers, content=data)
        return resp.json()  # type: ignore[no-any-return]

    async def get_blob(self, blob_id: str) -> dict[str, Any]:
        return (await self._request("GET", f"/v1/blobs/{blob_id}")).json()  # type: ignore[no-any-return]

    async def read_blob(self, blob_id: str, *, max_bytes: int | None = None) -> tuple[bytes, str]:
        """Returns (content, marking banner). Raises if the object exceeds max_bytes."""
        buf = bytearray()
        marking = ""
        async for chunk, banner in self._iter_blob(blob_id):
            marking = banner
            buf += chunk
            if max_bytes is not None and len(buf) > max_bytes:
                raise StrongboxAPIError(413, "payload_too_large", f"blob exceeds {max_bytes} bytes")
        return bytes(buf), marking

    async def iter_blob(self, blob_id: str) -> AsyncIterator[bytes]:
        async for chunk, _ in self._iter_blob(blob_id):
            yield chunk

    async def _iter_blob(self, blob_id: str) -> AsyncIterator[tuple[bytes, str]]:
        async with self._http.stream("GET", f"/v1/blobs/{blob_id}/content", headers=self._headers()) as resp:
            if resp.status_code >= 400:
                await resp.aread()
                _raise(resp)
            banner = resp.headers.get("X-Strongbox-Marking", "")
            async for chunk in resp.aiter_bytes():
                yield chunk, banner

    async def list_blobs(self, *, limit: int | None = None, cursor: str | None = None) -> dict[str, Any]:
        params = {k: v for k, v in {"limit": limit, "cursor": cursor}.items() if v is not None}
        return (await self._request("GET", "/v1/blobs", params=params)).json()  # type: ignore[no-any-return]

    async def delete_blob(self, blob_id: str, *, shred: bool = False) -> None:
        await self._request("DELETE", f"/v1/blobs/{blob_id}", params={"shred": str(shred).lower()})

    # ---- collections & records ----------------------------------------------------------
    async def create_collection(
        self,
        name: str,
        *,
        marking: str,
        json_schema: dict[str, Any] | None = None,
        indexed_fields: list[str] | None = None,
        encrypted: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "name": name,
            "marking": marking,
            "json_schema": json_schema,
            "indexed_fields": indexed_fields or [],
        }
        if encrypted is not None:
            body["encrypted"] = encrypted
        return (await self._request("POST", "/v1/collections", json=body, retry=False)).json()  # type: ignore[no-any-return]

    async def list_collections(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/v1/collections")).json()["items"]  # type: ignore[no-any-return]

    async def get_collection(self, name: str) -> dict[str, Any]:
        return (await self._request("GET", f"/v1/collections/{name}")).json()  # type: ignore[no-any-return]

    async def create_record(
        self,
        collection: str,
        data: dict[str, Any],
        *,
        marking: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        resp = await self._request(
            "POST",
            f"/v1/collections/{collection}/records",
            json={"data": data, "marking": marking},
            headers={"Idempotency-Key": idempotency_key or uuid.uuid4().hex},
        )
        return resp.json()  # type: ignore[no-any-return]

    async def get_record(self, collection: str, record_id: str) -> dict[str, Any]:
        return (await self._request("GET", f"/v1/collections/{collection}/records/{record_id}")).json()  # type: ignore[no-any-return]

    async def update_record(
        self,
        collection: str,
        record_id: str,
        data: dict[str, Any],
        *,
        expected_version: int,
        marking: str | None = None,
    ) -> dict[str, Any]:
        resp = await self._request(
            "PUT",
            f"/v1/collections/{collection}/records/{record_id}",
            json={"data": data, "marking": marking},
            headers={"If-Match": f'"v{expected_version}"'},
        )
        return resp.json()  # type: ignore[no-any-return]

    async def delete_record(
        self, collection: str, record_id: str, *, expected_version: int | None = None, purge: bool = False
    ) -> None:
        headers = {"If-Match": f'"v{expected_version}"'} if expected_version is not None else None
        await self._request(
            "DELETE",
            f"/v1/collections/{collection}/records/{record_id}",
            params={"purge": str(purge).lower()},
            headers=headers,
        )

    async def query(
        self,
        collection: str,
        filters: dict[str, Any] | None = None,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        body = {"filters": filters or {}, "limit": limit, "cursor": cursor}
        return (await self._request("POST", f"/v1/collections/{collection}/query", json=body)).json()  # type: ignore[no-any-return]


def _raise(resp: httpx.Response) -> None:
    try:
        body = resp.json()
        code, detail = body.get("code", "error"), body.get("detail", resp.text)
    except ValueError:
        code, detail = "error", resp.text[:500]
    raise StrongboxAPIError(resp.status_code, code, detail, resp.headers.get("x-request-id"))
