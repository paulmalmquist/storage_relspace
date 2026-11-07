"""Blob endpoints. Uploads stream raw bytes (no multipart) so services can push multi-GB objects
with O(chunk) memory; the marking and optional filename/metadata travel in headers."""

from __future__ import annotations

import base64
import binascii
import json
from functools import partial
from typing import Any
from urllib.parse import quote, unquote

import anyio
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from strongbox.api.deps import get_container, get_ctx
from strongbox.api.schemas import BlobList, BlobOut
from strongbox.errors import ValidationFailed
from strongbox.markings import Marking
from strongbox.services.blobs import BlobMeta
from strongbox.services.container import Container
from strongbox.services.guard import Ctx

router = APIRouter(prefix="/v1/blobs", tags=["blobs"])
MARKING_HEADER = "X-Strongbox-Marking"


def _parse_marking(value: str) -> Marking:
    try:
        return Marking.parse(value)
    except ValueError as exc:
        raise ValidationFailed(str(exc)) from exc


def _parse_metadata(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        data = json.loads(raw)
    except (binascii.Error, ValueError) as exc:
        raise ValidationFailed("X-Strongbox-Metadata must be base64url-encoded JSON") from exc
    if not isinstance(data, dict):
        raise ValidationFailed("X-Strongbox-Metadata must encode a JSON object")
    return data


@router.post(
    "",
    status_code=201,
    response_model=BlobOut,
    summary="Upload a blob (raw request body)",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
async def upload_blob(
    request: Request,
    response: Response,
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
    x_strongbox_marking: str = Header(
        ..., description="CUI banner, e.g. CUI//SP-EXPT//NOFORN, or UNCONTROLLED"
    ),
    x_strongbox_filename: str | None = Header(None, description="Percent-encoded original filename"),
    x_strongbox_metadata: str | None = Header(None, description="base64url(JSON object), sealed at rest"),
    idempotency_key: str | None = Header(None),
    content_type: str = Header("application/octet-stream"),
    content_length: int | None = Header(None),
) -> dict[str, Any]:
    upload = await run_in_threadpool(
        partial(
            c.blobs.begin_upload,
            ctx,
            marking=_parse_marking(x_strongbox_marking),
            content_type=content_type,
            filename=unquote(x_strongbox_filename) if x_strongbox_filename else None,
            metadata=_parse_metadata(x_strongbox_metadata),
            idempotency_key=idempotency_key,
            declared_size=content_length,
        )
    )
    if isinstance(upload, BlobMeta):  # idempotent replay
        response.status_code = 200
        meta = upload
    else:
        try:
            async for chunk in request.stream():
                if chunk:
                    await run_in_threadpool(upload.write, chunk)
            meta = await run_in_threadpool(upload.commit)
        except BaseException as exc:
            with anyio.CancelScope(shield=True):
                await run_in_threadpool(upload.abort, type(exc).__name__)
            raise
    response.headers["Location"] = f"/v1/blobs/{meta.id}"
    response.headers[MARKING_HEADER] = meta.marking.banner
    return meta.to_dict()


@router.get("", response_model=BlobList)
def list_blobs(
    limit: int | None = Query(None, ge=1, le=200),
    cursor: str | None = None,
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
) -> dict[str, Any]:
    items, nxt = c.blobs.list(ctx, limit=limit, cursor=cursor)
    return {"items": [m.to_dict() for m in items], "next_cursor": nxt}


@router.get("/{blob_id}", response_model=BlobOut)
def get_blob(
    blob_id: str, response: Response, ctx: Ctx = Depends(get_ctx), c: Container = Depends(get_container)
) -> dict[str, Any]:
    meta = c.blobs.get_meta(ctx, blob_id)
    response.headers[MARKING_HEADER] = meta.marking.banner
    return meta.to_dict()


@router.get(
    "/{blob_id}/content",
    response_class=StreamingResponse,
    responses={200: {"content": {"application/octet-stream": {}}, "description": "Decrypted content"}},
)
def download_blob(
    blob_id: str, ctx: Ctx = Depends(get_ctx), c: Container = Depends(get_container)
) -> StreamingResponse:
    meta, chunks = c.blobs.open_content(ctx, blob_id)
    headers = {MARKING_HEADER: meta.marking.banner}
    if meta.size_bytes is not None:
        headers["Content-Length"] = str(meta.size_bytes)
    if meta.filename:
        headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(meta.filename)}"
    return StreamingResponse(chunks, media_type=meta.content_type, headers=headers)


@router.delete("/{blob_id}", status_code=204)
def delete_blob(
    blob_id: str,
    shred: bool = Query(False, description="Destroy the data key and object; irreversible"),
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
) -> Response:
    c.blobs.delete(ctx, blob_id, shred=shred)
    return Response(status_code=204)
