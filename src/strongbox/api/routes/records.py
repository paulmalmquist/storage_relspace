"""Collection and record endpoints. Records use ETags ("v<version>") and require If-Match on update."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Response

from strongbox.api.deps import get_container, get_ctx
from strongbox.api.routes.blobs import MARKING_HEADER
from strongbox.api.schemas import (
    CollectionIn,
    CollectionList,
    CollectionOut,
    QueryIn,
    QueryOut,
    RecordIn,
    RecordOut,
)
from strongbox.errors import PreconditionRequired, ValidationFailed
from strongbox.markings import Marking
from strongbox.services.container import Container
from strongbox.services.guard import Ctx
from strongbox.services.records import RecordView

router = APIRouter(prefix="/v1/collections", tags=["records"])
_ETAG_RE = re.compile(r'^(?:W/)?"?v?(\d{1,9})"?$')


def _etag(version: int) -> str:
    return f'"v{version}"'


def _version(if_match: str | None, *, required: bool) -> int | None:
    if not if_match:
        if required:
            raise PreconditionRequired("If-Match with the record's ETag is required")
        return None
    m = _ETAG_RE.match(if_match.strip())
    if not m:
        raise ValidationFailed('If-Match must be an ETag such as "v3"')
    return int(m.group(1))


def _record_response(view: RecordView, response: Response) -> dict[str, Any]:
    response.headers["ETag"] = _etag(view.version)
    response.headers[MARKING_HEADER] = view.marking.banner
    return view.to_dict()


@router.post("", status_code=201, response_model=CollectionOut)
def create_collection(
    body: CollectionIn, ctx: Ctx = Depends(get_ctx), c: Container = Depends(get_container)
) -> dict[str, Any]:
    coll = c.records.create_collection(
        ctx,
        name=body.name,
        marking=Marking.parse(body.marking),
        json_schema=body.json_schema,
        indexed_fields=body.indexed_fields,
        encrypted=body.encrypted,
    )
    return coll.to_dict()


@router.get("", response_model=CollectionList)
def list_collections(ctx: Ctx = Depends(get_ctx), c: Container = Depends(get_container)) -> dict[str, Any]:
    return {"items": [coll.to_dict() for coll in c.records.list_collections(ctx)]}


@router.get("/{name}", response_model=CollectionOut)
def get_collection(
    name: str, ctx: Ctx = Depends(get_ctx), c: Container = Depends(get_container)
) -> dict[str, Any]:
    return c.records.get_collection(ctx, name).to_dict()


@router.post("/{name}/records", status_code=201, response_model=RecordOut)
def create_record(
    name: str,
    body: RecordIn,
    response: Response,
    idempotency_key: str | None = Header(None),
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
) -> dict[str, Any]:
    view = c.records.create_record(
        ctx,
        name,
        body.data,
        marking=Marking.parse(body.marking) if body.marking else None,
        idempotency_key=idempotency_key,
    )
    response.headers["Location"] = f"/v1/collections/{name}/records/{view.id}"
    return _record_response(view, response)


@router.get("/{name}/records/{record_id}", response_model=RecordOut)
def get_record(
    name: str,
    record_id: str,
    response: Response,
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
) -> dict[str, Any]:
    return _record_response(c.records.get_record(ctx, name, record_id), response)


@router.put("/{name}/records/{record_id}", response_model=RecordOut)
def update_record(
    name: str,
    record_id: str,
    body: RecordIn,
    response: Response,
    if_match: str | None = Header(None),
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
) -> dict[str, Any]:
    version = _version(if_match, required=True)
    if version is None:  # unreachable: required=True raises first; keeps the type narrow
        raise PreconditionRequired("If-Match is required")
    view = c.records.update_record(
        ctx,
        name,
        record_id,
        body.data,
        expected_version=version,
        marking=Marking.parse(body.marking) if body.marking else None,
    )
    return _record_response(view, response)


@router.delete("/{name}/records/{record_id}", status_code=204)
def delete_record(
    name: str,
    record_id: str,
    purge: bool = Query(False, description="Remove the row instead of soft-deleting it"),
    if_match: str | None = Header(None),
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
) -> Response:
    c.records.delete_record(
        ctx, name, record_id, expected_version=_version(if_match, required=False), purge=purge
    )
    return Response(status_code=204)


@router.post("/{name}/query", response_model=QueryOut)
def query_records(
    name: str,
    body: QueryIn,
    response: Response,
    ctx: Ctx = Depends(get_ctx),
    c: Container = Depends(get_container),
) -> dict[str, Any]:
    views, nxt = c.records.query(ctx, name, filters=body.filters, limit=body.limit, cursor=body.cursor)
    banner = Marking.combine(v.marking for v in views).banner
    response.headers[MARKING_HEADER] = banner
    return {"items": [v.to_dict() for v in views], "next_cursor": nxt, "marking": banner}
