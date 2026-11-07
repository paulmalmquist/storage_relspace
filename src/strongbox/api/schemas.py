"""Request/response models. Markings are validated and canonicalized on the way in."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from strongbox.auth.principal import PrincipalKind
from strongbox.markings import Marking

Scalar = str | int | float | bool | None


def _marking(value: str) -> str:
    return Marking.parse(value).banner


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Problem(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    code: str
    detail: str
    request_id: str | None = None


class WhoAmI(BaseModel):
    subject: str
    kind: str
    actor: str | None
    display_name: str | None
    scopes: list[str]
    us_person: bool
    cui_access: bool
    cui_categories: list[str]
    dissemination: list[str]
    llm_boundary_authorized: bool


class BlobOut(BaseModel):
    id: str
    marking: str
    content_type: str
    size_bytes: int | None
    filename: str | None
    metadata: dict[str, Any]
    state: str
    created_by: str
    created_at: str


class BlobList(BaseModel):
    items: list[BlobOut]
    next_cursor: str | None


class CollectionIn(_Model):
    name: str
    marking: str
    json_schema: dict[str, Any] | None = None
    indexed_fields: list[str] = Field(default_factory=list)
    encrypted: bool | None = None

    @field_validator("marking")
    @classmethod
    def _m(cls, v: str) -> str:
        return _marking(v)


class CollectionOut(BaseModel):
    name: str
    marking: str
    encrypted: bool
    indexed_fields: list[str]
    json_schema: dict[str, Any]
    version: int
    created_by: str
    created_at: str


class CollectionList(BaseModel):
    items: list[CollectionOut]


class RecordIn(_Model):
    data: dict[str, Any]
    marking: str | None = None

    @field_validator("marking")
    @classmethod
    def _m(cls, v: str | None) -> str | None:
        return None if v is None else _marking(v)


class RecordOut(BaseModel):
    id: str
    collection: str
    marking: str
    version: int
    data: dict[str, Any] | None
    content_withheld: bool
    withheld_reason: str | None = None
    created_by: str
    created_at: str
    updated_by: str
    updated_at: str


class QueryIn(_Model):
    filters: dict[str, Scalar] = Field(default_factory=dict)
    limit: int | None = Field(default=None, ge=1, le=200)
    cursor: str | None = None


class QueryOut(BaseModel):
    items: list[RecordOut]
    next_cursor: str | None
    marking: str = Field(description="Roll-up banner covering every item in this page")


class PrincipalIn(_Model):
    kind: PrincipalKind
    display_name: str | None = None
    scopes: list[str] = Field(default_factory=list)
    us_person: bool = False
    cui_access: bool = False
    cui_categories: list[str] = Field(default_factory=list)
    dissemination: list[str] = Field(default_factory=list)
    llm_boundary_authorized: bool = False
    disabled: bool = False


class AuditEvent(BaseModel):
    seq: int
    ts: str
    request_id: str | None
    actor: str
    actor_kind: str
    on_behalf_of: str | None
    action: str
    resource_type: str
    resource_id: str | None
    marking: str | None
    decision: str
    reason: str
    details: dict[str, Any]
    prev_hash: str
    hash: str


class AuditList(BaseModel):
    items: list[AuditEvent]


class AuditVerify(BaseModel):
    ok: bool
    checked: int
    head_seq: int
    first_invalid_seq: int | None
