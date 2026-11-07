"""Principals (users, services, agents), their attributes, and the registry that stores them.

Tokens only prove *who* is calling. Everything that drives CUI decisions - U.S.-person status,
CUI training/lawful-government-purpose access, category and dissemination authorizations, and
whether an agent's model runs inside an authorized boundary - comes from this admin-managed
registry, never from claims a caller can mint for itself.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any

from sqlalchemy import insert, select, update

from strongbox.storage import schema
from strongbox.storage.database import Database, utcnow

ALL = "*"

SCOPES = frozenset(
    {
        "blobs:read",
        "blobs:write",
        "blobs:delete",
        "records:read",
        "records:write",
        "records:delete",
        "collections:admin",
        "audit:read",
        "principals:admin",
        "delegate",  # may act on behalf of another principal (X-On-Behalf-Of)
    }
)


class PrincipalKind(StrEnum):
    USER = "user"
    SERVICE = "service"
    AGENT = "agent"


def _intersect(a: frozenset[str], b: frozenset[str]) -> frozenset[str]:
    if ALL in a:
        return b
    if ALL in b:
        return a
    return a & b


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    kind: PrincipalKind
    scopes: frozenset[str] = field(default_factory=frozenset)
    us_person: bool = False
    cui_access: bool = False
    cui_categories: frozenset[str] = field(default_factory=frozenset)
    dissemination: frozenset[str] = field(default_factory=frozenset)
    llm_boundary_authorized: bool = False
    display_name: str | None = None
    actor: str | None = None  # set when an agent/service acts on behalf of `subject`

    def has_scope(self, scope: str) -> bool:
        return ALL in self.scopes or scope in self.scopes

    def covers_category(self, category: str) -> bool:
        return ALL in self.cui_categories or category in self.cui_categories

    def covers_dissemination(self, ldc: str) -> bool:
        return ALL in self.dissemination or ldc in self.dissemination

    def delegated_to(self, actor: Principal) -> Principal:
        """Effective identity when `actor` works on behalf of this principal: the intersection of both.

        An agent can never do more than the person it acts for, nor more than the agent itself is cleared
        for; U.S.-person status requires both, so a non-U.S. person cannot borrow an agent's clearance.
        """
        return replace(
            self,
            kind=PrincipalKind.AGENT if actor.kind is PrincipalKind.AGENT else self.kind,
            scopes=_intersect(self.scopes, actor.scopes) - {"delegate", "principals:admin"},
            us_person=self.us_person and actor.us_person,
            cui_access=self.cui_access and actor.cui_access,
            cui_categories=_intersect(self.cui_categories, actor.cui_categories),
            dissemination=_intersect(self.dissemination, actor.dissemination),
            llm_boundary_authorized=actor.llm_boundary_authorized,
            actor=actor.subject,
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "kind": self.kind.value,
            "actor": self.actor,
            "display_name": self.display_name,
            "scopes": sorted(self.scopes),
            "us_person": self.us_person,
            "cui_access": self.cui_access,
            "cui_categories": sorted(self.cui_categories),
            "dissemination": sorted(self.dissemination),
            "llm_boundary_authorized": self.llm_boundary_authorized,
        }


@dataclass(frozen=True, slots=True)
class PrincipalSpec:
    """What an administrator sets for a principal."""

    subject: str
    kind: PrincipalKind
    scopes: Iterable[str] = ()
    us_person: bool = False
    cui_access: bool = False
    cui_categories: Iterable[str] = ()
    dissemination: Iterable[str] = ()
    llm_boundary_authorized: bool = False
    display_name: str | None = None
    disabled: bool = False

    def validate(self) -> None:
        if not self.subject or len(self.subject) > 255:
            raise ValueError("subject must be 1-255 characters")
        unknown = set(self.scopes) - SCOPES - {ALL}
        if unknown:
            raise ValueError(f"unknown scopes: {sorted(unknown)}")
        if self.llm_boundary_authorized and self.kind is not PrincipalKind.AGENT:
            raise ValueError("llm_boundary_authorized applies only to agent principals")


class PrincipalRegistry:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, subject: str) -> Principal | None:
        with self._db.engine.connect() as conn:
            row = conn.execute(
                select(schema.principals).where(schema.principals.c.subject == subject)
            ).first()
        if row is None or row.disabled:
            return None
        return Principal(
            subject=row.subject,
            kind=PrincipalKind(row.kind),
            scopes=frozenset(row.scopes),
            us_person=bool(row.us_person),
            cui_access=bool(row.cui_access),
            cui_categories=frozenset(c.upper() for c in row.cui_categories),
            dissemination=frozenset(d.upper() for d in row.dissemination),
            llm_boundary_authorized=bool(row.llm_boundary_authorized),
            display_name=row.display_name,
        )

    def put(self, spec: PrincipalSpec) -> None:
        spec.validate()
        now = utcnow()
        values = {
            "kind": spec.kind.value,
            "display_name": spec.display_name,
            "scopes": sorted(set(spec.scopes)),
            "us_person": spec.us_person,
            "cui_access": spec.cui_access,
            "cui_categories": sorted({c.upper() for c in spec.cui_categories}),
            "dissemination": sorted({d.upper() for d in spec.dissemination}),
            "llm_boundary_authorized": spec.llm_boundary_authorized,
            "disabled": spec.disabled,
            "updated_at": now,
        }
        with self._db.engine.begin() as conn:
            exists = conn.execute(
                select(schema.principals.c.subject).where(schema.principals.c.subject == spec.subject)
            ).first()
            if exists:
                conn.execute(
                    update(schema.principals)
                    .where(schema.principals.c.subject == spec.subject)
                    .values(**values)
                )
            else:
                conn.execute(insert(schema.principals).values(subject=spec.subject, created_at=now, **values))

    def list(self) -> list[dict[str, Any]]:
        with self._db.engine.connect() as conn:
            rows = conn.execute(select(schema.principals).order_by(schema.principals.c.subject)).all()
        out = []
        for r in rows:
            d = dict(r._mapping)
            d["created_at"] = d["created_at"].isoformat()
            d["updated_at"] = d["updated_at"].isoformat()
            out.append(d)
        return out
