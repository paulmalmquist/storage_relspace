"""Attribute-based access control for CUI. Deny by default; every rule returns a reason for the audit log.

Rules, in order:

1. The principal must hold the scope for the action.
2. Uncontrolled data: scope is sufficient.
3. CUI: the principal must have CUI access (training + lawful government purpose).
4. Every category on the object must be in the principal's authorized categories.
5. Every limited dissemination control must be authorized; NOFORN additionally requires a U.S. person.
6. Export-controlled categories (ITAR/EAR, e.g. SP-EXPT) require a U.S. person.
7. Content reads by agents are withheld unless the agent is registered as running inside an
   authorized LLM boundary. Agents can still see that the object exists and how it is marked.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from strongbox.auth.principal import Principal, PrincipalKind
from strongbox.markings import Marking


class Action(StrEnum):
    BLOB_CREATE = "blob.create"
    BLOB_READ_META = "blob.read_meta"
    BLOB_READ_CONTENT = "blob.read_content"
    BLOB_LIST = "blob.list"
    BLOB_DELETE = "blob.delete"
    BLOB_SHRED = "blob.shred"
    COLLECTION_CREATE = "collection.create"
    COLLECTION_READ = "collection.read"
    RECORD_CREATE = "record.create"
    RECORD_READ = "record.read"
    RECORD_READ_CONTENT = "record.read_content"
    RECORD_UPDATE = "record.update"
    RECORD_DELETE = "record.delete"
    RECORD_QUERY = "record.query"
    AUDIT_READ = "audit.read"
    PRINCIPAL_ADMIN = "principal.admin"


ACTION_SCOPES: dict[Action, str] = {
    Action.BLOB_CREATE: "blobs:write",
    Action.BLOB_READ_META: "blobs:read",
    Action.BLOB_READ_CONTENT: "blobs:read",
    Action.BLOB_LIST: "blobs:read",
    Action.BLOB_DELETE: "blobs:delete",
    Action.BLOB_SHRED: "blobs:delete",
    Action.COLLECTION_CREATE: "collections:admin",
    Action.COLLECTION_READ: "records:read",
    Action.RECORD_CREATE: "records:write",
    Action.RECORD_READ: "records:read",
    Action.RECORD_READ_CONTENT: "records:read",
    Action.RECORD_UPDATE: "records:write",
    Action.RECORD_DELETE: "records:delete",
    Action.RECORD_QUERY: "records:read",
    Action.AUDIT_READ: "audit:read",
    Action.PRINCIPAL_ADMIN: "principals:admin",
}

CONTENT_ACTIONS = frozenset({Action.BLOB_READ_CONTENT, Action.RECORD_READ_CONTENT})


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    conceal: bool = False  # deny as "not found" so the caller cannot probe for existence
    withheld: bool = False  # metadata visible, content not

    @property
    def label(self) -> str:
        return "allow" if self.allowed else "deny"


def _allow(reason: str) -> Decision:
    return Decision(True, reason)


def _deny(reason: str, *, conceal: bool = False, withheld: bool = False) -> Decision:
    return Decision(False, reason, conceal=conceal, withheld=withheld)


class PolicyEngine:
    def __init__(self, export_controlled_categories: Iterable[str]) -> None:
        self._export = frozenset(c.upper() for c in export_controlled_categories)

    def evaluate(self, principal: Principal, action: Action, marking: Marking | None = None) -> Decision:
        scope = ACTION_SCOPES[action]
        if not principal.has_scope(scope):
            return _deny(f"missing scope {scope}")
        if marking is None or not marking.controlled:
            return _allow(f"scope {scope}; uncontrolled")
        if not principal.cui_access:
            return _deny("principal is not authorized for CUI", conceal=True)
        missing = [c for c in marking.categories if not principal.covers_category(c)]
        if missing:
            return _deny(f"not authorized for CUI categories {missing}", conceal=True)
        for ldc in marking.dissemination:
            if ldc == "NOFORN" and not principal.us_person:
                return _deny("NOFORN requires a U.S. person", conceal=True)
            if ldc != "NOFORN" and not principal.covers_dissemination(ldc):
                return _deny(f"not authorized for dissemination control {ldc}", conceal=True)
        if marking.export_controlled(self._export) and not principal.us_person:
            return _deny("export-controlled (ITAR/EAR) data requires a U.S. person", conceal=True)
        if (
            action in CONTENT_ACTIONS
            and principal.kind is PrincipalKind.AGENT
            and not principal.llm_boundary_authorized
        ):
            return _deny(
                "CUI content withheld: this agent is not registered as running inside an authorized "
                "LLM boundary",
                withheld=True,
            )
        return _allow(f"scope {scope}; authorized for {marking.banner}")
