package auth

import (
	"fmt"

	"github.com/paulmalmquist/storage_relspace/internal/markings"
)

// Policy is attribute-based access control for CUI. Deny by default; every rule returns a reason
// for the audit log. Rules, in order:
//
//  1. The principal must hold the scope for the action.
//  2. Uncontrolled data: scope is sufficient.
//  3. CUI requires CUI access (training plus lawful government purpose).
//  4. Every category on the object must be authorized.
//  5. Every limited dissemination control must be authorized; NOFORN also requires a U.S. person.
//  6. Export-controlled categories (ITAR/EAR, e.g. SP-EXPT) require a U.S. person.
//  7. Content reads by agents are withheld unless the agent is registered as running inside an
//     authorized LLM boundary. Agents can still see that the object exists and how it is marked.

type Action string

const (
	BlobCreate        Action = "blob.create"
	BlobReadMeta      Action = "blob.read_meta"
	BlobReadContent   Action = "blob.read_content"
	BlobList          Action = "blob.list"
	BlobDelete        Action = "blob.delete"
	BlobShred         Action = "blob.shred"
	CollectionCreate  Action = "collection.create"
	CollectionRead    Action = "collection.read"
	RecordCreate      Action = "record.create"
	RecordRead        Action = "record.read"
	RecordReadContent Action = "record.read_content"
	RecordUpdate      Action = "record.update"
	RecordDelete      Action = "record.delete"
	RecordQuery       Action = "record.query"
	AuditRead         Action = "audit.read"
	PrincipalAdmin    Action = "principal.admin"
)

var actionScopes = map[Action]string{
	BlobCreate: "blobs:write", BlobReadMeta: "blobs:read", BlobReadContent: "blobs:read", BlobList: "blobs:read",
	BlobDelete: "blobs:delete", BlobShred: "blobs:delete", CollectionCreate: "collections:admin",
	CollectionRead: "records:read", RecordCreate: "records:write", RecordRead: "records:read",
	RecordReadContent: "records:read", RecordUpdate: "records:write", RecordDelete: "records:delete",
	RecordQuery: "records:read", AuditRead: "audit:read", PrincipalAdmin: "principals:admin",
}

type Decision struct {
	Allowed  bool
	Reason   string
	Conceal  bool // deny as "not found" so the caller cannot probe for existence
	Withheld bool // metadata visible, content not
}

func (d Decision) Label() string {
	if d.Allowed {
		return "allow"
	}
	return "deny"
}

type Policy struct{ export []string }

func NewPolicy(exportControlled []string) *Policy { return &Policy{export: exportControlled} }

// Evaluate decides one action. A nil marking means the action is not tied to marked data.
func (p *Policy) Evaluate(pr *Principal, action Action, m *markings.Marking) Decision {
	scope, ok := actionScopes[action]
	if !ok {
		return Decision{Reason: "unknown action " + string(action)}
	}
	if !pr.HasScope(scope) {
		return Decision{Reason: "missing scope " + scope}
	}
	if m == nil || !m.Controlled {
		return Decision{Allowed: true, Reason: "scope " + scope + "; uncontrolled"}
	}
	if !pr.CUIAccess {
		return Decision{Reason: "principal is not authorized for CUI", Conceal: true}
	}
	var missing []string
	for _, c := range m.Categories {
		if !pr.CUICategories.Has(c) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return Decision{Reason: fmt.Sprintf("not authorized for CUI categories %v", missing), Conceal: true}
	}
	for _, ldc := range m.Dissemination {
		if ldc == "NOFORN" && !pr.USPerson {
			return Decision{Reason: "NOFORN requires a U.S. person", Conceal: true}
		}
		if ldc != "NOFORN" && !pr.Dissemination.Has(ldc) {
			return Decision{Reason: "not authorized for dissemination control " + ldc, Conceal: true}
		}
	}
	if m.ExportControlled(p.export) && !pr.USPerson {
		return Decision{Reason: "export-controlled (ITAR/EAR) data requires a U.S. person", Conceal: true}
	}
	if (action == BlobReadContent || action == RecordReadContent) && pr.Kind == KindAgent && !pr.LLMBoundaryAuthorized {
		return Decision{
			Reason:   "CUI content withheld: this agent is not registered as running inside an authorized LLM boundary",
			Withheld: true,
		}
	}
	return Decision{Allowed: true, Reason: "scope " + scope + "; authorized for " + m.Banner()}
}
