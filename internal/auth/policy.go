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
	RecordHistory     Action = "record.history"
	RecordRestore     Action = "record.restore"
	RecordShare       Action = "record.share"
	BlobShare         Action = "blob.share"
	AppRead           Action = "app.read"
	AppManage         Action = "app.manage"
	TeamManage        Action = "team.manage"
	AuditRead         Action = "audit.read"
	PrincipalAdmin    Action = "principal.admin"
)

var actionScopes = map[Action]string{
	BlobCreate: "blobs:write", BlobReadMeta: "blobs:read", BlobReadContent: "blobs:read", BlobList: "blobs:read",
	BlobDelete: "blobs:delete", BlobShred: "blobs:delete", CollectionCreate: "collections:admin",
	CollectionRead: "records:read", RecordCreate: "records:write", RecordRead: "records:read",
	RecordReadContent: "records:read", RecordUpdate: "records:write", RecordDelete: "records:delete",
	RecordQuery: "records:read", RecordHistory: "records:read", RecordRestore: "records:write",
	RecordShare: "records:write", BlobShare: "blobs:write", AppRead: "", AppManage: "apps:manage", TeamManage: "",
	AuditRead: "audit:read", PrincipalAdmin: "principals:admin",
}

// Reason codes: stable, machine-readable, and safe to show to an app admin (they name rules, not
// resources).
const (
	CodeAuthorized    = "authorized"
	CodeUncontrolled  = "uncontrolled"
	CodeUnknownAction = "unknown_action"
	CodeMissingScope  = "missing_scope"
	CodeCUIAccess     = "cui_access_required"
	CodeCUICategory   = "cui_category_not_authorized"
	CodeNOFORN        = "noforn_requires_us_person"
	CodeDissemination = "dissemination_not_authorized"
	CodeExportControl = "export_controlled_requires_us_person"
	CodeLLMBoundary   = "llm_boundary_not_authorized"
)

type Decision struct {
	Allowed  bool
	Code     string
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
		return Decision{Code: CodeUnknownAction, Reason: "unknown action " + string(action)}
	}
	if scope != "" && !pr.HasScope(scope) {
		return Decision{Code: CodeMissingScope, Reason: "missing scope " + scope}
	}
	if m == nil || !m.Controlled {
		return Decision{Allowed: true, Code: CodeUncontrolled, Reason: "scope " + scope + "; uncontrolled"}
	}
	if !pr.CUIAccess {
		return Decision{Code: CodeCUIAccess, Reason: "principal is not authorized for CUI", Conceal: true}
	}
	var missing []string
	for _, c := range m.Categories {
		if !pr.CUICategories.Has(c) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return Decision{Code: CodeCUICategory, Reason: fmt.Sprintf("not authorized for CUI categories %v", missing), Conceal: true}
	}
	for _, ldc := range m.Dissemination {
		if ldc == "NOFORN" && !pr.USPerson {
			return Decision{Code: CodeNOFORN, Reason: "NOFORN requires a U.S. person", Conceal: true}
		}
		if ldc != "NOFORN" && !pr.Dissemination.Has(ldc) {
			return Decision{Code: CodeDissemination, Reason: "not authorized for dissemination control " + ldc, Conceal: true}
		}
	}
	if m.ExportControlled(p.export) && !pr.USPerson {
		return Decision{Code: CodeExportControl, Reason: "export-controlled (ITAR/EAR) data requires a U.S. person", Conceal: true}
	}
	if (action == BlobReadContent || action == RecordReadContent) && pr.Kind == KindAgent && !pr.LLMBoundaryAuthorized {
		return Decision{
			Code:     CodeLLMBoundary,
			Reason:   "CUI content withheld: this agent is not registered as running inside an authorized LLM boundary",
			Withheld: true,
		}
	}
	return Decision{Allowed: true, Code: CodeAuthorized, Reason: "scope " + scope + "; authorized for " + m.Banner()}
}
