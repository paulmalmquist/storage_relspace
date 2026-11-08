// Package service implements Strongbox's storage operations. Every database statement runs inside
// store.DB.Run under the caller's scope (app, subject, actor), so PostgreSQL row-level security
// applies to everything the service does. The service's own checks (CUI policy, sharing rights,
// delegation) run first and give precise errors; RLS is the independent backstop.
package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// AppIDPattern is the app identifier in URLs; the deployment's environment completes the scope.
var AppIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)

// Ctx is one caller's request.
type Ctx struct {
	Principal *auth.Principal
	RequestID string
	// App is the requested scope "<app_id>:<env>". Naming an app selects it; it grants nothing.
	App string
	// OpID is the client's operation ID (Idempotency-Key) for a mutation, or "".
	OpID string
}

// Actor is the authenticated caller: the agent or service when delegated, else the subject.
func (c Ctx) Actor() string {
	if c.Principal.Actor != "" {
		return c.Principal.Actor
	}
	return c.Principal.Subject
}

func (c Ctx) scope() store.Scope {
	return store.Scope{App: c.App, Subject: c.Principal.Subject, Actor: c.Actor(), Mode: store.ModeApp}
}

// App roles, lowest first.
var roleRank = map[string]int{"viewer": 1, "member": 2, "editor": 3, "admin": 4}

// Access is what the database says about the caller in the selected app, read at the start of
// every transaction (so revocations apply to the next transaction, with no cache).
type Access struct {
	App, Subject, Actor string
	Role                string            // viewer | member | editor | admin
	Teams               map[string]string // team id -> viewer | editor | admin
}

// AtLeast reports whether the caller's app role is at least role.
func (a *Access) AtLeast(role string) bool { return roleRank[a.Role] >= roleRank[role] }

// Core holds what every service needs: the scoped database, policy and audit.
type Core struct {
	DB         *store.DB
	Policy     *auth.Policy
	Audit      *audit.Log
	Conceal    bool
	operations *receipts
}

// auditedError is a denial or failure whose audit event must be written after the request
// transaction has rolled back.
type auditedError struct {
	entry audit.Entry
	err   error
}

func (e *auditedError) Error() string { return e.err.Error() }
func (e *auditedError) Unwrap() error { return e.err }

// inApp runs fn in one app transaction after admission. A caller who is not admitted (not a
// member, a delegating actor that is not a registered client, a suspended or unknown app) gets
// not_found, so app names cannot be probed.
func (k *Core) inApp(ctx context.Context, c Ctx, fn func(tx pgx.Tx, a *Access) error) error {
	if !store.ValidApp(c.App) {
		return errs.NotFound("app not found")
	}
	err := k.DB.Run(ctx, c.scope(), func(tx pgx.Tx) error {
		a, err := loadAccess(ctx, tx, c.App, c.Principal.Subject)
		if err != nil {
			return err
		}
		if a == nil {
			return &auditedError{entry: audit.Entry{App: c.App, Principal: c.Principal, RequestID: c.RequestID,
				Action: string(auth.AppRead), ResourceType: "app", ResourceID: c.App, Decision: "deny",
				Reason: "not admitted: not a member, unregistered delegating client, or app inactive"},
				err: errs.NotFound("app not found")}
		}
		a.Actor = c.Actor()
		return fn(tx, a)
	})
	return k.settle(ctx, err)
}

// inGlobal runs fn in a global-mode transaction (principals, global audit chain).
func (k *Core) inGlobal(ctx context.Context, c Ctx, fn func(tx pgx.Tx) error) error {
	err := k.DB.Run(ctx, store.Scope{Subject: c.Principal.Subject, Actor: c.Actor(), Mode: store.ModeGlobal}, fn)
	return k.settle(ctx, err)
}

// loadAccess returns nil when the scope's subject is not admitted to the app.
func loadAccess(ctx context.Context, tx pgx.Tx, app, subject string) (*Access, error) {
	var admitted bool
	var role *string
	var teams map[string]string
	err := tx.QueryRow(ctx, `SELECT sb_ctx_admitted(),
		(SELECT role FROM app_members WHERE app = $1 AND subject = $2),
		coalesce((SELECT jsonb_object_agg(team_id, role) FROM team_members WHERE app = $1 AND subject = $2), '{}')`,
		app, subject).Scan(&admitted, &role, &teams)
	if err != nil || !admitted || role == nil {
		return nil, err
	}
	return &Access{App: app, Subject: subject, Role: *role, Teams: teams}, nil
}

// settle records deferred audit events and maps database errors to API errors.
func (k *Core) settle(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrCommitUnknown) {
		return errs.Unavailable("transaction outcome unknown; resolve the operation before retrying").Wrap(err)
	}
	var ae *auditedError
	if errors.As(err, &ae) {
		if aerr := k.Audit.Standalone(ctx, ae.entry); aerr != nil {
			// Fail closed: the request is denied either way, but say the audit sink failed.
			return errs.Unavailable("audit log unavailable")
		}
		err = ae.err
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "42501":
			return errs.Forbidden("not permitted")
		case "23505":
			return errs.Conflict("conflicts with an existing resource")
		case "23503":
			return errs.Invalid("refers to something that does not exist in this app")
		case "23514":
			return errs.Invalid("violates a storage rule")
		case "57014":
			return errs.Unavailable("statement timed out")
		case "53400": // raised by the quota triggers; Detail names the limit
			return errs.QuotaExceeded("app quota %s reached", pg.Detail)
		case "40001", "40P01":
			return errs.Unavailable("concurrent update; retry")
		}
	}
	return err
}

// ---- policy and audit ----------------------------------------------------------------------------

type checkOpts struct {
	skipAllow   bool           // audit only denials (list filtering, internal re-checks)
	noConceal   bool           // report a denial as forbidden even if the policy would conceal it
	needContent bool           // a withheld decision is a denial (content reads)
	details     map[string]any // added to the audit event
}

func bannerOf(m *markings.Marking) string {
	if m == nil {
		return ""
	}
	return m.Banner()
}

func (k *Core) entry(c Ctx, action auth.Action, resType, resID string, m *markings.Marking, decision, reason string, details map[string]any) audit.Entry {
	return audit.Entry{App: c.App, Principal: c.Principal, RequestID: c.RequestID, Action: string(action),
		ResourceType: resType, ResourceID: resID, Marking: bannerOf(m), Decision: decision, Reason: reason, Details: details}
}

// check evaluates the CUI policy. Allows are audited in tx (committing with the operation);
// denials come back as an auditedError, recorded after the rollback.
func (k *Core) check(ctx context.Context, tx pgx.Tx, c Ctx, action auth.Action, resType, resID string, m *markings.Marking, o checkOpts) (auth.Decision, error) {
	d := k.Policy.Evaluate(c.Principal, action, m)
	if !d.Allowed && !d.Withheld || d.Withheld && o.needContent {
		var err error
		switch {
		case d.Withheld:
			err = errs.ContentWithheld("%s", d.Reason)
		case d.Conceal && k.Conceal && !o.noConceal:
			err = errs.NotFound("%s not found", resType)
		default:
			err = errs.Forbidden("%s", d.Reason)
		}
		return d, &auditedError{entry: k.entry(c, action, resType, resID, m, "deny", d.Reason, o.details), err: err}
	}
	if !o.skipAllow {
		if _, err := k.Audit.Append(ctx, tx, k.entry(c, action, resType, resID, m, "allow", d.Reason, o.details)); err != nil {
			return d, err
		}
	}
	return d, nil
}

// deny builds a denial for a sharing or role rule (not a CUI rule).
func (k *Core) deny(c Ctx, action auth.Action, resType, resID string, m *markings.Marking, reason string, err error) error {
	return &auditedError{entry: k.entry(c, action, resType, resID, m, "deny", reason, nil), err: err}
}

// note records a non-decision event (a completed store, an integrity failure) in tx.
func (k *Core) note(ctx context.Context, tx pgx.Tx, c Ctx, action auth.Action, resType, resID, decision, reason string, m *markings.Marking, details map[string]any) error {
	_, err := k.Audit.Append(ctx, tx, k.entry(c, action, resType, resID, m, decision, reason, details))
	return err
}

// noteAfter records an event in its own transaction (integrity failures found while streaming).
func (k *Core) noteAfter(ctx context.Context, c Ctx, action auth.Action, resType, resID, decision, reason string, m *markings.Marking) {
	_ = k.Audit.Standalone(ctx, k.entry(c, action, resType, resID, m, decision, reason, nil))
}

// ---- paging --------------------------------------------------------------------------------------

const MaxPage = 200

func ClampLimit(limit, def int) (int, error) {
	if limit == 0 {
		return def, nil
	}
	if limit < 0 {
		return 0, errs.Invalid("limit must be >= 1")
	}
	return min(limit, MaxPage), nil
}

type cursor struct {
	A string    `json:"a"` // app
	K string    `json:"k"` // listing
	T time.Time `json:"t"`
	I string    `json:"i"`
}

// EncodeCursor makes an opaque keyset cursor over (created_at, id), bound to one app and listing.
func EncodeCursor(app, listing string, t time.Time, id string) string {
	raw, _ := json.Marshal(cursor{A: app, K: listing, T: t.UTC(), I: id})
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeCursor rejects a cursor minted for a different app or listing.
func DecodeCursor(s, app, listing string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	var c cursor
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err != nil || c.I == "" || c.A != app || c.K != listing {
		return time.Time{}, "", errs.Invalid("invalid cursor")
	}
	return c.T, c.I, nil
}

// decodeJSON decodes with UseNumber so integers survive round trips exactly.
func decodeJSON(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
