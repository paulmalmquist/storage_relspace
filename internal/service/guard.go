package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
)

// Ctx is who is asking, plus the request id that ties audit events to logs and traces.
type Ctx struct {
	Principal *auth.Principal
	RequestID string
}

// Guard pairs every policy decision with an audit event.
type Guard struct {
	Policy  *auth.Policy
	Audit   *audit.Log
	conceal bool
}

func NewGuard(p *auth.Policy, a *audit.Log, concealDenied bool) *Guard {
	return &Guard{Policy: p, Audit: a, conceal: concealDenied}
}

type CheckOpts struct {
	Details        map[string]any
	SkipAllowAudit bool // the caller records the allow later (e.g. after a write completes)
	NoConceal      bool // denials on creates name the reason instead of claiming "not found"
}

func bannerPtr(m *markings.Marking) string {
	if m == nil {
		return ""
	}
	return m.Banner()
}

// Check evaluates and audits. It returns an error for denials, except content withholding, which is
// returned as a Decision with Withheld set so callers can still serve metadata.
func (g *Guard) Check(ctx context.Context, c Ctx, action auth.Action, resType, resID string, m *markings.Marking, o CheckOpts) (auth.Decision, error) {
	d := g.Policy.Evaluate(c.Principal, action, m)
	if d.Allowed && o.SkipAllowAudit {
		return d, nil
	}
	if _, err := g.Audit.Record(ctx, audit.Entry{
		Principal: c.Principal, Action: string(action), ResourceType: resType, ResourceID: resID,
		Marking: bannerPtr(m), Decision: d.Label(), Reason: d.Reason, RequestID: c.RequestID, Details: o.Details,
	}); err != nil {
		return d, err
	}
	if d.Allowed || d.Withheld {
		return d, nil
	}
	if d.Conceal && !o.NoConceal && g.conceal {
		return d, errs.NotFound("%s not found", resType)
	}
	return d, errs.Forbidden("%s", d.Reason)
}

// Peek evaluates without auditing (used to filter list results; the list itself is audited).
func (g *Guard) Peek(c Ctx, action auth.Action, m *markings.Marking) auth.Decision {
	return g.Policy.Evaluate(c.Principal, action, m)
}

// Note records an event that is not a policy decision (completed writes, integrity failures).
func (g *Guard) Note(ctx context.Context, c Ctx, action auth.Action, resType, resID, decision, reason string, m *markings.Marking, details map[string]any) error {
	_, err := g.Audit.Record(ctx, audit.Entry{
		Principal: c.Principal, Action: string(action), ResourceType: resType, ResourceID: resID,
		Marking: bannerPtr(m), Decision: decision, Reason: reason, RequestID: c.RequestID, Details: details,
	})
	return err
}

// ---- pagination ---------------------------------------------------------------------------------

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
	T time.Time `json:"t"`
	I string    `json:"i"`
}

// EncodeCursor makes an opaque keyset cursor over (created_at, id), newest first.
func EncodeCursor(t time.Time, id string) string {
	raw, _ := json.Marshal(cursor{T: t.UTC(), I: id})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func DecodeCursor(s string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	var c cursor
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err != nil || c.I == "" {
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
