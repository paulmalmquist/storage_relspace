// Package auth covers who is calling (tokens), what they are cleared for (the principal registry),
// and what CUI they may touch (the policy engine).
//
// Tokens only prove identity. Everything that drives CUI decisions - U.S.-person status, CUI access,
// category and dissemination authorizations, and whether an agent's model runs inside an authorized
// boundary - comes from the admin-managed registry, never from claims a caller can mint.
package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const All = "*"

var Scopes = map[string]bool{
	"blobs:read": true, "blobs:write": true, "blobs:delete": true,
	"records:read": true, "records:write": true, "records:delete": true,
	"collections:admin": true, "audit:read": true, "principals:admin": true,
	"apps:manage": true, // manage app membership (also requires the app's admin role)
	"delegate":    true, // may act on behalf of another principal (X-On-Behalf-Of)
}

// neverDelegated are scopes an intersection never carries, even when both sides hold "*".
var neverDelegated = []string{"delegate", "principals:admin"}

// concrete expands "*" to the named scopes so set algebra cannot resurrect a removed scope.
func concrete(s Set) Set {
	if !s[All] {
		return copySet(s)
	}
	out := Set{}
	for k := range Scopes {
		out[k] = true
	}
	return out
}

type Kind string

const (
	KindUser    Kind = "user"
	KindService Kind = "service"
	KindAgent   Kind = "agent"
)

// Set is a small string set.
type Set map[string]bool

func NewSet(items ...string) Set {
	s := Set{}
	for _, i := range items {
		s[i] = true
	}
	return s
}

func (s Set) Has(x string) bool { return s[All] || s[x] }

func (s Set) Sorted() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func intersect(a, b Set) Set {
	if a[All] {
		return copySet(b)
	}
	if b[All] {
		return copySet(a)
	}
	out := Set{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

func copySet(s Set) Set {
	out := Set{}
	for k := range s {
		out[k] = true
	}
	return out
}

type Principal struct {
	Subject               string
	Kind                  Kind
	Scopes                Set
	USPerson              bool
	CUIAccess             bool
	CUICategories         Set
	Dissemination         Set
	LLMBoundaryAuthorized bool
	DisplayName           string
	Actor                 string // set when an agent or service acts on behalf of Subject
}

func (p *Principal) HasScope(s string) bool { return p.Scopes.Has(s) }

// DelegatedTo returns the effective identity when actor works on behalf of p: the intersection of both.
// An agent can never do more than the person it acts for, nor more than the agent itself is cleared for.
// U.S.-person status requires both, so a non-U.S. person cannot borrow an agent's clearance.
func (p *Principal) DelegatedTo(actor *Principal) *Principal {
	scopes := intersect(concrete(p.Scopes), concrete(actor.Scopes))
	for _, s := range neverDelegated {
		delete(scopes, s)
	}
	kind := p.Kind
	if actor.Kind == KindAgent {
		kind = KindAgent
	}
	return &Principal{
		Subject:               p.Subject,
		Kind:                  kind,
		Scopes:                scopes,
		USPerson:              p.USPerson && actor.USPerson,
		CUIAccess:             p.CUIAccess && actor.CUIAccess,
		CUICategories:         intersect(p.CUICategories, actor.CUICategories),
		Dissemination:         intersect(p.Dissemination, actor.Dissemination),
		LLMBoundaryAuthorized: actor.LLMBoundaryAuthorized,
		DisplayName:           p.DisplayName,
		Actor:                 actor.Subject,
	}
}

func (p *Principal) Public() map[string]any {
	var actor, name any
	if p.Actor != "" {
		actor = p.Actor
	}
	if p.DisplayName != "" {
		name = p.DisplayName
	}
	return map[string]any{
		"subject": p.Subject, "kind": string(p.Kind), "actor": actor, "display_name": name,
		"scopes": p.Scopes.Sorted(), "us_person": p.USPerson, "cui_access": p.CUIAccess,
		"cui_categories": p.CUICategories.Sorted(), "dissemination": p.Dissemination.Sorted(),
		"llm_boundary_authorized": p.LLMBoundaryAuthorized,
	}
}

// Spec is what an administrator sets for a principal.
type Spec struct {
	Subject               string   `json:"-"`
	Kind                  Kind     `json:"kind"`
	DisplayName           string   `json:"display_name,omitempty"`
	Scopes                []string `json:"scopes"`
	USPerson              bool     `json:"us_person"`
	CUIAccess             bool     `json:"cui_access"`
	CUICategories         []string `json:"cui_categories"`
	Dissemination         []string `json:"dissemination"`
	LLMBoundaryAuthorized bool     `json:"llm_boundary_authorized"`
	Disabled              bool     `json:"disabled"`
}

func (s *Spec) Validate() error {
	if s.Subject == "" || len(s.Subject) > 255 {
		return errors.New("subject must be 1-255 characters")
	}
	if s.Kind != KindUser && s.Kind != KindService && s.Kind != KindAgent {
		return errors.New("kind must be user, service or agent")
	}
	var unknown []string
	for _, sc := range s.Scopes {
		if sc != All && !Scopes[sc] {
			unknown = append(unknown, sc)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown scopes: %v", unknown)
	}
	if s.LLMBoundaryAuthorized && s.Kind != KindAgent {
		return errors.New("llm_boundary_authorized applies only to agent principals")
	}
	return nil
}

func upperSorted(items []string) []string {
	set := Set{}
	for _, i := range items {
		if i = strings.ToUpper(strings.TrimSpace(i)); i != "" {
			set[i] = true
		}
	}
	return set.Sorted()
}

func dedupSorted(items []string) []string { return NewSet(items...).Sorted() }

// Registry stores principals in Postgres.
type Registry struct{ db *pgxpool.Pool }

func NewRegistry(db *pgxpool.Pool) *Registry { return &Registry{db: db} }

// Get returns nil for unknown or disabled principals.
func (r *Registry) Get(ctx context.Context, subject string) (*Principal, error) {
	var (
		kind, name             string
		scopes, cats, ldcs     []string
		us, cui, llm, disabled bool
	)
	err := r.db.QueryRow(ctx, `SELECT kind, coalesce(display_name, ''), scopes, us_person, cui_access,
		cui_categories, dissemination, llm_boundary_authorized, disabled FROM principals WHERE subject = $1`, subject).
		Scan(&kind, &name, &scopes, &us, &cui, &cats, &ldcs, &llm, &disabled)
	if errors.Is(err, pgx.ErrNoRows) || disabled {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Principal{
		Subject: subject, Kind: Kind(kind), Scopes: NewSet(scopes...), USPerson: us, CUIAccess: cui,
		CUICategories: NewSet(upperSorted(cats)...), Dissemination: NewSet(upperSorted(ldcs)...),
		LLMBoundaryAuthorized: llm, DisplayName: name,
	}, nil
}

// Execer is a pool or a transaction.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (r *Registry) Put(ctx context.Context, s Spec) error { return r.PutWith(ctx, r.db, s) }

// PutWith writes through q, so callers can commit the change with its audit event.
func (r *Registry) PutWith(ctx context.Context, q Execer, s Spec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	var name any
	if s.DisplayName != "" {
		name = s.DisplayName
	}
	_, err := q.Exec(ctx, `INSERT INTO principals (subject, kind, display_name, scopes, us_person, cui_access,
		cui_categories, dissemination, llm_boundary_authorized, disabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now(), now())
		ON CONFLICT (subject) DO UPDATE SET kind=EXCLUDED.kind, display_name=EXCLUDED.display_name,
		scopes=EXCLUDED.scopes, us_person=EXCLUDED.us_person, cui_access=EXCLUDED.cui_access,
		cui_categories=EXCLUDED.cui_categories, dissemination=EXCLUDED.dissemination,
		llm_boundary_authorized=EXCLUDED.llm_boundary_authorized, disabled=EXCLUDED.disabled, updated_at=now()`,
		s.Subject, string(s.Kind), name, dedupSorted(s.Scopes), s.USPerson, s.CUIAccess,
		upperSorted(s.CUICategories), upperSorted(s.Dissemination), s.LLMBoundaryAuthorized, s.Disabled)
	return err
}

func (r *Registry) List(ctx context.Context) ([]map[string]any, error) {
	rows, err := r.db.Query(ctx, `SELECT subject, kind, coalesce(display_name, ''), scopes, us_person, cui_access,
		cui_categories, dissemination, llm_boundary_authorized, disabled, created_at, updated_at
		FROM principals ORDER BY subject`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var (
			subject, kind, name    string
			scopes, cats, ldcs     []string
			us, cui, llm, disabled bool
			created, updated       time.Time
		)
		if err := rows.Scan(&subject, &kind, &name, &scopes, &us, &cui, &cats, &ldcs, &llm, &disabled, &created, &updated); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"subject": subject, "kind": kind, "display_name": name, "scopes": scopes, "us_person": us,
			"cui_access": cui, "cui_categories": cats, "dissemination": ldcs, "llm_boundary_authorized": llm,
			"disabled": disabled, "created_at": created.UTC().Format(time.RFC3339Nano),
			"updated_at": updated.UTC().Format(time.RFC3339Nano),
		})
	}
	return out, rows.Err()
}
