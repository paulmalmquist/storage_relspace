package service

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Sharing rights. Read/write/share/manage are separate: an editor cannot share or delete, and a
// grantee with can_share can share without being able to edit. CUI policy (markings, LLM boundary,
// delegation) is evaluated separately and always applies; owning a record never overrides it.
type Perm uint8

const (
	PermRead   Perm = 1 << iota
	PermWrite       // edit content and marking
	PermShare       // grant viewer/editor access, change visibility
	PermManage      // delete, purge, grant can_share
)

func (p Perm) Has(q Perm) bool { return p&q == q }

func (p Perm) Names() []string {
	out := []string{}
	for _, x := range []struct {
		p Perm
		n string
	}{{PermRead, "read"}, {PermWrite, "write"}, {PermShare, "share"}, {PermManage, "manage"}} {
		if p.Has(x.p) {
			out = append(out, x.n)
		}
	}
	return out
}

// Resource is the sharing-relevant part of a record or blob row.
type Resource struct {
	Kind       string // record | blob
	ID         string
	Owner      string
	Visibility string // private | team | app
	TeamID     string
}

// Authorizer computes sharing rights. The SQL implementation mirrors the RLS policies in
// 0003_rls.sql exactly (TestAuthorizerMatchesRLS checks that); a relation-based backend such as
// OpenFGA or SpiceDB could implement the same interface. RLS stays mandatory either way.
type Authorizer interface {
	Permissions(ctx context.Context, tx pgx.Tx, a *Access, r Resource) (Perm, []string, error)
}

type SQLAuthorizer struct{}

// Permissions returns the rights and the reason codes that produced them. Reason codes name rules
// (owner, app_visibility, team_role:editor, grant:viewer), never other resources.
func (SQLAuthorizer) Permissions(ctx context.Context, tx pgx.Tx, a *Access, r Resource) (Perm, []string, error) {
	var p Perm
	var why []string
	if r.Owner == a.Subject {
		return PermRead | PermWrite | PermShare | PermManage, []string{"owner"}, nil
	}
	switch r.Visibility {
	case "app":
		p |= PermRead
		why = append(why, "app_visibility")
		if a.AtLeast("editor") {
			p |= PermWrite
			why = append(why, "app_role:"+a.Role)
		}
		if a.Role == "admin" {
			p |= PermShare | PermManage
		}
	case "team":
		if role, ok := a.Teams[r.TeamID]; ok {
			p |= PermRead
			why = append(why, "team_role:"+role)
			if role == "editor" || role == "admin" {
				p |= PermWrite
			}
			if role == "admin" {
				p |= PermShare | PermManage
			}
		}
	}
	teams := make([]string, 0, len(a.Teams))
	for t := range a.Teams {
		teams = append(teams, t)
	}
	col := "record_id"
	if r.Kind == "blob" {
		col = "blob_id"
	}
	rows, err := tx.Query(ctx, `SELECT role, can_share, subject IS NOT NULL FROM resource_grants
		WHERE app = $1 AND `+col+` = $2 AND (subject = $3 OR team_id = ANY($4))`, a.App, r.ID, a.Subject, teams)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var role string
		var share, direct bool
		if err := rows.Scan(&role, &share, &direct); err != nil {
			return 0, nil, err
		}
		via := "grant"
		if !direct {
			via = "team_grant"
		}
		p |= PermRead
		why = append(why, via+":"+role)
		if role == "editor" {
			p |= PermWrite
		}
		if share {
			p |= PermShare
			why = append(why, via+":can_share")
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	if p == 0 {
		why = append(why, "not_shared_with_subject")
	}
	return p, why, nil
}
