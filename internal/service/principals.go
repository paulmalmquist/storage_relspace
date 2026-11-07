package service

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

// Principals administers the global principal registry (principals:admin). Changes commit with
// their audit event on the global chain.
type Principals struct {
	*Core
	Registry *auth.Registry
}

func (p *Principals) List(ctx context.Context, c Ctx) ([]map[string]any, error) {
	var out []map[string]any
	err := p.inGlobal(ctx, c, func(tx pgx.Tx) error {
		if _, err := p.check(ctx, tx, c, auth.PrincipalAdmin, "principal", "", nil, checkOpts{noConceal: true}); err != nil {
			return err
		}
		var err error
		out, err = p.Registry.List(ctx)
		return err
	})
	if out == nil {
		out = []map[string]any{}
	}
	return out, err
}

func (p *Principals) Put(ctx context.Context, c Ctx, spec auth.Spec) error {
	return p.inGlobal(ctx, c, func(tx pgx.Tx) error {
		if _, err := p.check(ctx, tx, c, auth.PrincipalAdmin, "principal", spec.Subject, nil, checkOpts{noConceal: true,
			details: map[string]any{"cui_categories": spec.CUICategories, "us_person": spec.USPerson, "scopes": spec.Scopes}}); err != nil {
			return err
		}
		if spec.Subject == c.Principal.Subject || spec.Subject == c.Principal.Actor {
			return errs.Forbidden("administrators cannot modify their own principal (separation of duties)")
		}
		if err := spec.Validate(); err != nil {
			return errs.Invalid("%v", err)
		}
		return p.Registry.PutWith(ctx, tx, spec)
	})
}
