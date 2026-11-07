package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Database roles. strongbox_owner owns every object and is the privileged maintenance path; the
// login that runs migrations is a member. strongbox_runtime holds the service's grants; the login
// the API server uses is a member of it and of nothing else that matters.
const (
	OwnerRole   = "strongbox_owner"
	RuntimeRole = "strongbox_runtime"
)

// BootstrapOptions configure `strongbox db bootstrap`.
type BootstrapOptions struct {
	Schema        string   // created if missing, owned by strongbox_owner
	RuntimeLogins []string // existing login roles to make members of strongbox_runtime
}

// Bootstrap creates the two group roles and the schema, makes the current login a member of the
// owner role and the given logins members of the runtime role. It needs CREATEROLE (Cloud SQL's
// cloudsqlsuperuser has it). It is idempotent and safe to run concurrently.
func Bootstrap(ctx context.Context, pool *pgxpool.Pool, o BootstrapOptions) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('strongbox.bootstrap'))`); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('strongbox.bootstrap'))`) //nolint:errcheck

	owner, runtime := pgx.Identifier{OwnerRole}.Sanitize(), pgx.Identifier{RuntimeRole}.Sanitize()
	for _, role := range []string{OwnerRole, RuntimeRole} {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if _, err := conn.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"); err != nil {
				return fmt.Errorf("create role %s: %w", role, err)
			}
		}
	}
	var me string
	if err := conn.QueryRow(ctx, `SELECT current_user`).Scan(&me); err != nil {
		return err
	}
	stmts := []string{"GRANT " + owner + " TO " + pgx.Identifier{me}.Sanitize()}
	schema := pgx.Identifier{o.Schema}.Sanitize()
	stmts = append(stmts,
		"CREATE SCHEMA IF NOT EXISTS "+schema+" AUTHORIZATION "+owner,
		// An existing schema (public, or one created earlier) must let the owner role create objects.
		"GRANT USAGE, CREATE ON SCHEMA "+schema+" TO "+owner,
		"GRANT USAGE ON SCHEMA "+schema+" TO "+runtime,
	)
	for _, login := range o.RuntimeLogins {
		if login == me {
			return fmt.Errorf("runtime login %q must differ from the bootstrapping login", login)
		}
		stmts = append(stmts, "GRANT "+runtime+" TO "+pgx.Identifier{login}.Sanitize())
	}
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}

// RoleReport describes the login a runtime pool connects as.
type RoleReport struct {
	User     string   `json:"user"`
	Problems []string `json:"problems"`
}

// OK reports whether the login is a restricted runtime login.
func (r RoleReport) OK() bool { return len(r.Problems) == 0 }

// CheckRuntime verifies that the pool's login can do nothing beyond strongbox_runtime: not a
// superuser, no BYPASSRLS, no role administration, not a member (or SET-capable) of the owner role
// or any privileged role, owns nothing in the schema, cannot create in the schema or database, and
// holds strongbox_runtime.
func CheckRuntime(ctx context.Context, pool *pgxpool.Pool) (RoleReport, error) {
	var r RoleReport
	var super, bypass, createRole, createDB, replication, runtimeMember, runtimeAdmin, ownerMember, escalates, schemaCreate, dbCreate bool
	var owned int
	err := pool.QueryRow(ctx, `
		SELECT current_user, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
		       EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1) AND pg_has_role(current_user, $1, 'USAGE'),
		       EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1) AND pg_has_role(current_user, $1, 'USAGE WITH ADMIN OPTION'),
		       EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $2) AND pg_has_role(current_user, $2, 'MEMBER'),
		       EXISTS (SELECT 1 FROM pg_roles p WHERE p.rolname <> current_user
		               AND (p.rolsuper OR p.rolbypassrls OR p.rolcreaterole OR p.rolname = $2)
		               AND pg_has_role(current_user, p.oid, 'MEMBER')),
		       (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		         WHERE n.nspname = current_schema() AND c.relowner = r.oid),
		       has_schema_privilege(current_user, current_schema(), 'CREATE'),
		       has_database_privilege(current_user, current_database(), 'CREATE')
		FROM pg_roles r WHERE r.rolname = current_user`, RuntimeRole, OwnerRole).
		Scan(&r.User, &super, &bypass, &createRole, &createDB, &replication, &runtimeMember, &runtimeAdmin,
			&ownerMember, &escalates, &owned, &schemaCreate, &dbCreate)
	if err != nil {
		return r, err
	}
	add := func(cond bool, msg string) {
		if cond {
			r.Problems = append(r.Problems, msg)
		}
	}
	add(super, "login is a superuser")
	add(bypass, "login has BYPASSRLS")
	add(createRole, "login has CREATEROLE")
	add(createDB, "login has CREATEDB")
	add(replication, "login has REPLICATION")
	add(!runtimeMember, "login is not a member of "+RuntimeRole)
	add(runtimeAdmin, "login can administer "+RuntimeRole)
	add(ownerMember, "login is a member of "+OwnerRole)
	add(escalates, "login is a member of a privileged role")
	add(owned > 0, fmt.Sprintf("login owns %d objects in the schema", owned))
	add(schemaCreate, "login can create objects in the schema")
	add(dbCreate, "login can create schemas in the database")
	return r, nil
}

// String renders the report for logs.
func (r RoleReport) String() string {
	if r.OK() {
		return r.User + ": restricted runtime login"
	}
	return r.User + ": " + strings.Join(r.Problems, "; ")
}
