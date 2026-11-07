// Package store holds the Postgres connection, schema migrations, database roles, the scoped
// transaction abstraction and the object-store backends.
package store

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Options configure a connection pool.
type Options struct {
	Schema           string        // search_path; every connection is pinned to it
	MaxConns         int32         // 0: pgxpool default
	StatementTimeout time.Duration // 0: none
	AppName          string
}

// Open connects to Postgres.
func Open(ctx context.Context, url string, o Options) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if o.Schema != "" {
		cfg.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{o.Schema}.Sanitize()
	}
	if o.StatementTimeout > 0 {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(o.StatementTimeout.Milliseconds(), 10)
		// A transaction left open (a crashed request, a stuck stream) is cut off instead of holding locks.
		cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = strconv.FormatInt(4*o.StatementTimeout.Milliseconds(), 10)
	}
	if o.AppName != "" {
		cfg.ConnConfig.RuntimeParams["application_name"] = o.AppName
	}
	if o.MaxConns > 0 {
		cfg.MaxConns = o.MaxConns
	}
	cfg.MaxConnLifetime = 30 * time.Minute
	return pgxpool.NewWithConfig(ctx, cfg)
}

// ErrLegacyPythonSchema reports a database created by the retired Python implementation.
var ErrLegacyPythonSchema = errors.New("database was initialized by the retired Python implementation (schema_info table); " +
	"it is not migrated automatically - see docs/STORED_FORMATS.md")

// Migrate applies embedded migrations in order, once, under an advisory lock (safe with many
// replicas). It must run as the privileged migration login: a member of strongbox_owner.
// Migrations never run implicitly at service start.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('strongbox.migrate'))`); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('strongbox.migrate'))`) //nolint:errcheck

	// A database initialized by the retired Python implementation has schema_info and no
	// schema_migrations. Its tables and blob contexts differ, so refuse instead of failing midway.
	var pythonEra bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('schema_info') IS NOT NULL AND to_regclass('schema_migrations') IS NULL`).
		Scan(&pythonEra); err != nil {
		return err
	}
	if pythonEra {
		return ErrLegacyPythonSchema
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad version prefix", base)
		}
		var applied bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		if version >= 2 {
			if err := checkMigrator(ctx, conn.Conn()); err != nil {
				return err
			}
		}
		sql, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", base, err)
			}
			if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// MigrationVersion reports the highest applied migration and the highest embedded one.
func MigrationVersion(ctx context.Context, pool *pgxpool.Pool) (applied, embedded int, err error) {
	names, _ := fs.Glob(migrations, "migrations/*.sql")
	for _, n := range names {
		v, _ := strconv.Atoi(strings.SplitN(strings.TrimPrefix(n, "migrations/"), "_", 2)[0])
		embedded = max(embedded, v)
	}
	err = pool.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&applied)
	return applied, embedded, err
}

func checkMigrator(ctx context.Context, conn *pgx.Conn) error {
	var exists, member bool
	err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1),
		EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1) AND pg_has_role(current_user, $1, 'MEMBER')`, OwnerRole).Scan(&exists, &member)
	if err != nil {
		return err
	}
	if !exists || !member {
		return fmt.Errorf("migrations need role %s and the migrating login must be a member of it; run `strongbox db bootstrap` with a login that has CREATEROLE", OwnerRole)
	}
	var runtime bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, RuntimeRole).Scan(&runtime); err != nil {
		return err
	}
	if !runtime {
		return fmt.Errorf("role %s does not exist; run `strongbox db bootstrap`", RuntimeRole)
	}
	return nil
}

// NewID returns a prefixed 128-bit random identifier, e.g. blb_3f2a...
func NewID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
