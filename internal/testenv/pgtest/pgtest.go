// Package pgtest gives integration tests an isolated, migrated schema and the restricted runtime login.
package pgtest

import (
	"context"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// RuntimeLogin is the restricted login integration tests connect as. It is a member of
// strongbox_runtime only, exactly like the production API server's login.
const (
	RuntimeLogin    = "strongbox_test_runtime"
	runtimePassword = "strongbox-test-runtime"
)

// DatabaseURL returns the integration database URL, skipping (locally) or failing (CI) without one.
func DatabaseURL(t testing.TB) string {
	t.Helper()
	u := os.Getenv("STRONGBOX_TEST_DATABASE_URL")
	if u == "" {
		if os.Getenv("STRONGBOX_REQUIRE_INTEGRATION") == "1" {
			t.Fatal("STRONGBOX_REQUIRE_INTEGRATION=1 but STRONGBOX_TEST_DATABASE_URL is not set")
		}
		t.Skip("set STRONGBOX_TEST_DATABASE_URL to run integration tests")
	}
	return u
}

// DB is a migrated, isolated schema with two pools: Migrator (the privileged login that owns the
// schema objects through strongbox_owner) and Runtime (the restricted login).
type DB struct {
	Schema     string
	URL        string // privileged
	RuntimeURL string
	Migrator   *pgxpool.Pool
	Runtime    *pgxpool.Pool
}

var bootstrapOnce sync.Once

// NewDB creates a fresh schema, migrates it and connects the restricted runtime login to it.
func NewDB(t testing.TB) *DB {
	t.Helper()
	return NewDBAt(t, DatabaseURL(t))
}

func NewDBAt(t testing.TB, adminURL string) *DB {
	t.Helper()
	ctx := context.Background()
	admin, err := store.Open(ctx, adminURL, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var bootErr error
	bootstrapOnce.Do(func() { bootErr = bootstrapRoles(ctx, admin) })
	if bootErr != nil {
		t.Fatal(bootErr)
	}
	schema := store.NewID("t")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema+" AUTHORIZATION "+store.OwnerRole+
		"; GRANT USAGE ON SCHEMA "+schema+" TO "+store.RuntimeRole); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	mig, err := store.Open(ctx, adminURL, store.Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mig.Close)
	if err := store.Migrate(ctx, mig); err != nil {
		t.Fatal(err)
	}
	rtURL := RuntimeURL(t, adminURL)
	rt, err := store.Open(ctx, rtURL, store.Options{Schema: schema, MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	return &DB{Schema: schema, URL: adminURL, RuntimeURL: rtURL, Migrator: mig, Runtime: rt}
}

// RuntimeURL rewrites the admin URL to connect as the restricted runtime login.
func RuntimeURL(t testing.TB, adminURL string) string {
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(RuntimeLogin, runtimePassword)
	return u.String()
}

func bootstrapRoles(ctx context.Context, admin *pgxpool.Pool) error {
	conn, err := admin.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('strongbox.test-login'))`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('strongbox.test-login'))`) //nolint:errcheck
	if _, err := conn.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '`+RuntimeLogin+`') THEN
			CREATE ROLE `+RuntimeLogin+` LOGIN PASSWORD '`+runtimePassword+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
		END IF; END $$`); err != nil {
		return err
	}
	return store.Bootstrap(ctx, admin, store.BootstrapOptions{Schema: "public", RuntimeLogins: []string{RuntimeLogin}})
}

// SeparateDatabase creates a real database for source/target recovery isolation tests.
func SeparateDatabase(t testing.TB) *DB {
	t.Helper()
	u, err := url.Parse(DatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.Open(context.Background(), u.String(), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	name := store.NewID("recovery")
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); admin.Close() })
	u.Path = "/" + name
	return NewDBAt(t, u.String())
}
