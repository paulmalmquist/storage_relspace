// Package testenv builds a real container against Postgres for integration tests.
// Each test gets its own schema, so tests can run in parallel and leave nothing behind.
// Tests are skipped when STRONGBOX_TEST_DATABASE_URL is unset, unless STRONGBOX_REQUIRE_INTEGRATION=1
// (set in CI), in which case a missing database fails the run instead of silently skipping.
package testenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

const Secret = "test-secret-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

var rw = []string{"blobs:read", "blobs:write", "blobs:delete", "records:read", "records:write", "records:delete"}

var agentScopes = []string{"records:read", "records:write", "blobs:read", "blobs:write", "delegate"}

// Principals seeded into every environment.
var Principals = []auth.Spec{
	{Subject: "admin@rel.test", Kind: auth.KindUser, Scopes: []string{"*"}, USPerson: true, CUIAccess: true, CUICategories: []string{"*"}, Dissemination: []string{"*"}},
	{Subject: "engineer@rel.test", Kind: auth.KindUser, Scopes: rw, USPerson: true, CUIAccess: true, CUICategories: []string{"SP-EXPT", "PROPIN"}},
	{Subject: "foreign@rel.test", Kind: auth.KindUser, Scopes: rw, CUIAccess: true, CUICategories: []string{"SP-EXPT", "PROPIN"}},
	{Subject: "intern@rel.test", Kind: auth.KindUser, Scopes: rw, USPerson: true},
	{Subject: "svc-mes@rel.test", Kind: auth.KindService, Scopes: append(append([]string{}, rw...), "collections:admin"), USPerson: true, CUIAccess: true, CUICategories: []string{"*"}},
	{Subject: "agent:assistant", Kind: auth.KindAgent, Scopes: agentScopes, USPerson: true, CUIAccess: true, CUICategories: []string{"*"}, Dissemination: []string{"*"}},
	{Subject: "agent:boundary", Kind: auth.KindAgent, Scopes: agentScopes, USPerson: true, CUIAccess: true, CUICategories: []string{"*"}, Dissemination: []string{"*"}, LLMBoundaryAuthorized: true},
}

type Env struct {
	C       *service.Container
	BlobDir string
	Schema  string
}

// DatabaseURL returns the integration database URL, skipping (locally) or failing (CI) without one.
func DatabaseURL(t testing.TB) string {
	t.Helper()
	url := os.Getenv("STRONGBOX_TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("STRONGBOX_REQUIRE_INTEGRATION") == "1" {
			t.Fatal("STRONGBOX_REQUIRE_INTEGRATION=1 but STRONGBOX_TEST_DATABASE_URL is not set")
		}
		t.Skip("set STRONGBOX_TEST_DATABASE_URL to run integration tests")
	}
	return url
}

// New returns a fresh environment or skips the test when no database is configured.
func New(t *testing.T) *Env {
	t.Helper()
	url := DatabaseURL(t)
	ctx := context.Background()
	schema := store.NewID("t")
	admin, err := store.Open(ctx, url, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	pool, err := store.Open(ctx, url, schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	keyring := filepath.Join(dir, "keyring.json")
	if _, err := crypto.CreateLocalKeyring(keyring); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.FromMap(map[string]string{
		"STRONGBOX_ENV": "test", "STRONGBOX_DEV_JWT_SECRET": Secret, "STRONGBOX_LOCAL_KEYRING_PATH": keyring,
		"STRONGBOX_BLOB_LOCAL_PATH": filepath.Join(dir, "blobs"), "STRONGBOX_CHUNK_SIZE": "4096",
		"STRONGBOX_MAX_BLOB_BYTES": fmt.Sprint(5 * 1024 * 1024), "STRONGBOX_DATABASE_URL": url,
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.Build(ctx, cfg, service.Overrides{DB: pool})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range Principals {
		if err := c.Principals.Put(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	return &Env{C: c, BlobDir: cfg.BlobLocalPath, Schema: schema}
}

// Ctx returns a request context for a seeded principal.
func (e *Env) Ctx(t *testing.T, subject string) service.Ctx {
	t.Helper()
	p, err := e.C.Principals.Get(context.Background(), subject)
	if err != nil || p == nil {
		t.Fatalf("principal %s: %v", subject, err)
	}
	return service.Ctx{Principal: p, RequestID: "test-request"}
}

// Token mints a dev token for subject.
func Token(t *testing.T, subject string) string {
	t.Helper()
	tok, err := auth.MintDevToken(Secret, subject, "strongbox", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// ObjectPath is where the local backend stores a blob's ciphertext.
func (e *Env) ObjectPath(id string) string { return filepath.Join(e.BlobDir, id[len(id)-2:], id) }
