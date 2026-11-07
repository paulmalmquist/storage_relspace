// Package testenv builds a real container against Postgres for integration tests. Each test gets its
// own schema, migrated by the privileged login, while the service connects as the restricted runtime
// login: the same role split as production. Tests are skipped when STRONGBOX_TEST_DATABASE_URL is
// unset, unless STRONGBOX_REQUIRE_INTEGRATION=1 (set in CI), in which case a missing database fails
// the run.
package testenv

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv/pgtest"
)

const Secret = "test-secret-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

// App is the app every seeded principal belongs to; Other is a second app for isolation tests.
const (
	AppID   = "acme"
	App     = "acme:test"
	OtherID = "rival"
	Other   = "rival:test"
)

var rw = []string{"blobs:read", "blobs:write", "blobs:delete", "records:read", "records:write", "records:delete"}

var agentScopes = []string{"records:read", "records:write", "blobs:read", "blobs:write", "delegate"}

// Principals seeded into every environment.
var Principals = []auth.Spec{
	{Subject: "admin@rel.test", Kind: auth.KindUser, Scopes: []string{"*"}, USPerson: true, CUIAccess: true, CUICategories: []string{"*"}, Dissemination: []string{"*"}},
	{Subject: "engineer@rel.test", Kind: auth.KindUser, Scopes: rw, USPerson: true, CUIAccess: true, CUICategories: []string{"SP-EXPT", "PROPIN"}},
	{Subject: "teammate@rel.test", Kind: auth.KindUser, Scopes: rw, USPerson: true, CUIAccess: true, CUICategories: []string{"SP-EXPT", "PROPIN"}},
	{Subject: "foreign@rel.test", Kind: auth.KindUser, Scopes: rw, CUIAccess: true, CUICategories: []string{"SP-EXPT", "PROPIN"}},
	{Subject: "intern@rel.test", Kind: auth.KindUser, Scopes: rw, USPerson: true},
	{Subject: "outsider@rel.test", Kind: auth.KindUser, Scopes: rw, USPerson: true, CUIAccess: true, CUICategories: []string{"*"}},
	{Subject: "svc-mes@rel.test", Kind: auth.KindService, Scopes: append(append([]string{}, rw...), "collections:admin", "delegate"), USPerson: true, CUIAccess: true, CUICategories: []string{"*"}},
	{Subject: "agent:assistant", Kind: auth.KindAgent, Scopes: agentScopes, USPerson: true, CUIAccess: true, CUICategories: []string{"*"}, Dissemination: []string{"*"}},
	{Subject: "agent:boundary", Kind: auth.KindAgent, Scopes: agentScopes, USPerson: true, CUIAccess: true, CUICategories: []string{"*"}, Dissemination: []string{"*"}, LLMBoundaryAuthorized: true},
}

// Members of App and their roles. outsider is a member of Other only. svc-mes and both agents are
// registered clients of App (they may act on behalf of members).
var Members = map[string]string{
	"admin@rel.test": "admin", "engineer@rel.test": "editor", "teammate@rel.test": "member", "foreign@rel.test": "member",
	"intern@rel.test": "viewer", "svc-mes@rel.test": "editor", "agent:assistant": "member", "agent:boundary": "member",
}

var Clients = []string{"svc-mes@rel.test", "agent:assistant", "agent:boundary"}

type Env struct {
	*pgtest.DB
	C       *service.Container
	BlobDir string
	Keyring string
}

// New returns a fresh environment or skips the test when no database is configured.
func New(t testing.TB) *Env {
	t.Helper()
	return build(t, "", true)
}

// Empty returns an environment with no principals and no apps, sharing keyring (a restore
// target that holds the same keys as the source).
func Empty(t testing.TB, keyring string) *Env {
	t.Helper()
	return build(t, keyring, false)
}

func build(t testing.TB, keyring string, seed bool) *Env {
	db := pgtest.NewDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	if keyring == "" {
		keyring = filepath.Join(dir, "keyring.json")
		if _, err := crypto.CreateLocalKeyring(keyring); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.FromMap(map[string]string{
		"STRONGBOX_ENV": "test", "STRONGBOX_DEV_JWT_SECRET": Secret, "STRONGBOX_LOCAL_KEYRING_PATH": keyring,
		"STRONGBOX_BLOB_LOCAL_PATH": filepath.Join(dir, "blobs"), "STRONGBOX_CHUNK_SIZE": "4096",
		"STRONGBOX_MAX_SINGLE_UPLOAD_BYTES": fmt.Sprint(5 * 1024 * 1024), "STRONGBOX_MAX_BLOB_BYTES": fmt.Sprint(8 * 1024 * 1024),
		"STRONGBOX_UPLOAD_PART_BYTES": "16384", "STRONGBOX_RATE_SUBJECT_PER_SECOND": "0", "STRONGBOX_RATE_APP_PER_SECOND": "0", "STRONGBOX_DATABASE_URL": db.RuntimeURL,
		"STRONGBOX_MIGRATION_DATABASE_URL": db.URL, "STRONGBOX_DB_SCHEMA": db.Schema,
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.Build(ctx, cfg, service.Overrides{Pool: db.Runtime})
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{DB: db, C: c, BlobDir: cfg.BlobLocalPath, Keyring: keyring}
	if !seed {
		return e
	}
	for _, p := range Principals {
		if err := c.Principals.Put(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	// App provisioning is a privileged operation (strongbox admin app create): done as the owner role.
	e.Admin(t, `INSERT INTO apps (app, created_by) VALUES ($1, 'test'), ($2, 'test')`, App, Other)
	for s, role := range Members {
		e.Admin(t, `INSERT INTO app_members (app, subject, role, added_by) VALUES ($1,$2,$3,'test')`, App, s, role)
	}
	e.Admin(t, `INSERT INTO app_members (app, subject, role, added_by) VALUES ($1,'outsider@rel.test','admin','test'),
		($1,'admin@rel.test','admin','test')`, Other)
	for _, s := range Clients {
		e.Admin(t, `INSERT INTO app_clients (app, subject, added_by) VALUES ($1,$2,'test')`, App, s)
	}
	return e
}

// Admin runs SQL as the privileged login (provisioning and test fixtures only).
func (e *Env) Admin(t testing.TB, sql string, args ...any) {
	t.Helper()
	if _, err := e.Migrator.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// Ctx returns a request context for a seeded principal in App.
func (e *Env) Ctx(t testing.TB, subject string) service.Ctx { return e.CtxIn(t, App, subject) }

// CtxIn returns a request context for a seeded principal in a given app.
func (e *Env) CtxIn(t testing.TB, app, subject string) service.Ctx {
	t.Helper()
	p, err := e.C.Principals.Get(context.Background(), subject)
	if err != nil || p == nil {
		t.Fatalf("principal %s: %v", subject, err)
	}
	return service.Ctx{Principal: p, RequestID: "test-request", App: app}
}

// OnBehalf returns a delegated context: actor acting for subject.
func (e *Env) OnBehalf(t testing.TB, subject, actor string) service.Ctx {
	t.Helper()
	u, a := e.Ctx(t, subject), e.Ctx(t, actor)
	u.Principal = u.Principal.DelegatedTo(a.Principal)
	return u
}

// Token mints a dev token for subject.
func Token(t testing.TB, subject string) string {
	t.Helper()
	tok, err := auth.MintDevToken(Secret, subject, "strongbox", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// ObjectPath is where the local backend stores a blob's ciphertext.
func (e *Env) ObjectPath(t testing.TB, id string) string {
	t.Helper()
	var key string
	if err := e.Migrator.QueryRow(context.Background(), `SELECT storage_key FROM blobs WHERE id = $1`, id).Scan(&key); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(e.BlobDir, filepath.FromSlash(key))
}
