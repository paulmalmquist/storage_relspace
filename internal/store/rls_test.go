package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv/pgtest"
)

// These tests exercise the database boundary directly, as the restricted runtime login, without the
// service layer: they show what RLS and grants enforce even if service code is wrong.

const (
	appA = "notes:test"
	appB = "tasks:test"
)

type fixture struct {
	db  *pgtest.DB
	rt  *store.DB
	ctx context.Context
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db := pgtest.NewDB(t)
	f := &fixture{db: db, rt: store.NewDB(db.Runtime), ctx: context.Background()}
	// Seed as the privileged login (superuser in tests; strongbox_owner in production).
	f.exec(t, `
		INSERT INTO principals (subject, kind) VALUES ('alice','user'), ('bob','user'), ('carol','user'),
			('mallory','user'), ('svc-web','service'), ('agent','agent');
		INSERT INTO apps (app, created_by) VALUES ('notes:test','t'), ('tasks:test','t');
		INSERT INTO app_members (app, subject, role, added_by) VALUES
			('notes:test','alice','member','t'), ('notes:test','bob','member','t'), ('notes:test','carol','viewer','t'),
			('notes:test','svc-web','admin','t'), ('tasks:test','mallory','admin','t'), ('tasks:test','alice','member','t');
		INSERT INTO app_clients (app, subject, added_by) VALUES ('notes:test','svc-web','t');
		INSERT INTO teams (app, id, name, created_by) VALUES ('notes:test','tm_1','crew','alice');
		INSERT INTO team_members (app, team_id, subject, role, added_by) VALUES ('notes:test','tm_1','bob','editor','alice');
		INSERT INTO collections (app, name, marking, encrypted, json_schema, created_by, token_version) VALUES
			('notes:test','notes','UNCONTROLLED',false,'{}','alice',2), ('tasks:test','notes','UNCONTROLLED',false,'{}','mallory',2);
		INSERT INTO records (app, id, collection, marking, data_plain, version, created_by, updated_by, owner, visibility, team_id, aad_version) VALUES
			('notes:test','r_private','notes','UNCONTROLLED','{"n":1}',1,'alice','alice','alice','private',NULL,2),
			('notes:test','r_team','notes','UNCONTROLLED','{"n":2}',1,'alice','alice','alice','team','tm_1',2),
			('notes:test','r_app','notes','UNCONTROLLED','{"n":3}',1,'alice','alice','alice','app',NULL,2),
			('tasks:test','r_other','notes','UNCONTROLLED','{"n":4}',1,'mallory','mallory','mallory','app',NULL,2),
			('_legacy','r_legacy','notes','UNCONTROLLED','{"n":5}',1,'alice','alice','alice','private',NULL,1);`)
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if strings.Contains(sql, "_legacy") {
		// A legacy row needs a legacy collection first.
		if _, err := f.db.Migrator.Exec(f.ctx, `INSERT INTO collections (app, name, marking, encrypted, json_schema, created_by, token_version)
			VALUES ('_legacy','notes','UNCONTROLLED',false,'{}','alice',1) ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Migrator.Exec(f.ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

func scope(app, subject string) store.Scope {
	return store.Scope{App: app, Subject: subject, Actor: subject, Mode: store.ModeApp}
}

func (f *fixture) ids(t *testing.T, s store.Scope, sql string, args ...any) []string {
	t.Helper()
	var out []string
	err := f.rt.Run(f.ctx, s, func(tx pgx.Tx) error {
		rows, err := tx.Query(f.ctx, sql, args...)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return out
}

func (f *fixture) try(s store.Scope, sql string, args ...any) (int64, error) {
	var n int64
	err := f.rt.Run(f.ctx, s, func(tx pgx.Tx) error {
		tag, err := tx.Exec(f.ctx, sql, args...)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func TestRuntimeRoleIsRestricted(t *testing.T) {
	f := setup(t)
	rep, err := store.CheckRuntime(f.ctx, f.db.Runtime)
	if err != nil || !rep.OK() {
		t.Fatalf("runtime login failed its own check: %v %v", rep, err)
	}
	if rep, _ := store.CheckRuntime(f.ctx, f.db.Migrator); rep.OK() {
		t.Fatal("privileged login passed the runtime check")
	}
	s := scope(appA, "alice")
	for _, stmt := range []string{
		`TRUNCATE records`,
		`ALTER TABLE records DISABLE ROW LEVEL SECURITY`,
		`ALTER TABLE records NO FORCE ROW LEVEL SECURITY`,
		`DROP POLICY app_boundary ON records`,
		`CREATE POLICY open ON records USING (true)`,
		`CREATE SCHEMA escape`,
		`CREATE TABLE stash (x int)`,
		`SET ROLE strongbox_owner`,
		`GRANT strongbox_owner TO current_user`,
		`UPDATE records SET app = 'tasks:test' WHERE id = 'r_private'`,
		`UPDATE records SET owner = 'bob' WHERE id = 'r_private'`,
		`DELETE FROM audit_events`,
		`UPDATE audit_events SET reason = 'x'`,
		`INSERT INTO apps (app, created_by) VALUES ('evil:test', 'alice')`,
		`INSERT INTO app_clients (app, subject, added_by) VALUES ('notes:test', 'agent', 'alice')`,
		`SELECT * FROM idempotency_keys`,
		`INSERT INTO schema_migrations (version) VALUES (999)`,
	} {
		if _, err := f.try(s, stmt); err == nil {
			t.Errorf("runtime role was allowed: %s", stmt)
		}
	}
}

func TestMissingOrMalformedContextFailsClosed(t *testing.T) {
	f := setup(t)
	conn, err := f.db.Runtime.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	q := func(sql string) error { _, err := conn.Exec(f.ctx, sql); return err }
	if err := q(`SELECT count(*) FROM records`); sqlState(err) != "42501" {
		t.Fatalf("query without context: %v", err)
	}
	for _, bad := range []string{"", "notes", "NOTES:test", "notes:qa", "notes:test;drop", "_legacy"} {
		err := pgx.BeginFunc(f.ctx, conn, func(tx pgx.Tx) error {
			_, _ = tx.Exec(f.ctx, `SELECT set_config('strongbox.app', $1, true), set_config('strongbox.subject','alice',true),
				set_config('strongbox.actor','alice',true), set_config('strongbox.mode','app',true)`, bad)
			_, err := tx.Exec(f.ctx, `SELECT count(*) FROM records`)
			return err
		})
		if sqlState(err) != "42501" {
			t.Fatalf("app %q: %v", bad, err)
		}
	}
	// Settings are transaction-local: after a scoped transaction commits, the next one on the same
	// connection has no identity.
	if err := pgx.BeginFunc(f.ctx, conn, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `SELECT set_config('strongbox.app','notes:test',true), set_config('strongbox.subject','alice',true),
			set_config('strongbox.actor','alice',true), set_config('strongbox.mode','app',true)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := q(`SELECT count(*) FROM records`); sqlState(err) != "42501" {
		t.Fatalf("identity leaked past commit: %v", err)
	}
	// Scope validation happens before any SQL.
	if err := f.rt.Run(f.ctx, store.Scope{App: appA, Subject: "alice", Mode: store.ModeApp}, func(pgx.Tx) error { return nil }); err == nil {
		t.Fatal("scope without an actor accepted")
	}
	if err := f.rt.Run(f.ctx, store.Scope{App: "", Subject: "alice", Actor: "alice", Mode: store.ModeApp}, func(pgx.Tx) error { return nil }); err == nil {
		t.Fatal("app-mode scope without an app accepted")
	}
}

func TestAppBoundary(t *testing.T) {
	f := setup(t)
	alice := scope(appA, "alice")
	got := f.ids(t, alice, `SELECT id FROM records ORDER BY id`)
	if strings.Join(got, ",") != "r_app,r_private,r_team" {
		t.Fatalf("alice in notes sees %v", got)
	}
	// Naming the other app's rows explicitly does not reach them.
	if got := f.ids(t, alice, `SELECT id FROM records WHERE app = 'tasks:test' OR id IN ('r_other','r_legacy')`); len(got) != 0 {
		t.Fatalf("cross-app read returned %v", got)
	}
	// Alice is a member of both apps: the same subject sees only the selected app's rows.
	if got := f.ids(t, scope(appB, "alice"), `SELECT id FROM records`); strings.Join(got, ",") != "r_other" {
		t.Fatalf("alice in tasks sees %v", got)
	}
	// Writing into another app is rejected by WITH CHECK.
	if _, err := f.try(alice, `INSERT INTO records (app, id, collection, marking, data_plain, version, created_by, updated_by, owner, visibility, aad_version)
		VALUES ('tasks:test','r_x','notes','UNCONTROLLED','{}',1,'alice','alice','alice','private',2)`); sqlState(err) != "42501" {
		t.Fatalf("insert into another app: %v", err)
	}
	// A cross-app relationship is not representable, even for the privileged login.
	if _, err := f.db.Migrator.Exec(f.ctx, `INSERT INTO resource_grants (id, app, record_id, subject, role, can_share, resource_owner, granted_by)
		VALUES ('g_x','notes:test','r_other','bob','viewer',false,'mallory','mallory')`); sqlState(err) != "23503" {
		t.Fatalf("cross-app grant: %v", err)
	}
	if _, err := f.db.Migrator.Exec(f.ctx, `INSERT INTO records (app, id, collection, marking, data_plain, version, created_by, updated_by, owner, visibility, team_id, aad_version)
		VALUES ('tasks:test','r_y','notes','UNCONTROLLED','{}',1,'mallory','mallory','mallory','team','tm_1',2)`); sqlState(err) != "23503" {
		t.Fatalf("record in tasks referencing a notes team: %v", err)
	}
	// Legacy rows are unreachable from every app.
	if got := f.ids(t, scope(appA, "alice"), `SELECT id FROM records WHERE id = 'r_legacy'`); len(got) != 0 {
		t.Fatal("legacy row visible")
	}
}

func TestAdmission(t *testing.T) {
	f := setup(t)
	if got := f.ids(t, scope(appA, "mallory"), `SELECT id FROM records`); len(got) != 0 {
		t.Fatalf("non-member sees %v", got)
	}
	if got := f.ids(t, scope(appA, "mallory"), `SELECT name FROM collections`); len(got) != 0 {
		t.Fatalf("non-member sees collections %v", got)
	}
	// Delegation: an unregistered actor cannot act for a member; the app's registered client can.
	obo := func(actor string) store.Scope {
		return store.Scope{App: appA, Subject: "alice", Actor: actor, Mode: store.ModeApp}
	}
	if got := f.ids(t, obo("agent"), `SELECT id FROM records`); len(got) != 0 {
		t.Fatalf("unregistered actor sees %v", got)
	}
	if got := f.ids(t, obo("svc-web"), `SELECT id FROM records ORDER BY id`); strings.Join(got, ",") != "r_app,r_private,r_team" {
		t.Fatalf("registered client acting for alice sees %v", got)
	}
	f.exec(t, `UPDATE apps SET status = 'suspended' WHERE app = 'notes:test'`)
	if got := f.ids(t, scope(appA, "alice"), `SELECT id FROM records`); len(got) != 0 {
		t.Fatalf("suspended app still serves %v", got)
	}
	// Workers are pinned to their app and see nothing else.
	w := store.Scope{App: appB, Subject: "system:worker", Actor: "system:worker", Mode: store.ModeWorker}
	if got := f.ids(t, w, `SELECT id FROM records`); strings.Join(got, ",") != "r_other" {
		t.Fatalf("worker for tasks sees %v", got)
	}
	g := store.Scope{Subject: "system", Actor: "system", Mode: store.ModeGlobal}
	if _, err := f.try(g, `SELECT 1 FROM records`); sqlState(err) != "42501" {
		t.Fatalf("global mode reached app data: %v", err)
	}
}

func TestSharingPolicies(t *testing.T) {
	f := setup(t)
	bob, carol := scope(appA, "bob"), scope(appA, "carol")
	if got := f.ids(t, bob, `SELECT id FROM records ORDER BY id`); strings.Join(got, ",") != "r_app,r_team" {
		t.Fatalf("bob sees %v", got)
	}
	if got := f.ids(t, carol, `SELECT id FROM records ORDER BY id`); strings.Join(got, ",") != "r_app" {
		t.Fatalf("carol (viewer, no team) sees %v", got)
	}
	// Team editor may edit the team record but not app-wide or private ones.
	if n, _ := f.try(bob, `UPDATE records SET version = version + 1 WHERE id = 'r_team'`); n != 1 {
		t.Fatal("team editor could not edit")
	}
	if n, _ := f.try(bob, `UPDATE records SET version = version + 1 WHERE id IN ('r_app','r_private')`); n != 0 {
		t.Fatal("bob edited records he may only read (or not see)")
	}
	// Editing is not sharing or deleting.
	if _, err := f.try(bob, `UPDATE records SET visibility = 'app', team_id = NULL WHERE id = 'r_team'`); sqlState(err) != "42501" {
		t.Fatalf("editor changed visibility: %v", err)
	}
	if _, err := f.try(bob, `UPDATE records SET deleted_at = now() WHERE id = 'r_team'`); sqlState(err) != "42501" {
		t.Fatalf("editor soft-deleted: %v", err)
	}
	if n, _ := f.try(bob, `DELETE FROM records WHERE id = 'r_team'`); n != 0 {
		t.Fatal("editor purged")
	}
	// A viewer grant reveals the private record to carol; it does not let her edit or share it.
	if _, err := f.try(scope(appA, "alice"), `INSERT INTO resource_grants (id, app, record_id, subject, role, can_share, resource_owner, granted_by)
		VALUES ('g_1','notes:test','r_private','carol','viewer',false,'alice','alice')`); err != nil {
		t.Fatal(err)
	}
	if got := f.ids(t, carol, `SELECT id FROM records WHERE id = 'r_private'`); len(got) != 1 {
		t.Fatal("viewer grant not honored")
	}
	if n, _ := f.try(carol, `UPDATE records SET version = version + 1 WHERE id = 'r_private'`); n != 0 {
		t.Fatal("viewer grant allowed an edit")
	}
	if _, err := f.try(carol, `INSERT INTO resource_grants (id, app, record_id, subject, role, can_share, resource_owner, granted_by)
		VALUES ('g_2','notes:test','r_private','bob','viewer',false,'alice','carol')`); sqlState(err) != "42501" {
		t.Fatalf("viewer re-shared: %v", err)
	}
	// Only managers hand out can_share.
	if _, err := f.try(bob, `INSERT INTO resource_grants (id, app, record_id, subject, role, can_share, resource_owner, granted_by)
		VALUES ('g_3','notes:test','r_team','carol','editor',true,'alice','bob')`); sqlState(err) != "42501" {
		t.Fatalf("non-manager granted can_share: %v", err)
	}
	// Viewers cannot create resources.
	if _, err := f.try(carol, `INSERT INTO records (app, id, collection, marking, data_plain, version, created_by, updated_by, owner, visibility, aad_version)
		VALUES ('notes:test','r_c','notes','UNCONTROLLED','{}',1,'carol','carol','carol','private',2)`); sqlState(err) != "42501" {
		t.Fatalf("viewer created a record: %v", err)
	}
	// Nobody creates a record owned by someone else.
	if _, err := f.try(bob, `INSERT INTO records (app, id, collection, marking, data_plain, version, created_by, updated_by, owner, visibility, aad_version)
		VALUES ('notes:test','r_b','notes','UNCONTROLLED','{}',1,'bob','bob','alice','private',2)`); sqlState(err) != "42501" {
		t.Fatalf("record created for another owner: %v", err)
	}
	// Revocation takes effect for the next transaction.
	f.exec(t, `DELETE FROM team_members WHERE subject = 'bob'`)
	if got := f.ids(t, bob, `SELECT id FROM records ORDER BY id`); strings.Join(got, ",") != "r_app" {
		t.Fatalf("after leaving the team bob sees %v", got)
	}
	f.exec(t, `DELETE FROM app_members WHERE app = 'notes:test' AND subject = 'bob'`)
	if got := f.ids(t, bob, `SELECT id FROM records`); len(got) != 0 {
		t.Fatalf("after removal from the app bob sees %v", got)
	}
}

// The restrictive app policy and the permissive sharing policies compose with AND: an app-wide or
// granted row in another app never becomes visible, whatever the permissive policies say.
func TestRestrictiveAndPermissiveComposition(t *testing.T) {
	f := setup(t)
	f.exec(t, `INSERT INTO resource_grants (id, app, record_id, subject, role, can_share, resource_owner, granted_by)
		VALUES ('g_o','tasks:test','r_other','alice','editor',true,'mallory','mallory')`)
	alice := scope(appA, "alice")
	if got := f.ids(t, alice, `SELECT id FROM records WHERE id = 'r_other'`); len(got) != 0 {
		t.Fatal("grant in another app widened the boundary")
	}
	if n, _ := f.try(alice, `UPDATE records SET version = 9 WHERE id = 'r_other'`); n != 0 {
		t.Fatal("cross-app edit through a grant")
	}
	// Inside tasks the grant applies.
	if n, _ := f.try(scope(appB, "alice"), `UPDATE records SET version = 9 WHERE id = 'r_other'`); n != 1 {
		t.Fatal("grant inside its own app ignored")
	}
	var policies []string
	rows, _ := f.db.Migrator.Query(f.ctx, `SELECT policyname || ':' || permissive FROM pg_policies
		WHERE schemaname = $1 AND tablename = 'records' AND 'strongbox_runtime' = ANY (roles) ORDER BY 1`, f.db.Schema)
	policies, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(policies, ",") != "app_boundary:RESTRICTIVE,creates:PERMISSIVE,edit:PERMISSIVE,purge:PERMISSIVE,read:PERMISSIVE" {
		t.Fatalf("unexpected policy set: %v", policies)
	}
}

// Policy predicates are index-backed: with sequential scans disabled the planner still has an index
// path for the list query and for the membership subqueries.
func TestPolicyPlansUseIndexes(t *testing.T) {
	f := setup(t)
	var plan []string
	err := f.rt.Run(f.ctx, scope(appA, "bob"), func(tx pgx.Tx) error {
		if _, err := tx.Exec(f.ctx, `SET LOCAL enable_seqscan = off`); err != nil {
			return err
		}
		rows, err := tx.Query(f.ctx, `EXPLAIN SELECT id FROM records WHERE app = 'notes:test' AND collection = 'notes'
			ORDER BY created_at DESC, id DESC LIMIT 50`)
		if err != nil {
			return err
		}
		plan, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(plan, "\n")
	t.Log("\n" + text)
	// Context readers are InitPlans (once per statement); team and grant lookups are hashed
	// subplans over their indexes (once per statement), never per-row probes.
	for _, want := range []string{"ix_records_list", "InitPlan", "hashed SubPlan", "ix_team_members_subject", "ix_grants_"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan does not contain %s", want)
		}
	}
	if strings.Contains(text, "Seq Scan") {
		t.Error("sequential scan in the policy plan")
	}
	// Admission runs once per statement inside sb_ctx_admitted(); its lookups are primary-key probes.
	for _, q := range []string{
		`EXPLAIN SELECT 1 FROM app_members WHERE app = 'notes:test' AND subject = 'bob'`,
		`EXPLAIN SELECT 1 FROM app_clients WHERE app = 'notes:test' AND subject = 'svc-web'`,
	} {
		rows, err := f.db.Migrator.Query(f.ctx, "/* */ "+q)
		if err != nil {
			t.Fatal(err)
		}
		lines, _ := pgx.CollectRows(rows, pgx.RowTo[string])
		if !strings.Contains(strings.Join(lines, " "), "_pkey") && !strings.Contains(strings.Join(lines, " "), "Seq Scan") {
			t.Errorf("%s: %v", q, lines)
		}
	}
}

// An exhausted pool fails fast with 503 instead of queueing until the request deadline.
func TestPoolExhaustionFailsFast(t *testing.T) {
	f := setup(t)
	pool, err := store.Open(f.ctx, f.db.RuntimeURL, store.Options{Schema: f.db.Schema, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db := store.NewDB(pool)
	db.AcquireTimeout = 100 * time.Millisecond
	hold, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = db.Run(f.ctx, scope("notes:test", "alice"), func(pgx.Tx) error { close(hold); <-release; return nil })
	}()
	<-hold
	start := time.Now()
	err = db.Run(f.ctx, scope("notes:test", "alice"), func(pgx.Tx) error { return nil })
	close(release)
	if !errs.Is(err, "unavailable") || time.Since(start) > 2*time.Second {
		t.Fatalf("waited %v: %v", time.Since(start), err)
	}
}
