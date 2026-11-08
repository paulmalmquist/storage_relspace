package store_test

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv/pgtest"
	"net/url"
	"testing"
)

func TestReviewRuntimeRejectsDirectGrantsAndFunctionOwnership(t *testing.T) {
	db, ctx := pgtest.NewDB(t), context.Background()
	login := store.NewID("review_login")
	quoted := pgx.Identifier{login}.Sanitize()
	if _, err := db.Migrator.Exec(ctx, `CREATE ROLE `+quoted+` LOGIN PASSWORD 'review-only' IN ROLE strongbox_runtime`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Migrator.Exec(ctx, `DROP OWNED BY `+quoted)
		_, _ = db.Migrator.Exec(ctx, `DROP ROLE `+quoted)
	})
	u, err := url.Parse(db.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(login, "review-only")
	pool, err := store.Open(ctx, u.String(), store.Options{Schema: db.Schema})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	check := func(want bool) {
		t.Helper()
		r, err := store.CheckRuntime(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if r.OK() != want {
			t.Fatalf("restricted=%v: %s", r.OK(), r.String())
		}
	}
	check(true)
	if _, err := db.Migrator.Exec(ctx, `GRANT SELECT ON records TO `+quoted); err != nil {
		t.Fatal(err)
	}
	check(false)
	if _, err := db.Migrator.Exec(ctx, `REVOKE SELECT ON records FROM `+quoted); err != nil {
		t.Fatal(err)
	}
	check(true)
	if _, err := db.Migrator.Exec(ctx, `CREATE FUNCTION review_owned() RETURNS integer LANGUAGE sql AS 'SELECT 1'; ALTER FUNCTION review_owned() OWNER TO `+quoted); err != nil {
		t.Fatal(err)
	}
	check(false)
}
