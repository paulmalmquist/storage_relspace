package store_test

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv/pgtest"
	"net/url"
	"testing"
)

func TestReviewRuntimeCheckRejectsExtraReadAllRole(t *testing.T) {
	db, ctx := pgtest.NewDB(t), context.Background()
	login := store.NewID("review_runtime")
	if _, err := db.Migrator.Exec(ctx, `CREATE ROLE `+pgx.Identifier{login}.Sanitize()+` LOGIN PASSWORD 'review-only' IN ROLE strongbox_runtime, pg_read_all_data`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Migrator.Exec(ctx, `DROP ROLE `+pgx.Identifier{login}.Sanitize()) })
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
	report, err := store.CheckRuntime(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if report.OK() {
		t.Fatalf("startup check accepted a login with pg_read_all_data: %+v", report)
	}
}
