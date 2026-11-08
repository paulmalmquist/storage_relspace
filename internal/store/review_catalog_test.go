package store_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/paulmalmquist/storage_relspace/internal/testenv/pgtest"
)

// Catalog assertions follow every future app table and definer function rather
// than maintaining a hand-picked list that can silently miss a new migration.
func TestReviewAllAppTablesForceRLSAndDefinersPinPath(t *testing.T) {
	db, ctx := pgtest.NewDB(t), context.Background()
	rows, err := db.Migrator.Query(ctx, `SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=$1 AND c.relkind IN ('r','p') AND EXISTS
            (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='app' AND NOT a.attisdropped)`, db.Schema)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
		var name string
		var enabled, forced bool
		err := r.Scan(&name, &enabled, &forced)
		if err == nil && (!enabled || !forced) {
			t.Errorf("%s does not force RLS", name)
		}
		return name, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) < 20 {
		t.Fatalf("catalog query unexpectedly found only %d app tables", len(tables))
	}
	rows, err = db.Migrator.Query(ctx, `SELECT p.proname,p.proconfig,
        EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname=$1 AND p.prosecdef`, db.Schema)
	if err != nil {
		t.Fatal(err)
	}
	defs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
		var name string
		var config []string
		var public bool
		err := r.Scan(&name, &config, &public)
		pinned := false
		for _, c := range config {
			if strings.HasPrefix(c, "search_path="+db.Schema+",") && strings.Contains(c, "pg_catalog") && strings.HasSuffix(c, "pg_temp") {
				pinned = true
			}
		}
		if err == nil && (!pinned || public) {
			t.Errorf("unsafe definer %s: pinned=%v public_execute=%v", name, pinned, public)
		}
		return name, err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(defs)
	if !slices.Equal(defs, []string{"sb_blob_usage", "sb_can_share_id", "sb_catalog_marking", "sb_record_usage", "sb_revision_pinned", "sb_set_visibility"}) {
		t.Fatalf("unexpected definer set: %v; review new functions explicitly", defs)
	}
}
