package admin_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
	"testing"
	"time"
)

func TestUsageRecountIncludesReservations(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	a := &admin.Admin{Pool: e.Migrator, Actor: "test-counters", Stripes: e.C.Config.AuditStripes}
	if _, err := e.C.Blobs.CreateSession(ctx, e.Ctx(t, "engineer@rel.test"), service.BlobInput{Marking: markings.None(), DeclaredSize: 10}); err != nil {
		t.Fatal(err)
	}
	e.Admin(t, `UPDATE blob_usage SET reserved_bytes=reserved_bytes+7,reservations=reservations+1 WHERE app=$1`, testenv.App)
	usage, err := a.AppUsage(ctx, testenv.App, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !usage.Drift {
		t.Fatal("reservation drift was not detected")
	}
	if _, err := a.AppUsage(ctx, testenv.App, true, true); err != nil {
		t.Fatal(err)
	}
	usage, err = a.AppUsage(ctx, testenv.App, true, false)
	if err != nil || usage.Drift || usage.ReservedBytes != 10 || usage.Reservations != 1 {
		t.Fatalf("reservation repair %+v %v", usage, err)
	}
}

func TestUsageRepairLocksBeforeTakingItsSnapshot(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	a := &admin.Admin{Pool: e.Migrator, Actor: "test-counters", Stripes: e.C.Config.AuditStripes}
	user := e.Ctx(t, "engineer@rel.test")
	if _, err := e.C.Records.CreateCollection(ctx, e.Ctx(t, "admin@rel.test"), service.CollectionInput{Name: "notes", Marking: markings.None()}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.C.Records.Create(ctx, user, "notes", service.RecordInput{Data: map[string]any{"x": 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.C.Blobs.Put(ctx, user, []byte("old data"), service.BlobInput{Marking: markings.None()}); err != nil {
		t.Fatal(err)
	}
	e.Admin(t, `UPDATE blob_usage SET blobs=blobs+1 WHERE app=$1`, testenv.App)
	// Pause the record recount, which follows the blob recount in AppUsage.
	e.Admin(t, `CREATE OR REPLACE FUNCTION sb_record_bytes(r records) RETURNS bigint LANGUAGE plpgsql VOLATILE AS $$
 BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(current_schema() || '.counter-snapshot-test',0));
  RETURN coalesce(r.size_bytes,octet_length(r.data_sealed),octet_length(r.data_plain::text),0)::bigint;
 END $$`)
	gate, err := e.Migrator.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Release()
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended(current_schema() || '.counter-snapshot-test',0))`); err != nil {
		t.Fatal(err)
	}
	defer gate.Exec(ctx, `SELECT pg_advisory_unlock_all()`)
	var holder int
	if err := gate.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&holder); err != nil {
		t.Fatal(err)
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	repairDone := make(chan error, 1)
	go func() { _, err := a.AppUsage(call, testenv.App, true, true); repairDone <- err }()
	waitFor(t, call, e.Migrator, `SELECT EXISTS(SELECT 1 FROM pg_locks blocked JOIN pg_locks held
  ON held.locktype=blocked.locktype AND held.classid=blocked.classid AND held.objid=blocked.objid
  WHERE held.pid=$1 AND held.granted AND NOT blocked.granted)`, holder)
	uploadDone := make(chan error, 1)
	go func() {
		_, err := e.C.Blobs.Put(call, user, []byte("new data"), service.BlobInput{Marking: markings.None()})
		uploadDone <- err
	}()
	// A correct repair blocks the writer. The old repair allows it to commit here.
	uploadFinished := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-uploadDone:
			if err != nil {
				t.Fatal(err)
			}
			uploadFinished = true
		default:
		}
		var blocked bool
		if err := e.Migrator.QueryRow(call, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation=$1::regclass AND mode='RowExclusiveLock' AND NOT granted)`, e.Schema+".blobs").Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if uploadFinished || blocked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_unlock_all()`); err != nil {
		t.Fatal(err)
	}
	if err := <-repairDone; err != nil {
		t.Fatal(err)
	}
	if !uploadFinished {
		if err := <-uploadDone; err != nil {
			t.Fatal(err)
		}
	}
	usage, err := a.AppUsage(call, testenv.App, true, false)
	if err != nil || usage.Drift || usage.Blobs != 2 || usage.BlobBytes != 16 {
		t.Fatalf("repair wrote stale totals after a concurrent upload: %+v %v", usage, err)
	}
}
func waitFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	for {
		var ok bool
		if err := pool.QueryRow(ctx, sql, args...).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}
