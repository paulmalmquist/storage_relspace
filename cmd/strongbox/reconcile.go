package main

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

func cmdReconcile(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reconcile", flag.ExitOnError)
	app := fs.String("app", "", "one app scope (<app_id>:<env>)")
	apply := fs.Bool("apply", false, "queue old unreferenced generations for worker cleanup; default is report only")
	fix := fs.Bool("fix-counters", false, "with -apply, recount and repair usage, including reservations")
	limit := fs.Int("limit", store.InventoryPageSize, "maximum objects/references checked this page (1-200)")
	cursor := fs.String("cursor", "", "next_cursor from a previous page of the same app")
	age := fs.Duration("min-age", store.OrphanGrace, "minimum orphan age (at least 24h)")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall maintenance deadline")
	_ = fs.Parse(args)
	if *app == "" || *timeout <= 0 {
		return errors.New("usage: strongbox reconcile -app APP [-apply] [-fix-counters] [-cursor CURSOR]")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	cfg, err := load()
	if err != nil {
		return err
	}
	pool, err := privileged(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	backend, err := service.BuildBackend(ctx, cfg)
	if err != nil {
		return err
	}
	a := &admin.Admin{Pool: pool, Actor: actor(), Stripes: cfg.AuditStripes}
	report, err := a.Reconcile(ctx, backend, *app, admin.ReconcileOptions{Apply: *apply, FixCounters: *fix, Limit: *limit, Cursor: *cursor, MinAge: *age, ObjectTimeout: cfg.RequestTimeout})
	if report != nil {
		printJSON(report)
	}
	return err
}
