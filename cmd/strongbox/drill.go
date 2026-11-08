package main

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/recovery"
	"github.com/paulmalmquist/storage_relspace/internal/service"
)

func cmdRestoreDrill(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore-drill", flag.ExitOnError)
	in := fs.String("in", "", "sealed export directory; target must be a disposable separate database without this app")
	timeout := fs.Duration("timeout", 30*time.Minute, "overall restore-drill deadline")
	_ = fs.Parse(args)
	if *in == "" || *timeout <= 0 {
		return errors.New("usage: strongbox restore-drill -in DIR [-timeout 30m]")
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
	target, err := service.Build(ctx, cfg, service.Overrides{Pool: pool})
	if err != nil {
		return err
	}
	report, err := recovery.Drill(ctx, target, pool, *in, actor())
	if report != nil {
		printJSON(report)
	}
	return err
}
