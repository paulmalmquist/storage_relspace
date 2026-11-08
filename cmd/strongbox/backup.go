package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func actor() string {
	return "admin-cli:" + firstNonEmpty(os.Getenv("STRONGBOX_ADMIN_ACTOR"), os.Getenv("USER"), "unknown")
}

// strongbox export -app APP -out DIR: one app's rows (one snapshot) and objects, ciphertext only.
func cmdExport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	app := fs.String("app", "", "app to export (<app_id>:<env>)")
	out := fs.String("out", "", "new or empty directory")
	_ = fs.Parse(args)
	if *app == "" || *out == "" {
		return errors.New("usage: strongbox export -app APP -out DIR")
	}
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
	kp, err := service.BuildKMS(ctx, cfg)
	if err != nil {
		return err
	}
	kp = crypto.WithTimeout(kp, cfg.KMSTimeout)
	m, err := backup.Export(ctx, pool, backend, *app, *out, actor(), version, kp)
	if err != nil {
		return err
	}
	printJSON(m)
	return nil
}

// strongbox validate-export -in DIR: offline; exits 1 when anything does not match.
func cmdValidateExport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("validate-export", flag.ExitOnError)
	authenticated := fs.Bool("authenticate", false, "also authenticate manifest and decrypted rows using configured KMS/keyring; no database needed")
	in := fs.String("in", "", "export directory")
	_ = fs.Parse(args)
	if *in == "" {
		return errors.New("usage: strongbox validate-export -in DIR")
	}
	_, rep, err := backup.Validate(*in)
	if err == nil && *authenticated {
		cfg, e := load()
		if e != nil {
			return e
		}
		kp, e := service.BuildKMS(ctx, cfg)
		if e != nil {
			return e
		}
		_, rep, err = backup.ValidateAuthenticated(ctx, *in, crypto.WithTimeout(kp, cfg.KMSTimeout))
	}
	if err != nil {
		return err
	}
	printJSON(rep)
	if !rep.OK() {
		return exitCode(1)
	}
	return nil
}

// strongbox restore -in DIR [-dry-run] [-verify] [-deep]: into the database and object store
// this process is configured for, which must not be the export's source.
func cmdRestore(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	in := fs.String("in", "", "export directory")
	dry := fs.Bool("dry-run", false, "insert and check everything in a transaction, then roll back; write no objects")
	allowLegacy := fs.Bool("allow-legacy", false, "explicitly accept unauthenticated format-1 exports")
	verify := fs.Bool("verify", true, "after restoring, check audit chains and usage, and decrypt every record and blob metadata (needs KMS)")
	deep := fs.Bool("deep", false, "with -verify, also stream and authenticate every blob's content")
	_ = fs.Parse(args)
	if *in == "" {
		return errors.New("usage: strongbox restore -in DIR [-dry-run] [-verify] [-deep]")
	}
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
	manifest, err := backup.Inspect(*in)
	if err != nil {
		return err
	}
	var kp crypto.KeyProvider
	var providers []crypto.KeyProvider
	if manifest.FormatVersion == 1 && !*allowLegacy {
		return errors.New("format-1 restore requires -allow-legacy; it has no manifest authentication")
	}
	if manifest.FormatVersion == 2 {
		kp, err = service.BuildKMS(ctx, cfg)
		if err != nil {
			return err
		}
		kp = crypto.WithTimeout(kp, cfg.KMSTimeout)
		providers = append(providers, kp)
	}
	rep, err := backup.Restore(ctx, pool, backend, *in, *dry, providers...)
	if rep != nil {
		printJSON(rep)
	}
	if err != nil || *dry || !*verify {
		return err
	}
	c, err := service.Build(ctx, cfg, service.Overrides{Pool: pool, KMS: kp})
	if err != nil {
		return err
	}
	v, err := c.VerifyApp(ctx, rep.App, *deep)
	if err != nil {
		return err
	}
	a := &admin.Admin{Pool: pool, Actor: actor(), Stripes: cfg.AuditStripes}
	u, err := a.AppUsage(ctx, rep.App, true, false)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+store.OwnerRole); err != nil {
		return err
	}
	chains, err := audit.New(nil, cfg.AuditStripes).Verify(ctx, tx)
	if err != nil {
		return err
	}
	printJSON(map[string]any{"decrypt": v, "usage": u, "audit": chains})
	if len(v.Problems) > 0 || u.Drift || !chains.OK {
		return exitCode(1)
	}
	return nil
}

// strongbox inventory: every app with its usage, collections, contract versions and pending work.
func cmdInventory(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	_ = fs.Parse(args)
	cfg, err := load()
	if err != nil {
		return err
	}
	pool, err := privileged(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, embedded, err := store.MigrationVersion(ctx, pool)
	if err != nil {
		return err
	}
	a := &admin.Admin{Pool: pool, Actor: actor(), Stripes: cfg.AuditStripes}
	apps, err := a.Apps(ctx)
	if err != nil {
		return err
	}
	type collection struct {
		Name            string  `json:"name"`
		Marking         string  `json:"marking"`
		Encrypted       bool    `json:"encrypted"`
		Version         int     `json:"version"`
		PendingVersion  *int    `json:"pending_version"`
		Records         int64   `json:"records"`
		Unversioned     int64   `json:"records_without_schema_version"`
		LegacyContexts  int64   `json:"records_with_legacy_aad"`
		RunningMigation *string `json:"running_migration"`
	}
	type entry struct {
		*admin.Usage
		Status      string       `json:"status"`
		Members     int64        `json:"members"`
		Collections []collection `json:"collections"`
		DeadJobs    int64        `json:"dead_outbox_jobs"`
	}
	out := map[string]any{"schema_version": applied, "build_schema_version": embedded, "build": version}
	var list []entry
	for _, app := range apps {
		u, err := a.AppUsage(ctx, app, false, false)
		if err != nil {
			return fmt.Errorf("%s: %w", app, err)
		}
		e := entry{Usage: u}
		err = pool.QueryRow(ctx, `SELECT status, (SELECT count(*) FROM app_members WHERE app = $1),
			(SELECT count(*) FROM outbox WHERE app = $1 AND status = 'dead') FROM apps WHERE app = $1`, app).Scan(&e.Status, &e.Members, &e.DeadJobs)
		if err != nil {
			return err
		}
		rows, err := pool.Query(ctx, `SELECT c.name, c.marking, c.encrypted, c.version, c.pending_version,
			(SELECT count(*) FROM records r WHERE r.app = c.app AND r.collection = c.name AND r.deleted_at IS NULL),
			(SELECT count(*) FROM records r WHERE r.app = c.app AND r.collection = c.name AND r.schema_version IS NULL),
			(SELECT count(*) FROM records r WHERE r.app = c.app AND r.collection = c.name AND r.aad_version = 1),
			(SELECT id FROM collection_migrations m WHERE m.app = c.app AND m.collection = c.name AND m.state = 'running')
			FROM collections c WHERE c.app = $1 ORDER BY c.name`, app)
		if err != nil {
			return err
		}
		for rows.Next() {
			var c collection
			if err := rows.Scan(&c.Name, &c.Marking, &c.Encrypted, &c.Version, &c.PendingVersion, &c.Records, &c.Unversioned,
				&c.LegacyContexts, &c.RunningMigation); err != nil {
				rows.Close()
				return err
			}
			e.Collections = append(e.Collections, c)
		}
		rows.Close()
		list = append(list, e)
	}
	out["apps"] = list
	printJSON(out)
	return nil
}
