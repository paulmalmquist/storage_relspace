// Package recovery exercises the full supported recovery path on an operator-supplied,
// disposable target. It never drops or overwrites an app or a database.
package recovery

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

type Report struct {
	App                string                `json:"app"`
	StartedAt          time.Time             `json:"started_at"`
	SnapshotAt         time.Time             `json:"snapshot_at"`
	SnapshotAgeSeconds float64               `json:"snapshot_age_seconds"`
	Seconds            map[string]float64    `json:"phase_seconds"`
	Restored           bool                  `json:"restored"`
	Passed             bool                  `json:"passed"`
	FailedPhase        string                `json:"failed_phase,omitempty"`
	Restore            *backup.RestoreReport `json:"restore,omitempty"`
	Decrypt            *service.VerifyReport `json:"decrypt,omitempty"`
	Usage              *admin.Usage          `json:"usage,omitempty"`
	Audit              *audit.VerifyResult   `json:"audit,omitempty"`
}

// Drill requires a sealed bundle, runs a no-object-write SQL dry run, restores, then decrypts
// every live payload, streams every active attachment, and verifies audit chains and counters.
// Snapshot age describes this input's age, not a measured guarantee about production data loss.
func Drill(ctx context.Context, target *service.Container, pool *pgxpool.Pool, dir, actor string) (report *Report, err error) {
	report = &Report{StartedAt: time.Now().UTC(), Seconds: map[string]float64{}}
	defer func() { report.Seconds["total"] = time.Since(report.StartedAt).Seconds() }()
	phase := func(name string, fn func() error) error {
		started := time.Now()
		err := fn()
		report.Seconds[name] = time.Since(started).Seconds()
		if err != nil {
			report.FailedPhase = name
		}
		return err
	}
	manifest, e := backup.Inspect(dir)
	if e != nil {
		report.FailedPhase = "inspect"
		return report, e
	}
	if manifest.FormatVersion != 2 {
		report.FailedPhase = "inspect"
		return report, errors.New("restore drills require an authenticated format-2 export")
	}
	report.App = manifest.App
	report.SnapshotAt = manifest.SnapshotAt
	if !manifest.SnapshotAt.IsZero() {
		report.SnapshotAgeSeconds = report.StartedAt.Sub(manifest.SnapshotAt).Seconds()
	}
	if err = phase("dry_run", func() error { _, err := backup.Restore(ctx, pool, target.Backend, dir, true, target.KMS); return err }); err != nil {
		return report, err
	}
	if err = phase("restore", func() error {
		var err error
		report.Restore, err = backup.Restore(ctx, pool, target.Backend, dir, false, target.KMS)
		report.Restored = err == nil
		return err
	}); err != nil {
		return report, err
	}
	if err = phase("decrypt", func() error {
		var err error
		report.Decrypt, err = target.VerifyApp(ctx, manifest.App, true)
		if err == nil && len(report.Decrypt.Problems) > 0 {
			err = errors.New("deep content verification failed")
		}
		return err
	}); err != nil {
		return report, err
	}
	if err = phase("usage", func() error {
		a := &admin.Admin{Pool: pool, Actor: actor, Stripes: target.Config.AuditStripes}
		var err error
		report.Usage, err = a.AppUsage(ctx, manifest.App, true, false)
		if err == nil && report.Usage.Drift {
			err = errors.New("restored usage counters differ from data")
		}
		return err
	}); err != nil {
		return report, err
	}
	if err = phase("audit", func() error {
		return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+store.OwnerRole); err != nil {
				return err
			}
			result, err := audit.New(nil, target.Config.AuditStripes).Verify(ctx, tx)
			report.Audit = &result
			if err == nil && !result.OK {
				err = errors.New("audit chain verification failed")
			}
			return err
		})
	}); err != nil {
		return report, err
	}
	report.Passed = true
	return report, nil
}
