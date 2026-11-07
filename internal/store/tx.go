package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

// Mode selects which rows a transaction may reach (see 0003_rls.sql).
type Mode string

const (
	ModeApp        Mode = "app"        // a request for one app, subject to membership and sharing
	ModeWorker     Mode = "worker"     // background work pinned to one app
	ModeGlobal     Mode = "global"     // principals and the global audit chain; no app data
	ModeDispatcher Mode = "dispatcher" // queue bookkeeping across apps; no app content
)

var (
	appPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}:(dev|test|staging|prod)$`)
	subjectPattern = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,255}$`)
)

// ValidApp reports whether s is a well-formed app scope "<app_id>:<env>".
func ValidApp(s string) bool { return appPattern.MatchString(s) }

// Scope is the identity a transaction runs under. It is set with transaction-local settings, so it
// never outlives the transaction and never leaks to the next user of a pooled connection.
type Scope struct {
	App     string // "<app_id>:<env>"; required for app and worker modes
	Subject string // the user (or service) the work is for
	Actor   string // the authenticated caller; equals Subject unless delegated
	Mode    Mode
}

func (s Scope) validate() error {
	switch s.Mode {
	case ModeApp, ModeWorker:
		if !appPattern.MatchString(s.App) {
			return errs.Internal("scoped transaction without a valid app")
		}
	case ModeGlobal, ModeDispatcher:
		if s.App != "" {
			return errs.Internal("global transaction with an app")
		}
	default:
		return errs.Internal("scoped transaction without a mode")
	}
	if !subjectPattern.MatchString(s.Subject) || !subjectPattern.MatchString(s.Actor) {
		return errs.Internal("scoped transaction without a subject or actor")
	}
	return nil
}

// DB is the only way services reach Postgres: every statement runs inside Run, under a Scope.
type DB struct {
	pool          *pgxpool.Pool
	commitTimeout time.Duration
}

// NewDB wraps a runtime pool.
func NewDB(pool *pgxpool.Pool) *DB { return &DB{pool: pool, commitTimeout: 10 * time.Second} }

// Ping checks connectivity (readiness probes).
func (d *DB) Ping(ctx context.Context) error { return d.pool.Ping(ctx) }

// Stat exposes pool statistics for metrics.
func (d *DB) Stat() *pgxpool.Stat { return d.pool.Stat() }

// Close closes the pool.
func (d *DB) Close() { d.pool.Close() }

// ErrCommitUnknown means COMMIT was sent but its outcome was not observed. Callers that need
// exactly-once effects resolve it through operation receipts.
var ErrCommitUnknown = errors.New("transaction outcome unknown")

// Run executes fn in one transaction under scope s. Every call starts a fresh transaction with
// fresh context settings; retries call Run again.
//
// Rollback is explicit and bounded: if fn fails, panics, or ctx is cancelled before commit, the
// transaction is rolled back on a detached context with a timeout, not left to cancellation. A
// connection whose rollback fails is not idle, and pgxpool destroys it on release.
func (d *DB) Run(ctx context.Context, s Scope, fn func(tx pgx.Tx) error) (err error) {
	if err := s.validate(); err != nil {
		return err
	}
	conn, err := d.pool.Acquire(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return errs.Unavailable("database busy: %v", ctx.Err())
		}
		return err
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		// Runs on error and while panicking.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rctx)
	}()
	if _, err = tx.Exec(ctx, `SELECT set_config('strongbox.app', $1, true), set_config('strongbox.subject', $2, true),
		set_config('strongbox.actor', $3, true), set_config('strongbox.mode', $4, true)`,
		s.App, s.Subject, s.Actor, string(s.Mode)); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err // cancelled before commit: roll back rather than commit half-observed work
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.commitTimeout)
	defer cancel()
	if err = tx.Commit(cctx); err != nil {
		finished = true // the transaction is closed either way
		if conn.Conn().PgConn().IsClosed() {
			return fmt.Errorf("%w: %v", ErrCommitUnknown, err)
		}
		return err
	}
	finished = true
	return nil
}
