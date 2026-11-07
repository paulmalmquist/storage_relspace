package service

import (
	"context"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/cache"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

type Container struct {
	Config             *config.Config
	Pool               *pgxpool.Pool // runtime login; reached only through DB
	DB                 *store.DB
	KMS                crypto.KeyProvider
	Backend            store.Backend
	Keys               *Keys
	Audit              *audit.Log
	Core               *Core
	Principals         *auth.Registry
	PrincipalAdmin     *Principals
	Blobs              *Blobs
	Records            *Records
	Sharing            *Sharing
	Auditing           *Auditing
	Worker             *Worker
	receipts           *receipts
	Verifier           auth.Verifier
	DelegationVerifier auth.Verifier
}

// Overrides replace components (tests, alternative deployments).
type Overrides struct {
	Pool               *pgxpool.Pool
	KMS                crypto.KeyProvider
	Backend            store.Backend
	Verifier           auth.Verifier
	DelegationVerifier auth.Verifier
}

func Build(ctx context.Context, cfg *config.Config, o Overrides) (*Container, error) {
	if cfg.RequireFIPS {
		if err := crypto.AssertFIPS(); err != nil {
			return nil, err
		}
	}
	var err error
	pool := o.Pool
	if pool == nil {
		if pool, err = store.Open(ctx, cfg.DatabaseURL, store.Options{Schema: cfg.DBSchema, MaxConns: cfg.DBMaxConns,
			StatementTimeout: cfg.DBStatementTimeout, AppName: "strongbox"}); err != nil {
			return nil, err
		}
	}
	kp := o.KMS
	if kp == nil {
		if kp, err = BuildKMS(ctx, cfg); err != nil {
			return nil, err
		}
	}
	backend := o.Backend
	if backend == nil {
		if backend, err = BuildBackend(ctx, cfg); err != nil {
			return nil, err
		}
	}
	verifier := o.Verifier
	if verifier == nil {
		if verifier, err = BuildVerifier(ctx, cfg, cfg.JWTAudiences); err != nil {
			return nil, err
		}
	}
	delegation := o.DelegationVerifier
	if delegation == nil {
		if delegation, err = BuildVerifier(ctx, cfg, cfg.DelegationAudiences); err != nil {
			return nil, err
		}
	}
	db := store.NewDB(pool)
	keys := NewKeys(kp, cfg.DataKeyRotation, cfg.DataKeyCacheTTL, 4096)
	auditLog := audit.New(db, cfg.AuditStripes)
	core := &Core{DB: db, Policy: auth.NewPolicy(cfg.ExportControlledCategories), Audit: auditLog, Conceal: cfg.ConcealDenied}
	rc := &receipts{core: core, keys: keys}
	authz := SQLAuthorizer{}
	records := &Records{Core: core, keys: keys, receipts: rc, authz: authz, MaxBytes: cfg.MaxRecordBytes,
		MaxResponseBytes: 8 << 20, schemas: cache.New[*jsonschema.Schema](1024, time.Hour)}
	blobs := &Blobs{Core: core, keys: keys, receipts: rc, authz: authz, backend: backend, kms: kp, ChunkSize: cfg.ChunkSize,
		MaxBytes: cfg.MaxBlobBytes, MaxMetaSize: cfg.MaxBlobMetadataBytes, LeaseTTL: 2 * time.Minute}
	registry := auth.NewRegistry(pool)
	return &Container{
		Config: cfg, Pool: pool, DB: db, KMS: kp, Backend: backend, Keys: keys, Audit: auditLog, Core: core,
		Principals: registry, PrincipalAdmin: &Principals{Core: core, Registry: registry}, Blobs: blobs, Records: records,
		Sharing:  &Sharing{Core: core, authz: authz, records: records, blobs: blobs, AppEnv: cfg.AppEnv, Registry: registry},
		Auditing: &Auditing{core: core},
		Worker: &Worker{core: core, blobs: blobs, Backend: backend, ID: "worker-" + nonce(), Batch: 100, Lease: time.Minute,
			Interval: 15 * time.Second},
		receipts: rc, Verifier: verifier, DelegationVerifier: delegation,
	}, nil
}

// AppScope completes an app id from a URL with this deployment's environment.
func (c *Container) AppScope(appID string) (string, error) {
	if !AppIDPattern.MatchString(appID) {
		return "", errs.NotFound("app not found")
	}
	return appID + ":" + c.Config.AppEnv, nil
}

// Operation returns the caller's own receipt for an operation ID.
func (c *Container) Operation(ctx context.Context, cx Ctx, opID string) (*Receipt, error) {
	return c.receipts.Get(ctx, cx, opID)
}

func BuildKMS(ctx context.Context, cfg *config.Config) (crypto.KeyProvider, error) {
	if cfg.KMSBackend == "gcp" {
		client, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			return nil, err
		}
		return crypto.NewGCPKeyProvider(cfg.KMSKeyName, client)
	}
	return crypto.LoadLocalKeyring(cfg.LocalKeyringPath)
}

func BuildBackend(ctx context.Context, cfg *config.Config) (store.Backend, error) {
	switch cfg.BlobBackend {
	case "gcs":
		return store.NewGCS(ctx, cfg.GCSBucket, cfg.GCSPrefix)
	case "s3":
		return store.NewS3(ctx, cfg.S3Bucket, cfg.S3Prefix, cfg.S3EndpointURL, cfg.S3Region)
	default:
		return store.NewLocal(cfg.BlobLocalPath)
	}
}

func BuildVerifier(ctx context.Context, cfg *config.Config, audiences []string) (auth.Verifier, error) {
	if cfg.AuthMode == "oidc" {
		return auth.NewOIDCVerifier(ctx, cfg.OIDCIssuer, cfg.OIDCJWKSURL, audiences, cfg.JWTLeeway, cfg.MaxTokenLifetime)
	}
	return auth.NewDevVerifier(cfg.DevJWTSecret, audiences, cfg.JWTLeeway, cfg.MaxTokenLifetime), nil
}

// ---- audit reads ---------------------------------------------------------------------------------

// Auditing serves audit reads: an app's chains to that app's admins with audit:read, the global
// chain to principals with audit:read.
type Auditing struct{ core *Core }

func (a *Auditing) appAdmin(ctx context.Context, tx pgx.Tx, c Ctx, acc *Access) error {
	if acc.Role != "admin" {
		return a.core.deny(c, auth.AuditRead, "audit", c.App, nil, "app role "+acc.Role, errs.Forbidden("reading the audit log requires the app admin role"))
	}
	_, err := a.core.check(ctx, tx, c, auth.AuditRead, "audit", c.App, nil, checkOpts{noConceal: true, skipAllow: true})
	return err
}

// Events lists one chain of the app (or the global chain when c.App is empty).
func (a *Auditing) Events(ctx context.Context, c Ctx, chain string, after int64, limit int) ([]audit.Event, []string, error) {
	var events []audit.Event
	var chains []string
	run := func(tx pgx.Tx) error {
		var err error
		if chains, err = audit.Chains(ctx, tx); err != nil {
			return err
		}
		if chain == "" && len(chains) > 0 {
			chain = chains[0]
		}
		events, err = audit.List(ctx, tx, chain, after, limit)
		return err
	}
	var err error
	if c.App == "" {
		err = a.core.inGlobal(ctx, c, func(tx pgx.Tx) error {
			if _, err := a.core.check(ctx, tx, c, auth.AuditRead, "audit", "global", nil, checkOpts{noConceal: true, skipAllow: true}); err != nil {
				return err
			}
			return run(tx)
		})
	} else {
		err = a.core.inApp(ctx, c, func(tx pgx.Tx, acc *Access) error {
			if err := a.appAdmin(ctx, tx, c, acc); err != nil {
				return err
			}
			return run(tx)
		})
	}
	if events == nil {
		events = []audit.Event{}
	}
	return events, chains, err
}

// Verify checks every chain of the app (or the global chain).
func (a *Auditing) Verify(ctx context.Context, c Ctx) (audit.VerifyResult, error) {
	var out audit.VerifyResult
	var err error
	if c.App == "" {
		err = a.core.inGlobal(ctx, c, func(tx pgx.Tx) error {
			if _, err := a.core.check(ctx, tx, c, auth.AuditRead, "audit", "global", nil, checkOpts{noConceal: true, skipAllow: true}); err != nil {
				return err
			}
			out, err = a.core.Audit.Verify(ctx, tx)
			return err
		})
	} else {
		err = a.core.inApp(ctx, c, func(tx pgx.Tx, acc *Access) error {
			if err := a.appAdmin(ctx, tx, c, acc); err != nil {
				return err
			}
			out, err = a.core.Audit.Verify(ctx, tx)
			return err
		})
	}
	return out, err
}

// Record appends a standalone event (authentication failures, principal administration).
func (a *Auditing) Record(ctx context.Context, e audit.Entry) error {
	return a.core.Audit.Standalone(ctx, e)
}

// Limits are the request limits this deployment enforces, advertised at GET /v1/limits.
func (c *Container) Limits() map[string]any {
	return map[string]any{
		"max_single_upload_bytes": c.Blobs.MaxBytes,
		"max_blob_metadata_bytes": c.Config.MaxBlobMetadataBytes,
		"max_record_bytes":        c.Config.MaxRecordBytes,
		"max_page":                MaxPage,
		"chunk_size":              c.Config.ChunkSize,
		"app_env":                 c.Config.AppEnv,
	}
}
