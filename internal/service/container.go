package service

import (
	"context"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Container wires configuration into concrete components. The API and CLI build exactly one.
type Container struct {
	Config             *config.Config
	DB                 *pgxpool.Pool
	KMS                crypto.KeyProvider
	Backend            store.Backend
	Keys               *Keys
	Audit              *audit.Log
	Guard              *Guard
	Principals         *auth.Registry
	Blobs              *Blobs
	Records            *Records
	Verifier           auth.Verifier
	DelegationVerifier auth.Verifier
}

// Overrides replace components (tests, alternative deployments).
type Overrides struct {
	DB                 *pgxpool.Pool
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
	db := o.DB
	if db == nil {
		if db, err = store.Open(ctx, cfg.DatabaseURL, ""); err != nil {
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
	keys := NewKeys(db, kp, cfg.DataKeyRotation, cfg.DataKeyCacheTTL)
	sealer := Sealer{keys: keys}
	auditLog := audit.New(db)
	guard := NewGuard(auth.NewPolicy(cfg.ExportControlledCategories), auditLog, cfg.ConcealDenied)
	return &Container{
		Config: cfg, DB: db, KMS: kp, Backend: backend, Keys: keys, Audit: auditLog, Guard: guard,
		Principals: auth.NewRegistry(db),
		Blobs: &Blobs{db: db, backend: backend, kms: kp, sealer: sealer, guard: guard, ChunkSize: cfg.ChunkSize,
			MaxBytes: cfg.MaxBlobBytes, MaxMetaSize: cfg.MaxBlobMetadataBytes},
		Records:            &Records{db: db, keys: keys, sealer: sealer, guard: guard, MaxBytes: cfg.MaxRecordBytes},
		Verifier:           verifier,
		DelegationVerifier: delegation,
	}, nil
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
