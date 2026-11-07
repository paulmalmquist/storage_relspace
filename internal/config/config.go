// Package config loads STRONGBOX_* settings from the environment. Production mode refuses unsafe settings.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	KiB = 1024
	MiB = 1024 * KiB
	GiB = 1024 * MiB
)

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

type Config struct {
	Env string // dev | test | production

	DatabaseURL string // runtime login: member of strongbox_runtime only
	// MigrationDatabaseURL is the privileged login (member of strongbox_owner) used by init, db and
	// admin commands. It defaults to DatabaseURL for single-login development setups.
	MigrationDatabaseURL  string
	DBSchema              string
	DBMaxConns            int32
	DBStatementTimeout    time.Duration
	AllowPrivilegedDBRole bool // development only: let serve run with a login that fails the role check

	// AppEnv is the environment this deployment serves. Requests name an app; the environment is
	// fixed by the deployment, never chosen by the caller.
	AppEnv       string
	AuditStripes int

	KMSBackend       string // local | gcp
	KMSKeyName       string
	LocalKeyringPath string

	BlobBackend   string // local | gcs | s3
	BlobLocalPath string
	GCSBucket     string
	GCSPrefix     string
	S3Bucket      string
	S3Prefix      string
	S3EndpointURL string
	S3Region      string

	MaxBlobBytes         int64 // largest blob, through an upload session
	MaxSingleUploadBytes int64 // largest one-request upload; below the transport's request limit
	UploadPartBytes      int   // plaintext per upload-session part (a multiple of ChunkSize)
	UploadSessionTTL     time.Duration
	ChunkSize            int
	MaxRecordBytes       int
	MaxBlobMetadataBytes int

	// Request budgets. Rate limits are per process: with N instances the cluster-wide ceiling is N
	// times these values.
	RateSubjectPerSecond float64 // per (app, subject); 0 disables
	RateSubjectBurst     int
	RateAppPerSecond     float64 // per app; 0 disables
	RateAppBurst         int
	MaxInFlightPerApp    int           // concurrent requests per app; 0 disables
	DBAcquireTimeout     time.Duration // waiting for a pooled connection beyond this is 503
	RequestTimeout       time.Duration // non-streaming requests
	KMSTimeout           time.Duration
	MetricsExporter      string // none | gcp (Cloud Monitoring) | stdout

	DataKeyRotation time.Duration
	DataKeyCacheTTL time.Duration

	AuthMode            string // dev-hs256 | oidc
	DevJWTSecret        string
	JWTAudiences        []string
	DelegationAudiences []string
	OIDCIssuer          string
	OIDCJWKSURL         string
	JWTLeeway           time.Duration
	MaxTokenLifetime    time.Duration

	ExportControlledCategories []string
	ConcealDenied              bool

	RequireFIPS bool
	ExposeDocs  bool
	LogLevel    string

	// Deprecations lists accepted-but-deprecated settings; commands log them at startup.
	Deprecations []string
}

// Load reads the process environment.
func Load() (*Config, error) { return FromLookup(os.LookupEnv) }

// FromMap builds a config from explicit values (tests).
func FromMap(m map[string]string) (*Config, error) {
	return FromLookup(func(k string) (string, bool) { v, ok := m[k]; return v, ok })
}

type reader struct {
	lookup func(string) (string, bool)
	errs   []string
}

func (r *reader) str(name, def string) string {
	if v, ok := r.lookup("STRONGBOX_" + name); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func (r *reader) integer(name string, def int64) int64 {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		r.errs = append(r.errs, fmt.Sprintf("STRONGBOX_%s must be an integer", name))
		return def
	}
	return n
}

func (r *reader) float(name string, def float64) float64 {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		r.errs = append(r.errs, fmt.Sprintf("STRONGBOX_%s must be a number", name))
		return def
	}
	return f
}

func (r *reader) boolean(name string, def bool) bool {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.errs = append(r.errs, fmt.Sprintf("STRONGBOX_%s must be true or false", name))
		return def
	}
	return b
}

// list accepts a JSON array (["a","b"]) or a comma-separated string.
func (r *reader) list(name string, def []string) []string {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	if strings.HasPrefix(v, "[") {
		var out []string
		if err := json.Unmarshal([]byte(v), &out); err != nil {
			r.errs = append(r.errs, fmt.Sprintf("STRONGBOX_%s must be a JSON array of strings", name))
			return def
		}
		return out
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func FromLookup(lookup func(string) (string, bool)) (*Config, error) {
	r := &reader{lookup: lookup}
	c := &Config{
		Env:                        r.str("ENV", "dev"),
		DatabaseURL:                r.str("DATABASE_URL", "postgres://postgres@localhost:5432/strongbox"),
		MigrationDatabaseURL:       r.str("MIGRATION_DATABASE_URL", ""),
		DBSchema:                   r.str("DB_SCHEMA", "strongbox"),
		DBMaxConns:                 int32(r.integer("DB_MAX_CONNS", 10)),
		DBStatementTimeout:         time.Duration(r.integer("DB_STATEMENT_TIMEOUT_MS", 15000)) * time.Millisecond,
		AllowPrivilegedDBRole:      r.boolean("ALLOW_PRIVILEGED_DB_ROLE", false),
		AppEnv:                     r.str("APP_ENV", ""),
		AuditStripes:               int(r.integer("AUDIT_STRIPES", 4)),
		KMSBackend:                 r.str("KMS_BACKEND", "local"),
		KMSKeyName:                 r.str("KMS_KEY_NAME", ""),
		LocalKeyringPath:           r.str("LOCAL_KEYRING_PATH", ".strongbox/keyring.json"),
		BlobBackend:                r.str("BLOB_BACKEND", "local"),
		BlobLocalPath:              r.str("BLOB_LOCAL_PATH", ".strongbox/blobs"),
		GCSBucket:                  r.str("GCS_BUCKET", ""),
		GCSPrefix:                  r.str("GCS_PREFIX", "objects/"),
		S3Bucket:                   r.str("S3_BUCKET", ""),
		S3Prefix:                   r.str("S3_PREFIX", "objects/"),
		S3EndpointURL:              r.str("S3_ENDPOINT_URL", ""),
		S3Region:                   r.str("S3_REGION", ""),
		MaxBlobBytes:               r.integer("MAX_BLOB_BYTES", 5*GiB),
		MaxSingleUploadBytes:       r.integer("MAX_SINGLE_UPLOAD_BYTES", 16*MiB),
		UploadPartBytes:            int(r.integer("UPLOAD_PART_BYTES", 8*MiB)),
		UploadSessionTTL:           time.Duration(r.integer("UPLOAD_SESSION_TTL_SECONDS", 24*3600)) * time.Second,
		RateSubjectPerSecond:       r.float("RATE_SUBJECT_PER_SECOND", 50),
		RateSubjectBurst:           int(r.integer("RATE_SUBJECT_BURST", 100)),
		RateAppPerSecond:           r.float("RATE_APP_PER_SECOND", 500),
		RateAppBurst:               int(r.integer("RATE_APP_BURST", 1000)),
		MaxInFlightPerApp:          int(r.integer("MAX_IN_FLIGHT_PER_APP", 64)),
		DBAcquireTimeout:           time.Duration(r.integer("DB_ACQUIRE_TIMEOUT_MS", 3000)) * time.Millisecond,
		RequestTimeout:             time.Duration(r.integer("REQUEST_TIMEOUT_MS", 30000)) * time.Millisecond,
		KMSTimeout:                 time.Duration(r.integer("KMS_TIMEOUT_MS", 10000)) * time.Millisecond,
		MetricsExporter:            r.str("METRICS_EXPORTER", "none"),
		ChunkSize:                  int(r.integer("CHUNK_SIZE", 64*KiB)),
		MaxRecordBytes:             int(r.integer("MAX_RECORD_BYTES", 1*MiB)),
		MaxBlobMetadataBytes:       int(r.integer("MAX_BLOB_METADATA_BYTES", 16*KiB)),
		DataKeyRotation:            time.Duration(r.integer("DATA_KEY_ROTATION_SECONDS", 7*24*3600)) * time.Second,
		DataKeyCacheTTL:            time.Duration(r.integer("DATA_KEY_CACHE_TTL_SECONDS", 300)) * time.Second,
		AuthMode:                   r.str("AUTH_MODE", "dev-hs256"),
		DevJWTSecret:               r.str("DEV_JWT_SECRET", ""),
		JWTAudiences:               r.list("JWT_AUDIENCES", []string{"strongbox"}),
		DelegationAudiences:        r.list("DELEGATION_AUDIENCES", []string{"strongbox"}),
		OIDCIssuer:                 r.str("OIDC_ISSUER", "https://accounts.google.com"),
		OIDCJWKSURL:                r.str("OIDC_JWKS_URL", "https://www.googleapis.com/oauth2/v3/certs"),
		JWTLeeway:                  time.Duration(r.integer("JWT_LEEWAY_SECONDS", 30)) * time.Second,
		MaxTokenLifetime:           time.Duration(r.integer("MAX_TOKEN_LIFETIME_SECONDS", 86400)) * time.Second,
		ExportControlledCategories: r.list("EXPORT_CONTROLLED_CATEGORIES", []string{"SP-EXPT", "EXPT", "SP-EXPTR", "EXPTR"}),
		ConcealDenied:              r.boolean("CONCEAL_DENIED_RESOURCES", true),
		RequireFIPS:                r.boolean("REQUIRE_FIPS", false),
		ExposeDocs:                 r.boolean("EXPOSE_DOCS", true),
		LogLevel:                   r.str("LOG_LEVEL", "INFO"),
	}
	if len(r.errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %s", strings.Join(r.errs, "; "))
	}
	var deprecated bool
	if c.DatabaseURL, deprecated = normalizeDBURL(c.DatabaseURL); deprecated {
		c.Deprecations = append(c.Deprecations, "STRONGBOX_DATABASE_URL uses a driver-qualified scheme "+
			"(postgresql+psycopg://); use postgres:// instead. Support for the old form will be removed.")
	}
	if c.MigrationDatabaseURL == "" {
		c.MigrationDatabaseURL = c.DatabaseURL
	} else {
		c.MigrationDatabaseURL, _ = normalizeDBURL(c.MigrationDatabaseURL)
	}
	if c.AppEnv == "" {
		c.AppEnv = map[string]string{"dev": "dev", "test": "test", "production": "prod"}[c.Env]
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// normalizeDBURL accepts the legacy driver-qualified URL form (postgresql+psycopg://) that earlier
// deployments were configured with. It is deprecated: the second result reports when it was used.
func normalizeDBURL(u string) (string, bool) {
	for _, p := range []string{"postgresql+psycopg://", "postgresql+psycopg2://"} {
		if strings.HasPrefix(u, p) {
			return "postgresql://" + strings.TrimPrefix(u, p), true
		}
	}
	return u, false
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func (c *Config) Validate() error {
	var problems []string
	add := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }

	if !oneOf(c.Env, "dev", "test", "production") {
		add("env must be dev, test or production")
	}
	if !oneOf(c.KMSBackend, "local", "gcp") {
		add("kms_backend must be local or gcp")
	}
	if !oneOf(c.BlobBackend, "local", "gcs", "s3") {
		add("blob_backend must be local, gcs or s3")
	}
	if !oneOf(c.AuthMode, "dev-hs256", "oidc") {
		add("auth_mode must be dev-hs256 or oidc")
	}
	if c.ChunkSize < 4*KiB || c.ChunkSize > 4*MiB {
		add("chunk_size must be between 4 KiB and 4 MiB")
	}
	// Cloud Run limits HTTP/1 request bodies to 32 MiB; stay well under it.
	if c.MaxSingleUploadBytes < 1 || c.MaxSingleUploadBytes > 32*MiB {
		add("max_single_upload_bytes must be between 1 byte and 32 MiB")
	}
	if c.ChunkSize > 0 && (c.UploadPartBytes < c.ChunkSize || c.UploadPartBytes%c.ChunkSize != 0 || int64(c.UploadPartBytes) > c.MaxSingleUploadBytes) {
		add("upload_part_bytes must be a multiple of chunk_size and at most max_single_upload_bytes")
	}
	if c.MaxBlobBytes < c.MaxSingleUploadBytes {
		add("max_blob_bytes must be at least max_single_upload_bytes")
	}
	if c.UploadSessionTTL < time.Minute {
		add("upload_session_ttl_seconds must be at least 60")
	}
	if c.RateSubjectPerSecond < 0 || c.RateAppPerSecond < 0 || c.MaxInFlightPerApp < 0 {
		add("rate limits must not be negative")
	}
	if (c.RateSubjectPerSecond > 0 && c.RateSubjectBurst < 1) || (c.RateAppPerSecond > 0 && c.RateAppBurst < 1) {
		add("rate limit bursts must be at least 1")
	}
	if c.DBAcquireTimeout <= 0 || c.RequestTimeout <= 0 || c.KMSTimeout <= 0 {
		add("timeouts must be positive")
	}
	if !oneOf(c.MetricsExporter, "none", "gcp", "stdout") {
		add("metrics_exporter must be none, gcp or stdout")
	}
	if !strings.HasPrefix(c.DatabaseURL, "postgres://") && !strings.HasPrefix(c.DatabaseURL, "postgresql://") {
		add("database_url must be a postgres:// URL")
	}
	if !oneOf(c.AppEnv, "dev", "test", "staging", "prod") {
		add("app_env must be dev, test, staging or prod")
	}
	if !schemaName.MatchString(c.DBSchema) {
		add("db_schema must match %s", schemaName)
	}
	if c.DBMaxConns < 2 || c.DBMaxConns > 200 {
		add("db_max_conns must be between 2 and 200")
	}
	if c.AuditStripes < 1 || c.AuditStripes > 64 {
		add("audit_stripes must be between 1 and 64")
	}
	if c.KMSBackend == "gcp" && c.KMSKeyName == "" {
		add("STRONGBOX_KMS_KEY_NAME is required when kms_backend=gcp")
	}
	if c.BlobBackend == "gcs" && c.GCSBucket == "" {
		add("STRONGBOX_GCS_BUCKET is required when blob_backend=gcs")
	}
	if c.BlobBackend == "s3" && c.S3Bucket == "" {
		add("STRONGBOX_S3_BUCKET is required when blob_backend=s3")
	}
	if c.AuthMode == "dev-hs256" && len(c.DevJWTSecret) < 32 {
		add("STRONGBOX_DEV_JWT_SECRET must be at least 32 characters in dev-hs256 mode")
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(problems, "; "))
	}

	if c.Env == "production" {
		if c.KMSBackend == "local" {
			add("kms_backend=local (use gcp with an HSM-protected key)")
		}
		if c.AuthMode == "dev-hs256" {
			add("auth_mode=dev-hs256 (use oidc)")
		}
		if c.BlobBackend == "local" {
			add("blob_backend=local (use gcs or s3)")
		}
		if !c.RequireFIPS {
			add("require_fips=false (CUI requires FIPS-validated crypto)")
		}
		if c.ExposeDocs {
			add("expose_docs=true")
		}
		if c.AllowPrivilegedDBRole {
			add("allow_privileged_db_role=true")
		}
		if c.AppEnv == "dev" || c.AppEnv == "test" {
			add("app_env=%s", c.AppEnv)
		}
		if len(problems) > 0 {
			return fmt.Errorf("refusing to start in production: %s", strings.Join(problems, "; "))
		}
	}
	return nil
}
