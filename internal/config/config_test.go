package config

import (
	"strings"
	"testing"
)

const secret = "0123456789abcdef0123456789abcdef"

func TestDefaultsAndLists(t *testing.T) {
	c, err := FromMap(map[string]string{
		"STRONGBOX_DEV_JWT_SECRET":       secret,
		"STRONGBOX_JWT_AUDIENCES":        `["a","b"]`,
		"STRONGBOX_DELEGATION_AUDIENCES": "x, y",
		"STRONGBOX_DATABASE_URL":         "postgresql+psycopg://u@h:5432/db",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.ChunkSize != 64*KiB || len(c.JWTAudiences) != 2 || c.DelegationAudiences[1] != "y" {
		t.Fatalf("unexpected config %+v", c)
	}
	if c.DatabaseURL != "postgresql://u@h:5432/db" {
		t.Fatalf("SQLAlchemy URL not normalized: %s", c.DatabaseURL)
	}
}

func TestRejections(t *testing.T) {
	cases := map[string]map[string]string{
		"DEV_JWT_SECRET":             {"STRONGBOX_DEV_JWT_SECRET": "short"},
		"chunk_size":                 {"STRONGBOX_DEV_JWT_SECRET": secret, "STRONGBOX_CHUNK_SIZE": "10"},
		"KMS_KEY_NAME":               {"STRONGBOX_DEV_JWT_SECRET": secret, "STRONGBOX_KMS_BACKEND": "gcp"},
		"refusing to start":          {"STRONGBOX_ENV": "production", "STRONGBOX_DEV_JWT_SECRET": secret},
		"must be an integer":         {"STRONGBOX_DEV_JWT_SECRET": secret, "STRONGBOX_MAX_BLOB_BYTES": "lots"},
		"database_url must be a pos": {"STRONGBOX_DEV_JWT_SECRET": secret, "STRONGBOX_DATABASE_URL": "sqlite:///x.db"},
	}
	for want, env := range cases {
		if _, err := FromMap(env); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want error containing %q, got %v", want, err)
		}
	}
}

func TestProductionAccepted(t *testing.T) {
	_, err := FromMap(map[string]string{
		"STRONGBOX_ENV": "production", "STRONGBOX_AUTH_MODE": "oidc", "STRONGBOX_KMS_BACKEND": "gcp",
		"STRONGBOX_KMS_KEY_NAME": "projects/p/locations/us-east4/keyRings/r/cryptoKeys/k", "STRONGBOX_BLOB_BACKEND": "gcs",
		"STRONGBOX_GCS_BUCKET": "b", "STRONGBOX_REQUIRE_FIPS": "true", "STRONGBOX_EXPOSE_DOCS": "false",
	})
	if err != nil {
		t.Fatal(err)
	}
}
