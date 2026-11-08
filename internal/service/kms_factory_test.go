package service_test

import (
	"context"
	"crypto/fips140"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"path/filepath"
	"testing"
)

func TestStandaloneKMSFactoryHonorsRequiredFIPS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if _, err := crypto.CreateLocalKeyring(path); err != nil {
		t.Fatal(err)
	}
	_, err := service.BuildKMS(context.Background(), &config.Config{KMSBackend: "local", LocalKeyringPath: path, RequireFIPS: true})
	if fips140.Enabled() && err != nil {
		t.Fatal(err)
	}
	if !fips140.Enabled() && err == nil {
		t.Fatal("standalone factory ignored required FIPS mode")
	}
}
