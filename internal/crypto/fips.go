package crypto

import (
	"crypto/fips140"
	"runtime"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

// FIPSStatus reports the state of Go's native FIPS 140-3 module.
//
// Build with GOFIPS140=v1.0.0 (the module version submitted for CMVP validation) and run with
// GODEBUG=fips140=on, or fips140=only to make non-approved algorithms fail outright. No OpenSSL is
// involved, so the validation boundary is the Go module itself plus Cloud KMS HSMs for key wrapping.
func FIPSStatus() map[string]any {
	return map[string]any{
		"fips_enabled":   fips140.Enabled(),
		"fips_enforced":  fips140.Enforced(),
		"module_version": fips140.Version(),
		"go_version":     runtime.Version(),
	}
}

// AssertFIPS fails unless the FIPS 140-3 module is active.
func AssertFIPS() error {
	if !fips140.Enabled() {
		return errs.Config("FIPS 140-3 mode is required but not active; build with GOFIPS140=v1.0.0 " +
			"and run with GODEBUG=fips140=on (or =only), or unset STRONGBOX_REQUIRE_FIPS outside production")
	}
	return nil
}
