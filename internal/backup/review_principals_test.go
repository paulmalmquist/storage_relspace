package backup_test

import (
	"context"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestReviewSharedRestoreCannotImportPlatformAdministrator(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	dir := reviewExport(t, src)
	dst := testenv.Empty(t, src.Keyring)
	if err := dst.C.Principals.Put(ctx, auth.Spec{Subject: "target-operator@rel.test", Kind: auth.KindUser, Scopes: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	dst.Admin(t, `INSERT INTO apps(app,created_by) VALUES($1,'target-operator@rel.test')`, testenv.Other)
	dst.Admin(t, `INSERT INTO app_members(app,subject,role,added_by) VALUES($1,'target-operator@rel.test','admin','target-operator@rel.test')`, testenv.Other)
	if _, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, false); err != nil {
		t.Logf("restore refused: %v", err)
		return
	} // refusing unprovisioned source identities is safe
	imported := dst.Ctx(t, "admin@rel.test") // this principal came only from the source app's export
	imported.App = ""                        // the global principal-administration endpoint has no app path
	err := dst.C.PrincipalAdmin.Put(ctx, imported, auth.Spec{Subject: "target-operator@rel.test", Kind: auth.KindUser, Disabled: true})
	if err == nil {
		t.Fatal("restoring one app imported a platform administrator able to disable another app's operator")
	}
}
