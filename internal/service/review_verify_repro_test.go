package service_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestReviewDeepVerifyChecksMultipartDigestList(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	user := env.Ctx(t, "engineer@rel.test")
	session := must[*service.UploadSession](t)(env.C.Blobs.CreateSession(ctx, user, service.BlobInput{Marking: cuiExpt, DeclaredSize: 1}))
	if _, err := env.C.Blobs.PutPart(ctx, user, session.ID, 1, bytes.NewReader([]byte("a"))); err != nil {
		t.Fatal(err)
	}
	must[*service.BlobMeta](t)(env.C.Blobs.CompleteSession(ctx, user, session.ID))
	env.Admin(t, `UPDATE blobs SET ciphertext_sha256=$2 WHERE id=$1`, session.ID, strings.Repeat("0", 64))
	_, _, err := env.C.Blobs.ReadAll(ctx, user, session.ID)
	wantCode(t, err, "integrity_violation")
	report, err := env.C.VerifyApp(ctx, testenv.App, true)
	if err == nil && len(report.Problems) == 0 {
		t.Fatal("deep verification accepted a multipart digest list rejected by the normal read path")
	}
}
