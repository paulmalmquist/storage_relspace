package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

type reviewReceiptKeyBarrier struct {
	crypto.KeyProvider
	entered chan struct{}
	release chan struct{}
}

func (p *reviewReceiptKeyBarrier) Wrap(ctx context.Context, key, aad []byte) (crypto.WrappedKey, error) {
	if strings.HasSuffix(string(aad), "|receipts|receipt") {
		p.entered <- struct{}{}
		select {
		case <-p.release:
		case <-ctx.Done():
			return crypto.WrappedKey{}, ctx.Err()
		}
	}
	return p.KeyProvider.Wrap(ctx, key, aad)
}
func TestReviewConcurrentFirstReceiptsRemainReplayable(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	kms := &reviewReceiptKeyBarrier{KeyProvider: env.C.KMS, entered: make(chan struct{}, 2), release: make(chan struct{})}
	c, err := service.Build(ctx, env.C.Config, service.Overrides{Pool: env.Runtime, KMS: kms, Backend: env.C.Backend})
	if err != nil {
		t.Fatal(err)
	}
	users := []service.Ctx{env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "teammate@rel.test")}
	users[0].OpID = "review-first-receipt-a"
	users[1].OpID = "review-first-receipt-b"
	done := make(chan error, 2)
	for _, u := range users {
		go func(u service.Ctx) { _, err := c.Records.Create(ctx, u, "notes", in(`{"tag":"value"}`)); done <- err }(u)
	}
	timer := time.NewTimer(time.Second)
	waiting := true
	for n := 0; n < 2 && waiting; n++ {
		select {
		case <-kms.entered:
		case <-timer.C:
			waiting = false
		}
	}
	timer.Stop()
	close(kms.release)
	for range users {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range users {
		got, err := c.Records.Create(ctx, u, "notes", in(`{"tag":"value"}`))
		if err != nil {
			t.Errorf("identical retry %s failed after concurrent key creation: %v", u.OpID, err)
			continue
		}
		if !got.Replayed {
			t.Error("retry created another record")
		}
	}
}

func TestReviewTrimmedReceiptNeverReturnsDifferentVersion(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	if _, err := env.C.Records.CreateCollection(ctx, env.Ctx(t, "admin@rel.test"), service.CollectionInput{Name: "short", Marking: cuiExpt, HistoryLimit: 1}); err != nil {
		t.Fatal(err)
	}
	user := env.Ctx(t, "engineer@rel.test")
	rec := must[*service.Record](t)(env.C.Records.Create(ctx, user, "short", in(`{"n":1}`)))
	user.OpID = "review-original-update"
	original := must[*service.Record](t)(env.C.Records.Update(ctx, user, "short", rec.ID, in(`{"n":2}`), 1))
	later := user
	later.OpID = "review-later-update"
	must[*service.Record](t)(env.C.Records.Update(ctx, later, "short", rec.ID, in(`{"n":3}`), 2))
	replay, err := env.C.Records.Update(ctx, user, "short", rec.ID, in(`{"n":2}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Version != original.Version || replay.Data["n"] != original.Data["n"] {
		t.Fatalf("receipt for version %d silently replayed version %d with data %v", original.Version, replay.Version, replay.Data)
	}
}

func TestReviewBlobDeleteUsesReceipt(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	user := env.Ctx(t, "engineer@rel.test")
	blob := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, user, []byte("delete once"), service.BlobInput{Marking: cuiExpt}))
	user.OpID = "review-blob-delete"
	if err := env.C.Blobs.Delete(ctx, user, blob.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := env.C.Blobs.Delete(ctx, user, blob.ID, false); err != nil {
		t.Fatalf("blob delete ignores its operation ID; retry returned %v", err)
	}
}
