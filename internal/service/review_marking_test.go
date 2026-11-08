package service_test

import (
	"context"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

// A resource owner is not a classification authority. In particular, an encrypted
// UNCONTROLLED collection must not permit laundering shared CUI into UNCONTROLLED.
func TestReviewOwnerCannotLowerRecordMarking(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	owner := env.Ctx(t, "admin@rel.test")
	enc := true
	if _, err := env.C.Records.CreateCollection(ctx, owner, service.CollectionInput{
		Name: "classified", Marking: markings.None(), Encrypted: &enc,
	}); err != nil {
		t.Fatal(err)
	}
	r := must[*service.Record](t)(env.C.Records.Create(ctx, owner, "classified", service.RecordInput{
		Data: map[string]any{"secret": "regulated content"}, Marking: &expt, Visibility: "app",
	}))
	reader := env.Ctx(t, "intern@rel.test")
	_, err := env.C.Records.Get(ctx, reader, "classified", r.ID)
	wantCode(t, err, "not_found")
	lower := markings.None()
	_, err = env.C.Records.Update(ctx, owner, "classified", r.ID, service.RecordInput{
		Data: map[string]any{"secret": "regulated content"}, Marking: &lower,
	}, 1)
	if err == nil {
		leaked, readErr := env.C.Records.Get(ctx, reader, "classified", r.ID)
		t.Fatalf("owner lowered CUI to UNCONTROLLED; uncleared reader got %+v, error %v", leaked, readErr)
	}
	wantCode(t, err, "validation_failed")
	got := must[*service.Record](t)(env.C.Records.Get(ctx, owner, "classified", r.ID))
	if got.Version != 1 || !got.Marking.Equal(expt) {
		t.Fatalf("rejected downgrade changed the record: %+v", got)
	}
}
