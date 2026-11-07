package audit_test

import (
	"context"
	"sync"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func activity(t *testing.T, env *testenv.Env) string {
	t.Helper()
	ctx := context.Background()
	meta, err := env.C.Blobs.Put(ctx, env.Ctx(t, "engineer@rel.test"), []byte("x"), service.BlobInput{Marking: markings.MustParse("CUI//SP-EXPT")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.C.Blobs.ReadAll(ctx, env.Ctx(t, "engineer@rel.test"), meta.ID); err != nil {
		t.Fatal(err)
	}
	_, _ = env.C.Blobs.Meta(ctx, env.Ctx(t, "foreign@rel.test"), meta.ID)
	return meta.ID
}

func TestEventsCoverAllowAndDeny(t *testing.T) {
	env := testenv.New(t)
	activity(t, env)
	events, _ := env.C.Audit.List(context.Background(), 0, 100)
	want := map[string]bool{"blob.create/allow/engineer@rel.test": false, "blob.read_content/allow/engineer@rel.test": false,
		"blob.read_meta/deny/foreign@rel.test": false}
	for _, e := range events {
		k := e.Action + "/" + e.Decision + "/" + e.Actor
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing audit event %s", k)
		}
	}
}

func TestChainVerifiesAndDetectsTampering(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	activity(t, env)
	r, err := env.C.Audit.Verify(ctx)
	if err != nil || !r.OK || r.Checked != r.HeadSeq || r.Checked < 3 {
		t.Fatalf("verify: %v %+v", err, r)
	}
	if _, err := env.C.DB.Exec(ctx, `UPDATE audit_events SET actor='someone-else' WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	r, _ = env.C.Audit.Verify(ctx)
	if r.OK || r.FirstInvalidSeq == nil || *r.FirstInvalidSeq != 2 {
		t.Fatalf("edit not detected: %+v", r)
	}
}

func TestDeletionAndTruncationDetected(t *testing.T) {
	for _, q := range []string{`DELETE FROM audit_events WHERE seq=1`, `DELETE FROM audit_events WHERE seq=(SELECT max(seq) FROM audit_events)`} {
		env, ctx := testenv.New(t), context.Background()
		activity(t, env)
		if _, err := env.C.DB.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
		if r, _ := env.C.Audit.Verify(ctx); r.OK {
			t.Fatalf("not detected: %s", q)
		}
	}
}

func TestDelegatedActionsRecordBothIdentities(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	user, agent := env.Ctx(t, "engineer@rel.test").Principal, env.Ctx(t, "agent:assistant").Principal
	c := service.Ctx{Principal: user.DelegatedTo(agent), RequestID: "r"}
	if _, _, err := env.C.Blobs.List(ctx, c, 0, ""); err != nil {
		t.Fatal(err)
	}
	events, _ := env.C.Audit.List(ctx, 0, 100)
	last := events[len(events)-1]
	if last.Actor != "agent:assistant" || last.OnBehalfOf == nil || *last.OnBehalfOf != "engineer@rel.test" || last.ActorKind != "agent" {
		t.Fatalf("delegation not recorded: %+v", last)
	}
}

// Separate Log instances stand in for separate replicas; ordering relies on SELECT ... FOR UPDATE.
func TestConcurrentWritersKeepChainValid(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	logs := []*audit.Log{audit.New(env.C.DB), audit.New(env.C.DB)}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 10 {
				if _, err := logs[i%2].Record(ctx, audit.Entry{Action: "test.concurrency", ResourceType: "test",
					ResourceID: string(rune('a' + j)), Decision: "allow", Reason: "load"}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	r, err := env.C.Audit.Verify(ctx)
	if err != nil || !r.OK || r.Checked != 80 {
		t.Fatalf("chain after concurrent writes: %v %+v", err, r)
	}
}
