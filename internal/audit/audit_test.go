package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
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
	meta, err := env.C.Blobs.Put(ctx, env.Ctx(t, "engineer@rel.test"), []byte("x"),
		service.BlobInput{Marking: markings.MustParse("CUI//SP-EXPT//NOFORN"), Visibility: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.C.Blobs.ReadAll(ctx, env.Ctx(t, "engineer@rel.test"), meta.ID); err != nil {
		t.Fatal(err)
	}
	_, _ = env.C.Blobs.Meta(ctx, env.Ctx(t, "foreign@rel.test"), meta.ID)
	return meta.ID
}

func allEvents(t *testing.T, env *testenv.Env) []audit.Event {
	t.Helper()
	admin := env.Ctx(t, "admin@rel.test")
	var out []audit.Event
	_, chains, err := env.C.Auditing.Events(context.Background(), admin, "", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range chains {
		ev, _, err := env.C.Auditing.Events(context.Background(), admin, ch, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev...)
	}
	return out
}

func TestEventsCoverAllowAndDeny(t *testing.T) {
	env := testenv.New(t)
	activity(t, env)
	want := map[string]bool{"blob.create/allow/engineer@rel.test": false, "blob.read_content/allow/engineer@rel.test": false,
		"blob.read_meta/deny/foreign@rel.test": false}
	for _, e := range allEvents(t, env) {
		if *e.App != testenv.App || !strings.HasPrefix(e.Chain, "app:"+testenv.App+":") {
			t.Fatalf("event on the wrong chain: %+v", e)
		}
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

func TestChainsVerifyAndDetectTampering(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	activity(t, env)
	admin := env.Ctx(t, "admin@rel.test")
	r, err := env.C.Auditing.Verify(ctx, admin)
	if err != nil || !r.OK || len(r.Chains) == 0 {
		t.Fatalf("verify: %v %+v", err, r)
	}
	victim := r.Chains[0]
	env.Admin(t, `UPDATE audit_events SET actor='someone-else' WHERE chain=$1 AND seq=1`, victim.Chain)
	r, _ = env.C.Auditing.Verify(ctx, admin)
	if r.OK {
		t.Fatal("edit not detected")
	}
	for _, c := range r.Chains {
		if c.Chain == victim.Chain && (c.OK || c.FirstInvalidSeq == nil || *c.FirstInvalidSeq != 1) {
			t.Fatalf("wrong chain result %+v", c)
		}
	}
}

func TestOnlyAppAdminsReadTheAppLog(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	activity(t, env)
	_, _, err := env.C.Auditing.Events(ctx, env.Ctx(t, "engineer@rel.test"), "", 0, 10)
	if err == nil {
		t.Fatal("non-admin read the app audit log")
	}
	// The other app's admin sees only the other app's chains.
	_, chains, err := env.C.Auditing.Events(ctx, env.CtxIn(t, testenv.Other, "outsider@rel.test"), "", 0, 10)
	if err == nil && len(chains) != 0 {
		t.Fatalf("other app sees chains %v", chains)
	}
}

func TestConcurrentWritersKeepChainsIntact(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if _, err := env.C.Blobs.Put(ctx, eng, []byte("x"), service.BlobInput{}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	r, err := env.C.Auditing.Verify(ctx, env.Ctx(t, "admin@rel.test"))
	var total int64
	for _, c := range r.Chains {
		total += c.Checked
	}
	if err != nil || !r.OK || total < 80 || len(r.Chains) < 2 {
		t.Fatalf("verify after concurrency: %v ok=%v events=%d chains=%d", err, r.OK, total, len(r.Chains))
	}
}

// Delivery exports committed events exactly in chain order and advances a cursor; a second pass
// sends nothing new.
func TestDeliveryIsCursorBased(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	activity(t, env)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	s1, err := env.C.Worker.RunOnce(ctx)
	if err != nil || s1.AuditDelivered < 3 {
		t.Fatalf("first pass: %v %+v", err, s1)
	}
	lines := strings.Count(buf.String(), `"audit":true`)
	if lines != s1.AuditDelivered {
		t.Fatalf("%d lines for %d events", lines, s1.AuditDelivered)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		_ = json.Unmarshal([]byte(line), &m)
		if m["audit"] == true && (m["chain"] == nil || m["hash"] == nil) {
			t.Fatalf("delivered event lacks chain linkage: %s", line)
		}
	}
	s2, _ := env.C.Worker.RunOnce(ctx)
	if s2.AuditDelivered != 0 || s2.AuditUndelivered != 0 {
		t.Fatalf("second pass re-delivered: %+v", s2)
	}
}
