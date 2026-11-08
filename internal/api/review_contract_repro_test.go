package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paulmalmquist/storage_relspace/internal/api"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestReviewMutationsRequireOperationID(t *testing.T) {
	_, c := setup(t)
	r := c.do("POST", app+"/collections", strings.NewReader(ncrBody), map[string]string{"Authorization": "Bearer " + testenv.Token(t, "admin@rel.test")})
	if r.status >= 200 && r.status < 300 {
		t.Fatalf("collection mutation without Idempotency-Key succeeded: %d", r.status)
	}
}
func TestReviewDeleteRequiresIfMatch(t *testing.T) {
	_, c := setup(t)
	if r := c.do("POST", app+"/collections", strings.NewReader(ncrBody), as(t, "admin@rel.test", "Idempotency-Key", "review-collection-1")); r.status != 201 {
		t.Fatal(string(r.body))
	}
	r := c.do("POST", app+"/collections/ncr/records", strings.NewReader(`{"data":{"part_number":"A"}}`), as(t, "engineer@rel.test", "Idempotency-Key", "review-create-0001"))
	if r.status != 201 {
		t.Fatal(string(r.body))
	}
	id := r.json(t)["id"].(string)
	r = c.do("DELETE", app+"/collections/ncr/records/"+id, nil, as(t, "engineer@rel.test", "Idempotency-Key", "review-delete-0001"))
	if r.status != 428 {
		t.Fatalf("delete without If-Match returned %d, want 428; %s", r.status, r.body)
	}
}

type reviewDeadlineVerifier struct{ observed bool }

func (v *reviewDeadlineVerifier) Verify(ctx context.Context, _ string) (*auth.VerifiedToken, error) {
	_, v.observed = ctx.Deadline()
	return &auth.VerifiedToken{Subject: "engineer@rel.test"}, nil
}
func TestReviewDeadlineStartsBeforeAuthentication(t *testing.T) {
	env := testenv.New(t)
	env.C.Config.RequestTimeout = 25 * time.Millisecond
	v := &reviewDeadlineVerifier{}
	env.C.Verifier = v
	req := httptest.NewRequest(http.MethodGet, app, nil)
	req.Header.Set("Authorization", "Bearer test")
	rec := httptest.NewRecorder()
	api.New(env.C).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("request failed: %d %s", rec.Code, rec.Body.String())
	}
	if !v.observed {
		t.Fatal("authentication and principal-pool acquisition run without the configured request deadline")
	}
}

func TestReviewPrincipalLookupUsesAcquisitionBudget(t *testing.T) {
	env := testenv.New(t)
	env.C.Config.RequestTimeout = 25 * time.Millisecond
	env.C.DB.AcquireTimeout = 20 * time.Millisecond
	var held []*pgxpool.Conn
	for i := int32(0); i < env.Runtime.Config().MaxConns; i++ {
		conn, err := env.Runtime.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	defer func() {
		for _, c := range held {
			c.Release()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, app, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testenv.Token(t, "engineer@rel.test"))
	rec := httptest.NewRecorder()
	api.New(env.C).ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("pool-exhausted authentication ignored the 20ms acquisition budget and returned %d: %s", rec.Code, rec.Body.String())
	}
}
