package api

import (
	"net/http/httptest"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

func TestBudgets(t *testing.T) {
	b := newBudget(&config.Config{RateSubjectPerSecond: 1, RateSubjectBurst: 2, RateAppPerSecond: 100, RateAppBurst: 5, MaxInFlightPerApp: 3})
	var releases []func()
	for i := range 2 {
		rel, err := b.admit("notes:test", "alice")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		releases = append(releases, rel)
	}
	_, err := b.admit("notes:test", "alice")
	if e, ok := errs.As(err); !ok || e.Code != "rate_limited" || e.RetryAfter < 1 {
		t.Fatalf("third request from one subject: %v", err)
	}
	// Another subject has its own bucket but shares the app's in-flight cap (3).
	rel, err := b.admit("notes:test", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.admit("notes:test", "carol"); !errs.Is(err, "rate_limited") {
		t.Fatalf("fourth concurrent request for the app: %v", err)
	}
	rel()
	rel() // idempotent
	if r, err := b.admit("notes:test", "carol"); err != nil {
		t.Fatalf("after a release: %v", err)
	} else {
		r()
	}
	for _, r := range releases {
		r()
	}
	// Another app is independent.
	if r, err := b.admit("tasks:test", "alice"); err != nil {
		t.Fatal(err)
	} else {
		r()
	}
	// The app bucket (burst 5) applies across subjects; refused requests consumed nothing, so
	// alice 2 + bob 1 + carol 1 leave one token.
	if r, err := b.admit("notes:test", "dave"); err != nil {
		t.Fatalf("fifth admitted request: %v", err)
	} else {
		r()
	}
	if _, err := b.admit("notes:test", "erin"); !errs.Is(err, "rate_limited") {
		t.Fatalf("app bucket: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	audited := 0
	for range 50 {
		if b.auditAuthFailure(req) {
			audited++
		}
	}
	if audited != 20 {
		t.Fatalf("%d of 50 auth failures written to the chain; want the burst of 20", audited)
	}
}
