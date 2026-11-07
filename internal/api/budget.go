package api

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/paulmalmquist/storage_relspace/internal/cache"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/telemetry"
)

// budget enforces per-process request budgets: token buckets per (app, subject) and per app, a cap
// on concurrent requests per app, and a bucket per client address for audited authentication
// failures. All state is held in bounded LRUs, so a flood of distinct subjects or addresses
// cannot grow memory. Limits are per instance: with N instances the cluster-wide ceiling is N
// times each value, and Cloud Run's max instances bounds N.
type budget struct {
	subjectRate  rate.Limit
	subjectBurst int
	appRate      rate.Limit
	appBurst     int
	maxInFlight  int

	subjects *cache.LRU[*rate.Limiter]
	apps     *cache.LRU[*rate.Limiter]
	authFail *cache.LRU[*rate.Limiter]

	mu       sync.Mutex
	inFlight map[string]int
}

func newBudget(cfg *config.Config) *budget {
	return &budget{
		subjectRate: rate.Limit(cfg.RateSubjectPerSecond), subjectBurst: cfg.RateSubjectBurst,
		appRate: rate.Limit(cfg.RateAppPerSecond), appBurst: cfg.RateAppBurst, maxInFlight: cfg.MaxInFlightPerApp,
		subjects: cache.New[*rate.Limiter](20_000, 10*time.Minute),
		apps:     cache.New[*rate.Limiter](2_000, time.Hour),
		authFail: cache.New[*rate.Limiter](20_000, 10*time.Minute),
		inFlight: map[string]int{},
	}
}

func limiter(c *cache.LRU[*rate.Limiter], key string, r rate.Limit, burst int) *rate.Limiter {
	l, _ := c.GetOrLoad(key, func() (*rate.Limiter, error) { return rate.NewLimiter(r, burst), nil })
	return l
}

func retryAfter(d time.Duration) error {
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	telemetry.RateLimited.Add(context.Background(), 1, telemetry.Code("rate"))
	return errs.TooManyRequests("rate limit reached; retry after %d seconds", secs).WithRetryAfter(secs)
}

// admit charges one request to the app and to (app, subject) and reserves an in-flight slot. The
// returned release must be called when the request finishes. A refused request consumes nothing.
func (b *budget) admit(app, subject string) (func(), error) {
	if b == nil {
		return func() {}, nil
	}
	release := func() {}
	if b.maxInFlight > 0 {
		b.mu.Lock()
		if b.inFlight[app] >= b.maxInFlight {
			b.mu.Unlock()
			telemetry.RateLimited.Add(context.Background(), 1, telemetry.Code("in_flight"))
			return nil, errs.TooManyRequests("too many concurrent requests for this app; retry shortly").WithRetryAfter(1)
		}
		b.inFlight[app]++
		b.mu.Unlock()
		var once sync.Once
		release = func() {
			once.Do(func() {
				b.mu.Lock()
				if b.inFlight[app]--; b.inFlight[app] <= 0 {
					delete(b.inFlight, app)
				}
				b.mu.Unlock()
			})
		}
	}
	now := time.Now()
	var taken []*rate.Reservation
	refuse := func(d time.Duration) (func(), error) {
		for _, r := range taken {
			r.CancelAt(now)
		}
		release()
		return nil, retryAfter(d)
	}
	if b.appRate > 0 {
		r := limiter(b.apps, app, b.appRate, b.appBurst).ReserveN(now, 1)
		if !r.OK() {
			return refuse(time.Second)
		}
		taken = append(taken, r)
		if d := r.DelayFrom(now); d > 0 {
			return refuse(d)
		}
	}
	if b.subjectRate > 0 {
		r := limiter(b.subjects, app+"\x00"+subject, b.subjectRate, b.subjectBurst).ReserveN(now, 1)
		if !r.OK() {
			return refuse(time.Second)
		}
		taken = append(taken, r)
		if d := r.DelayFrom(now); d > 0 {
			return refuse(d)
		}
	}
	return release, nil
}

// auditAuthFailure reports whether an authentication failure from this client address should be
// written to the audit chain (up to 1 per second, burst 20). Beyond that, failures are still logged
// as structured audit lines, but they do not cost a database write each.
func (b *budget) auditAuthFailure(r *http.Request) bool {
	if b == nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return limiter(b.authFail, host, 1, 20).Allow()
}

func (b *budget) String() string {
	return fmt.Sprintf("subject %.0f/s burst %d, app %.0f/s burst %d, %d in flight per app",
		float64(b.subjectRate), b.subjectBurst, float64(b.appRate), b.appBurst, b.maxInFlight)
}
