// Package telemetry holds Strongbox's OpenTelemetry metrics.
//
// Label policy: attributes are drawn from small fixed sets (route templates, methods, status
// codes, error codes, operation kinds, outcomes). App IDs, subjects, resource IDs, markings,
// filenames and raw paths are never attributes: they are high-cardinality, and several are
// sensitive. Per-app numbers come from the database (GET /v1/apps/{app}/usage, the admin CLI), not
// from metrics. TestLabelsAreBounded enforces this.
package telemetry

import (
	"context"
	"errors"
	"runtime/metrics"
	"time"

	mexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

const scope = "github.com/paulmalmquist/storage_relspace"

// Instruments are created once from the global provider. Before Setup (and in tests that do not
// call it) they are no-ops.
var (
	RequestDuration metric.Float64Histogram
	Errors          metric.Int64Counter
	RateLimited     metric.Int64Counter
	PoolWait        metric.Float64Histogram
	KMSDuration     metric.Float64Histogram
	Replays         metric.Int64Counter
	OutboxJobs      metric.Int64Counter
	AuditDelivered  metric.Int64Counter
	AuthAuditSkips  metric.Int64Counter
)

func init() { create(otel.GetMeterProvider()) }

// Install points the instruments at mp (tests use a manual reader).
func Install(mp metric.MeterProvider) { create(mp) }

// AllowedKeys are the only attribute keys Strongbox records.
var AllowedKeys = map[string]bool{"http.route": true, "http.request.method": true, "http.response.status_code": true,
	"code": true, "op": true, "outcome": true, "state": true, "result": true}

func create(mp metric.MeterProvider) {
	m := mp.Meter(scope)
	sec := metric.WithUnit("s")
	buckets := metric.WithExplicitBucketBoundaries(0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)
	RequestDuration, _ = m.Float64Histogram("http.server.request.duration", sec, buckets,
		metric.WithDescription("API request latency by route template, method and status"))
	Errors, _ = m.Int64Counter("strongbox.errors", metric.WithDescription("Error responses by stable error code"))
	RateLimited, _ = m.Int64Counter("strongbox.rate_limited", metric.WithDescription("Requests refused by a request budget"))
	PoolWait, _ = m.Float64Histogram("strongbox.db.pool.wait", sec, buckets,
		metric.WithDescription("Time spent waiting for a database connection"))
	KMSDuration, _ = m.Float64Histogram("strongbox.kms.duration", sec, buckets,
		metric.WithDescription("Cloud KMS wrap/unwrap latency by operation and outcome"))
	Replays, _ = m.Int64Counter("strongbox.operation.replays", metric.WithDescription("Retried operations answered from a receipt"))
	OutboxJobs, _ = m.Int64Counter("strongbox.outbox.jobs", metric.WithDescription("Outbox jobs by kind and outcome"))
	AuditDelivered, _ = m.Int64Counter("strongbox.audit.delivered", metric.WithDescription("Audit events delivered to the log sink"))
	AuthAuditSkips, _ = m.Int64Counter("strongbox.auth.audit_suppressed",
		metric.WithDescription("Authentication failures logged without a chain write (per-address burst exceeded)"))
}

// Gauges are read when metrics are collected.
type Gauges struct {
	Pool         func() (acquired, idle, total, max int64)
	OutboxLag    func() time.Duration // age of the oldest runnable job
	AuditBacklog func() int64         // committed audit events not yet delivered
	DeadJobs     func() int64
	CacheStats   func() (hits, misses int64)
}

// Setup installs the meter provider. exporter is none, stdout (development) or gcp (Cloud
// Monitoring, using the runtime service account). It returns a shutdown function that flushes.
func Setup(ctx context.Context, exporter, service, version string, g Gauges) (func(context.Context) error, error) {
	var reader sdkmetric.Reader
	switch exporter {
	case "", "none":
		return func(context.Context) error { return nil }, nil
	case "stdout":
		exp, err := stdoutmetric.New()
		if err != nil {
			return nil, err
		}
		reader = sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(time.Minute))
	case "gcp":
		exp, err := mexporter.New()
		if err != nil {
			return nil, err
		}
		reader = sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(time.Minute))
	default:
		return nil, errors.New("unknown metrics exporter " + exporter)
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", service), attribute.String("service.version", version)))
	if err != nil {
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res))
	otel.SetMeterProvider(mp)
	create(mp)
	if err := RegisterGauges(mp, g); err != nil {
		return nil, err
	}
	return mp.Shutdown, nil
}

// RegisterGauges adds observable instruments for pool, worker, cache and runtime state.
func RegisterGauges(mp metric.MeterProvider, g Gauges) error {
	m := mp.Meter(scope)
	pool, _ := m.Int64ObservableGauge("strongbox.db.pool.connections", metric.WithDescription("Pool connections by state"))
	lag, _ := m.Float64ObservableGauge("strongbox.outbox.lag", metric.WithUnit("s"), metric.WithDescription("Age of the oldest runnable outbox job"))
	backlog, _ := m.Int64ObservableGauge("strongbox.audit.backlog", metric.WithDescription("Committed audit events not yet delivered"))
	dead, _ := m.Int64ObservableGauge("strongbox.outbox.dead", metric.WithDescription("Outbox jobs that exhausted their retries"))
	cache, _ := m.Int64ObservableCounter("strongbox.cache.lookups", metric.WithDescription("Data-key cache lookups by result"))
	heap, _ := m.Int64ObservableGauge("strongbox.runtime.heap", metric.WithUnit("By"), metric.WithDescription("Live heap bytes"))
	goroutines, _ := m.Int64ObservableGauge("strongbox.runtime.goroutines")
	samples := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/sched/goroutines:goroutines"}}
	_, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		if g.Pool != nil {
			acquired, idle, total, max := g.Pool()
			o.ObserveInt64(pool, acquired, metric.WithAttributes(attribute.String("state", "acquired")))
			o.ObserveInt64(pool, idle, metric.WithAttributes(attribute.String("state", "idle")))
			o.ObserveInt64(pool, total, metric.WithAttributes(attribute.String("state", "total")))
			o.ObserveInt64(pool, max, metric.WithAttributes(attribute.String("state", "max")))
		}
		if g.OutboxLag != nil {
			o.ObserveFloat64(lag, g.OutboxLag().Seconds())
		}
		if g.AuditBacklog != nil {
			o.ObserveInt64(backlog, g.AuditBacklog())
		}
		if g.DeadJobs != nil {
			o.ObserveInt64(dead, g.DeadJobs())
		}
		if g.CacheStats != nil {
			hits, misses := g.CacheStats()
			o.ObserveInt64(cache, hits, metric.WithAttributes(attribute.String("result", "hit")))
			o.ObserveInt64(cache, misses, metric.WithAttributes(attribute.String("result", "miss")))
		}
		metrics.Read(samples)
		if samples[0].Value.Kind() == metrics.KindUint64 {
			o.ObserveInt64(heap, int64(samples[0].Value.Uint64()))
		}
		if samples[1].Value.Kind() == metrics.KindUint64 {
			o.ObserveInt64(goroutines, int64(samples[1].Value.Uint64()))
		}
		return nil
	}, pool, lag, backlog, dead, cache, heap, goroutines)
	return err
}

// Attr helpers keep attribute keys consistent.
func Route(pattern, method string, status int) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("http.route", pattern), attribute.String("http.request.method", method),
		attribute.Int("http.response.status_code", status))
}

func Code(code string) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("code", code))
}

func Outcome(op, outcome string) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("op", op), attribute.String("outcome", outcome))
}
