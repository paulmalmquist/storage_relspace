package api_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/paulmalmquist/storage_relspace/internal/api"
	"github.com/paulmalmquist/storage_relspace/internal/telemetry"
)

// Metrics carry only bounded, non-sensitive labels: route templates, never paths, apps, subjects,
// IDs or markings.
func TestLabelsAreBounded(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	telemetry.Install(mp)
	t.Cleanup(func() { telemetry.Install(sdkmetric.NewMeterProvider()) })
	if err := telemetry.RegisterGauges(mp, telemetry.Gauges{}); err != nil {
		t.Fatal(err)
	}

	_, c := setup(t)
	if r := c.do("POST", app+"/collections", strings.NewReader(ncrBody), as(t, "admin@rel.test")); r.status != 201 {
		t.Fatalf("collection %d %s", r.status, r.body)
	}
	rec := c.do("POST", app+"/collections/ncr/records", strings.NewReader(`{"data":{"part_number":"TR-1042"}}`),
		as(t, "engineer@rel.test", "Idempotency-Key", "op-metrics-1")).json(t)
	c.do("POST", app+"/collections/ncr/records", strings.NewReader(`{"data":{"part_number":"TR-1042"}}`),
		as(t, "engineer@rel.test", "Idempotency-Key", "op-metrics-1")) // replay
	c.do("GET", app+"/collections/ncr/records/"+rec["id"].(string), nil, as(t, "intern@rel.test")) // concealed 404
	c.do("GET", "/v1/apps/rival/blobs", nil, as(t, "engineer@rel.test"))                           // not a member
	c.upload("engineer@rel.test", bytes.Repeat([]byte("x"), 5000))
	c.do("GET", "/no/such/route", nil, nil)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			seen[m.Name] = true
			for _, set := range attributeSets(m.Data) {
				for _, kv := range set {
					key, val := string(kv.Key), kv.Value.String()
					if !telemetry.AllowedKeys[key] {
						t.Errorf("%s: label %q is not in the allowed set", m.Name, key)
					}
					for _, bad := range []string{"acme", "rival", "@rel.test", "rec_", "blb_", "CUI", "/v1/apps/acme"} {
						if strings.Contains(val, bad) {
							t.Errorf("%s: label %s=%q carries request data", m.Name, key, val)
						}
					}
				}
			}
		}
	}
	for _, want := range []string{"http.server.request.duration", "strongbox.errors", "strongbox.db.pool.wait",
		"strongbox.kms.duration", "strongbox.operation.replays"} {
		if !seen[want] {
			t.Errorf("metric %s was not recorded", want)
		}
	}
	_ = api.MarkingHeader
}

func attributeSets(d metricdata.Aggregation) [][]attribute.KeyValue {
	var out [][]attribute.KeyValue
	switch v := d.(type) {
	case metricdata.Sum[int64]:
		for _, p := range v.DataPoints {
			out = append(out, p.Attributes.ToSlice())
		}
	case metricdata.Sum[float64]:
		for _, p := range v.DataPoints {
			out = append(out, p.Attributes.ToSlice())
		}
	case metricdata.Gauge[int64]:
		for _, p := range v.DataPoints {
			out = append(out, p.Attributes.ToSlice())
		}
	case metricdata.Gauge[float64]:
		for _, p := range v.DataPoints {
			out = append(out, p.Attributes.ToSlice())
		}
	case metricdata.Histogram[float64]:
		for _, p := range v.DataPoints {
			out = append(out, p.Attributes.ToSlice())
		}
	}
	return out
}
