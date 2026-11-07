package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/api"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

const expt = "CUI//SP-EXPT//NOFORN"

const ncrBody = `{"name":"ncr","marking":"cui//sp-expt","indexed_fields":["part_number"],
	"json_schema":{"type":"object","required":["part_number"],"properties":{"part_number":{"type":"string"},"status":{"type":"string"}}}}`

type client struct {
	t   *testing.T
	srv *httptest.Server
}

func setup(t *testing.T) (*testenv.Env, *client) {
	env := testenv.New(t)
	srv := httptest.NewServer(api.New(env.C))
	t.Cleanup(srv.Close)
	return env, &client{t: t, srv: srv}
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("not JSON (%d): %s", r.status, r.body)
	}
	return m
}

func (c *client) do(method, path string, body io.Reader, headers map[string]string) resp {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+path, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

func as(t *testing.T, subject string, extra ...string) map[string]string {
	h := map[string]string{"Authorization": "Bearer " + testenv.Token(t, subject)}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = extra[i+1]
	}
	return h
}

func (c *client) upload(subject string, data []byte, extra ...string) map[string]any {
	c.t.Helper()
	md := base64.RawURLEncoding.EncodeToString([]byte(`{"test":"HF-12"}`))
	h := as(c.t, subject, append([]string{api.MarkingHeader, expt, "Content-Type", "text/plain",
		"X-Strongbox-Filename", "hot%20fire%20log.txt", "X-Strongbox-Metadata", md}, extra...)...)
	r := c.do("POST", "/v1/blobs", bytes.NewReader(data), h)
	if r.status != 201 && r.status != 200 {
		c.t.Fatalf("upload %d: %s", r.status, r.body)
	}
	return r.json(c.t)
}

func TestHealthAndSecurityHeaders(t *testing.T) {
	_, c := setup(t)
	r := c.do("GET", "/healthz", nil, nil)
	if r.status != 200 || r.header.Get("Cache-Control") != "no-store" || r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %v", r.status, r.header)
	}
	if len(r.header.Get("X-Request-ID")) < 8 {
		t.Fatal("missing request id")
	}
	if c.do("GET", "/readyz", nil, nil).status != 200 {
		t.Fatal("not ready")
	}
	r = c.do("GET", "/v1/whoami", nil, as(t, "engineer@rel.test", "X-Request-ID", "trace-abc-123"))
	if r.header.Get("X-Request-ID") != "trace-abc-123" {
		t.Fatal("request id not propagated")
	}
}

func TestAuthenticationFailures(t *testing.T) {
	env, c := setup(t)
	r := c.do("GET", "/v1/whoami", nil, nil)
	if r.status != 401 || r.header.Get("Content-Type") != "application/problem+json" || r.header.Get("WWW-Authenticate") != "Bearer" ||
		r.json(t)["code"] != "unauthenticated" {
		t.Fatalf("%d %s", r.status, r.body)
	}
	wrongAud, _ := auth.MintDevToken(testenv.Secret, "engineer@rel.test", "other", time.Hour)
	forged, _ := auth.MintDevToken(strings.Repeat("y", 40), "admin@rel.test", "strongbox", time.Hour)
	for _, tok := range []string{wrongAud, forged, testenv.Token(t, "nobody@rel.test")} {
		if c.do("GET", "/v1/whoami", nil, map[string]string{"Authorization": "Bearer " + tok}).status != 401 {
			t.Fatal("bad token accepted")
		}
	}
	events, _ := env.C.Audit.List(context.Background(), 0, 100)
	n, sawNobody := 0, false
	for _, e := range events {
		if e.Action == "auth.authenticate" {
			n++
			sawNobody = sawNobody || e.Actor == "nobody@rel.test"
		}
	}
	if n != 4 || !sawNobody {
		t.Fatalf("auth failures audited: %d, nobody=%v", n, sawNobody)
	}
}

func TestBlobRoundTrip(t *testing.T) {
	_, c := setup(t)
	data := make([]byte, 200_000)
	_, _ = rand.Read(data)
	meta := c.upload("engineer@rel.test", data)
	if meta["marking"] != expt || meta["filename"] != "hot fire log.txt" || meta["metadata"].(map[string]any)["test"] != "HF-12" {
		t.Fatalf("meta %v", meta)
	}
	id := meta["id"].(string)
	r := c.do("GET", "/v1/blobs/"+id+"/content", nil, as(t, "engineer@rel.test"))
	if r.status != 200 || !bytes.Equal(r.body, data) || r.header.Get(api.MarkingHeader) != expt {
		t.Fatalf("download %d", r.status)
	}
	if !strings.Contains(r.header.Get("Content-Disposition"), "filename*=UTF-8''hot%20fire%20log.txt") {
		t.Fatalf("disposition %s", r.header.Get("Content-Disposition"))
	}
	list := c.do("GET", "/v1/blobs", nil, as(t, "engineer@rel.test")).json(t)
	if items := list["items"].([]any); len(items) != 1 || list["next_cursor"] != nil {
		t.Fatalf("list %v", list)
	}
}

func TestBlobIdempotencyConcealmentLimits(t *testing.T) {
	_, c := setup(t)
	a := c.upload("engineer@rel.test", []byte("x"), "Idempotency-Key", "upload-1")
	r := c.do("POST", "/v1/blobs", strings.NewReader("x"), as(t, "engineer@rel.test", api.MarkingHeader, expt, "Idempotency-Key", "upload-1"))
	if r.status != 200 || r.json(t)["id"] != a["id"] {
		t.Fatalf("replay %d", r.status)
	}
	r = c.do("GET", "/v1/blobs/"+a["id"].(string), nil, as(t, "foreign@rel.test"))
	if r.status != 404 || r.json(t)["code"] != "not_found" {
		t.Fatalf("foreign national: %d", r.status)
	}
	if c.do("POST", "/v1/blobs", strings.NewReader("x"), as(t, "engineer@rel.test", api.MarkingHeader, "SECRET")).status != 422 {
		t.Fatal("bad marking accepted")
	}
	big := bytes.Repeat([]byte("x"), 5*1024*1024+1)
	if r := c.do("POST", "/v1/blobs", bytes.NewReader(big), as(t, "engineer@rel.test", api.MarkingHeader, expt)); r.status != 413 {
		t.Fatalf("oversize: %d", r.status)
	}
	if c.do("DELETE", "/v1/blobs/"+a["id"].(string)+"?shred=true", nil, as(t, "engineer@rel.test")).status != 204 {
		t.Fatal("shred")
	}
	if c.do("GET", "/v1/blobs/"+a["id"].(string), nil, as(t, "admin@rel.test")).status != 404 {
		t.Fatal("shredded blob still visible")
	}
}

func TestRecordsFlow(t *testing.T) {
	_, c := setup(t)
	if c.do("POST", "/v1/collections", strings.NewReader(ncrBody), as(t, "engineer@rel.test")).status != 403 {
		t.Fatal("engineer created a collection")
	}
	r := c.do("POST", "/v1/collections", strings.NewReader(ncrBody), as(t, "svc-mes@rel.test"))
	if r.status != 201 || r.json(t)["marking"] != "CUI//SP-EXPT" || r.json(t)["encrypted"] != true {
		t.Fatalf("collection %d %s", r.status, r.body)
	}
	r = c.do("POST", "/v1/collections/ncr/records", strings.NewReader(`{"data":{"part_number":"TR-1","status":"open"}}`),
		as(t, "engineer@rel.test", "Idempotency-Key", "ncr-1"))
	if r.status != 201 || r.header.Get("ETag") != `"v1"` || r.header.Get(api.MarkingHeader) != "CUI//SP-EXPT" {
		t.Fatalf("create %d %v", r.status, r.header)
	}
	url := "/v1/collections/ncr/records/" + r.json(t)["id"].(string)
	body := `{"data":{"part_number":"TR-1","status":"closed"}}`
	if c.do("PUT", url, strings.NewReader(body), as(t, "engineer@rel.test")).status != 428 {
		t.Fatal("update without If-Match")
	}
	r = c.do("PUT", url, strings.NewReader(body), as(t, "engineer@rel.test", "If-Match", `"v1"`))
	if r.status != 200 || r.header.Get("ETag") != `"v2"` {
		t.Fatalf("update %d %s", r.status, r.body)
	}
	if c.do("PUT", url, strings.NewReader(body), as(t, "engineer@rel.test", "If-Match", `"v1"`)).status != 412 {
		t.Fatal("stale update accepted")
	}
	q := c.do("POST", "/v1/collections/ncr/query", strings.NewReader(`{"filters":{"part_number":"TR-1"}}`), as(t, "engineer@rel.test")).json(t)
	items := q["items"].([]any)
	if q["marking"] != "CUI//SP-EXPT" || len(items) != 1 || items[0].(map[string]any)["data"].(map[string]any)["status"] != "closed" {
		t.Fatalf("query %v", q)
	}
	bad := c.do("POST", "/v1/collections/ncr/records", strings.NewReader(`{"data":{"status":"x"}}`), as(t, "engineer@rel.test"))
	if bad.status != 422 || !strings.Contains(bad.json(t)["detail"].(string), "part_number") {
		t.Fatalf("schema error %d %s", bad.status, bad.body)
	}
	if c.do("POST", "/v1/collections/ncr/records", strings.NewReader(`{"data":{},"extra":1}`), as(t, "engineer@rel.test")).status != 422 {
		t.Fatal("unknown field accepted")
	}
	if c.do("DELETE", url, nil, as(t, "engineer@rel.test", "If-Match", `"v2"`)).status != 204 {
		t.Fatal("delete")
	}
}

func TestDelegation(t *testing.T) {
	_, c := setup(t)
	c.do("POST", "/v1/collections", strings.NewReader(ncrBody), as(t, "svc-mes@rel.test"))
	rec := c.do("POST", "/v1/collections/ncr/records", strings.NewReader(`{"data":{"part_number":"TR-9"}}`), as(t, "engineer@rel.test")).json(t)
	url := "/v1/collections/ncr/records/" + rec["id"].(string)
	obo := func(agent, user string) map[string]string {
		return as(t, agent, api.OnBehalfOf, testenv.Token(t, user))
	}
	r := c.do("GET", url, nil, obo("agent:assistant", "engineer@rel.test")).json(t)
	if r["content_withheld"] != true || r["data"] != nil {
		t.Fatalf("agent outside boundary: %v", r)
	}
	if c.do("GET", url, nil, obo("agent:boundary", "foreign@rel.test")).status != 404 {
		t.Fatal("foreign national reached ITAR data through an agent")
	}
	if d := c.do("GET", url, nil, obo("agent:boundary", "engineer@rel.test")).json(t)["data"].(map[string]any); d["part_number"] != "TR-9" {
		t.Fatal("cleared agent")
	}
	if c.do("GET", url, nil, obo("engineer@rel.test", "admin@rel.test")).status != 403 {
		t.Fatal("delegation without the delegate scope")
	}
	who := c.do("GET", "/v1/whoami", nil, obo("agent:boundary", "engineer@rel.test")).json(t)
	if who["subject"] != "engineer@rel.test" || who["actor"] != "agent:boundary" || strings.Contains(string(mustJSON(who["scopes"])), "delegate") {
		t.Fatalf("whoami %v", who)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestAdminEndpoints(t *testing.T) {
	_, c := setup(t)
	if c.do("GET", "/v1/audit/verify", nil, as(t, "engineer@rel.test")).status != 403 {
		t.Fatal("engineer read audit")
	}
	r := c.do("PUT", "/v1/principals/new.hire@rel.test", strings.NewReader(
		`{"kind":"user","scopes":["records:read"],"us_person":true,"cui_access":true,"cui_categories":["propin"]}`), as(t, "admin@rel.test"))
	if r.status != 200 {
		t.Fatalf("put principal %d %s", r.status, r.body)
	}
	if cats := c.do("GET", "/v1/whoami", nil, as(t, "new.hire@rel.test")).json(t)["cui_categories"].([]any); len(cats) != 1 || cats[0] != "PROPIN" {
		t.Fatalf("categories %v", cats)
	}
	if c.do("PUT", "/v1/principals/admin@rel.test", strings.NewReader(`{"kind":"user","scopes":["*"]}`), as(t, "admin@rel.test")).status != 403 {
		t.Fatal("self-edit allowed")
	}
	if c.do("PUT", "/v1/principals/x", strings.NewReader(`{"kind":"user","scopes":["root"]}`), as(t, "admin@rel.test")).status != 422 {
		t.Fatal("unknown scope accepted")
	}
	if v := c.do("GET", "/v1/audit/verify", nil, as(t, "admin@rel.test")).json(t); v["ok"] != true {
		t.Fatalf("verify %v", v)
	}
	if items := c.do("GET", "/v1/audit/events?limit=5", nil, as(t, "admin@rel.test")).json(t)["items"].([]any); len(items) != 5 {
		t.Fatalf("events %d", len(items))
	}
}

// Every API route must be documented in the OpenAPI contract, and vice versa.
func TestOpenAPIContract(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(api.OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for p, ops := range doc.Paths {
		norm := strings.NewReplacer("{blob_id}", "{id}", "{record_id}", "{id}").Replace(p)
		for m := range ops {
			documented[strings.ToUpper(m)+" "+norm] = true
		}
	}
	for _, r := range api.Routes() {
		if !documented[r] {
			t.Errorf("route %s missing from openapi.json", r)
		}
		delete(documented, r)
	}
	for r := range documented {
		t.Errorf("openapi.json documents %s, which the server does not serve", r)
	}
}
