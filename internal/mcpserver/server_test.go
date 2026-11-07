package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paulmalmquist/storage_relspace/internal/api"
	"github.com/paulmalmquist/storage_relspace/internal/mcpserver"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
	"github.com/paulmalmquist/storage_relspace/pkg/client"
)

// End to end: MCP client -> MCP server -> Go client -> real API -> services -> Postgres.

type fixture struct {
	env *testenv.Env
	api *httptest.Server
}

func setup(t *testing.T) *fixture {
	t.Helper()
	env := testenv.New(t)
	srv := httptest.NewServer(api.New(env.C))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	svc := client.New(srv.URL, client.StaticToken(testenv.Token(t, "svc-mes@rel.test")))
	var schema map[string]any
	_ = json.Unmarshal([]byte(`{"type":"object","required":["part_number"],"properties":{"part_number":{"type":"string"},"status":{"type":"string"}}}`), &schema)
	for _, c := range []client.CollectionSpec{
		{Name: "ncr", Marking: "CUI//SP-EXPT", JSONSchema: schema, IndexedFields: []string{"part_number"}},
		{Name: "tooling", Marking: "UNCONTROLLED", IndexedFields: []string{"bay"}},
	} {
		if _, err := svc.CreateCollection(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.CreateRecord(ctx, "ncr", map[string]any{"part_number": "TR-7", "status": "open"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutBlob(ctx, []byte("hot-fire notes: chamber pressure nominal"), client.BlobOptions{Marking: "CUI//SP-EXPT", ContentType: "text/plain", Filename: "hf.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutBlob(ctx, []byte("cafeteria menu"), client.BlobOptions{Marking: "UNCONTROLLED", ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	return &fixture{env: env, api: srv}
}

// session connects an in-memory MCP client to a server acting as agent on behalf of user (stdio mode).
func (f *fixture) session(t *testing.T, agent, user string) *mcp.ClientSession {
	t.Helper()
	cl := client.New(f.api.URL, client.StaticToken(testenv.Token(t, agent)))
	srv := mcpserver.New(cl, mcpserver.Options{DefaultOnBehalfOf: testenv.Token(t, user)})
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		return nil, res.Content[0].(*mcp.TextContent).Text
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m, ""
}

func TestToolCatalog(t *testing.T) {
	f := setup(t)
	cs := f.session(t, "agent:assistant", "engineer@rel.test")
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		tools[tl.Name] = tl
		if strings.Contains(tl.Name, "delete") || strings.Contains(tl.Name, "shred") {
			t.Errorf("destructive tool exposed: %s", tl.Name)
		}
	}
	if len(tools) != 11 || !tools["query_records"].Annotations.ReadOnlyHint || !*tools["update_record"].Annotations.DestructiveHint {
		t.Fatalf("catalog: %d tools", len(tools))
	}
}

func TestAgentOutsideBoundarySeesMetadataNotCUI(t *testing.T) {
	f := setup(t)
	cs := f.session(t, "agent:assistant", "engineer@rel.test")
	page, errText := call(t, cs, "query_records", map[string]any{"collection": "ncr", "filters": map[string]any{"part_number": "TR-7"}})
	if errText != "" {
		t.Fatal(errText)
	}
	rec := page["records"].([]any)[0].(map[string]any)
	if page["marking"] != "CUI//SP-EXPT" || rec["content_withheld"] != true || rec["data"] != nil || rec["handling"] == nil {
		t.Fatalf("record %v", rec)
	}
	blobs, _ := call(t, cs, "list_blobs", nil)
	var cuiID, publicID string
	for _, b := range blobs["blobs"].([]any) {
		m := b.(map[string]any)
		if m["marking"] == "UNCONTROLLED" {
			publicID = m["id"].(string)
		} else {
			cuiID = m["id"].(string)
		}
	}
	read, _ := call(t, cs, "read_blob_text", map[string]any{"blob_id": cuiID})
	if read["content_withheld"] != true || read["text"] != nil {
		t.Fatalf("CUI text reached an agent outside the boundary: %v", read)
	}
	pub, _ := call(t, cs, "read_blob_text", map[string]any{"blob_id": publicID})
	if pub["text"] != "cafeteria menu" {
		t.Fatalf("public text: %v", pub)
	}
}

func TestAgentInsideBoundaryReadsCUI(t *testing.T) {
	f := setup(t)
	cs := f.session(t, "agent:boundary", "engineer@rel.test")
	page, _ := call(t, cs, "query_records", map[string]any{"collection": "ncr", "filters": map[string]any{"part_number": "TR-7"}})
	if d := page["records"].([]any)[0].(map[string]any)["data"].(map[string]any); d["status"] != "open" {
		t.Fatalf("data %v", d)
	}
	blobs, _ := call(t, cs, "list_blobs", nil)
	for _, b := range blobs["blobs"].([]any) {
		m := b.(map[string]any)
		if m["marking"] != "UNCONTROLLED" {
			txt, _ := call(t, cs, "read_blob_text", map[string]any{"blob_id": m["id"]})
			if !strings.HasPrefix(txt["text"].(string), "hot-fire notes") || txt["marking"] != "CUI//SP-EXPT" {
				t.Fatalf("text %v", txt)
			}
		}
	}
}

func TestForeignNationalCannotReachITARThroughAgent(t *testing.T) {
	f := setup(t)
	cs := f.session(t, "agent:boundary", "foreign@rel.test")
	if _, errText := call(t, cs, "query_records", map[string]any{"collection": "ncr"}); !strings.Contains(errText, "not_found") {
		t.Fatalf("expected not_found, got %q", errText)
	}
	blobs, _ := call(t, cs, "list_blobs", nil)
	for _, b := range blobs["blobs"].([]any) {
		if b.(map[string]any)["marking"] != "UNCONTROLLED" {
			t.Fatal("ITAR blob listed for a foreign national")
		}
	}
}

func TestWritesAuditedWithBothIdentities(t *testing.T) {
	f := setup(t)
	cs := f.session(t, "agent:assistant", "engineer@rel.test")
	rec, errText := call(t, cs, "create_record", map[string]any{"collection": "ncr", "data": map[string]any{"part_number": "TR-8", "status": "open"}})
	if errText != "" || rec["marking"] != "CUI//SP-EXPT" || rec["created_by"] != "engineer@rel.test" {
		t.Fatalf("create %v %s", rec, errText)
	}
	if _, errText := call(t, cs, "put_blob_text", map[string]any{"text": "summary", "marking": "CUI//SP-EXPT", "filename": "summary.md"}); errText != "" {
		t.Fatal(errText)
	}
	events, _ := f.env.C.Audit.List(context.Background(), 0, 1000)
	n := 0
	for _, e := range events {
		if (e.Action == "record.create" || e.Action == "blob.create") && e.Decision == "allow" && e.Actor == "agent:assistant" &&
			e.OnBehalfOf != nil && *e.OnBehalfOf == "engineer@rel.test" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("delegated writes audited: %d", n)
	}
	if _, errText := call(t, cs, "create_record", map[string]any{"collection": "ncr", "data": map[string]any{"status": "x"}}); !strings.Contains(errText, "validation_failed") {
		t.Fatalf("schema error not surfaced: %q", errText)
	}
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// Streamable HTTP: the user's token arrives on the MCP request and is forwarded as X-On-Behalf-Of.
func TestStreamableHTTPDelegation(t *testing.T) {
	f := setup(t)
	verify := func(ctx context.Context, tok string) (string, time.Time, error) {
		vt, err := f.env.C.DelegationVerifier.Verify(ctx, tok)
		if err != nil {
			return "", time.Time{}, err
		}
		return vt.Subject, vt.ExpiresAt, nil
	}
	srv := mcpserver.New(client.New(f.api.URL, client.StaticToken(testenv.Token(t, "agent:boundary"))), mcpserver.Options{})
	mcpHTTP := httptest.NewServer(mcpserver.HTTPHandler(srv, verify, "http://mcp.test", "http://issuer.test"))
	t.Cleanup(mcpHTTP.Close)

	if resp, err := http.Post(mcpHTTP.URL+"/mcp", "application/json", strings.NewReader("{}")); err != nil || resp.StatusCode != 401 {
		t.Fatalf("unauthenticated MCP request: %v %v", err, resp.StatusCode)
	}

	for user, want := range map[string]string{"engineer@rel.test": "engineer@rel.test", "foreign@rel.test": "foreign@rel.test"} {
		transport := &mcp.StreamableClientTransport{Endpoint: mcpHTTP.URL + "/mcp",
			HTTPClient: &http.Client{Transport: bearer{testenv.Token(t, user), http.DefaultTransport}}}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(context.Background(), transport, nil)
		if err != nil {
			t.Fatal(err)
		}
		who, errText := call(t, cs, "whoami", nil)
		if errText != "" || who["subject"] != want || who["actor"] != "agent:boundary" {
			t.Fatalf("whoami as %s: %v %s", user, who, errText)
		}
		_, errText = call(t, cs, "query_records", map[string]any{"collection": "ncr"})
		if (user == "foreign@rel.test") != strings.Contains(errText, "not_found") {
			t.Fatalf("%s query: %q", user, errText)
		}
		_ = cs.Close()
	}
}
