// Package client is a Go client for the Strongbox API, for other services and for the MCP server.
//
//	ts, _ := client.GoogleIDToken(ctx, "strongbox-api")
//	sb := client.New("https://strongbox.internal", ts, client.WithServerlessAuth())
//	blob, _ := sb.PutBlob(ctx, data, client.BlobOptions{Marking: "CUI//SP-EXPT", Filename: "weld-map.csv"})
//
// Create calls carry an Idempotency-Key automatically, so retries after transient failures never
// duplicate data.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/idtoken"
)

// TokenSource returns a bearer token; it is called before every request so tokens can refresh.
type TokenSource func(ctx context.Context) (string, error)

func StaticToken(t string) TokenSource {
	return func(context.Context) (string, error) { return t, nil }
}

// GoogleIDToken mints Google-signed ID tokens for audience from the runtime's service account
// (metadata server on Cloud Run/GKE, or Application Default Credentials locally).
func GoogleIDToken(ctx context.Context, audience string) (TokenSource, error) {
	ts, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		return nil, err
	}
	return func(context.Context) (string, error) {
		t, err := ts.Token()
		if err != nil {
			return "", err
		}
		return t.AccessToken, nil
	}, nil
}

type APIError struct {
	Status    int
	Code      string
	Detail    string
	RequestID string
}

func (e *APIError) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Detail) }

type Client struct {
	base       string
	http       *http.Client
	token      TokenSource
	obo        TokenSource
	serverless bool
	retries    int
}

type Option func(*Client)

func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }
func WithOnBehalfOf(t TokenSource) Option  { return func(c *Client) { c.obo = t } }
func WithRetries(n int) Option             { return func(c *Client) { c.retries = n } }

// WithServerlessAuth also sends the token as X-Serverless-Authorization. Cloud Run IAM reads that header
// when present, which leaves Authorization untouched for Strongbox's own verification.
func WithServerlessAuth() Option { return func(c *Client) { c.serverless = true } }

func New(baseURL string, token TokenSource, opts ...Option) *Client {
	c := &Client{base: strings.TrimRight(baseURL, "/"), http: &http.Client{Timeout: 5 * time.Minute}, token: token, retries: 3}
	for _, o := range opts {
		o(c)
	}
	return c
}

// OnBehalfOf returns a copy that adds X-On-Behalf-Of, sharing the connection pool.
func (c *Client) OnBehalfOf(t TokenSource) *Client {
	cp := *c
	cp.obo = t
	return &cp
}

func newKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type request struct {
	method  string
	path    string
	query   url.Values
	body    []byte    // replayable body
	stream  io.Reader // non-replayable body (no retries)
	headers map[string]string
	retry   bool
}

func (c *Client) send(ctx context.Context, rq request) (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		u := c.base + rq.path
		if len(rq.query) > 0 {
			u += "?" + rq.query.Encode()
		}
		var body io.Reader = rq.stream
		if rq.body != nil {
			body = bytes.NewReader(rq.body)
		}
		req, err := http.NewRequestWithContext(ctx, rq.method, u, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Request-ID", newKey())
		if c.token != nil {
			tok, err := c.token(ctx)
			if err != nil {
				return nil, fmt.Errorf("token: %w", err)
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			if c.serverless {
				req.Header.Set("X-Serverless-Authorization", "Bearer "+tok)
			}
		}
		if c.obo != nil {
			tok, err := c.obo(ctx)
			if err != nil {
				return nil, fmt.Errorf("on-behalf-of token: %w", err)
			}
			req.Header.Set("X-On-Behalf-Of", tok)
		}
		for k, v := range rq.headers {
			req.Header.Set(k, v)
		}
		resp, err := c.http.Do(req)
		retryable := rq.retry && rq.stream == nil && attempt <= c.retries
		if err != nil {
			if !retryable || ctx.Err() != nil {
				return nil, err
			}
		} else if resp.StatusCode < 502 || resp.StatusCode > 504 || !retryable {
			if resp.StatusCode >= 400 {
				defer resp.Body.Close()
				return nil, decodeError(resp)
			}
			return resp, nil
		} else {
			_ = resp.Body.Close()
		}
		n, _ := rand.Int(rand.Reader, big.NewInt(1000))
		delay := min(8*time.Second, time.Duration(250<<attempt)*time.Millisecond) / 2
		delay += time.Duration(n.Int64()) * delay / 1000
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
}

func decodeError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var p struct{ Code, Detail string }
	if json.Unmarshal(raw, &p) != nil || p.Code == "" {
		p.Code, p.Detail = "error", strings.TrimSpace(string(raw))
	}
	return &APIError{Status: resp.StatusCode, Code: p.Code, Detail: p.Detail, RequestID: resp.Header.Get("X-Request-ID")}
}

func (c *Client) doJSON(ctx context.Context, rq request) (map[string]any, error) {
	resp, err := c.send(ctx, rq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	var out map[string]any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

func jsonBody(v any) []byte { b, _ := json.Marshal(v); return b }

func jsonHeaders(extra ...string) map[string]string {
	h := map[string]string{"Content-Type": "application/json"}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = extra[i+1]
	}
	return h
}

// ---- identity -------------------------------------------------------------------------------------

func (c *Client) WhoAmI(ctx context.Context) (map[string]any, error) {
	return c.doJSON(ctx, request{method: "GET", path: "/v1/whoami", retry: true})
}

// ---- blobs ----------------------------------------------------------------------------------------

type BlobOptions struct {
	Marking        string
	ContentType    string
	Filename       string
	Metadata       map[string]any
	IdempotencyKey string
}

func (o BlobOptions) headers() map[string]string {
	ct := o.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	key := o.IdempotencyKey
	if key == "" {
		key = newKey()
	}
	h := map[string]string{"X-Strongbox-Marking": o.Marking, "Content-Type": ct, "Idempotency-Key": key}
	if o.Filename != "" {
		h["X-Strongbox-Filename"] = url.PathEscape(o.Filename)
	}
	if o.Metadata != nil {
		h["X-Strongbox-Metadata"] = base64.RawURLEncoding.EncodeToString(jsonBody(o.Metadata))
	}
	return h
}

// PutBlob uploads bytes (retried on transient failures).
func (c *Client) PutBlob(ctx context.Context, data []byte, o BlobOptions) (map[string]any, error) {
	return c.doJSON(ctx, request{method: "POST", path: "/v1/blobs", body: data, headers: o.headers(), retry: true})
}

// PutBlobStream uploads from a reader without buffering (not retried).
func (c *Client) PutBlobStream(ctx context.Context, r io.Reader, o BlobOptions) (map[string]any, error) {
	return c.doJSON(ctx, request{method: "POST", path: "/v1/blobs", stream: r, headers: o.headers()})
}

func (c *Client) GetBlob(ctx context.Context, id string) (map[string]any, error) {
	return c.doJSON(ctx, request{method: "GET", path: "/v1/blobs/" + url.PathEscape(id), retry: true})
}

// OpenBlob streams content. The caller must close the reader. The marking banner is returned with it.
func (c *Client) OpenBlob(ctx context.Context, id string) (io.ReadCloser, string, error) {
	resp, err := c.send(ctx, request{method: "GET", path: "/v1/blobs/" + url.PathEscape(id) + "/content", retry: true})
	if err != nil {
		return nil, "", err
	}
	return resp.Body, resp.Header.Get("X-Strongbox-Marking"), nil
}

// ReadBlob reads content into memory, failing if it exceeds maxBytes (0 for no limit).
func (c *Client) ReadBlob(ctx context.Context, id string, maxBytes int64) ([]byte, string, error) {
	rc, banner, err := c.OpenBlob(ctx, id)
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	var r io.Reader = rc
	if maxBytes > 0 {
		r = io.LimitReader(rc, maxBytes+1)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, "", err
	}
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		return nil, "", &APIError{Status: 413, Code: "payload_too_large", Detail: fmt.Sprintf("blob exceeds %d bytes", maxBytes)}
	}
	return data, banner, nil
}

func (c *Client) ListBlobs(ctx context.Context, limit int, cursor string) (map[string]any, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	return c.doJSON(ctx, request{method: "GET", path: "/v1/blobs", query: q, retry: true})
}

func (c *Client) DeleteBlob(ctx context.Context, id string, shred bool) error {
	_, err := c.doJSON(ctx, request{method: "DELETE", path: "/v1/blobs/" + url.PathEscape(id),
		query: url.Values{"shred": {strconv.FormatBool(shred)}}, retry: true})
	return err
}

// ---- collections & records ------------------------------------------------------------------------

type CollectionSpec struct {
	Name          string         `json:"name"`
	Marking       string         `json:"marking"`
	JSONSchema    map[string]any `json:"json_schema,omitempty"`
	IndexedFields []string       `json:"indexed_fields,omitempty"`
	Encrypted     *bool          `json:"encrypted,omitempty"`
}

func (c *Client) CreateCollection(ctx context.Context, s CollectionSpec) (map[string]any, error) {
	return c.doJSON(ctx, request{method: "POST", path: "/v1/collections", body: jsonBody(s), headers: jsonHeaders()})
}

func (c *Client) ListCollections(ctx context.Context) ([]any, error) {
	out, err := c.doJSON(ctx, request{method: "GET", path: "/v1/collections", retry: true})
	if err != nil {
		return nil, err
	}
	items, _ := out["items"].([]any)
	return items, nil
}

func (c *Client) GetCollection(ctx context.Context, name string) (map[string]any, error) {
	return c.doJSON(ctx, request{method: "GET", path: "/v1/collections/" + url.PathEscape(name), retry: true})
}

func recordPath(coll, id string) string {
	return "/v1/collections/" + url.PathEscape(coll) + "/records/" + url.PathEscape(id)
}

func (c *Client) CreateRecord(ctx context.Context, coll string, data map[string]any, marking string) (map[string]any, error) {
	body := map[string]any{"data": data}
	if marking != "" {
		body["marking"] = marking
	}
	return c.doJSON(ctx, request{method: "POST", path: "/v1/collections/" + url.PathEscape(coll) + "/records",
		body: jsonBody(body), headers: jsonHeaders("Idempotency-Key", newKey()), retry: true})
}

func (c *Client) GetRecord(ctx context.Context, coll, id string) (map[string]any, error) {
	return c.doJSON(ctx, request{method: "GET", path: recordPath(coll, id), retry: true})
}

func (c *Client) UpdateRecord(ctx context.Context, coll, id string, data map[string]any, expectedVersion int, marking string) (map[string]any, error) {
	body := map[string]any{"data": data}
	if marking != "" {
		body["marking"] = marking
	}
	return c.doJSON(ctx, request{method: "PUT", path: recordPath(coll, id), body: jsonBody(body),
		headers: jsonHeaders("If-Match", fmt.Sprintf(`"v%d"`, expectedVersion)), retry: true})
}

func (c *Client) DeleteRecord(ctx context.Context, coll, id string, expectedVersion int, purge bool) error {
	h := map[string]string{}
	if expectedVersion > 0 {
		h["If-Match"] = fmt.Sprintf(`"v%d"`, expectedVersion)
	}
	_, err := c.doJSON(ctx, request{method: "DELETE", path: recordPath(coll, id),
		query: url.Values{"purge": {strconv.FormatBool(purge)}}, headers: h, retry: true})
	return err
}

func (c *Client) Query(ctx context.Context, coll string, filters map[string]any, limit int, cursor string) (map[string]any, error) {
	body := map[string]any{"filters": filters}
	if filters == nil {
		body["filters"] = map[string]any{}
	}
	if limit > 0 {
		body["limit"] = limit
	}
	if cursor != "" {
		body["cursor"] = cursor
	}
	return c.doJSON(ctx, request{method: "POST", path: "/v1/collections/" + url.PathEscape(coll) + "/query",
		body: jsonBody(body), headers: jsonHeaders(), retry: true})
}

// IsCode reports whether err is an API error with the given code.
func IsCode(err error, code string) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == code
}
