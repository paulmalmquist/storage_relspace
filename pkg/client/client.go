// Package client is the Go SDK for the Strongbox API, used by other services and by the MCP server.
//
//	ts, _ := client.GoogleIDToken(ctx, "strongbox-api")
//	sb := client.New("https://strongbox.internal", ts, client.WithServerlessAuth())
//	notes := sb.App("notes")
//	rec, _ := notes.CreateRecord(ctx, "notes", client.RecordInput{Data: map[string]any{"title": "hi"}})
//	rec, _ = notes.UpdateRecord(ctx, "notes", rec.ID, rec.Version, client.RecordInput{Data: ...})
//
// Every mutation carries an operation ID (Idempotency-Key), generated per call unless the caller
// supplies one with WithOperationID. Retries of transient failures (network errors, 429, 502-504)
// reuse the same ID, so a retried write never applies twice and a lost response is recovered from
// the server's receipt. Retries are bounded, back off with jitter, honor Retry-After and stop when
// the context is cancelled.
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
	"sync"
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

// APIError is a problem+json error from the server. Code is stable; Status is the HTTP status.
type APIError struct {
	Status    int
	Code      string
	Detail    string
	RequestID string
}

func (e *APIError) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Detail) }

// IsCode reports whether err is an API error with the given code.
func IsCode(err error, code string) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == code
}

// IsConflict reports a version conflict (another writer won): re-read and retry.
func IsConflict(err error) bool { return IsCode(err, "precondition_failed") }

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

// App returns a handle for one app's resources.
func (c *Client) App(appID string) *App {
	return &App{c: c, id: appID, base: "/v1/apps/" + url.PathEscape(appID)}
}

type opKey struct{}

// WithOperationID fixes the Idempotency-Key for the next mutation made with ctx. Use it when your
// own system already has a stable ID for the operation (a job ID, a form submission ID), so a
// retry from a restarted process is recognized too.
func WithOperationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, opKey{}, id)
}

func operationID(ctx context.Context) string {
	if id, ok := ctx.Value(opKey{}).(string); ok && id != "" {
		return id
	}
	return newKey()
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
}

func retryable(status int) bool {
	return status == 429 || status == 502 || status == 503 || status == 504
}

func (c *Client) send(ctx context.Context, rq request) (*http.Response, error) {
	if rq.method != "GET" && rq.method != "HEAD" {
		if rq.headers == nil {
			rq.headers = map[string]string{}
		}
		if rq.headers["Idempotency-Key"] == "" {
			rq.headers["Idempotency-Key"] = operationID(ctx)
		}
	}
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
		canRetry := rq.stream == nil && attempt <= c.retries
		var wait time.Duration
		switch {
		case err != nil:
			if !canRetry || ctx.Err() != nil {
				return nil, err
			}
		case resp.StatusCode == 409 && canRetry && resp.Header.Get("Retry-After") != "":
			// operation_in_progress: the same operation is still running elsewhere.
			wait = retryAfter(resp)
			_ = resp.Body.Close()
		case !retryable(resp.StatusCode) || !canRetry:
			if resp.StatusCode >= 400 {
				defer resp.Body.Close()
				return nil, decodeError(resp)
			}
			return resp, nil
		default:
			wait = retryAfter(resp)
			_ = resp.Body.Close()
		}
		if wait == 0 {
			n, _ := rand.Int(rand.Reader, big.NewInt(1000))
			wait = min(8*time.Second, time.Duration(250<<attempt)*time.Millisecond) / 2
			wait += time.Duration(n.Int64()) * wait / 1000
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func retryAfter(resp *http.Response) time.Duration {
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 && s <= 60 {
		return time.Duration(s) * time.Second
	}
	return 0
}

func decodeError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var p struct{ Code, Detail string }
	if json.Unmarshal(raw, &p) != nil || p.Code == "" {
		p.Code, p.Detail = "error", strings.TrimSpace(string(raw))
	}
	return &APIError{Status: resp.StatusCode, Code: p.Code, Detail: p.Detail, RequestID: resp.Header.Get("X-Request-ID")}
}

func (c *Client) do(ctx context.Context, rq request, out any) error {
	resp, err := c.send(ctx, rq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func jsonBody(v any) []byte { b, _ := json.Marshal(v); return b }

func jsonHeaders(extra ...string) map[string]string {
	h := map[string]string{"Content-Type": "application/json"}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = extra[i+1]
	}
	return h
}

func etag(version int) string { return fmt.Sprintf(`"v%d"`, version) }

// ---- identity -------------------------------------------------------------------------------------

func (c *Client) WhoAmI(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, request{method: "GET", path: "/v1/whoami"}, &out)
}

// Limits are the server's request limits.
type Limits struct {
	MaxSingleUploadBytes int64  `json:"max_single_upload_bytes"`
	MaxBlobBytes         int64  `json:"max_blob_bytes"`
	MaxBlobMetadataBytes int    `json:"max_blob_metadata_bytes"`
	MaxRecordBytes       int    `json:"max_record_bytes"`
	MaxPage              int    `json:"max_page"`
	ChunkSize            int    `json:"chunk_size"`
	AppEnv               string `json:"app_env"`
	UploadSession        struct {
		PartSize          int64 `json:"part_size"`
		MaxParts          int   `json:"max_parts"`
		SessionTTLSeconds int   `json:"session_ttl_seconds"`
	} `json:"upload_session"`
}

func (c *Client) Limits(ctx context.Context) (*Limits, error) {
	var out Limits
	return &out, c.do(ctx, request{method: "GET", path: "/v1/limits"}, &out)
}

// ---- types ----------------------------------------------------------------------------------------

type Record struct {
	ID              string         `json:"id"`
	Collection      string         `json:"collection"`
	Marking         string         `json:"marking"`
	Version         int            `json:"version"`
	Data            map[string]any `json:"data"`
	ContentWithheld bool           `json:"content_withheld"`
	WithheldReason  string         `json:"withheld_reason,omitempty"`
	Owner           string         `json:"owner"`
	Visibility      string         `json:"visibility"`
	TeamID          *string        `json:"team_id"`
	Deleted         bool           `json:"deleted"`
	SchemaVersion   *int           `json:"schema_version"`
	Replayed        bool           `json:"replayed,omitempty"`
	CreatedBy       string         `json:"created_by"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedBy       string         `json:"updated_by"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type Blob struct {
	ID          string         `json:"id"`
	Marking     string         `json:"marking"`
	ContentType string         `json:"content_type"`
	SizeBytes   *int64         `json:"size_bytes"`
	Filename    *string        `json:"filename"`
	Metadata    map[string]any `json:"metadata"`
	State       string         `json:"state"`
	Owner       string         `json:"owner"`
	Visibility  string         `json:"visibility"`
	TeamID      *string        `json:"team_id"`
	CreatedBy   string         `json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	Replayed    bool           `json:"replayed,omitempty"`
}

type Collection struct {
	Name          string         `json:"name"`
	Marking       string         `json:"marking"`
	Encrypted     bool           `json:"encrypted"`
	IndexedFields []string       `json:"indexed_fields"`
	JSONSchema    map[string]any `json:"json_schema"`
	UniqueFields  []string       `json:"unique_fields"`
	Version       int            `json:"version"`
	// PendingVersion is set while a migration to a new contract runs.
	PendingVersion       *int      `json:"pending_version"`
	HistoryLimit         int       `json:"history_limit"`
	DeletedRetentionDays int       `json:"deleted_retention_days"`
	CreatedBy            string    `json:"created_by"`
	CreatedAt            time.Time `json:"created_at"`
}

type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
	Marking    string  `json:"marking,omitempty"`
}

type Revision struct {
	Version   int       `json:"version"`
	Op        string    `json:"op"`
	Marking   *string   `json:"marking"`
	Concealed bool      `json:"concealed,omitempty"`
	SizeBytes int       `json:"size_bytes"`
	Subject   string    `json:"subject"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}

type History struct {
	Items      []Revision `json:"items"`
	NextBefore *int       `json:"next_before"`
}

type Receipt struct {
	OpID            string         `json:"op_id"`
	Type            string         `json:"op_type"`
	Status          string         `json:"status"`
	ResourceType    string         `json:"resource_type,omitempty"`
	ResourceID      string         `json:"resource_id,omitempty"`
	ResourceVersion int            `json:"resource_version,omitempty"`
	Result          map[string]any `json:"result"`
}

type Grant struct {
	ID        string  `json:"id"`
	Subject   *string `json:"subject"`
	TeamID    *string `json:"team_id"`
	Role      string  `json:"role"`
	CanShare  bool    `json:"can_share"`
	GrantedBy string  `json:"granted_by"`
}

type Team struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Members map[string]string `json:"members"`
}

type AppInfo struct {
	App   string            `json:"app"`
	Role  string            `json:"role"`
	Teams map[string]string `json:"teams"`
}

// ---- app ------------------------------------------------------------------------------------------

// App is one app's resources. All methods are safe for concurrent use.
type App struct {
	c    *Client
	id   string
	base string
}

func (a *App) Info(ctx context.Context) (*AppInfo, error) {
	var out AppInfo
	return &out, a.c.do(ctx, request{method: "GET", path: a.base}, &out)
}

// Operation reports what happened to one of your operations (after a lost response).
func (a *App) Operation(ctx context.Context, opID string) (*Receipt, error) {
	var out Receipt
	return &out, a.c.do(ctx, request{method: "GET", path: a.base + "/operations/" + url.PathEscape(opID)}, &out)
}

func (a *App) CreateTeam(ctx context.Context, name string) (*Team, error) {
	var out Team
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/teams", body: jsonBody(map[string]string{"name": name}), headers: jsonHeaders()}, &out)
}

func (a *App) SetTeamMember(ctx context.Context, team, subject, role string) error {
	return a.c.do(ctx, request{method: "PUT", path: a.base + "/teams/" + url.PathEscape(team) + "/members/" + url.PathEscape(subject),
		body: jsonBody(map[string]string{"role": role}), headers: jsonHeaders()}, nil)
}

// ---- blobs ----------------------------------------------------------------------------------------

type BlobOptions struct {
	Marking     string
	ContentType string
	Filename    string
	Metadata    map[string]any
	Visibility  string // private (default) | team | app
	TeamID      string
}

func (o BlobOptions) headers(opID string) map[string]string {
	ct := o.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	m := o.Marking
	if m == "" {
		m = "UNCONTROLLED"
	}
	h := map[string]string{"X-Strongbox-Marking": m, "Content-Type": ct, "Idempotency-Key": opID}
	if o.Filename != "" {
		h["X-Strongbox-Filename"] = url.PathEscape(o.Filename)
	}
	if o.Metadata != nil {
		h["X-Strongbox-Metadata"] = base64.RawURLEncoding.EncodeToString(jsonBody(o.Metadata))
	}
	if o.Visibility != "" {
		h["X-Strongbox-Visibility"] = o.Visibility
	}
	if o.TeamID != "" {
		h["X-Strongbox-Team"] = o.TeamID
	}
	return h
}

// PutBlob uploads bytes in one request (retried on transient failures with the same operation ID).
func (a *App) PutBlob(ctx context.Context, data []byte, o BlobOptions) (*Blob, error) {
	var out Blob
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/blobs", body: data, headers: o.headers(operationID(ctx))}, &out)
}

// PutBlobStream uploads from a reader without buffering (not retried).
func (a *App) PutBlobStream(ctx context.Context, r io.Reader, o BlobOptions) (*Blob, error) {
	var out Blob
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/blobs", stream: r, headers: o.headers(operationID(ctx))}, &out)
}

// UploadSession is a blob being uploaded in parts.
type UploadSession struct {
	UploadID      string `json:"upload_id"`
	BlobID        string `json:"blob_id"`
	Marking       string `json:"marking"`
	SizeBytes     int64  `json:"size_bytes"`
	PartSize      int64  `json:"part_size"`
	PartCount     int    `json:"part_count"`
	ReceivedParts []int  `json:"received_parts"`
	State         string `json:"state"`
	ExpiresAt     string `json:"expires_at"`
}

// CreateUpload declares a blob of size bytes and reserves it against the app's quota.
func (a *App) CreateUpload(ctx context.Context, size int64, o BlobOptions) (*UploadSession, error) {
	marking := o.Marking
	if marking == "" {
		marking = "UNCONTROLLED"
	}
	body := map[string]any{"size_bytes": size, "marking": marking, "content_type": o.ContentType, "filename": o.Filename,
		"metadata": o.Metadata, "visibility": o.Visibility, "team_id": o.TeamID}
	var out UploadSession
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/uploads", body: jsonBody(body),
		headers: jsonHeaders("Idempotency-Key", operationID(ctx))}, &out)
}

// GetUpload reports which parts have arrived.
func (a *App) GetUpload(ctx context.Context, id string) (*UploadSession, error) {
	var out UploadSession
	return &out, a.c.do(ctx, request{method: "GET", path: a.base + "/uploads/" + url.PathEscape(id)}, &out)
}

// UploadPart sends part n (1-based). Parts are idempotent: re-sending replaces the earlier copy.
func (a *App) UploadPart(ctx context.Context, id string, n int, data []byte) error {
	return a.c.do(ctx, request{method: "PUT", path: fmt.Sprintf("%s/uploads/%s/parts/%d", a.base, url.PathEscape(id), n),
		body: data, headers: map[string]string{"Content-Type": "application/octet-stream"}}, nil)
}

// CompleteUpload activates the blob once every part is present.
func (a *App) CompleteUpload(ctx context.Context, id string) (*Blob, error) {
	var out Blob
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/uploads/" + url.PathEscape(id) + "/complete",
		headers: map[string]string{"Idempotency-Key": operationID(ctx)}}, &out)
}

// AbortUpload discards a pending session.
func (a *App) AbortUpload(ctx context.Context, id string) error {
	return a.c.do(ctx, request{method: "DELETE", path: a.base + "/uploads/" + url.PathEscape(id)}, nil)
}

// PutLargeBlob uploads size bytes from r through an upload session, sending up to parallel parts
// at once (each retried on transient failures). If ctx ends, the session is left pending for
// ResumeLargeBlob until it expires.
func (a *App) PutLargeBlob(ctx context.Context, r io.ReaderAt, size int64, o BlobOptions, parallel int) (*Blob, error) {
	sess, err := a.CreateUpload(WithOperationID(ctx, operationID(ctx)), size, o)
	if err != nil {
		return nil, err
	}
	return a.ResumeLargeBlob(ctx, sess.UploadID, r, parallel)
}

// ResumeLargeBlob sends the parts a session is still missing, then completes it.
func (a *App) ResumeLargeBlob(ctx context.Context, id string, r io.ReaderAt, parallel int) (*Blob, error) {
	sess, err := a.GetUpload(ctx, id)
	if err != nil {
		return nil, err
	}
	have := map[int]bool{}
	for _, n := range sess.ReceivedParts {
		have[n] = true
	}
	parallel = max(1, min(parallel, 8))
	sem := make(chan struct{}, parallel)
	errc := make(chan error, sess.PartCount)
	var wg sync.WaitGroup
	for n := 1; n <= sess.PartCount; n++ {
		if have[n] {
			continue
		}
		start := int64(n-1) * sess.PartSize
		length := min(sess.PartSize, sess.SizeBytes-start)
		wg.Add(1)
		sem <- struct{}{}
		go func(n int, start, length int64) {
			defer wg.Done()
			defer func() { <-sem }()
			buf := make([]byte, length)
			if _, err := r.ReadAt(buf, start); err != nil && !(errors.Is(err, io.EOF) && int64(len(buf)) == length) {
				errc <- fmt.Errorf("read part %d: %w", n, err)
				return
			}
			if err := a.UploadPart(WithOperationID(ctx, fmt.Sprintf("part-%s-%d", id, n)), id, n, buf); err != nil {
				errc <- fmt.Errorf("part %d: %w", n, err)
			}
		}(n, start, length)
	}
	wg.Wait()
	close(errc)
	if err := <-errc; err != nil {
		return nil, err
	}
	return a.CompleteUpload(WithOperationID(ctx, "complete-"+id), id)
}

// Usage counts resources visible to the caller; limits are app-wide (nil is unlimited).
type Usage struct {
	App            string `json:"app"`
	Scope          string `json:"scope"`
	BlobBytes      int64  `json:"blob_bytes"`
	Blobs          int64  `json:"blobs"`
	ReservedBytes  int64  `json:"reserved_bytes"`
	Records        int64  `json:"records"`
	RecordBytes    int64  `json:"record_bytes"`
	MaxBlobBytes   *int64 `json:"max_blob_bytes"`
	MaxBlobs       *int64 `json:"max_blobs"`
	MaxRecords     *int64 `json:"max_records"`
	MaxRecordBytes *int64 `json:"max_record_bytes"`
}

func (a *App) Usage(ctx context.Context) (*Usage, error) {
	var out Usage
	return &out, a.c.do(ctx, request{method: "GET", path: a.base + "/usage"}, &out)
}

func (a *App) GetBlob(ctx context.Context, id string) (*Blob, error) {
	var out Blob
	return &out, a.c.do(ctx, request{method: "GET", path: a.base + "/blobs/" + url.PathEscape(id)}, &out)
}

// OpenBlob streams content. The caller must close the reader. The marking banner is returned with it.
func (a *App) OpenBlob(ctx context.Context, id string) (io.ReadCloser, string, error) {
	resp, err := a.c.send(ctx, request{method: "GET", path: a.base + "/blobs/" + url.PathEscape(id) + "/content"})
	if err != nil {
		return nil, "", err
	}
	return resp.Body, resp.Header.Get("X-Strongbox-Marking"), nil
}

// ReadBlob reads content into memory, failing if it exceeds maxBytes (0 for no limit).
func (a *App) ReadBlob(ctx context.Context, id string, maxBytes int64) ([]byte, string, error) {
	rc, banner, err := a.OpenBlob(ctx, id)
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

func (a *App) ListBlobs(ctx context.Context, limit int, cursor string) (*Page[Blob], error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	var out Page[Blob]
	return &out, a.c.do(ctx, request{method: "GET", path: a.base + "/blobs", query: q}, &out)
}

func (a *App) DeleteBlob(ctx context.Context, id string, shred bool) error {
	return a.c.do(ctx, request{method: "DELETE", path: a.base + "/blobs/" + url.PathEscape(id),
		query: url.Values{"shred": {strconv.FormatBool(shred)}}, headers: map[string]string{"Idempotency-Key": operationID(ctx)}}, nil)
}

// ---- collections & records ------------------------------------------------------------------------

type CollectionSpec struct {
	Name          string         `json:"name"`
	Marking       string         `json:"marking"`
	JSONSchema    map[string]any `json:"json_schema,omitempty"`
	IndexedFields []string       `json:"indexed_fields,omitempty"`
	UniqueFields  []string       `json:"unique_fields,omitempty"`
	Encrypted     *bool          `json:"encrypted,omitempty"`
	HistoryLimit  int            `json:"history_limit,omitempty"`
	// DeletedRetentionDays: how long deleted records stay restorable (default 30).
	DeletedRetentionDays int `json:"deleted_retention_days,omitempty"`
}

func (a *App) CreateCollection(ctx context.Context, s CollectionSpec) (*Collection, error) {
	var out Collection
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/collections", body: jsonBody(s),
		headers: jsonHeaders("Idempotency-Key", operationID(ctx))}, &out)
}

// Contract is a new version of a collection's contract.
type Contract struct {
	JSONSchema      map[string]any `json:"json_schema"`
	IndexedFields   []string       `json:"indexed_fields,omitempty"`
	UniqueFields    []string       `json:"unique_fields,omitempty"`
	Defaults        map[string]any `json:"defaults,omitempty"`
	ExpectedVersion int            `json:"expected_version"`
}

type Migration struct {
	ID          string `json:"id"`
	Collection  string `json:"collection"`
	FromVersion int    `json:"from_version"`
	ToVersion   int    `json:"to_version"`
	State       string `json:"state"` // running | succeeded | failed | cancelled
	Processed   int64  `json:"processed"`
	Rewritten   int64  `json:"rewritten"`
	Failures    []struct {
		RecordID string `json:"record_id"`
		Reason   string `json:"reason"`
	} `json:"failures"`
}

type ContractChange struct {
	Collection Collection `json:"collection"`
	Version    int        `json:"version"`
	Immediate  bool       `json:"immediate"`
	Reason     string     `json:"reason,omitempty"`
	Migration  *Migration `json:"migration"`
}

// ChangeContract stages a new contract version. Immediate is true when it took effect at once;
// otherwise Migration tracks the job that validates existing records before the switch.
func (a *App) ChangeContract(ctx context.Context, collection string, c Contract) (*ContractChange, error) {
	var out ContractChange
	return &out, a.c.do(ctx, request{method: "PUT", path: a.base + "/collections/" + url.PathEscape(collection) + "/contract",
		body: jsonBody(c), headers: jsonHeaders("Idempotency-Key", operationID(ctx))}, &out)
}

func (a *App) GetMigration(ctx context.Context, collection, id string) (*Migration, error) {
	var out Migration
	return &out, a.c.do(ctx, request{method: "GET", path: a.base + "/collections/" + url.PathEscape(collection) + "/migrations/" + url.PathEscape(id)}, &out)
}

func (a *App) CancelMigration(ctx context.Context, collection, id string) (*Migration, error) {
	var out Migration
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/collections/" + url.PathEscape(collection) + "/migrations/" + url.PathEscape(id) + "/cancel"}, &out)
}

func (a *App) ListCollections(ctx context.Context) ([]Collection, error) {
	var out Page[Collection]
	return out.Items, a.c.do(ctx, request{method: "GET", path: a.base + "/collections"}, &out)
}

func (a *App) GetCollection(ctx context.Context, name string) (*Collection, error) {
	var out Collection
	return &out, a.c.do(ctx, request{method: "GET", path: a.base + "/collections/" + url.PathEscape(name)}, &out)
}

func (a *App) recordPath(coll, id string) string {
	return a.base + "/collections/" + url.PathEscape(coll) + "/records/" + url.PathEscape(id)
}

// RecordInput is a record body. Visibility and TeamID apply on create.
type RecordInput struct {
	Data       map[string]any `json:"data"`
	Marking    string         `json:"marking,omitempty"`
	Visibility string         `json:"visibility,omitempty"`
	TeamID     string         `json:"team_id,omitempty"`
}

func (a *App) CreateRecord(ctx context.Context, coll string, in RecordInput) (*Record, error) {
	var out Record
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/collections/" + url.PathEscape(coll) + "/records",
		body: jsonBody(in), headers: jsonHeaders("Idempotency-Key", operationID(ctx))}, &out)
}

func (a *App) GetRecord(ctx context.Context, coll, id string) (*Record, error) {
	var out Record
	return &out, a.c.do(ctx, request{method: "GET", path: a.recordPath(coll, id)}, &out)
}

// UpdateRecord replaces data if the record is still at expectedVersion; otherwise IsConflict(err).
func (a *App) UpdateRecord(ctx context.Context, coll, id string, expectedVersion int, in RecordInput) (*Record, error) {
	var out Record
	return &out, a.c.do(ctx, request{method: "PUT", path: a.recordPath(coll, id), body: jsonBody(in),
		headers: jsonHeaders("If-Match", etag(expectedVersion), "Idempotency-Key", operationID(ctx))}, &out)
}

// Mutate is read-modify-write with conflict recovery: it re-reads and re-applies fn when another
// writer got there first, up to attempts times.
func (a *App) Mutate(ctx context.Context, coll, id string, attempts int, fn func(data map[string]any) (map[string]any, error)) (*Record, error) {
	for i := 0; ; i++ {
		cur, err := a.GetRecord(ctx, coll, id)
		if err != nil {
			return nil, err
		}
		next, err := fn(cur.Data)
		if err != nil {
			return nil, err
		}
		rec, err := a.UpdateRecord(ctx, coll, id, cur.Version, RecordInput{Data: next})
		if err == nil || !IsConflict(err) || i+1 >= attempts {
			return rec, err
		}
	}
}

// DeleteRecord deletes (expectedVersion 0: whatever is current, still atomic). purge also drops history.
func (a *App) DeleteRecord(ctx context.Context, coll, id string, expectedVersion int, purge bool) error {
	if expectedVersion <= 0 {
		return fmt.Errorf("expectedVersion must be positive")
	}
	h := map[string]string{"Idempotency-Key": operationID(ctx)}
	if expectedVersion > 0 {
		h["If-Match"] = etag(expectedVersion)
	}
	return a.c.do(ctx, request{method: "DELETE", path: a.recordPath(coll, id), query: url.Values{"purge": {strconv.FormatBool(purge)}}, headers: h}, nil)
}

func (a *App) Query(ctx context.Context, coll string, filters map[string]any, limit int, cursor string) (*Page[Record], error) {
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
	var out Page[Record]
	return &out, a.c.do(ctx, request{method: "POST", path: a.base + "/collections/" + url.PathEscape(coll) + "/query",
		body: jsonBody(body), headers: jsonHeaders()}, &out)
}

// QueryAll follows cursors until fn returns false or the results end.
func (a *App) QueryAll(ctx context.Context, coll string, filters map[string]any, fn func(Record) bool) error {
	cursor := ""
	for {
		page, err := a.Query(ctx, coll, filters, 200, cursor)
		if err != nil {
			return err
		}
		for _, r := range page.Items {
			if !fn(r) {
				return nil
			}
		}
		if page.NextCursor == nil {
			return nil
		}
		cursor = *page.NextCursor
	}
}

func (a *App) History(ctx context.Context, coll, id string, before, limit int) (*History, error) {
	q := url.Values{}
	if before > 0 {
		q.Set("before", strconv.Itoa(before))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out History
	return &out, a.c.do(ctx, request{method: "GET", path: a.recordPath(coll, id) + "/history", query: q}, &out)
}

func (a *App) Revision(ctx context.Context, coll, id string, version int) (*Record, error) {
	var out Record
	return &out, a.c.do(ctx, request{method: "GET", path: a.recordPath(coll, id) + "/history/" + strconv.Itoa(version)}, &out)
}

// Restore makes version current again as a new version (undo), if the record is at currentVersion.
func (a *App) Restore(ctx context.Context, coll, id string, version, currentVersion int) (*Record, error) {
	var out Record
	return &out, a.c.do(ctx, request{method: "POST", path: a.recordPath(coll, id) + "/restore",
		body: jsonBody(map[string]int{"version": version}), headers: jsonHeaders("If-Match", etag(currentVersion), "Idempotency-Key", operationID(ctx))}, &out)
}

// ---- sharing --------------------------------------------------------------------------------------

// ResourcePath names a record (collection, id) or a blob ("", id).
func (a *App) resourcePath(coll, id string) string {
	if coll == "" {
		return a.base + "/blobs/" + url.PathEscape(id)
	}
	return a.recordPath(coll, id)
}

// Share sets visibility: private, team (with teamID) or app.
func (a *App) Share(ctx context.Context, coll, id, visibility, teamID string) error {
	return a.c.do(ctx, request{method: "PUT", path: a.resourcePath(coll, id) + "/sharing",
		body: jsonBody(map[string]string{"visibility": visibility, "team_id": teamID}), headers: jsonHeaders()}, nil)
}

type GrantInput struct {
	Subject  string `json:"subject,omitempty"`
	TeamID   string `json:"team_id,omitempty"`
	Role     string `json:"role"`
	CanShare bool   `json:"can_share,omitempty"`
}

func (a *App) Grant(ctx context.Context, coll, id string, g GrantInput) (*Grant, error) {
	var out Grant
	return &out, a.c.do(ctx, request{method: "POST", path: a.resourcePath(coll, id) + "/grants", body: jsonBody(g), headers: jsonHeaders()}, &out)
}

func (a *App) Revoke(ctx context.Context, coll, id, grantID string) error {
	return a.c.do(ctx, request{method: "DELETE", path: a.resourcePath(coll, id) + "/grants/" + url.PathEscape(grantID)}, nil)
}
