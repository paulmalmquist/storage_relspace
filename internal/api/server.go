// Package api is the inter-service HTTP API.
//
//   - Authenticate with "Authorization: Bearer <OIDC ID token>" (Google-signed for Cloud Run/GKE workloads).
//   - Agents and services acting for a user also send "X-On-Behalf-Of: <user token>"; access is the
//     intersection of both principals.
//   - Every CUI response carries X-Strongbox-Marking with its banner; propagate it downstream.
//   - Errors are application/problem+json with a stable "code".
package api

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

//go:embed openapi.json
var OpenAPI []byte

const (
	MarkingHeader = "X-Strongbox-Marking"
	OnBehalfOf    = "X-On-Behalf-Of"
	maxJSONBody   = 2 << 20
)

type ctxKey int

const requestIDKey ctxKey = 1

var ridRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,64}$`)

type Server struct {
	c   *service.Container
	mux *http.ServeMux
}

// New returns the API handler with middleware applied.
func New(c *service.Container) http.Handler {
	s := &Server{c: c, mux: http.NewServeMux()}
	s.routes()
	return s.middleware(s.mux)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /readyz", s.readyz)
	if s.c.Config.ExposeDocs {
		m.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(OpenAPI)
		})
	}
	m.HandleFunc("GET /v1/whoami", s.authed(s.whoami))
	m.HandleFunc("GET /v1/principals", s.authed(s.listPrincipals))
	m.HandleFunc("PUT /v1/principals/{subject}", s.authed(s.putPrincipal))
	m.HandleFunc("GET /v1/audit/events", s.authed(s.auditEvents))
	m.HandleFunc("GET /v1/audit/verify", s.authed(s.auditVerify))

	m.HandleFunc("POST /v1/blobs", s.authed(s.uploadBlob))
	m.HandleFunc("GET /v1/blobs", s.authed(s.listBlobs))
	m.HandleFunc("GET /v1/blobs/{id}", s.authed(s.getBlob))
	m.HandleFunc("GET /v1/blobs/{id}/content", s.authed(s.downloadBlob))
	m.HandleFunc("DELETE /v1/blobs/{id}", s.authed(s.deleteBlob))

	m.HandleFunc("POST /v1/collections", s.authed(s.createCollection))
	m.HandleFunc("GET /v1/collections", s.authed(s.listCollections))
	m.HandleFunc("GET /v1/collections/{name}", s.authed(s.getCollection))
	m.HandleFunc("POST /v1/collections/{name}/records", s.authed(s.createRecord))
	m.HandleFunc("GET /v1/collections/{name}/records/{id}", s.authed(s.getRecord))
	m.HandleFunc("PUT /v1/collections/{name}/records/{id}", s.authed(s.updateRecord))
	m.HandleFunc("DELETE /v1/collections/{name}/records/{id}", s.authed(s.deleteRecord))
	m.HandleFunc("POST /v1/collections/{name}/query", s.authed(s.queryRecords))
}

// Routes lists the registered API patterns (used by the OpenAPI contract test).
func Routes() []string {
	return []string{
		"GET /v1/whoami", "GET /v1/principals", "PUT /v1/principals/{subject}", "GET /v1/audit/events",
		"GET /v1/audit/verify", "POST /v1/blobs", "GET /v1/blobs", "GET /v1/blobs/{id}", "GET /v1/blobs/{id}/content",
		"DELETE /v1/blobs/{id}", "POST /v1/collections", "GET /v1/collections", "GET /v1/collections/{name}",
		"POST /v1/collections/{name}/records", "GET /v1/collections/{name}/records/{id}",
		"PUT /v1/collections/{name}/records/{id}", "DELETE /v1/collections/{name}/records/{id}",
		"POST /v1/collections/{name}/query",
	}
}

// ---- middleware -----------------------------------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := r.Header.Get("X-Request-ID")
		if !ridRe.MatchString(rid) {
			rid = strings.TrimPrefix(store.NewID("r"), "r_")
		}
		h := w.Header()
		h.Set("X-Request-ID", rid)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		sw := &statusWriter{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey, rid))
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity, as net/http does
					panic(rec)
				}
				slog.Error("panic", "request_id", rid, "panic", rec)
				if sw.status == 0 {
					problem(sw, r, 500, "internal_error", "InternalError", "internal error")
				}
			}
			slog.Info("request", "request_id", rid, "method", r.Method, "path", r.URL.Path, "status", sw.status,
				"bytes", sw.bytes, "duration_ms", time.Since(start).Milliseconds())
		}()
		next.ServeHTTP(sw, r)
	})
}

func requestID(r *http.Request) string {
	rid, _ := r.Context().Value(requestIDKey).(string)
	return rid
}

type handler func(w http.ResponseWriter, r *http.Request, c service.Ctx) error

// authed authenticates (including delegation) and maps returned errors to problem responses.
func (s *Server) authed(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err == nil {
			err = h(w, r, service.Ctx{Principal: p, RequestID: requestID(r)})
		}
		if err != nil {
			s.fail(w, r, err)
		}
	}
}

func (s *Server) authFailure(r *http.Request, reason, subject string) error {
	if subject == "" {
		subject = "anonymous"
	}
	if _, err := s.c.Audit.Record(r.Context(), audit.Entry{Anonymous: subject, Action: "auth.authenticate",
		ResourceType: "session", Decision: "deny", Reason: reason, RequestID: requestID(r)}); err != nil {
		return err
	}
	return errs.Unauthenticated("%s", reason)
}

func (s *Server) authenticate(r *http.Request) (*auth.Principal, error) {
	ctx := r.Context()
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	if !strings.EqualFold(scheme, "bearer") || token == "" {
		return nil, s.authFailure(r, "missing bearer token", "")
	}
	vt, err := s.c.Verifier.Verify(ctx, token)
	if err != nil {
		return nil, s.authFailure(r, detail(err), "")
	}
	p, err := s.c.Principals.Get(ctx, vt.Subject)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, s.authFailure(r, "unknown or disabled principal", vt.Subject)
	}
	obo := strings.TrimSpace(r.Header.Get(OnBehalfOf))
	if obo == "" {
		return p, nil
	}
	if !p.HasScope("delegate") {
		if _, err := s.c.Audit.Record(ctx, audit.Entry{Principal: p, Action: "auth.delegate", ResourceType: "session",
			Decision: "deny", Reason: "caller lacks the delegate scope", RequestID: requestID(r)}); err != nil {
			return nil, err
		}
		return nil, errs.Forbidden("caller may not act on behalf of other principals")
	}
	dt, err := s.c.DelegationVerifier.Verify(ctx, obo)
	if err != nil {
		return nil, s.authFailure(r, "invalid on-behalf-of token: "+detail(err), p.Subject)
	}
	delegator, err := s.c.Principals.Get(ctx, dt.Subject)
	if err != nil {
		return nil, err
	}
	if delegator == nil {
		return nil, s.authFailure(r, "unknown or disabled on-behalf-of principal", dt.Subject)
	}
	if delegator.Kind == auth.KindAgent {
		return nil, errs.Forbidden("agents cannot delegate to other agents")
	}
	return delegator.DelegatedTo(p), nil
}

func detail(err error) string {
	if e, ok := errs.As(err); ok {
		return e.Detail
	}
	return err.Error()
}

// ---- responses ------------------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "encoding error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func problem(w http.ResponseWriter, r *http.Request, status int, code, title, det string) {
	if status == 401 {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	var rid any
	if id := requestID(r); id != "" {
		rid = id
	}
	body, _ := json.Marshal(map[string]any{"type": "about:blank", "title": title, "status": status, "code": code,
		"detail": det, "request_id": rid})
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

var titles = map[string]string{
	"unauthenticated": "Unauthenticated", "forbidden": "AccessDenied", "content_withheld": "ContentWithheld",
	"not_found": "NotFound", "conflict": "Conflict", "precondition_failed": "PreconditionFailed",
	"payload_too_large": "PayloadTooLarge", "validation_failed": "ValidationFailed",
	"precondition_required": "PreconditionRequired", "integrity_violation": "IntegrityViolation",
	"configuration_error": "ConfigurationError",
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		err = errs.PayloadTooLarge("request body exceeds %d bytes", mbe.Limit)
	}
	e, ok := errs.As(err)
	if !ok {
		slog.Error("unhandled error", "request_id", requestID(r), "error", err)
		problem(w, r, 500, "internal_error", "InternalError", "internal error")
		return
	}
	if e.Status >= 500 {
		slog.Error("request failed", "request_id", requestID(r), "code", e.Code, "detail", e.Detail)
	}
	problem(w, r, e.Status, e.Code, titles[e.Code], e.Detail)
}

// decode reads a JSON body strictly (unknown fields rejected, numbers kept exact).
func decode(r *http.Request, w http.ResponseWriter, limit int64, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return errs.Invalid("invalid JSON body: %v", err)
	}
	return nil
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.c.DB.Ping(ctx); err != nil {
		writeJSON(w, 503, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
