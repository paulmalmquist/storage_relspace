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
	"strconv"
	"strings"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/telemetry"
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
	c         *service.Container
	mux       *http.ServeMux
	budget    *budget
	authSlots chan struct{}
}

// New returns the API handler with middleware applied.
func New(c *service.Container) http.Handler {
	s := &Server{c: c, mux: http.NewServeMux(), budget: newBudget(c.Config),
		authSlots: make(chan struct{}, max(1, int(c.Pool.Config().MaxConns)/4))}
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
	for pattern, h := range s.table() {
		m.HandleFunc(pattern, s.authed(h))
	}
}

// table maps every authenticated route to its handler. App-scoped routes live under
// /v1/apps/{app}: the path names the app, the deployment fixes the environment, and membership
// (checked in the database) decides access.
func (s *Server) table() map[string]handler {
	const a = "/v1/apps/{app}"
	const rec = a + "/collections/{name}/records/{id}"
	return map[string]handler{
		"GET /v1/whoami":                                           s.whoami,
		"GET /v1/limits":                                           s.limits,
		"GET /v1/principals":                                       s.listPrincipals,
		"PUT /v1/principals/{subject}":                             s.putPrincipal,
		"GET /v1/audit/events":                                     s.auditEvents,
		"GET /v1/audit/verify":                                     s.auditVerify,
		"POST " + a + "/records/batch":                             s.app(s.batchRecords),
		"GET " + a:                                                 s.app(s.getApp),
		"GET " + a + "/members":                                    s.app(s.listMembers),
		"PUT " + a + "/members/{subject}":                          s.app(s.putMember),
		"DELETE " + a + "/members/{subject}":                       s.app(s.removeMember),
		"GET " + a + "/teams":                                      s.app(s.listTeams),
		"POST " + a + "/teams":                                     s.app(s.createTeam),
		"PUT " + a + "/teams/{team}/members/{subject}":             s.app(s.putTeamMember),
		"DELETE " + a + "/teams/{team}/members/{subject}":          s.app(s.removeTeamMember),
		"POST " + a + "/blobs":                                     s.app(s.uploadBlob),
		"POST " + a + "/uploads":                                   s.app(s.createUpload),
		"GET " + a + "/uploads/{id}":                               s.app(s.getUpload),
		"PUT " + a + "/uploads/{id}/parts/{n}":                     s.app(s.putUploadPart),
		"POST " + a + "/uploads/{id}/complete":                     s.app(s.completeUpload),
		"DELETE " + a + "/uploads/{id}":                            s.app(s.abortUpload),
		"GET " + a + "/usage":                                      s.app(s.appUsage),
		"GET " + a + "/blobs":                                      s.app(s.listBlobs),
		"GET " + a + "/blobs/{id}":                                 s.app(s.getBlob),
		"GET " + a + "/blobs/{id}/content":                         s.app(s.downloadBlob),
		"DELETE " + a + "/blobs/{id}":                              s.app(s.deleteBlob),
		"PUT " + a + "/blobs/{id}/sharing":                         s.app(s.setSharing("blob")),
		"GET " + a + "/blobs/{id}/grants":                          s.app(s.listGrants("blob")),
		"POST " + a + "/blobs/{id}/grants":                         s.app(s.addGrant("blob")),
		"DELETE " + a + "/blobs/{id}/grants/{grant}":               s.app(s.removeGrant("blob")),
		"POST " + a + "/collections":                               s.app(s.createCollection),
		"GET " + a + "/collections":                                s.app(s.listCollections),
		"GET " + a + "/collections/{name}":                         s.app(s.getCollection),
		"PUT " + a + "/collections/{name}/contract":                s.app(s.changeContract),
		"GET " + a + "/collections/{name}/versions":                s.app(s.contractVersions),
		"GET " + a + "/collections/{name}/migrations/{id}":         s.app(s.getMigration),
		"POST " + a + "/collections/{name}/migrations/{id}/cancel": s.app(s.cancelMigration),
		"POST " + a + "/collections/{name}/records":                s.app(s.createRecord),
		"POST " + a + "/collections/{name}/query":                  s.app(s.queryRecords),
		"GET " + rec:                                               s.app(s.getRecord),
		"PUT " + rec:                                               s.app(s.updateRecord),
		"DELETE " + rec:                                            s.app(s.deleteRecord),
		"GET " + rec + "/history":                                  s.app(s.recordHistory),
		"GET " + rec + "/history/{version}":                        s.app(s.recordRevision),
		"POST " + rec + "/restore":                                 s.app(s.restoreRecord),
		"PUT " + rec + "/sharing":                                  s.app(s.setSharing("record")),
		"GET " + rec + "/grants":                                   s.app(s.listGrants("record")),
		"POST " + rec + "/grants":                                  s.app(s.addGrant("record")),
		"DELETE " + rec + "/grants/{grant}":                        s.app(s.removeGrant("record")),
		"GET " + a + "/operations/{op_id}":                         s.app(s.getOperation),
		"POST " + a + "/explain":                                   s.app(s.explain),
		"GET " + a + "/audit/events":                               s.app(s.auditEvents),
		"GET " + a + "/audit/verify":                               s.app(s.auditVerify),
	}
}

// Routes lists the registered API patterns (used by the OpenAPI contract test).
func Routes() []string {
	s := &Server{}
	out := make([]string, 0, 64)
	for k := range s.table() {
		out = append(out, k)
	}
	return out
}

// streaming routes carry bodies whose duration depends on their size; every other route gets the
// request deadline.
var streaming = map[string]bool{
	"POST /v1/apps/{app}/blobs":                 true,
	"GET /v1/apps/{app}/blobs/{id}/content":     true,
	"PUT /v1/apps/{app}/uploads/{id}/parts/{n}": true,
}

// app resolves the {app} path segment into the request's scope, charges the request to the app's
// and the caller's budgets, applies the request deadline, and passes the client operation ID
// (Idempotency-Key) through.
func (s *Server) app(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
		app, err := s.c.AppScope(r.PathValue("app"))
		if err != nil {
			return err
		}
		release, err := s.budget.admit(app, c.Principal.Subject)
		if err != nil {
			return err
		}
		defer release()
		if !streaming[r.Pattern] && s.c.Config.RequestTimeout > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), s.c.Config.RequestTimeout)
			defer cancel()
			r = r.WithContext(ctx)
		}
		c.App = app
		c.OpID = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if r.Method != "GET" && r.Method != "HEAD" && !strings.HasSuffix(r.Pattern, "/query") && !strings.HasSuffix(r.Pattern, "/explain") && !service.ValidOpID(c.OpID) {
			return errs.Invalid("a valid Idempotency-Key is required for mutations")
		}
		return h(w, r, c)
	}
}

// ---- middleware -----------------------------------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

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
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			telemetry.RequestDuration.Record(context.Background(), time.Since(start).Seconds(), telemetry.Route(route, r.Method, sw.status))
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
		timeout := s.c.Config.RequestTimeout
		if streaming[r.Pattern] {
			timeout = s.c.Config.StreamTimeout
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		if deadline, ok := ctx.Deadline(); ok {
			controller := http.NewResponseController(w)
			_ = controller.SetReadDeadline(deadline)
			_ = controller.SetWriteDeadline(deadline)
		}
		r = r.WithContext(ctx)
		p, err := func() (*auth.Principal, error) {
			actx, cancel := context.WithTimeout(ctx, s.c.Config.RequestTimeout)
			defer cancel()
			select {
			case s.authSlots <- struct{}{}:
				defer func() { <-s.authSlots }()
			case <-actx.Done():
				return nil, errs.Unavailable("authentication busy; retry shortly")
			}
			return s.authenticate(r.WithContext(actx))
		}()
		if err == nil {
			err = h(w, r, service.Ctx{Principal: p, RequestID: requestID(r)})
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				err = errs.Unavailable("request timed out; resolve mutations by their operation ID").Wrap(err)
			}
			s.fail(w, r, err)
		}
	}
}

func (s *Server) authFailure(r *http.Request, reason, subject string) error {
	if subject == "" {
		subject = "anonymous"
	}
	if !s.budget.auditAuthFailure(r) {
		// A burst of failures from one address: keep the record (structured log, exported to the
		// audit sink) without a database write per attempt.
		telemetry.AuthAuditSkips.Add(r.Context(), 1)
		slog.Warn("authentication failure", "audit", true, "chain_write", "suppressed", "subject", subject,
			"reason", reason, "request_id", requestID(r), "remote", r.RemoteAddr)
		return errs.Unauthenticated("%s", reason)
	}
	if err := s.c.Auditing.Record(r.Context(), audit.Entry{Anonymous: subject, Action: "auth.authenticate",
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
		if err := s.c.Auditing.Record(ctx, audit.Entry{Principal: p, Action: "auth.delegate", ResourceType: "session",
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
	"configuration_error": "ConfigurationError", "internal_error": "InternalError", "rate_limited": "TooManyRequests",
	"result_expired": "ResultExpired", "unavailable": "ServiceUnavailable", "quota_exceeded": "QuotaExceeded", "idempotency_key_reused": "IdempotencyKeyReused",
	"operation_in_progress": "OperationInProgress", "upload_expired": "UploadExpired", "upload_incomplete": "UploadIncomplete",
	"unique_violation": "UniqueViolation", "migration_in_progress": "MigrationInProgress", "migration_finished": "MigrationFinished",
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
	telemetry.Errors.Add(r.Context(), 1, telemetry.Code(e.Code))
	switch {
	case e.RetryAfter > 0:
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	case e.Code == "rate_limited" || e.Code == "operation_in_progress" || e.Code == "unavailable":
		w.Header().Set("Retry-After", "1")
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
