package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
)

func parseMarking(v string) (markings.Marking, error) {
	m, err := markings.Parse(v)
	if err != nil {
		return m, errs.Invalid("%v", err)
	}
	return m, nil
}

func intParam(r *http.Request, name string, def, lo, hi int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, errs.Invalid("%s must be an integer between %d and %d", name, lo, hi)
	}
	return n, nil
}

func boolParam(r *http.Request, name string) (bool, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, errs.Invalid("%s must be true or false", name)
	}
	return b, nil
}

// ---- identity, principals, audit -----------------------------------------------------------------

func (s *Server) whoami(w http.ResponseWriter, _ *http.Request, c service.Ctx) error {
	writeJSON(w, 200, c.Principal.Public())
	return nil
}

func (s *Server) listPrincipals(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	if _, err := s.c.Guard.Check(r.Context(), c, auth.PrincipalAdmin, "principal", "", nil, service.CheckOpts{}); err != nil {
		return err
	}
	items, err := s.c.Principals.List(r.Context())
	if err != nil {
		return err
	}
	if items == nil {
		items = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
	return nil
}

func (s *Server) putPrincipal(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	subject := r.PathValue("subject")
	var spec auth.Spec
	if err := decode(r, w, maxJSONBody, &spec); err != nil {
		return err
	}
	spec.Subject = subject
	if _, err := s.c.Guard.Check(r.Context(), c, auth.PrincipalAdmin, "principal", subject, nil, service.CheckOpts{
		Details: map[string]any{"cui_categories": spec.CUICategories, "us_person": spec.USPerson, "scopes": spec.Scopes},
	}); err != nil {
		return err
	}
	if subject == c.Principal.Subject || subject == c.Principal.Actor {
		return errs.Forbidden("administrators cannot modify their own principal (separation of duties)")
	}
	if err := spec.Validate(); err != nil {
		return errs.Invalid("%v", err)
	}
	if err := s.c.Principals.Put(r.Context(), spec); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"subject": subject, "updated": true})
	return nil
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	if _, err := s.c.Guard.Check(r.Context(), c, auth.AuditRead, "audit", "", nil, service.CheckOpts{}); err != nil {
		return err
	}
	after, err := intParam(r, "after_seq", 0, 0, 1<<62)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", 100, 1, 1000)
	if err != nil {
		return err
	}
	events, err := s.c.Audit.List(r.Context(), int64(after), limit)
	if err != nil {
		return err
	}
	var items any = events
	if events == nil {
		items = []any{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
	return nil
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	if _, err := s.c.Guard.Check(r.Context(), c, auth.AuditRead, "audit", "", nil, service.CheckOpts{}); err != nil {
		return err
	}
	res, err := s.c.Audit.Verify(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, res)
	return nil
}

// ---- blobs ----------------------------------------------------------------------------------------

func (s *Server) uploadBlob(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	h := r.Header
	if h.Get(MarkingHeader) == "" {
		return errs.Invalid("X-Strongbox-Marking header is required (use UNCONTROLLED for non-CUI data)")
	}
	m, err := parseMarking(h.Get(MarkingHeader))
	if err != nil {
		return err
	}
	in := service.BlobInput{Marking: m, ContentType: h.Get("Content-Type"), IdempotencyKey: h.Get("Idempotency-Key"),
		DeclaredSize: r.ContentLength}
	if fn := h.Get("X-Strongbox-Filename"); fn != "" {
		if in.Filename, err = url.PathUnescape(fn); err != nil {
			return errs.Invalid("X-Strongbox-Filename must be percent-encoded")
		}
	}
	if md := h.Get("X-Strongbox-Metadata"); md != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(md, "="))
		if err == nil {
			err = json.Unmarshal(raw, &in.Metadata)
		}
		if err != nil || in.Metadata == nil {
			return errs.Invalid("X-Strongbox-Metadata must be base64url-encoded JSON object")
		}
	}
	upload, existing, err := s.c.Blobs.Begin(r.Context(), c, in)
	if err != nil {
		return err
	}
	status, meta := 200, existing
	if upload != nil {
		buf := make([]byte, 256*1024)
		for {
			n, rerr := r.Body.Read(buf)
			if n > 0 {
				if _, err := upload.Write(buf[:n]); err != nil {
					return err
				}
			}
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				upload.Abort("client read error")
				return errs.Invalid("could not read request body: %v", rerr)
			}
		}
		if meta, err = upload.Commit(); err != nil {
			return err
		}
		status = 201
	}
	w.Header().Set("Location", "/v1/blobs/"+meta.ID)
	w.Header().Set(MarkingHeader, meta.Marking.Banner())
	writeJSON(w, status, meta.JSON())
	return nil
}

func (s *Server) listBlobs(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	limit, err := intParam(r, "limit", 0, 1, 200)
	if err != nil {
		return err
	}
	items, next, err := s.c.Blobs.List(r.Context(), c, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(items))
	for _, m := range items {
		out = append(out, m.JSON())
	}
	writeJSON(w, 200, map[string]any{"items": out, "next_cursor": nullable(next)})
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	meta, err := s.c.Blobs.Meta(r.Context(), c, r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set(MarkingHeader, meta.Marking.Banner())
	writeJSON(w, 200, meta.JSON())
	return nil
}

func (s *Server) downloadBlob(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	meta, body, err := s.c.Blobs.Open(r.Context(), c, r.PathValue("id"))
	if err != nil {
		return err
	}
	defer body.Close()
	h := w.Header()
	h.Set(MarkingHeader, meta.Marking.Banner())
	h.Set("Content-Type", meta.ContentType)
	if meta.SizeBytes != nil {
		h.Set("Content-Length", strconv.FormatInt(*meta.SizeBytes, 10))
	}
	if meta.Filename != "" {
		h.Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(meta.Filename))
	}
	w.WriteHeader(200)
	// A failure after this point (integrity, storage) aborts the stream; Content-Length lets clients notice.
	if _, err := io.Copy(w, body); err != nil {
		panic(http.ErrAbortHandler)
	}
	return nil
}

func (s *Server) deleteBlob(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	shred, err := boolParam(r, "shred")
	if err != nil {
		return err
	}
	if err := s.c.Blobs.Delete(r.Context(), c, r.PathValue("id"), shred); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

// ---- collections & records ------------------------------------------------------------------------

type collectionIn struct {
	Name          string         `json:"name"`
	Marking       string         `json:"marking"`
	JSONSchema    map[string]any `json:"json_schema"`
	IndexedFields []string       `json:"indexed_fields"`
	Encrypted     *bool          `json:"encrypted"`
}

type recordIn struct {
	Data    map[string]any `json:"data"`
	Marking *string        `json:"marking"`
}

func (in recordIn) marking() (*markings.Marking, error) {
	if in.Marking == nil {
		return nil, nil
	}
	m, err := parseMarking(*in.Marking)
	return &m, err
}

var etagRe = regexp.MustCompile(`^(?:W/)?"?v?(\d{1,9})"?$`)

func ifMatch(r *http.Request, required bool) (*int, error) {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" {
		if required {
			return nil, errs.PreconditionRequired("If-Match with the record's ETag is required")
		}
		return nil, nil
	}
	m := etagRe.FindStringSubmatch(v)
	if m == nil {
		return nil, errs.Invalid(`If-Match must be an ETag such as "v3"`)
	}
	n, _ := strconv.Atoi(m[1])
	return &n, nil
}

func writeRecord(w http.ResponseWriter, status int, rec *service.Record) {
	w.Header().Set("ETag", `"v`+strconv.Itoa(rec.Version)+`"`)
	w.Header().Set(MarkingHeader, rec.Marking.Banner())
	writeJSON(w, status, rec.JSON())
}

func (s *Server) createCollection(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in collectionIn
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	m, err := parseMarking(in.Marking)
	if err != nil {
		return err
	}
	col, err := s.c.Records.CreateCollection(r.Context(), c, service.CollectionInput{Name: in.Name, Marking: m,
		JSONSchema: in.JSONSchema, IndexedFields: in.IndexedFields, Encrypted: in.Encrypted})
	if err != nil {
		return err
	}
	writeJSON(w, 201, col.JSON())
	return nil
}

func (s *Server) listCollections(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	cols, err := s.c.Records.ListCollections(r.Context(), c)
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(cols))
	for _, col := range cols {
		out = append(out, col.JSON())
	}
	writeJSON(w, 200, map[string]any{"items": out})
	return nil
}

func (s *Server) getCollection(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	col, err := s.c.Records.GetCollection(r.Context(), c, r.PathValue("name"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, col.JSON())
	return nil
}

func (s *Server) createRecord(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in recordIn
	if err := decode(r, w, int64(s.c.Config.MaxRecordBytes)+64*1024, &in); err != nil {
		return err
	}
	m, err := in.marking()
	if err != nil {
		return err
	}
	name := r.PathValue("name")
	rec, err := s.c.Records.Create(r.Context(), c, name, in.Data, m, r.Header.Get("Idempotency-Key"))
	if err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/collections/"+name+"/records/"+rec.ID)
	writeRecord(w, 201, rec)
	return nil
}

func (s *Server) getRecord(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	rec, err := s.c.Records.Get(r.Context(), c, r.PathValue("name"), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeRecord(w, 200, rec)
	return nil
}

func (s *Server) updateRecord(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	version, err := ifMatch(r, true)
	if err != nil {
		return err
	}
	var in recordIn
	if err := decode(r, w, int64(s.c.Config.MaxRecordBytes)+64*1024, &in); err != nil {
		return err
	}
	m, err := in.marking()
	if err != nil {
		return err
	}
	rec, err := s.c.Records.Update(r.Context(), c, r.PathValue("name"), r.PathValue("id"), in.Data, *version, m)
	if err != nil {
		return err
	}
	writeRecord(w, 200, rec)
	return nil
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	purge, err := boolParam(r, "purge")
	if err != nil {
		return err
	}
	version, err := ifMatch(r, false)
	if err != nil {
		return err
	}
	if err := s.c.Records.Delete(r.Context(), c, r.PathValue("name"), r.PathValue("id"), version, purge); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

type queryIn struct {
	Filters map[string]any `json:"filters"`
	Limit   *int           `json:"limit"`
	Cursor  *string        `json:"cursor"`
}

func (s *Server) queryRecords(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in queryIn
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	limit := 0
	if in.Limit != nil {
		if *in.Limit < 1 || *in.Limit > 200 {
			return errs.Invalid("limit must be between 1 and 200")
		}
		limit = *in.Limit
	}
	cur := ""
	if in.Cursor != nil {
		cur = *in.Cursor
	}
	recs, next, err := s.c.Records.Query(r.Context(), c, r.PathValue("name"), in.Filters, limit, cur)
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(recs))
	ms := make([]markings.Marking, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.JSON())
		ms = append(ms, rec.Marking)
	}
	banner := markings.Combine(ms).Banner()
	w.Header().Set(MarkingHeader, banner)
	writeJSON(w, 200, map[string]any{"items": out, "next_cursor": nullable(next), "marking": banner})
	return nil
}
