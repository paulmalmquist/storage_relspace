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

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---- identity, principals, audit -----------------------------------------------------------------

func (s *Server) whoami(w http.ResponseWriter, _ *http.Request, c service.Ctx) error {
	writeJSON(w, 200, c.Principal.Public())
	return nil
}

func (s *Server) listPrincipals(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	items, err := s.c.PrincipalAdmin.List(r.Context(), c)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"items": items})
	return nil
}

func (s *Server) putPrincipal(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var spec auth.Spec
	if err := decode(r, w, maxJSONBody, &spec); err != nil {
		return err
	}
	spec.Subject = r.PathValue("subject")
	if err := s.c.PrincipalAdmin.Put(r.Context(), c, spec); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"subject": spec.Subject, "updated": true})
	return nil
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	after, err := intParam(r, "after_seq", 0, 0, 1<<62)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", 100, 1, 1000)
	if err != nil {
		return err
	}
	events, chains, err := s.c.Auditing.Events(r.Context(), c, r.URL.Query().Get("chain"), int64(after), limit)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"items": events, "chains": chains})
	return nil
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	res, err := s.c.Auditing.Verify(r.Context(), c)
	if err != nil {
		return err
	}
	writeJSON(w, 200, res)
	return nil
}

// ---- apps, members, teams ------------------------------------------------------------------------

func (s *Server) getApp(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	info, err := s.c.Sharing.App(r.Context(), c)
	if err != nil {
		return err
	}
	writeJSON(w, 200, info)
	return nil
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	items, err := s.c.Sharing.Members(r.Context(), c)
	if err != nil {
		return err
	}
	if items == nil {
		items = []service.Member{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
	return nil
}

type roleIn struct {
	Role string `json:"role"`
}

func (s *Server) putMember(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in roleIn
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	if err := s.c.Sharing.PutMember(r.Context(), c, r.PathValue("subject"), in.Role); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"subject": r.PathValue("subject"), "role": in.Role})
	return nil
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	if err := s.c.Sharing.RemoveMember(r.Context(), c, r.PathValue("subject")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) listTeams(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	items, err := s.c.Sharing.Teams(r.Context(), c)
	if err != nil {
		return err
	}
	if items == nil {
		items = []service.Team{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
	return nil
}

func (s *Server) createTeam(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	t, err := s.c.Sharing.CreateTeam(r.Context(), c, in.Name)
	if err != nil {
		return err
	}
	writeJSON(w, 201, t)
	return nil
}

func (s *Server) putTeamMember(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in roleIn
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	if err := s.c.Sharing.PutTeamMember(r.Context(), c, r.PathValue("team"), r.PathValue("subject"), in.Role); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"team_id": r.PathValue("team"), "subject": r.PathValue("subject"), "role": in.Role})
	return nil
}

func (s *Server) removeTeamMember(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	if err := s.c.Sharing.RemoveTeamMember(r.Context(), c, r.PathValue("team"), r.PathValue("subject")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

// ---- sharing (records and blobs) ----------------------------------------------------------------

func ref(kind string, r *http.Request) service.ResourceRef {
	return service.ResourceRef{Kind: kind, Collection: r.PathValue("name"), ID: r.PathValue("id")}
}

type sharingIn struct {
	Visibility string `json:"visibility"`
	TeamID     string `json:"team_id"`
}

func (s *Server) setSharing(kind string) handler {
	return func(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
		var in sharingIn
		if err := decode(r, w, maxJSONBody, &in); err != nil {
			return err
		}
		if err := s.c.Sharing.SetVisibility(r.Context(), c, ref(kind, r), in.Visibility, in.TeamID); err != nil {
			return err
		}
		writeJSON(w, 200, map[string]any{"visibility": in.Visibility, "team_id": nullable(in.TeamID)})
		return nil
	}
}

func (s *Server) listGrants(kind string) handler {
	return func(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
		items, err := s.c.Sharing.Grants(r.Context(), c, ref(kind, r))
		if err != nil {
			return err
		}
		if items == nil {
			items = []service.Grant{}
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return nil
	}
}

type grantIn struct {
	Subject  string `json:"subject"`
	TeamID   string `json:"team_id"`
	Role     string `json:"role"`
	CanShare bool   `json:"can_share"`
}

func (s *Server) addGrant(kind string) handler {
	return func(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
		var in grantIn
		if err := decode(r, w, maxJSONBody, &in); err != nil {
			return err
		}
		g, err := s.c.Sharing.AddGrant(r.Context(), c, ref(kind, r), service.GrantInput{Subject: in.Subject, TeamID: in.TeamID,
			Role: in.Role, CanShare: in.CanShare})
		if err != nil {
			return err
		}
		writeJSON(w, 201, g)
		return nil
	}
}

func (s *Server) removeGrant(kind string) handler {
	return func(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
		if err := s.c.Sharing.RemoveGrant(r.Context(), c, ref(kind, r), r.PathValue("grant")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	}
}

type explainIn struct {
	Subject    string `json:"subject"`
	Kind       string `json:"kind"`
	Collection string `json:"collection"`
	ID         string `json:"id"`
}

func (s *Server) explain(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in explainIn
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	ex, err := s.c.Sharing.Explain(r.Context(), c, in.Subject, service.ResourceRef{Kind: in.Kind, Collection: in.Collection, ID: in.ID})
	if err != nil {
		return err
	}
	writeJSON(w, 200, ex)
	return nil
}

func (s *Server) getOperation(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	rc, err := s.c.Operation(r.Context(), c, r.PathValue("op_id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, rc)
	return nil
}

// ---- blobs ----------------------------------------------------------------------------------------

func (s *Server) blobInput(r *http.Request) (service.BlobInput, error) {
	h := r.Header
	if h.Get(MarkingHeader) == "" {
		return service.BlobInput{}, errs.Invalid("X-Strongbox-Marking header is required (use UNCONTROLLED for non-CUI data)")
	}
	m, err := parseMarking(h.Get(MarkingHeader))
	if err != nil {
		return service.BlobInput{}, err
	}
	in := service.BlobInput{Marking: m, ContentType: h.Get("Content-Type"), DeclaredSize: r.ContentLength,
		Visibility: h.Get("X-Strongbox-Visibility"), TeamID: h.Get("X-Strongbox-Team")}
	if fn := h.Get("X-Strongbox-Filename"); fn != "" {
		if in.Filename, err = url.PathUnescape(fn); err != nil {
			return in, errs.Invalid("X-Strongbox-Filename must be percent-encoded")
		}
	}
	if md := h.Get("X-Strongbox-Metadata"); md != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(md, "="))
		if err == nil {
			err = json.Unmarshal(raw, &in.Metadata)
		}
		if err != nil || in.Metadata == nil {
			return in, errs.Invalid("X-Strongbox-Metadata must be base64url-encoded JSON object")
		}
	}
	return in, nil
}

func (s *Server) uploadBlob(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	in, err := s.blobInput(r)
	if err != nil {
		return err
	}
	upload, replay, err := s.c.Blobs.Begin(r.Context(), c, in)
	if err != nil {
		return err
	}
	var meta *service.BlobMeta
	status := 201
	if replay != nil {
		if err := replay.Verify(r.Body); err != nil {
			return err
		}
		meta, status = replay.Meta, 200
	} else {
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
	}
	w.Header().Set("Location", "/v1/apps/"+r.PathValue("app")+"/blobs/"+meta.ID)
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
	UniqueFields         []string       `json:"unique_fields"`
	DeletedRetentionDays int            `json:"deleted_retention_days"`
	Name                 string         `json:"name"`
	Marking              string         `json:"marking"`
	JSONSchema           map[string]any `json:"json_schema"`
	IndexedFields        []string       `json:"indexed_fields"`
	Encrypted            *bool          `json:"encrypted"`
	HistoryLimit         int            `json:"history_limit"`
}

type recordIn struct {
	AttachmentID *string        `json:"attachment_id"`
	Data         map[string]any `json:"data"`
	Marking      *string        `json:"marking"`
	Visibility   string         `json:"visibility"`
	TeamID       string         `json:"team_id"`
}

func (in recordIn) input() (service.RecordInput, error) {
	out := service.RecordInput{AttachmentID: in.AttachmentID, Data: in.Data, Visibility: in.Visibility, TeamID: in.TeamID}
	if in.Marking != nil {
		m, err := parseMarking(*in.Marking)
		if err != nil {
			return out, err
		}
		out.Marking = &m
	}
	return out, nil
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
	w.Header().Set("ETag", rec.ETag())
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
		JSONSchema: in.JSONSchema, IndexedFields: in.IndexedFields, UniqueFields: in.UniqueFields, Encrypted: in.Encrypted,
		HistoryLimit: in.HistoryLimit, DeletedRetentionDays: in.DeletedRetentionDays})
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

func (s *Server) recordBody(w http.ResponseWriter, r *http.Request) (service.RecordInput, error) {
	var in recordIn
	if err := decode(r, w, int64(s.c.Config.MaxRecordBytes)+64*1024, &in); err != nil {
		return service.RecordInput{}, err
	}
	return in.input()
}

func (s *Server) createRecord(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	in, err := s.recordBody(w, r)
	if err != nil {
		return err
	}
	name := r.PathValue("name")
	rec, err := s.c.Records.Create(r.Context(), c, name, in)
	if err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/apps/"+r.PathValue("app")+"/collections/"+name+"/records/"+rec.ID)
	status := 201
	if rec.Replayed {
		status = 200
	}
	writeRecord(w, status, rec)
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
	in, err := s.recordBody(w, r)
	if err != nil {
		return err
	}
	if in.Visibility != "" || in.TeamID != "" {
		return errs.Invalid("visibility changes go through PUT .../sharing")
	}
	rec, err := s.c.Records.Update(r.Context(), c, r.PathValue("name"), r.PathValue("id"), in, *version)
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
	version, err := ifMatch(r, true)
	if err != nil {
		return err
	}
	if err := s.c.Records.Delete(r.Context(), c, r.PathValue("name"), r.PathValue("id"), version, purge); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) recordHistory(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	before, err := intParam(r, "before", 0, 0, 1<<30)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", 0, 1, 200)
	if err != nil {
		return err
	}
	revs, next, err := s.c.Records.History(r.Context(), c, r.PathValue("name"), r.PathValue("id"), before, limit)
	if err != nil {
		return err
	}
	if revs == nil {
		revs = []service.Revision{}
	}
	var nb any
	if next > 0 {
		nb = next
	}
	writeJSON(w, 200, map[string]any{"items": revs, "next_before": nb})
	return nil
}

func (s *Server) recordRevision(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	v, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || v < 1 {
		return errs.Invalid("version must be a positive integer")
	}
	rec, err := s.c.Records.RevisionContent(r.Context(), c, r.PathValue("name"), r.PathValue("id"), v)
	if err != nil {
		return err
	}
	w.Header().Set(MarkingHeader, rec.Marking.Banner())
	writeJSON(w, 200, rec.JSON())
	return nil
}

func (s *Server) restoreRecord(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	current, err := ifMatch(r, true)
	if err != nil {
		return err
	}
	var in struct {
		Version int `json:"version"`
	}
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	if in.Version < 1 {
		return errs.Invalid("version must be a positive integer")
	}
	rec, err := s.c.Records.Restore(r.Context(), c, r.PathValue("name"), r.PathValue("id"), in.Version, *current)
	if err != nil {
		return err
	}
	writeRecord(w, 200, rec)
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

// ---- limits --------------------------------------------------------------------------------------

// limits advertises what this deployment accepts, so clients choose single-request or multipart
// uploads correctly.
func (s *Server) limits(w http.ResponseWriter, _ *http.Request, _ service.Ctx) error {
	writeJSON(w, 200, s.c.Limits())
	return nil
}
