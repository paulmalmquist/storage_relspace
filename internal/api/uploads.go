package api

import (
	"net/http"
	"strconv"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/service"
)

// Upload sessions: POST /uploads declares the blob, PUT /uploads/{id}/parts/{n} sends each part
// (exactly part_size bytes, the last part the remainder), POST /uploads/{id}/complete activates it.

type sessionIn struct {
	SizeBytes   *int64         `json:"size_bytes"`
	Marking     string         `json:"marking"`
	ContentType string         `json:"content_type"`
	Filename    string         `json:"filename"`
	Metadata    map[string]any `json:"metadata"`
	Visibility  string         `json:"visibility"`
	TeamID      string         `json:"team_id"`
}

func (s *Server) createUpload(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in sessionIn
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	if in.SizeBytes == nil || *in.SizeBytes < 0 {
		return errs.Invalid("size_bytes is required")
	}
	if in.Marking == "" {
		return errs.Invalid("marking is required (use UNCONTROLLED for non-CUI data)")
	}
	m, err := parseMarking(in.Marking)
	if err != nil {
		return err
	}
	sess, err := s.c.Blobs.CreateSession(r.Context(), c, service.BlobInput{Marking: m, ContentType: in.ContentType,
		Filename: in.Filename, Metadata: in.Metadata, DeclaredSize: *in.SizeBytes, Visibility: in.Visibility, TeamID: in.TeamID})
	if err != nil {
		return err
	}
	status := 201
	if sess.Replayed {
		status = 200
	}
	w.Header().Set("Location", "/v1/apps/"+r.PathValue("app")+"/uploads/"+sess.ID)
	w.Header().Set(MarkingHeader, sess.Marking.Banner())
	writeJSON(w, status, sess.JSON())
	return nil
}

func (s *Server) getUpload(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	sess, err := s.c.Blobs.Session(r.Context(), c, r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set(MarkingHeader, sess.Marking.Banner())
	writeJSON(w, 200, sess.JSON())
	return nil
}

func (s *Server) putUploadPart(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		return errs.Invalid("part number must be an integer")
	}
	// One part never exceeds the single-request limit; the service checks the exact size.
	r.Body = http.MaxBytesReader(w, r.Body, s.c.Blobs.MaxBytes)
	size, err := s.c.Blobs.PutPart(r.Context(), c, r.PathValue("id"), n, r.Body)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"part_number": n, "size_bytes": size})
	return nil
}

func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	meta, err := s.c.Blobs.CompleteSession(r.Context(), c, r.PathValue("id"))
	if err != nil {
		return err
	}
	status := 201
	if meta.Replayed {
		status = 200
	}
	w.Header().Set("Location", "/v1/apps/"+r.PathValue("app")+"/blobs/"+meta.ID)
	w.Header().Set(MarkingHeader, meta.Marking.Banner())
	writeJSON(w, status, meta.JSON())
	return nil
}

func (s *Server) abortUpload(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	if err := s.c.Blobs.AbortSession(r.Context(), c, r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) appUsage(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	u, err := s.c.Sharing.Usage(r.Context(), c)
	if err != nil {
		return err
	}
	writeJSON(w, 200, u)
	return nil
}
