package api

import (
	"net/http"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/service"
)

type contractIn struct {
	JSONSchema      map[string]any `json:"json_schema"`
	IndexedFields   []string       `json:"indexed_fields"`
	UniqueFields    []string       `json:"unique_fields"`
	Defaults        map[string]any `json:"defaults"`
	ExpectedVersion *int           `json:"expected_version"`
}

// changeContract: 200 when the new version took effect, 202 when a migration was started.
func (s *Server) changeContract(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var in contractIn
	if err := decode(r, w, maxJSONBody, &in); err != nil {
		return err
	}
	if in.ExpectedVersion == nil {
		return errs.Invalid("expected_version is required (the contract version you are changing)")
	}
	ch, err := s.c.Records.ChangeContract(r.Context(), c, r.PathValue("name"), service.ContractInput{JSONSchema: in.JSONSchema,
		IndexedFields: in.IndexedFields, UniqueFields: in.UniqueFields, Defaults: in.Defaults, ExpectedVersion: *in.ExpectedVersion})
	if err != nil {
		return err
	}
	out := map[string]any{"collection": ch.Collection.JSON(), "version": ch.Version, "immediate": ch.Immediate, "migration": nil}
	status := 200
	if !ch.Immediate {
		out["reason"] = ch.Reason
		if ch.Migration != nil {
			out["migration"] = ch.Migration
			status = 202
		}
	}
	writeJSON(w, status, out)
	return nil
}

func (s *Server) contractVersions(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	vs, err := s.c.Records.ContractVersions(r.Context(), c, r.PathValue("name"))
	if err != nil {
		return err
	}
	if vs == nil {
		vs = []service.ContractVersion{}
	}
	writeJSON(w, 200, map[string]any{"items": vs})
	return nil
}

func (s *Server) getMigration(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	m, err := s.c.Records.GetMigration(r.Context(), c, r.PathValue("name"), r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set(MarkingHeader, m.Marking)
	writeJSON(w, 200, m)
	return nil
}

func (s *Server) cancelMigration(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	m, err := s.c.Records.CancelMigration(r.Context(), c, r.PathValue("name"), r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set(MarkingHeader, m.Marking)
	writeJSON(w, 200, m)
	return nil
}
