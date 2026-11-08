package api

import (
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"net/http"
)

func (s *Server) batchRecords(w http.ResponseWriter, r *http.Request, c service.Ctx) error {
	var input struct {
		Operations []struct {
			Type            string    `json:"type"`
			Collection      string    `json:"collection"`
			ID              string    `json:"id"`
			ExpectedVersion int       `json:"expected_version"`
			RestoreVersion  int       `json:"restore_version"`
			Record          *recordIn `json:"record"`
		} `json:"operations"`
	}
	if err := decode(r, w, service.MaxBatchBytes, &input); err != nil {
		return err
	}
	if len(input.Operations) < 1 || len(input.Operations) > service.MaxBatchOperations {
		return errs.Invalid("batch must contain 1-25 operations")
	}
	operations := make([]service.BatchOperation, len(input.Operations))
	for i, v := range input.Operations {
		operations[i] = service.BatchOperation{Type: v.Type, Collection: v.Collection, ID: v.ID, ExpectedVersion: v.ExpectedVersion, RestoreVersion: v.RestoreVersion}
		if v.Record != nil {
			record, err := v.Record.input()
			if err != nil {
				return err
			}
			operations[i].Record = &record
		}
	}
	if err := s.budget.charge(c.App, c.Principal.Subject, len(operations)-1); err != nil {
		return err
	}
	result, err := s.c.Records.Batch(r.Context(), c, operations)
	if err != nil {
		return err
	}
	w.Header().Set(MarkingHeader, result.Marking)
	writeJSON(w, 200, result)
	return nil
}
