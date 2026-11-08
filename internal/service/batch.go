package service

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
)

const MaxBatchOperations = 25
const MaxBatchBytes = 1 << 20
const BatchTimeout = 10 * time.Second

type BatchOperation struct {
	Type            string
	Collection      string
	ID              string
	ExpectedVersion int
	RestoreVersion  int
	Record          *RecordInput
}
type BatchOutcome struct {
	Type       string `json:"type"`
	Collection string `json:"collection"`
	ID         string `json:"id"`
	Version    int    `json:"version"`
	Marking    string `json:"marking"`
}
type BatchResult struct {
	Operations []BatchOutcome `json:"operations"`
	Marking    string         `json:"marking"`
	Replayed   bool           `json:"replayed"`
}

func batchPayload(ops []BatchOperation) ([]map[string]any, error) {
	if len(ops) < 1 || len(ops) > MaxBatchOperations {
		return nil, errs.Invalid("batch must contain 1-%d operations", MaxBatchOperations)
	}
	seen := map[string]bool{}
	out := make([]map[string]any, len(ops))
	for i, op := range ops {
		if !nameRe.MatchString(op.Collection) {
			return nil, errs.Invalid("invalid collection name")
		}
		switch op.Type {
		case "create":
			if op.ID != "" || op.ExpectedVersion != 0 || op.RestoreVersion != 0 || op.Record == nil {
				return nil, errs.Invalid("create needs record input and no existing ID/version")
			}
		case "update", "delete", "restore":
			if op.ID == "" {
				return nil, errs.Invalid("record ID is required")
			}
			if op.ExpectedVersion < 1 {
				return nil, errs.PreconditionRequired("every existing record needs expected_version")
			}
			if op.ExpectedVersion >= 1<<31-1 {
				return nil, errs.Invalid("expected_version exceeds the supported range")
			}
			target := op.Collection + "/" + op.ID
			if seen[target] {
				return nil, errs.Invalid("a record may occur only once in a batch")
			}
			seen[target] = true
			if op.Type == "update" && (op.Record == nil || op.RestoreVersion != 0) {
				return nil, errs.Invalid("update needs record input and no restore_version")
			}
			if op.Type != "update" && op.Record != nil {
				return nil, errs.Invalid("delete/restore cannot include record input")
			}
			if op.Type == "restore" && op.RestoreVersion < 1 {
				return nil, errs.Invalid("restore_version must be positive")
			}
			if op.Type == "delete" && op.RestoreVersion != 0 {
				return nil, errs.Invalid("delete cannot include restore_version")
			}
		default:
			return nil, errs.Invalid("batch type must be create, update, delete or restore")
		}
		payload := map[string]any{"type": op.Type, "collection": op.Collection, "id": op.ID, "expected_version": op.ExpectedVersion, "restore_version": op.RestoreVersion}
		if op.Record != nil {
			if op.Type == "update" && (op.Record.Visibility != "" || op.Record.TeamID != "") {
				return nil, errs.Invalid("visibility changes use the sharing endpoint")
			}
			banner := ""
			if op.Record.Marking != nil {
				banner = op.Record.Marking.Banner()
			}
			payload["record"] = map[string]any{"data": op.Record.Data, "marking": banner, "visibility": op.Record.Visibility, "team_id": op.Record.TeamID}
		}
		out[i] = payload
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBatchBytes {
		return nil, errs.PayloadTooLarge("batch exceeds 1 MiB")
	}
	return out, nil
}

// Batch reuses the same transaction-local command implementations as ordinary record mutations.
// Only its metadata outcome is receipted; no record content is returned or stored in receipts.
func (r *Records) Batch(ctx context.Context, c Ctx, ops []BatchOperation) (*BatchResult, error) {
	if !ValidOpID(c.OpID) {
		return nil, errs.Invalid("a valid operation ID is required")
	}
	payload, err := batchPayload(ops)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
	var out *BatchResult
	err = r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		rc, err := r.receipts.claim(ctx, tx, c, Operation{Type: "record.batch", Target: "records", Payload: payload}, 0, "")
		if err != nil {
			return err
		}
		if rc != nil {
			out = &BatchResult{}
			if err := decodeOutcome(rc, out); err != nil {
				return err
			}
			out.Replayed = true
			return nil
		}
		collections := []string{}
		for _, op := range ops {
			collections = append(collections, op.Collection)
		}
		slices.Sort(collections)
		collections = slices.Compact(collections)
		for _, name := range collections {
			if _, err := r.readableCollection(ctx, tx, c, name, false); err != nil {
				return err
			}
			if err := lockContract(ctx, tx, c.App, name, false); err != nil {
				return err
			}
		}
		order := append([]BatchOperation(nil), ops...)
		slices.SortFunc(order, func(x, y BatchOperation) int {
			a, b := x.Collection+"/"+x.ID, y.Collection+"/"+y.ID
			if a < b {
				return -1
			}
			if a > b {
				return 1
			}
			return 0
		})
		// Check visibility/classification and mutation rights before taking any row lock.
		// RLS knows sharing, but not CUI clearances; locking first can reveal a hidden row's
		// contention. Commands repeat their normal checks after locks and before mutations.
		for _, op := range order {
			if op.ID == "" {
				continue
			}
			col, err := r.readableCollection(ctx, tx, c, op.Collection, false)
			if err != nil {
				return err
			}
			need, action, deleted := PermWrite, auth.RecordUpdate, op.Type == "restore"
			if op.Type == "delete" {
				need, action = PermManage, auth.RecordDelete
			}
			if deleted {
				action = auth.RecordRestore
				row, err := r.row(ctx, tx, c.App, op.Collection, op.ID, true)
				if err != nil {
					return err
				}
				if row.deletedAt != nil {
					permission, _, err := r.authz.Permissions(ctx, tx, a, row.resource())
					if err != nil {
						return err
					}
					if !permission.Has(PermManage) {
						return errs.NotFound("record not found")
					}
					need = PermManage
				}
			}
			_, m, err := r.writable(ctx, tx, c, a, col, op.ID, need, action, deleted)
			if err != nil {
				return err
			}
			if _, err := r.check(ctx, tx, c, action, "record", op.ID, &m, checkOpts{noConceal: true, skipAllow: true}); err != nil {
				return err
			}
		}

		for _, op := range order {
			if op.ID != "" {
				// Locks only rows admitted by RLS; the command's normal checks decide every outcome.
				rows, err := tx.Query(ctx, `SELECT id FROM records WHERE app=$1 AND collection=$2 AND id=$3 FOR UPDATE`, c.App, op.Collection, op.ID)
				if err != nil {
					return err
				}
				for rows.Next() {
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return err
				}
			}
		}
		child := c
		child.OpID = ""
		result := &BatchResult{Operations: make([]BatchOutcome, 0, len(ops))}
		var combined []markings.Marking
		for i, op := range ops {
			var record *Record
			var err error
			switch op.Type {
			case "create":
				record, err = r.createTx(ctx, child, tx, a, op.Collection, *op.Record)
			case "update":
				record, err = r.updateTx(ctx, child, tx, a, op.Collection, op.ID, *op.Record, op.ExpectedVersion)
			case "restore":
				record, err = r.restoreTx(ctx, child, tx, a, op.Collection, op.ID, op.RestoreVersion, op.ExpectedVersion)
			case "delete":
				err = r.deleteTx(ctx, child, tx, a, op.Collection, op.ID, &op.ExpectedVersion, false)
				if err == nil {
					var row *recordRow
					row, err = r.row(ctx, tx, c.App, op.Collection, op.ID, true)
					if err == nil {
						var m markings.Marking
						m, err = markings.Parse(row.marking)
						record = &Record{ID: row.id, Version: row.version, Marking: m}
					}
				}
			}
			if err != nil {
				return fmt.Errorf("batch operation %d: %w", i+1, err)
			}
			result.Operations = append(result.Operations, BatchOutcome{Type: op.Type, Collection: op.Collection, ID: record.ID, Version: record.Version, Marking: record.Marking.Banner()})
			combined = append(combined, record.Marking)
		}
		result.Marking = markings.Combine(combined).Banner()
		if err := r.receipts.complete(ctx, tx, c, "record_batch", c.OpID, 0, outcome(result)); err != nil {
			return err
		}
		out = result
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r *receipts) authorizeBatch(ctx context.Context, tx pgx.Tx, c Ctx, receipt *Receipt) error {
	var result BatchResult
	if err := decodeOutcome(receipt, &result); err != nil {
		return errs.Integrity("invalid batch receipt")
	}
	if len(result.Operations) < 1 || len(result.Operations) > MaxBatchOperations {
		return errs.Integrity("invalid batch receipt size")
	}
	for _, op := range result.Operations {
		if op.ID == "" || op.Version < 1 {
			return errs.Integrity("invalid batch receipt resource")
		}
		if err := r.authorize(ctx, tx, c, &Receipt{ResourceType: "record", ResourceID: op.ID, ResourceVersion: op.Version}); err != nil {
			return err
		}
		m, err := markings.Parse(op.Marking)
		if err != nil {
			return errs.Integrity("invalid batch receipt marking")
		}
		if _, err := r.core.check(ctx, tx, c, auth.RecordRead, "record", op.ID, &m, checkOpts{skipAllow: true}); err != nil {
			return err
		}
	}
	return nil
}
