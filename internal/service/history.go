package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
)

// Record history and undo.
//
// Every committed version is kept in record_revisions, written in the same transaction as the
// change. Restoring a version writes a new version (compare-and-swap on the current one); history
// is never rewritten. History is read under current policy: the record must still be visible, a
// deleted record's history is visible only to those who may manage it, and each revision's content
// is authorized against that revision's marking. The retention worker trims history to the
// collection's history_limit.

// Revision is one entry in a record's history.
type Revision struct {
	Version   int              `json:"version"`
	Op        string           `json:"op"`
	Marking   *string          `json:"marking"` // nil when the caller may not see this revision's marking
	Concealed bool             `json:"concealed,omitempty"`
	SizeBytes int              `json:"size_bytes"`
	Subject   string           `json:"subject"`
	Actor     string           `json:"actor"`
	CreatedAt time.Time        `json:"created_at"`
	marking   markings.Marking `json:"-"`
}

// revision copies the version just written (rr) into history.
func (r *Records) revision(ctx context.Context, tx pgx.Tx, c Ctx, col *Collection, rr *recordRow, op string, size int) error {
	_, err := tx.Exec(ctx, `INSERT INTO record_revisions (app, record_id, version, collection, marking, op, data_plain,
		data_sealed, key_id, aad_version, size_bytes, subject, actor, attachment_id)
		SELECT app, id, version, collection, marking, $4, data_plain, data_sealed, key_id, aad_version, $5, $6, $7, attachment_id
		FROM records WHERE app = $1 AND id = $2 AND version = $3`,
		col.App, rr.id, rr.version, op, size, c.Principal.Subject, c.Actor())
	if err != nil {
		return err
	}
	// History expiry happens on write and touches only this record (primary-key range), so it is
	// bounded by the limit and needs no background scan. Lowering a limit applies on each record's
	// next write.
	if col.HistoryLimit < 1 {
		return nil // not loaded; never prune on a guess
	}
	_, err = tx.Exec(ctx, `DELETE FROM record_revisions WHERE app = $1 AND record_id = $2 AND version <= $3
		AND NOT sb_revision_pinned(app, record_id, version)`,
		col.App, rr.id, rr.version-col.HistoryLimit)
	return err
}

// historyAccess loads the record (deleted ones included) and checks the caller may see its history.
func (r *Records) historyAccess(ctx context.Context, tx pgx.Tx, c Ctx, a *Access, coll, id string) (*Collection, *recordRow, error) {
	col, err := r.readableCollection(ctx, tx, c, coll, false)
	if err != nil {
		return nil, nil, err
	}
	rr, err := r.row(ctx, tx, c.App, coll, id, true)
	if err != nil {
		return nil, nil, err
	}
	m, err := markings.Parse(rr.marking)
	if err != nil {
		return nil, nil, errs.Integrity("stored marking is invalid")
	}
	if _, err := r.check(ctx, tx, c, auth.RecordHistory, "record", id, &m, checkOpts{skipAllow: true}); err != nil {
		return nil, nil, err
	}
	if rr.deletedAt != nil {
		perm, why, err := r.authz.Permissions(ctx, tx, a, rr.resource())
		if err != nil {
			return nil, nil, err
		}
		if !perm.Has(PermManage) {
			// Deleted records are protected: readers lose access at deletion.
			return nil, nil, r.deny(c, auth.RecordHistory, "record", id, &m, "deleted; sharing: "+strings.Join(why, ","),
				errs.NotFound("record not found"))
		}
	}
	return col, rr, nil
}

// History lists versions newest first. before (0: from the newest) pages backwards.
func (r *Records) History(ctx context.Context, c Ctx, coll, id string, before, limit int) ([]Revision, int, error) {
	n, err := ClampLimit(limit, 50)
	if err != nil {
		return nil, 0, err
	}
	var out []Revision
	next := 0
	err = r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if _, _, err := r.historyAccess(ctx, tx, c, a, coll, id); err != nil {
			return err
		}
		if before <= 0 {
			before = 1 << 30
		}
		rows, err := tx.Query(ctx, `SELECT version, op, marking, size_bytes, subject, actor, created_at FROM record_revisions
			WHERE app = $1 AND record_id = $2 AND version < $3 ORDER BY version DESC LIMIT $4`, c.App, id, before, n+1)
		if err != nil {
			return err
		}
		all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Revision, error) {
			var rv Revision
			var banner string
			err := row.Scan(&rv.Version, &rv.Op, &banner, &rv.SizeBytes, &rv.Subject, &rv.Actor, &rv.CreatedAt)
			if err == nil {
				rv.marking, err = markings.Parse(banner)
				rv.Marking = &banner
			}
			return rv, err
		})
		if err != nil {
			return err
		}
		if len(all) > n {
			all, next = all[:n], all[n-1].Version
		}
		for i := range all {
			if !r.Policy.Evaluate(c.Principal, auth.RecordRead, &all[i].marking).Allowed {
				all[i].Marking, all[i].Concealed = nil, true
			}
		}
		out = all
		return r.note(ctx, tx, c, auth.RecordHistory, "record", id, "allow", "listed history", nil, map[string]any{"returned": len(out)})
	})
	return out, next, err
}

// RevisionContent returns one historical version, authorized against that version's marking.
func (r *Records) RevisionContent(ctx context.Context, c Ctx, coll, id string, version int) (*Record, error) {
	var out *Record
	err := r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		col, rr, err := r.historyAccess(ctx, tx, c, a, coll, id)
		if err != nil {
			return err
		}
		rec, err := r.revisionRecord(ctx, tx, c, col, rr, version, true)
		out = rec
		return err
	})
	return out, err
}

// revisionRecord builds the record as it was at version. needContent makes a withheld decision an
// error (explicit history reads); otherwise content is just omitted (replays).
func (r *Records) revisionRecord(ctx context.Context, tx pgx.Tx, c Ctx, col *Collection, rr *recordRow, version int, needContent bool) (*Record, error) {
	var banner, op string
	var plain, sealed []byte
	var keyID *string
	var aadVersion int
	var created time.Time
	var subject string
	var attachment *string
	err := tx.QueryRow(ctx, `SELECT marking, op, data_plain, data_sealed, key_id, aad_version, created_at, subject, attachment_id
		FROM record_revisions WHERE app = $1 AND record_id = $2 AND version = $3`, col.App, rr.id, version).
		Scan(&banner, &op, &plain, &sealed, &keyID, &aadVersion, &created, &subject, &attachment)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.NotFound("version %d is not in this record's history", version)
	}
	if err != nil {
		return nil, err
	}
	m, err := markings.Parse(banner)
	if err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	if _, err := r.check(ctx, tx, c, auth.RecordReadContent, "record", rr.id, &m,
		checkOpts{needContent: needContent, details: map[string]any{"version": version}}); err != nil {
		return nil, err
	}
	rec := &Record{ID: rr.id, Collection: col.Name, Marking: m, Version: version, Owner: rr.owner, Visibility: rr.visibility,
		Deleted: op == "delete", CreatedBy: rr.createdBy, CreatedAt: rr.createdAt, UpdatedBy: subject, UpdatedAt: created}
	if rr.teamID != nil {
		rec.TeamID = *rr.teamID
	}
	if rec.Deleted {
		return rec, nil
	}
	if d := r.Policy.Evaluate(c.Principal, auth.RecordReadContent, &m); !d.Allowed {
		rec.Withheld, rec.WithheldReason = true, d.Reason
		return rec, nil
	}
	rec.Data, err = r.open(ctx, tx, col, rr.id, m, version, aadVersion, plain, sealed, keyID)
	if err == nil {
		rec.AttachmentID, err = r.visibleAttachment(ctx, tx, c, attachment)
	}
	return rec, err
}

// Restore makes the content of an earlier version current again as a new version (undo). It also
// undeletes. expectedVersion is the record's current version (compare-and-swap). The new marking
// is never lower than the current one.
func (r *Records) Restore(ctx context.Context, c Ctx, coll, id string, version, expectedVersion int) (*Record, error) {
	var out *Record
	err := r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		var err error
		out, err = r.restoreTx(ctx, c, tx, a, coll, id, version, expectedVersion)
		return err
	})
	return out, err
}
func (r *Records) restoreTx(ctx context.Context, c Ctx, tx pgx.Tx, a *Access, coll, id string, version, expectedVersion int) (*Record, error) {
	var out *Record
	err := func() error {
		if err := lockContract(ctx, tx, c.App, coll, false); err != nil {
			return err
		}
		col, err := r.readableCollection(ctx, tx, c, coll, false)
		if err != nil {
			return err
		}
		if rc, err := r.receipts.claim(ctx, tx, c, Operation{Type: "record.restore", Target: coll + "/" + id,
			ExpectedVersion: expectedVersion, Payload: map[string]any{"version": version}}, 0, ""); err != nil || rc != nil {
			if rc != nil {
				out, err = r.replay(ctx, tx, c, col, rc)
			}
			return err
		}
		probe, err := r.row(ctx, tx, c.App, coll, id, true)
		if err != nil {
			return err
		}
		need := PermWrite
		if probe.deletedAt != nil {
			need = PermManage
		}
		rr, cur, err := r.writable(ctx, tx, c, a, col, id, need, auth.RecordRestore, true)
		if err != nil {
			return err
		}
		if rr.version != expectedVersion {
			return errs.PreconditionFailed("record is at version %d, not %d", rr.version, expectedVersion)
		}
		var banner, op string
		var plain, sealed []byte
		var keyID *string
		var aadVersion int
		var attachment *string
		err = tx.QueryRow(ctx, `SELECT marking, op, data_plain, data_sealed, key_id, aad_version, attachment_id FROM record_revisions
			WHERE app = $1 AND record_id = $2 AND version = $3`, c.App, id, version).
			Scan(&banner, &op, &plain, &sealed, &keyID, &aadVersion, &attachment)
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFound("version %d is not in this record's history", version)
		}
		if err != nil {
			return err
		}
		if op == "delete" {
			return errs.Invalid("version %d is a deletion; restore a version with content", version)
		}
		old, err := markings.Parse(banner)
		if err != nil {
			return errs.Integrity("stored marking is invalid")
		}
		m := markings.Combine([]markings.Marking{old, cur})
		if m, err = recordMarking(col, &m); err != nil {
			return err
		}
		for _, mk := range []markings.Marking{cur, old, m} {
			if _, err := r.check(ctx, tx, c, auth.RecordRestore, "record", id, &mk, checkOpts{noConceal: true, skipAllow: true}); err != nil {
				return err
			}
		}
		data, err := r.open(ctx, tx, col, id, old, version, aadVersion, plain, sealed, keyID)
		if err != nil {
			return err
		}
		if err := r.validate(col, data); err != nil {
			return errs.Invalid("version %d no longer satisfies the collection schema: %s", version, err.Error())
		}
		if !sameAttachment(rr.attachmentID, attachment) {
			request := attachment
			if request == nil {
				empty := ""
				request = &empty
			}
			if _, err = r.attachmentForWrite(ctx, tx, c, rr.owner, rr.attachmentID, request, m); err != nil {
				return err
			}
		}
		next := expectedVersion + 1
		st, err := r.seal(ctx, tx, col, id, data, m, next)
		if err != nil {
			return err
		}
		toks, err := r.tokens(ctx, tx, col, data)
		if err != nil {
			return err
		}
		nr, err := scanRecord(tx.QueryRow(ctx, `UPDATE records SET marking=$5, data_plain=$6, data_sealed=$7, key_id=$8,
			version=$9, aad_version=2, updated_by=$10, updated_at=now(), deleted_at=NULL, schema_version=$11, attachment_id=$12
			WHERE app=$1 AND collection=$2 AND id=$3 AND version=$4 RETURNING `+recordCols,
			c.App, col.Name, id, expectedVersion, m.Banner(), st.plain, st.sealed, st.keyID, next, c.Principal.Subject, col.Version, attachment))
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.PreconditionFailed("record changed concurrently")
		}
		if err != nil {
			return err
		}
		if err := r.writeIndex(ctx, tx, col, id, toks); err != nil {
			return err
		}
		if err := r.revision(ctx, tx, c, col, nr, "restore", st.size); err != nil {
			return err
		}
		if err := r.receipts.complete(ctx, tx, c, "record", id, next, map[string]any{"collection": col.Name, "restored_from": version}); err != nil {
			return err
		}
		if err := r.note(ctx, tx, c, auth.RecordRestore, "record", id, "allow", "restored version", &m,
			map[string]any{"collection": col.Name, "restored_from": version, "version": next}); err != nil {
			return err
		}
		out, err = r.view(ctx, tx, c, col, nr)
		return err
	}()
	return out, err
}

// replay answers a retried operation from its receipt: the exact version the original call wrote,
// authorized under current policy and that version's marking.
func (r *Records) replay(ctx context.Context, tx pgx.Tx, c Ctx, col *Collection, rc *Receipt) (*Record, error) {
	if rc.ResourceType != "record" {
		return nil, errs.Internal("receipt does not describe a record")
	}
	rr, err := r.row(ctx, tx, c.App, col.Name, rc.ResourceID, true)
	if err != nil {
		return nil, err // no longer visible: revoked or purged
	}
	m, err := markings.Parse(rr.marking)
	if err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	if _, err := r.check(ctx, tx, c, auth.RecordRead, "record", rr.id, &m, checkOpts{skipAllow: true}); err != nil {
		return nil, err
	}
	rec, err := r.revisionRecord(ctx, tx, c, col, rr, rc.ResourceVersion, false)
	if errs.Is(err, "not_found") {
		return nil, errs.Coded(410, "result_expired", "the original result is no longer retained")
	}
	if err != nil {
		return nil, err
	}
	rec.Replayed = true
	return rec, nil
}
