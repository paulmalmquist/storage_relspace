package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
)

// attachment_id is a managed reference outside application JSON. A writable record
// does not grant the right to read, share, pin or release somebody else's file.
func (r *Records) attachmentForWrite(ctx context.Context, tx pgx.Tx, c Ctx, owner string, current, requested *string, m markings.Marking) (*string, error) {
	if requested == nil {
		return current, nil
	}
	if c.Principal.Subject != owner {
		return nil, errs.Forbidden("only the record owner can set an attachment")
	}
	if *requested == "" {
		return nil, nil
	}
	var banner string
	err := tx.QueryRow(ctx, `SELECT marking FROM blobs WHERE app=$1 AND id=$2 AND owner=$3 AND state='active'`, c.App, *requested, owner).Scan(&banner)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.NotFound("attachment not found")
	}
	if err != nil {
		return nil, err
	}
	bm, err := markings.Parse(banner)
	if err != nil {
		return nil, errs.Integrity("stored attachment marking is invalid")
	}
	if _, err := r.check(ctx, tx, c, auth.BlobReadContent, "attachment", *requested, &bm, checkOpts{needContent: true, skipAllow: true}); err != nil {
		return nil, err
	}
	if !m.Dominates(bm) {
		return nil, errs.Invalid("record marking must cover its attachment")
	}
	return requested, nil
}

// A historical link may have been released. Reads (including receipt replay) use
// current blob RLS and content policy. Absence and loss of file access look alike.
func (r *Records) visibleAttachment(ctx context.Context, tx pgx.Tx, c Ctx, id *string) (*string, error) {
	if id == nil {
		return nil, nil
	}
	allowed, err := r.visibleAttachments(ctx, tx, c, []string{*id})
	if err != nil || !allowed[*id] {
		return nil, err
	}
	return id, nil
}

// One RLS-filtered query serves an entire record page, independent of link count.
func (r *Records) visibleAttachments(ctx context.Context, tx pgx.Tx, c Ctx, ids []string) (map[string]bool, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT id,marking FROM blobs WHERE app=$1 AND id=ANY($2) AND state='active'`, c.App, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	visible := map[string]bool{}
	for rows.Next() {
		var id, banner string
		if err := rows.Scan(&id, &banner); err != nil {
			return nil, err
		}
		m, err := markings.Parse(banner)
		if err != nil {
			return nil, errs.Integrity("stored attachment marking is invalid")
		}
		visible[id] = r.Policy.Evaluate(c.Principal, auth.BlobReadContent, &m).Allowed
	}
	return visible, rows.Err()
}

func attachmentConstraint(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23503" && pg.ConstraintName == "active_record_attachment"
}

func sameAttachment(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
