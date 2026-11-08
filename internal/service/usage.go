package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
)

// AppUsage is what an app has stored against its quota. nil limits are unlimited.
type AppUsage struct {
	App            string `json:"app"`
	Scope          string `json:"scope"`
	BlobBytes      int64  `json:"blob_bytes"`
	Blobs          int64  `json:"blobs"`
	ReservedBytes  int64  `json:"reserved_bytes"`
	Records        int64  `json:"records"`
	RecordBytes    int64  `json:"record_bytes"`
	MaxBlobBytes   *int64 `json:"max_blob_bytes"`
	MaxBlobs       *int64 `json:"max_blobs"`
	MaxRecords     *int64 `json:"max_records"`
	MaxRecordBytes *int64 `json:"max_record_bytes"`
}

// Usage reports only resources visible under the caller's sharing and classification
// rights. Quotas remain app-wide; privileged full usage is available through the admin CLI.
func (s *Sharing) Usage(ctx context.Context, c Ctx) (*AppUsage, error) {
	u := &AppUsage{App: c.App, Scope: "visible"}
	err := s.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		rows, err := tx.Query(ctx, `SELECT marking,count(*),sum(sb_record_bytes(records)) FROM records
            WHERE app=$1 AND deleted_at IS NULL GROUP BY marking`, c.App)
		if err != nil {
			return err
		}
		for rows.Next() {
			var banner string
			var count, size int64
			if err := rows.Scan(&banner, &count, &size); err != nil {
				rows.Close()
				return err
			}
			m, err := markings.Parse(banner)
			if err == nil && s.Policy.Evaluate(c.Principal, auth.RecordRead, &m).Allowed {
				u.Records += count
				u.RecordBytes += size
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT marking,state,count(*),coalesce(sum(size_bytes),0),sum(reserved_bytes)
            FROM blobs WHERE app=$1 AND (state='active' OR (state='pending' AND owner=$2)) GROUP BY marking,state`, c.App, c.Principal.Subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var banner, state string
			var count, size, reserved int64
			if err := rows.Scan(&banner, &state, &count, &size, &reserved); err != nil {
				rows.Close()
				return err
			}
			m, err := markings.Parse(banner)
			if err == nil && s.Policy.Evaluate(c.Principal, auth.BlobReadMeta, &m).Allowed {
				if state == "active" {
					u.Blobs += count
					u.BlobBytes += size
				} else {
					u.ReservedBytes += reserved
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT max_blob_bytes,max_blobs,max_records,max_record_bytes FROM app_quotas WHERE app=$1`, c.App).
			Scan(&u.MaxBlobBytes, &u.MaxBlobs, &u.MaxRecords, &u.MaxRecordBytes)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return u, err
}
