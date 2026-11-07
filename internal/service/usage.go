package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// AppUsage is what an app has stored against its quota. nil limits are unlimited.
type AppUsage struct {
	App            string `json:"app"`
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

// Usage reports the app's counters (maintained by database triggers) and limits. Any member may
// read it: it says how much the app stores, not what.
func (s *Sharing) Usage(ctx context.Context, c Ctx) (*AppUsage, error) {
	u := &AppUsage{App: c.App}
	err := s.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(bytes),0), coalesce(sum(blobs),0), coalesce(sum(reserved_bytes),0)
			FROM blob_usage WHERE app = $1`, c.App).Scan(&u.BlobBytes, &u.Blobs, &u.ReservedBytes); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(records),0), coalesce(sum(bytes),0) FROM record_usage WHERE app = $1`, c.App).
			Scan(&u.Records, &u.RecordBytes); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT max_blob_bytes, max_blobs, max_records, max_record_bytes FROM app_quotas WHERE app = $1`, c.App).
			Scan(&u.MaxBlobBytes, &u.MaxBlobs, &u.MaxRecords, &u.MaxRecordBytes)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return u, err
}
