package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// VerifyReport is what VerifyApp checked. Problems name resources, never content.
type VerifyReport struct {
	App       string   `json:"app"`
	Records   int64    `json:"records"`
	Revisions int64    `json:"revisions"`
	Blobs     int64    `json:"blobs"`
	BlobBytes int64    `json:"blob_bytes"`
	Problems  []string `json:"problems"`
}

func (v *VerifyReport) addf(f string, a ...any) {
	if len(v.Problems) < 200 {
		v.Problems = append(v.Problems, fmt.Sprintf(f, a...))
	}
}

// VerifyApp opens every live record, every revision and every active blob's metadata under its
// stored encryption context; with deep, it also streams and authenticates every blob's content.
// It is the check after a restore (or a key incident): it needs the KMS keys that wrapped the data.
// Run it on a pool whose login can read the whole app (the migration login), in worker mode.
func (c *Container) VerifyApp(ctx context.Context, app string, deep bool) (*VerifyReport, error) {
	rep := &VerifyReport{App: app}
	scope := store.Scope{App: app, Subject: workerSubject, Actor: "verify", Mode: store.ModeWorker}
	cols := map[string]*Collection{}
	collection := func(tx pgx.Tx, name string) (*Collection, error) {
		if col, ok := cols[name]; ok {
			return col, nil
		}
		col, err := c.Records.collection(ctx, tx, app, name)
		cols[name] = col
		return col, err
	}
	// Records, in keyset pages so no transaction stays open for long.
	for after := ""; ; {
		var page []*recordRow
		err := c.DB.Run(ctx, scope, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT `+recordCols+` FROM records WHERE app = $1 AND id > $2 AND deleted_at IS NULL
				ORDER BY id LIMIT 500`, app, after)
			if err != nil {
				return err
			}
			if page, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (*recordRow, error) { return scanRecord(r) }); err != nil {
				return err
			}
			for _, rr := range page {
				col, err := collection(tx, rr.collection)
				if err != nil {
					return err
				}
				m, err := markings.Parse(rr.marking)
				if err == nil {
					_, err = c.Records.open(ctx, tx, col, rr.id, m, rr.version, rr.aadVersion, rr.plain, rr.sealed, rr.keyID)
				}
				if err != nil {
					rep.addf("record %s: %v", rr.id, err)
				}
				rep.Records++
			}
			return nil
		})
		if err != nil {
			return rep, err
		}
		if len(page) == 0 {
			break
		}
		after = page[len(page)-1].id
	}
	type revKey struct {
		id      string
		version int
	}
	for after := (revKey{}); ; {
		n := 0
		err := c.DB.Run(ctx, scope, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT record_id, version, collection, marking, data_plain, data_sealed, key_id, aad_version
				FROM record_revisions WHERE app = $1 AND (record_id, version) > ($2, $3) AND op <> 'delete'
				ORDER BY record_id, version LIMIT 500`, app, after.id, after.version)
			if err != nil {
				return err
			}
			type rev struct {
				id, coll, marking string
				version, aad      int
				plain, sealed     []byte
				keyID             *string
			}
			revs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (rev, error) {
				var v rev
				return v, r.Scan(&v.id, &v.version, &v.coll, &v.marking, &v.plain, &v.sealed, &v.keyID, &v.aad)
			})
			if err != nil {
				return err
			}
			for _, v := range revs {
				col, err := collection(tx, v.coll)
				if err != nil {
					return err
				}
				m, err := markings.Parse(v.marking)
				if err == nil {
					_, err = c.Records.open(ctx, tx, col, v.id, m, v.version, v.aad, v.plain, v.sealed, v.keyID)
				}
				if err != nil {
					rep.addf("record %s version %d: %v", v.id, v.version, err)
				}
				rep.Revisions++
				after = revKey{v.id, v.version}
			}
			n = len(revs)
			return nil
		})
		if err != nil {
			return rep, err
		}
		if n == 0 {
			break
		}
	}
	for after := ""; ; {
		var page []*blobRow
		err := c.DB.Run(ctx, scope, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT `+blobCols+` FROM blobs WHERE app = $1 AND id > $2 AND state = 'active' ORDER BY id LIMIT 200`, app, after)
			if err != nil {
				return err
			}
			if page, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (*blobRow, error) { return scanBlob(r) }); err != nil {
				return err
			}
			for _, row := range page {
				m, err := markings.Parse(row.marking)
				if err == nil {
					_, err = c.Blobs.meta(ctx, tx, app, row, m)
				}
				if err == nil && deep {
					var n int64
					n, err = c.verifyContent(ctx, tx, app, row, m)
					rep.BlobBytes += n
				}
				if err != nil {
					rep.addf("blob %s: %v", row.id, err)
				}
				rep.Blobs++
			}
			return nil
		})
		if err != nil {
			return rep, err
		}
		if len(page) == 0 {
			break
		}
		after = page[len(page)-1].id
	}
	return rep, nil
}

func (c *Container) verifyContent(ctx context.Context, tx pgx.Tx, app string, row *blobRow, m markings.Marking) (int64, error) {
	dek, err := c.Blobs.unwrapCtx(ctx, row, app, m)
	if err != nil {
		return 0, err
	}
	var src io.ReadCloser
	expected := ""
	if row.layout == "parts" {
		parts, err := c.Blobs.partsTx(ctx, tx, app, row)
		if err != nil {
			return 0, err
		}
		src = &partsReader{ctx: ctx, backend: c.Backend, parts: parts}
	} else {
		if src, err = c.Backend.Read(ctx, row.storageKey); err != nil {
			return 0, err
		}
		if row.sha != nil {
			expected = *row.sha
		}
	}
	defer src.Close()
	sha := sha256.New()
	dec, err := crypto.NewDecryptingReader(io.TeeReader(src, sha), dek, blobCtx(row.aadVersion, "blob", app, row.id, m))
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(io.Discard, dec)
	if err != nil {
		return n, err
	}
	if row.size == nil || n != *row.size {
		return n, fmt.Errorf("plaintext size mismatch")
	}
	if expected != "" && hex.EncodeToString(sha.Sum(nil)) != expected {
		return n, fmt.Errorf("ciphertext digest mismatch")
	}
	return n, nil
}
