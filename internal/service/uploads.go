package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Upload sessions store a blob as parts, so no single request has to carry more than the
// transport allows (Cloud Run: 32 MiB per HTTP/1 request). The caller declares the total size up
// front; the server fixes the part size, reserves the size against the app's quota, and seals each
// part independently with its global segment indices (crypto.NewPartEncryptor). Parts may arrive
// in any order, from any instance, and may be retried: a re-sent part replaces the previous object,
// which is queued for deletion. Complete checks that every part is present with its exact size and
// activates the blob; the concatenation of parts is an ordinary SBX2 stream.

type UploadSession struct {
	ID        string
	Marking   markings.Marking
	SizeBytes int64
	PartSize  int
	PartCount int
	Received  []int
	State     string
	ExpiresAt *time.Time
	Replayed  bool
}

func (s *UploadSession) JSON() map[string]any {
	received := s.Received
	if received == nil {
		received = []int{}
	}
	out := map[string]any{"upload_id": s.ID, "blob_id": s.ID, "marking": s.Marking.Banner(), "size_bytes": s.SizeBytes,
		"part_size": s.PartSize, "part_count": s.PartCount, "received_parts": received, "state": s.State}
	if s.ExpiresAt != nil {
		out["expires_at"] = s.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if s.Replayed {
		out["replayed"] = true
	}
	return out
}

func partCount(size int64, partSize int) int {
	if size == 0 {
		return 1
	}
	return int((size + int64(partSize) - 1) / int64(partSize))
}

// partLength is the exact plaintext size of part n (1-based).
func partLength(size int64, partSize, n int) int64 {
	last := partCount(size, partSize)
	if n < last {
		return int64(partSize)
	}
	return size - int64(last-1)*int64(partSize)
}

// CreateSession authorizes a blob of the declared size and reserves it against the app's quota.
func (b *Blobs) CreateSession(ctx context.Context, c Ctx, in BlobInput) (*UploadSession, error) {
	if err := b.validateMeta(&in); err != nil {
		return nil, err
	}
	if in.DeclaredSize < 0 {
		return nil, errs.Invalid("size_bytes is required")
	}
	if in.DeclaredSize > b.MaxBlob {
		return nil, errs.PayloadTooLarge("blob exceeds %d bytes", b.MaxBlob)
	}
	var out *UploadSession
	err := b.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if !a.AtLeast("member") {
			return b.deny(c, auth.BlobCreate, "blob", "", &in.Marking, "app role viewer", errs.Forbidden("viewers cannot upload"))
		}
		vis, team, err := sharing(a, in.Visibility, in.TeamID)
		if err != nil {
			return err
		}
		if _, err := b.check(ctx, tx, c, auth.BlobCreate, "blob", "", &in.Marking, checkOpts{noConceal: true, skipAllow: true}); err != nil {
			return err
		}
		rc, err := b.receipts.claim(ctx, tx, c, Operation{Type: "upload.create", Marking: in.Marking.Banner(),
			Payload: map[string]any{"content_type": in.ContentType, "filename": in.Filename, "metadata": in.Metadata,
				"size_bytes": in.DeclaredSize, "visibility": vis, "team_id": team}}, 0, "")
		if err != nil {
			return err
		}
		if rc != nil {
			out, err = b.sessionTx(ctx, tx, c, rc.ResourceID, true)
			if out != nil {
				out.Replayed = true
			}
			return err
		}
		id := store.NewID("blb")
		dek := crypto.NewDataKey()
		wrapped, err := b.kms.Wrap(ctx, dek, blobCtx(3, "blob-dek", c.App, id, in.Marking))
		if err != nil {
			return kmsError(err)
		}
		metaKey, sealed, err := b.keys.SealJSON(ctx, tx, c.App, metaScope, blobCtx(3, "blob-meta", c.App, id, in.Marking),
			sealedMeta{Filename: in.Filename, Metadata: in.Metadata})
		if err != nil {
			return err
		}
		expires := time.Now().Add(b.SessionTTL)
		if _, err := tx.Exec(ctx, `INSERT INTO blobs (app, id, state, marking, content_type, chunk_size, kek_id, wrapped_dek,
			meta_key_id, sealed_meta, storage_key, created_by, owner, visibility, team_id, aad_version, lease_owner, lease_expires,
			layout, part_size, declared_size, reserved_bytes)
			VALUES ($1,$2,'pending',$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12,$13,3,'session',$14,'parts',$15,$16,$16)`,
			c.App, id, in.Marking.Banner(), in.ContentType, b.ChunkSize, wrapped.KEKID, wrapped.Ciphertext, metaKey, sealed,
			objectKey(c.App, id, nonce()), c.Principal.Subject, vis, team, expires, b.PartSize, in.DeclaredSize); err != nil {
			return err
		}
		if err := b.receipts.complete(ctx, tx, c, "blob", id, 0, map[string]any{"session": true}); err != nil {
			return err
		}
		if err := b.note(ctx, tx, c, auth.BlobCreate, "blob", id, "allow", "upload session started", &in.Marking,
			map[string]any{"size_bytes": in.DeclaredSize, "parts": partCount(in.DeclaredSize, b.PartSize)}); err != nil {
			return err
		}
		out = &UploadSession{ID: id, Marking: in.Marking, SizeBytes: in.DeclaredSize, PartSize: b.PartSize,
			PartCount: partCount(in.DeclaredSize, b.PartSize), State: "pending", ExpiresAt: &expires}
		return nil
	})
	return out, err
}

// sessionRow loads a session the caller started. Sessions belong to their uploader alone.
func (b *Blobs) sessionRow(ctx context.Context, tx pgx.Tx, c Ctx, id string, lock string) (*blobRow, markings.Marking, error) {
	r, err := scanBlob(tx.QueryRow(ctx, `SELECT `+blobCols+` FROM blobs WHERE app = $1 AND id = $2 AND layout = 'parts'`+lock, c.App, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && r.owner != c.Principal.Subject) {
		return nil, markings.Marking{}, errs.NotFound("upload not found")
	}
	if err != nil {
		return nil, markings.Marking{}, err
	}
	m, err := markings.Parse(r.marking)
	if err != nil {
		return nil, m, errs.Integrity("stored marking is invalid")
	}
	return r, m, nil
}

func (b *Blobs) sessionTx(ctx context.Context, tx pgx.Tx, c Ctx, id string, anyState bool) (*UploadSession, error) {
	r, m, err := b.sessionRow(ctx, tx, c, id, "")
	if err != nil {
		return nil, err
	}
	if !anyState && r.state != "pending" {
		return nil, errs.NotFound("upload not found")
	}
	if _, err := b.check(ctx, tx, c, auth.BlobReadMeta, "upload", id, &m, checkOpts{}); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT part_number FROM blob_parts WHERE app = $1 AND blob_id = $2 ORDER BY part_number`, c.App, id)
	if err != nil {
		return nil, err
	}
	received, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		return nil, err
	}
	s := &UploadSession{ID: r.id, Marking: m, SizeBytes: *r.declaredSize, PartSize: *r.partSize,
		PartCount: partCount(*r.declaredSize, *r.partSize), Received: received, State: r.state}
	if r.state == "pending" {
		s.ExpiresAt = r.leaseExpires
	}
	return s, nil
}

// Session reports which parts have arrived, so an interrupted client can resume.
func (b *Blobs) Session(ctx context.Context, c Ctx, id string) (*UploadSession, error) {
	var out *UploadSession
	err := b.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		var err error
		out, err = b.sessionTx(ctx, tx, c, id, true)
		return err
	})
	return out, err
}

// PutPart stores part n. body must be exactly the part's size.
func (b *Blobs) PutPart(ctx context.Context, c Ctx, id string, n int, body io.Reader) (int64, error) {
	var row *blobRow
	var m markings.Marking
	var want int64
	err := b.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		var err error
		if row, m, err = b.sessionRow(ctx, tx, c, id, ""); err != nil {
			return err
		}
		if row.state != "pending" && !(row.state == "active" && c.OpID != "") {
			return errs.Coded(409, "upload_expired", "this upload is %s", row.state)
		}
		if _, err := b.check(ctx, tx, c, auth.BlobCreate, "blob", id, &m, checkOpts{noConceal: true, skipAllow: true}); err != nil {
			return err
		}
		count := partCount(*row.declaredSize, *row.partSize)
		if n < 1 || n > count {
			return errs.Invalid("part number must be between 1 and %d", count)
		}
		want = partLength(*row.declaredSize, *row.partSize, n)
		// Activity keeps the session alive.
		_, err = tx.Exec(ctx, `UPDATE blobs SET lease_expires = $3 WHERE app = $1 AND id = $2 AND state = 'pending'`,
			c.App, id, time.Now().Add(b.SessionTTL))
		return err
	})
	if err != nil {
		return 0, err
	}
	dek, err := b.unwrapCtx(ctx, row, c.App, m)
	if err != nil {
		return 0, err
	}
	first := uint64((int64(n-1) * int64(*row.partSize)) / int64(row.chunkSize))
	enc, err := crypto.NewPartEncryptor(dek, blobCtx(row.aadVersion, "blob", c.App, id, m), row.chunkSize, first, n == partCount(*row.declaredSize, *row.partSize))
	if err != nil {
		return 0, err
	}
	key := fmt.Sprintf("%s/p%05d-%s", row.storageKey, n, nonce())
	w, err := b.backend.OpenWriter(ctx, key)
	if err != nil {
		return 0, err
	}
	sha := sha256.New()
	var written, cipherBytes int64
	emit := func(p []byte) error {
		if len(p) == 0 {
			return nil
		}
		sha.Write(p)
		cipherBytes += int64(len(p))
		_, err := w.Write(p)
		return err
	}
	fail := func(err error) (int64, error) { _ = w.Abort(); return 0, err }
	if n == 1 {
		if err := emit(enc.Header()); err != nil {
			return fail(err)
		}
	}
	buf := make([]byte, 256*1024)
	plainHash := sha256.New()
	src := io.TeeReader(io.LimitReader(body, want+1), plainHash)
	for {
		k, rerr := src.Read(buf)
		if k > 0 {
			written += int64(k)
			if written > want {
				return fail(errs.Invalid("part %d must be exactly %d bytes", n, want))
			}
			ct, err := enc.Update(buf[:k])
			if err == nil {
				err = emit(ct)
			}
			if err != nil {
				return fail(err)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return fail(errs.Invalid("could not read part: %v", rerr))
		}
	}
	if written != want {
		return fail(errs.Invalid("part %d must be exactly %d bytes; got %d", n, want, written))
	}
	tail, err := enc.Finalize()
	if err == nil {
		err = emit(tail)
	}
	if err == nil {
		err = w.Commit()
	}
	if err != nil {
		return fail(err)
	}
	digest := hex.EncodeToString(sha.Sum(nil))
	replayed := false
	err = b.DB.Run(ctx, c.scope(), func(tx pgx.Tx) error {
		replay, err := b.receipts.claim(ctx, tx, c, Operation{Type: "upload.part", Target: fmt.Sprintf("%s/%d", id, n), Payload: hex.EncodeToString(plainHash.Sum(nil))}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			replayed = true
			return nil
		}
		// FOR SHARE: parts may be stored concurrently, but not while Complete (FOR UPDATE) runs.
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM blobs WHERE app = $1 AND id = $2 FOR SHARE`, c.App, id).Scan(&state); err != nil {
			return err
		}
		if state != "pending" {
			return errs.Coded(409, "upload_expired", "this upload is %s", state)
		}
		// Serialize replacement of this part even when it does not exist yet.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "strongbox.part:"+c.App+"/"+id+fmt.Sprint("/", n)); err != nil {
			return err
		}
		var old *string
		if err := tx.QueryRow(ctx, `SELECT storage_key FROM blob_parts WHERE app = $1 AND blob_id = $2 AND part_number = $3 FOR UPDATE`,
			c.App, id, n).Scan(&old); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO blob_parts (app, blob_id, part_number, storage_key, size_bytes, cipher_bytes, ciphertext_sha256)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (app, blob_id, part_number) DO UPDATE SET storage_key = EXCLUDED.storage_key,
			size_bytes = EXCLUDED.size_bytes, cipher_bytes = EXCLUDED.cipher_bytes, ciphertext_sha256 = EXCLUDED.ciphertext_sha256,
			created_at = now()`, c.App, id, n, key, want, cipherBytes, digest); err != nil {
			return err
		}
		if old != nil && *old != key {
			if err := enqueueObjectDelete(ctx, tx, c.App, id, []string{*old}, 0); err != nil {
				return err
			}
		}
		if err := b.note(ctx, tx, c, auth.BlobCreate, "blob", id, "allow", "upload part stored", &m, map[string]any{"part": n}); err != nil {
			return err
		}
		return b.receipts.complete(ctx, tx, c, "blob", id, 0, map[string]any{"part": n})
	})
	if err != nil {
		if errors.Is(err, store.ErrCommitUnknown) {
			// The part row may already reference this key. Deleting the object
			// here would turn a lost acknowledgement into permanent data loss.
			return 0, b.settle(ctx, err)
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = b.backend.Delete(cleanup, key)
		var pg interface{ SQLState() string }
		if errors.As(err, &pg) && pg.SQLState() == "42501" { // the row no longer passes RLS for this uploader
			return 0, errs.NotFound("upload not found")
		}
		return 0, err
	}
	if replayed {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = b.backend.Delete(cleanup, key)
	}
	return want, nil
}

func (b *Blobs) unwrapCtx(ctx context.Context, row *blobRow, app string, m markings.Marking) ([]byte, error) {
	dek, err := b.kms.Unwrap(ctx, crypto.WrappedKey{KEKID: row.kekID, Ciphertext: row.wrappedDEK}, blobCtx(row.aadVersion, "blob-dek", app, row.id, m))
	if err != nil {
		return nil, kmsError(err)
	}
	return dek, nil
}

// partsDigest is the digest stored for a parts-layout blob: SHA-256 over the parts' ciphertext
// digests in order.
func partsDigest(digests []string) string {
	h := sha256.New()
	for _, d := range digests {
		raw, _ := hex.DecodeString(d)
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CompleteSession activates the blob once every part is present with its exact size.
func (b *Blobs) CompleteSession(ctx context.Context, c Ctx, id string) (*BlobMeta, error) {
	var out *BlobMeta
	err := b.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		rc, err := b.receipts.claim(ctx, tx, c, Operation{Type: "upload.complete", Target: id}, 0, "")
		if err != nil {
			return err
		}
		if rc != nil {
			if out, err = b.metaTx(ctx, tx, c, id, false); out != nil {
				out.Replayed = true
			}
			return err
		}
		row, m, err := b.sessionRow(ctx, tx, c, id, " FOR UPDATE")
		if err != nil {
			return err
		}
		if row.state != "pending" {
			if row.state == "active" {
				out, err = b.metaTx(ctx, tx, c, id, false)
				return err
			}
			return errs.Coded(409, "upload_expired", "this upload is %s", row.state)
		}
		count := partCount(*row.declaredSize, *row.partSize)
		rows, err := tx.Query(ctx, `SELECT part_number, size_bytes, ciphertext_sha256 FROM blob_parts
			WHERE app = $1 AND blob_id = $2 ORDER BY part_number`, c.App, id)
		if err != nil {
			return err
		}
		type part struct {
			n      int
			size   int64
			digest string
		}
		parts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (part, error) {
			var p part
			return p, r.Scan(&p.n, &p.size, &p.digest)
		})
		if err != nil {
			return err
		}
		var missing []int
		have := map[int]part{}
		for _, p := range parts {
			have[p.n] = p
		}
		digests := make([]string, 0, count)
		for i := 1; i <= count; i++ {
			p, ok := have[i]
			if !ok || p.size != partLength(*row.declaredSize, *row.partSize, i) {
				missing = append(missing, i)
				continue
			}
			digests = append(digests, p.digest)
		}
		if len(missing) > 0 {
			if len(missing) > 20 {
				missing = missing[:20]
			}
			return errs.Coded(409, "upload_incomplete", "parts missing or the wrong size: %v", missing)
		}
		tag, err := tx.Exec(ctx, `UPDATE blobs SET state = 'active', size_bytes = $3, ciphertext_sha256 = $4,
			lease_owner = NULL, lease_expires = NULL WHERE app = $1 AND id = $2 AND state = 'pending'`,
			c.App, id, *row.declaredSize, partsDigest(digests))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errs.Coded(409, "upload_expired", "this upload is no longer pending")
		}
		if err := b.receipts.complete(ctx, tx, c, "blob", id, 1, nil); err != nil {
			return err
		}
		if err := b.note(ctx, tx, c, auth.BlobCreate, "blob", id, "allow", "blob stored", &m,
			map[string]any{"size_bytes": *row.declaredSize, "parts": count}); err != nil {
			return err
		}
		out, err = b.metaTx(ctx, tx, c, id, false)
		return err
	})
	return out, err
}

// AbortSession discards a pending session and queues its parts for deletion.
func (b *Blobs) AbortSession(ctx context.Context, c Ctx, id string) error {
	return b.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		replay, err := b.receipts.claim(ctx, tx, c, Operation{Type: "blob.abort", Target: id}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			return nil
		}
		row, m, err := b.sessionRow(ctx, tx, c, id, " FOR UPDATE")
		if err != nil {
			return err
		}
		if row.state != "pending" {
			return errs.Coded(409, "upload_expired", "this upload is %s", row.state)
		}
		if err := b.abortPending(ctx, tx, c.App, id, ""); err != nil {
			return err
		}
		if err := b.note(ctx, tx, c, auth.BlobCreate, "blob", id, "error", "upload session aborted by the uploader", &m, nil); err != nil {
			return err
		}
		return b.receipts.complete(ctx, tx, c, "blob", id, 0, nil)
	})
}

// ---- reading parts ---------------------------------------------------------------------------------

type partRef struct {
	key, digest string
}

// partsReader concatenates a blob's part objects, opening each lazily and checking its digest
// when it ends.
type partsReader struct {
	ctx     context.Context
	backend store.Backend
	parts   []partRef
	i       int
	cur     io.ReadCloser
	sha     hash.Hash
}

func (r *partsReader) Read(p []byte) (int, error) {
	for {
		if r.cur == nil {
			if r.i >= len(r.parts) {
				return 0, io.EOF
			}
			src, err := r.backend.Read(r.ctx, r.parts[r.i].key)
			if err != nil {
				return 0, err
			}
			r.cur, r.sha = src, sha256.New()
		}
		n, err := r.cur.Read(p)
		r.sha.Write(p[:n])
		if errors.Is(err, io.EOF) {
			_ = r.cur.Close()
			r.cur = nil
			if hex.EncodeToString(r.sha.Sum(nil)) != r.parts[r.i].digest {
				return n, errs.Integrity("stored ciphertext digest mismatch in part %d", r.i+1)
			}
			r.i++
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (r *partsReader) Close() error {
	if r.cur != nil {
		return r.cur.Close()
	}
	return nil
}

// partsTx validates both the inventory and its ordered aggregate digest for reads and verification.
func (b *Blobs) partsTx(ctx context.Context, tx pgx.Tx, app string, row *blobRow) ([]partRef, error) {
	rows, err := tx.Query(ctx, `SELECT part_number,storage_key,ciphertext_sha256,size_bytes FROM blob_parts
        WHERE app=$1 AND blob_id=$2 ORDER BY part_number`, app, row.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var parts []partRef
	var digests []string
	for rows.Next() {
		var p partRef
		var n int
		var size int64
		if err := rows.Scan(&n, &p.key, &p.digest, &size); err != nil {
			return nil, err
		}
		if row.declaredSize == nil || row.partSize == nil || n != len(parts)+1 || size != partLength(*row.declaredSize, *row.partSize, n) {
			return nil, errs.Integrity("stored part number or size does not match the blob")
		}
		raw, err := hex.DecodeString(p.digest)
		if err != nil || len(raw) != sha256.Size {
			return nil, errs.Integrity("stored part digest is invalid")
		}
		parts = append(parts, p)
		digests = append(digests, p.digest)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if row.declaredSize == nil || row.partSize == nil || *row.partSize <= 0 || row.sha == nil || partsDigest(digests) != *row.sha || len(parts) != partCount(*row.declaredSize, *row.partSize) {
		return nil, errs.Integrity("stored part list does not match the blob")
	}
	return parts, nil
}

func (b *Blobs) openParts(ctx context.Context, c Ctx, row *blobRow) (io.ReadCloser, error) {
	var parts []partRef
	err := b.DB.Run(ctx, c.scope(), func(tx pgx.Tx) error { var err error; parts, err = b.partsTx(ctx, tx, c.App, row); return err })
	if err != nil {
		return nil, err
	}
	return &partsReader{ctx: ctx, backend: b.backend, parts: parts}, nil
}
