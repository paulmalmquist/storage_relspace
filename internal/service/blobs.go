package service

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Blob storage: per-object data keys, streaming AES-256-GCM, sealed metadata, crypto-shredding.

const metaScope = "blobmeta"

var contentTypeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(\s*;\s*[A-Za-z0-9_.-]+=[^;\s]{1,64}){0,3}$`)

func blobCtx(kind, id string, m markings.Marking) []byte {
	return []byte(fmt.Sprintf("strongbox/%s/v2|%s|%s", kind, id, m.Banner()))
}

type BlobMeta struct {
	ID          string
	Marking     markings.Marking
	ContentType string
	SizeBytes   *int64
	Filename    string
	Metadata    map[string]any
	State       string
	CreatedBy   string
	CreatedAt   time.Time
}

func (b *BlobMeta) JSON() map[string]any {
	var fn any
	if b.Filename != "" {
		fn = b.Filename
	}
	md := b.Metadata
	if md == nil {
		md = map[string]any{}
	}
	return map[string]any{
		"id": b.ID, "marking": b.Marking.Banner(), "content_type": b.ContentType, "size_bytes": b.SizeBytes,
		"filename": fn, "metadata": md, "state": b.State, "created_by": b.CreatedBy,
		"created_at": b.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

type sealedMeta struct {
	Filename string         `json:"filename,omitempty"`
	Metadata map[string]any `json:"metadata"`
}

type Blobs struct {
	db          *pgxpool.Pool
	backend     store.Backend
	kms         crypto.KeyProvider
	sealer      Sealer
	guard       *Guard
	ChunkSize   int
	MaxBytes    int64
	MaxMetaSize int
}

type BlobInput struct {
	Marking        markings.Marking
	ContentType    string
	Filename       string
	Metadata       map[string]any
	IdempotencyKey string
	DeclaredSize   int64 // -1 when unknown
}

// Upload is an in-progress blob write. Exactly one of Commit or Abort must be called.
type Upload struct {
	svc     *Blobs
	ctx     context.Context
	c       Ctx
	ID      string
	marking markings.Marking
	enc     *crypto.StreamEncryptor
	writer  store.Writer
	sha     hash.Hash
	size    int64
	idem    string
	open    bool
}

func (b *Blobs) validate(in *BlobInput) error {
	if in.ContentType == "" {
		in.ContentType = "application/octet-stream"
	}
	if !contentTypeRe.MatchString(in.ContentType) {
		return errs.Invalid("invalid content type")
	}
	if len(in.Filename) > 255 || strings.ContainsAny(in.Filename, "\x00/\\") {
		return errs.Invalid("filename must be <= 255 characters without path separators")
	}
	if in.Metadata != nil {
		raw, _ := json.Marshal(in.Metadata)
		if len(raw) > b.MaxMetaSize {
			return errs.Invalid("metadata exceeds %d bytes", b.MaxMetaSize)
		}
	}
	if len(in.IdempotencyKey) > 255 {
		return errs.Invalid("idempotency key must be 1-255 characters")
	}
	return nil
}

// Begin authorizes and opens an upload. If the idempotency key was already used, it returns the
// existing blob's metadata and a nil Upload.
func (b *Blobs) Begin(ctx context.Context, c Ctx, in BlobInput) (*Upload, *BlobMeta, error) {
	if err := b.validate(&in); err != nil {
		return nil, nil, err
	}
	if _, err := b.guard.Check(ctx, c, auth.BlobCreate, "blob", "", &in.Marking, CheckOpts{SkipAllowAudit: true, NoConceal: true}); err != nil {
		return nil, nil, err
	}
	if in.DeclaredSize > b.MaxBytes {
		return nil, nil, errs.PayloadTooLarge("blob exceeds %d bytes", b.MaxBytes)
	}
	if in.IdempotencyKey != "" {
		var existing string
		err := b.db.QueryRow(ctx, `SELECT resource_id FROM idempotency_keys WHERE principal=$1 AND resource_type='blob' AND key=$2`,
			c.Principal.Subject, in.IdempotencyKey).Scan(&existing)
		if err == nil {
			meta, err := b.Meta(ctx, c, existing)
			return nil, meta, err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, err
		}
	}

	id := store.NewID("blb")
	dek := crypto.NewDataKey()
	wrapped, err := b.kms.Wrap(ctx, dek, blobCtx("blob-dek", id, in.Marking))
	if err != nil {
		return nil, nil, err
	}
	metaKey, sealed, err := b.sealer.SealJSON(ctx, metaScope, blobCtx("blob-meta", id, in.Marking),
		sealedMeta{Filename: in.Filename, Metadata: in.Metadata})
	if err != nil {
		return nil, nil, err
	}
	if _, err := b.db.Exec(ctx, `INSERT INTO blobs (id, state, marking, content_type, chunk_size, kek_id, wrapped_dek,
		meta_key_id, sealed_meta, storage_key, created_by) VALUES ($1,'pending',$2,$3,$4,$5,$6,$7,$8,$1,$9)`,
		id, in.Marking.Banner(), in.ContentType, b.ChunkSize, wrapped.KEKID, wrapped.Ciphertext, metaKey, sealed,
		c.Principal.Subject); err != nil {
		return nil, nil, err
	}
	writer, err := b.backend.OpenWriter(ctx, id)
	if err != nil {
		_, _ = b.db.Exec(context.WithoutCancel(ctx), `DELETE FROM blobs WHERE id=$1`, id)
		return nil, nil, err
	}
	enc, err := crypto.NewStreamEncryptor(dek, blobCtx("blob", id, in.Marking), b.ChunkSize)
	if err != nil {
		_ = writer.Abort()
		return nil, nil, err
	}
	u := &Upload{svc: b, ctx: ctx, c: c, ID: id, marking: in.Marking, enc: enc, writer: writer,
		sha: sha256.New(), idem: in.IdempotencyKey, open: true}
	if err := u.emit(enc.Header()); err != nil {
		u.Abort("write failed")
		return nil, nil, err
	}
	return u, nil, nil
}

func (u *Upload) emit(ct []byte) error {
	if len(ct) == 0 {
		return nil
	}
	u.sha.Write(ct)
	_, err := u.writer.Write(ct)
	return err
}

// Write accepts plaintext.
func (u *Upload) Write(p []byte) (int, error) {
	if !u.open {
		return 0, errors.New("upload is closed")
	}
	u.size += int64(len(p))
	if u.size > u.svc.MaxBytes {
		u.Abort("size limit exceeded")
		return 0, errs.PayloadTooLarge("blob exceeds %d bytes", u.svc.MaxBytes)
	}
	ct, err := u.enc.Update(p)
	if err == nil {
		err = u.emit(ct)
	}
	if err != nil {
		u.Abort("write failed")
		return 0, err
	}
	return len(p), nil
}

func (u *Upload) Commit() (*BlobMeta, error) {
	if !u.open {
		return nil, errors.New("upload is closed")
	}
	tail, err := u.enc.Finalize()
	if err == nil {
		err = u.emit(tail)
	}
	if err == nil {
		err = u.writer.Commit()
	}
	if err != nil {
		u.Abort("commit failed")
		return nil, err
	}
	u.open = false
	ctx := context.WithoutCancel(u.ctx)
	err = pgx.BeginFunc(ctx, u.svc.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE blobs SET state='active', size_bytes=$2, ciphertext_sha256=$3 WHERE id=$1`,
			u.ID, u.size, hex.EncodeToString(u.sha.Sum(nil))); err != nil {
			return err
		}
		if u.idem != "" {
			_, err := tx.Exec(ctx, `INSERT INTO idempotency_keys (principal, resource_type, key, resource_id)
				VALUES ($1,'blob',$2,$3) ON CONFLICT DO NOTHING`, u.c.Principal.Subject, u.idem, u.ID)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := u.svc.guard.Note(ctx, u.c, auth.BlobCreate, "blob", u.ID, "allow", "blob stored", &u.marking,
		map[string]any{"size_bytes": u.size}); err != nil {
		return nil, err
	}
	return u.svc.load(ctx, u.ID, "active")
}

// Abort discards the upload. Safe to call more than once.
func (u *Upload) Abort(reason string) {
	if !u.open {
		return
	}
	u.open = false
	ctx := context.WithoutCancel(u.ctx)
	_ = u.writer.Abort()
	_, _ = u.svc.db.Exec(ctx, `DELETE FROM blobs WHERE id=$1`, u.ID)
	_ = u.svc.guard.Note(ctx, u.c, auth.BlobCreate, "blob", u.ID, "error", "upload aborted: "+reason, &u.marking, nil)
}

// Put stores a small in-memory object.
func (b *Blobs) Put(ctx context.Context, c Ctx, data []byte, in BlobInput) (*BlobMeta, error) {
	in.DeclaredSize = int64(len(data))
	u, existing, err := b.Begin(ctx, c, in)
	if err != nil || existing != nil {
		return existing, err
	}
	if _, err := u.Write(data); err != nil {
		return nil, err
	}
	return u.Commit()
}

// ---- reads ---------------------------------------------------------------------------------------

type blobRow struct {
	id, state, marking, contentType, kekID, metaKeyID, storageKey, createdBy string
	size                                                                     *int64
	wrappedDEK, sealedMeta                                                   []byte
	sha                                                                      *string
	createdAt                                                                time.Time
}

const blobCols = `id, state, marking, content_type, size_bytes, kek_id, wrapped_dek, meta_key_id, sealed_meta,
	ciphertext_sha256, storage_key, created_by, created_at`

func scanBlob(row pgx.Row) (*blobRow, error) {
	var r blobRow
	err := row.Scan(&r.id, &r.state, &r.marking, &r.contentType, &r.size, &r.kekID, &r.wrappedDEK, &r.metaKeyID,
		&r.sealedMeta, &r.sha, &r.storageKey, &r.createdBy, &r.createdAt)
	return &r, err
}

func (b *Blobs) row(ctx context.Context, id string, states ...string) (*blobRow, error) {
	r, err := scanBlob(b.db.QueryRow(ctx, `SELECT `+blobCols+` FROM blobs WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.NotFound("blob not found")
	}
	if err != nil {
		return nil, err
	}
	for _, s := range states {
		if r.state == s {
			return r, nil
		}
	}
	return nil, errs.NotFound("blob not found")
}

func (b *Blobs) meta(ctx context.Context, r *blobRow) (*BlobMeta, error) {
	m, err := markings.Parse(r.marking)
	if err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	var sm sealedMeta
	if err := b.sealer.OpenJSON(ctx, metaScope, r.metaKeyID, blobCtx("blob-meta", r.id, m), r.sealedMeta, &sm); err != nil {
		return nil, err
	}
	return &BlobMeta{ID: r.id, Marking: m, ContentType: r.contentType, SizeBytes: r.size, Filename: sm.Filename,
		Metadata: sm.Metadata, State: r.state, CreatedBy: r.createdBy, CreatedAt: r.createdAt}, nil
}

func (b *Blobs) load(ctx context.Context, id string, states ...string) (*BlobMeta, error) {
	r, err := b.row(ctx, id, states...)
	if err != nil {
		return nil, err
	}
	return b.meta(ctx, r)
}

func (b *Blobs) Meta(ctx context.Context, c Ctx, id string) (*BlobMeta, error) {
	r, err := b.row(ctx, id, "active")
	if err != nil {
		return nil, err
	}
	m, err := markings.Parse(r.marking)
	if err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	if _, err := b.guard.Check(ctx, c, auth.BlobReadMeta, "blob", id, &m, CheckOpts{}); err != nil {
		return nil, err
	}
	return b.meta(ctx, r)
}

// contentReader decrypts, checks the stored ciphertext digest at EOF, and audits integrity failures.
type contentReader struct {
	io.Reader
	src      io.Closer
	sha      hash.Hash
	expected string
	onError  func(error)
	failed   bool
}

func (r *contentReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) && r.expected != "" && hex.EncodeToString(r.sha.Sum(nil)) != r.expected {
		err = errs.Integrity("stored ciphertext digest mismatch")
	}
	if err != nil && !errors.Is(err, io.EOF) && errs.Is(err, "integrity_violation") && !r.failed {
		r.failed = true
		r.onError(err)
	}
	return n, err
}

func (r *contentReader) Close() error { return r.src.Close() }

// Open authorizes and returns metadata plus a plaintext reader. The first segment is decrypted before
// returning, so a missing object, wrong key or tampering at the start fails before a response begins.
func (b *Blobs) Open(ctx context.Context, c Ctx, id string) (*BlobMeta, io.ReadCloser, error) {
	r, err := b.row(ctx, id, "active")
	if err != nil {
		return nil, nil, err
	}
	m, err := markings.Parse(r.marking)
	if err != nil {
		return nil, nil, errs.Integrity("stored marking is invalid")
	}
	d, err := b.guard.Check(ctx, c, auth.BlobReadContent, "blob", id, &m, CheckOpts{})
	if err != nil {
		return nil, nil, err
	}
	if d.Withheld {
		return nil, nil, errs.ContentWithheld("%s", d.Reason)
	}
	meta, err := b.meta(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	audited := func(err error) {
		_ = b.guard.Note(context.WithoutCancel(ctx), c, auth.BlobReadContent, "blob", id, "error",
			"integrity failure: "+err.Error(), &m, nil)
	}
	dek, err := b.kms.Unwrap(ctx, crypto.WrappedKey{KEKID: r.kekID, Ciphertext: r.wrappedDEK}, blobCtx("blob-dek", id, m))
	if err != nil {
		if errs.Is(err, "integrity_violation") {
			audited(err)
		}
		return nil, nil, err
	}
	src, err := b.backend.Read(ctx, r.storageKey)
	if err != nil {
		return nil, nil, err
	}
	sha := sha256.New()
	dec, err := crypto.NewDecryptingReader(io.TeeReader(src, sha), dek, blobCtx("blob", id, m))
	if err != nil {
		_ = src.Close()
		return nil, nil, err
	}
	expected := ""
	if r.sha != nil {
		expected = *r.sha
	}
	cr := &contentReader{Reader: dec, src: src, sha: sha, expected: expected, onError: audited}
	buffered := bufio.NewReaderSize(cr, 256*1024)
	if _, err := buffered.Peek(1); err != nil && !errors.Is(err, io.EOF) {
		_ = src.Close()
		return nil, nil, err
	}
	return meta, struct {
		io.Reader
		io.Closer
	}{buffered, cr}, nil
}

// ReadAll is Open plus io.ReadAll, for small objects.
func (b *Blobs) ReadAll(ctx context.Context, c Ctx, id string) (*BlobMeta, []byte, error) {
	meta, rc, err := b.Open(ctx, c, id)
	if err != nil {
		return nil, nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	return meta, data, err
}

func (b *Blobs) List(ctx context.Context, c Ctx, limit int, cur string) ([]*BlobMeta, string, error) {
	if _, err := b.guard.Check(ctx, c, auth.BlobList, "blob", "", nil, CheckOpts{SkipAllowAudit: true}); err != nil {
		return nil, "", err
	}
	n, err := ClampLimit(limit, 50)
	if err != nil {
		return nil, "", err
	}
	q := `SELECT ` + blobCols + ` FROM blobs WHERE state='active'`
	args := []any{}
	if cur != "" {
		t, cid, err := DecodeCursor(cur)
		if err != nil {
			return nil, "", err
		}
		q += ` AND (created_at < $1 OR (created_at = $1 AND id < $2))`
		args = append(args, t, cid)
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT %d`, n+1)
	rows, err := b.db.Query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	var all []*blobRow
	for rows.Next() {
		r, err := scanBlob(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	more := len(all) > n
	if more {
		all = all[:n]
	}
	var items []*BlobMeta
	for _, r := range all {
		m, err := markings.Parse(r.marking)
		if err != nil || !b.guard.Peek(c, auth.BlobReadMeta, &m).Allowed {
			continue
		}
		meta, err := b.meta(ctx, r)
		if err != nil {
			return nil, "", err
		}
		items = append(items, meta)
	}
	if err := b.guard.Note(ctx, c, auth.BlobList, "blob", "", "allow", "listed blobs", nil,
		map[string]any{"returned": len(items), "scanned": len(all)}); err != nil {
		return nil, "", err
	}
	next := ""
	if more && len(all) > 0 {
		last := all[len(all)-1]
		next = EncodeCursor(last.createdAt, last.id)
	}
	return items, next, nil
}

// Delete soft-deletes (ciphertext kept for retention) or shreds. Shredding destroys the only copy of
// the wrapped data key and the object, which makes every copy of the ciphertext, including backups,
// unrecoverable.
func (b *Blobs) Delete(ctx context.Context, c Ctx, id string, shred bool) error {
	states := []string{"active"}
	action := auth.BlobDelete
	if shred {
		states, action = []string{"active", "deleted"}, auth.BlobShred
	}
	r, err := b.row(ctx, id, states...)
	if err != nil {
		return err
	}
	m, err := markings.Parse(r.marking)
	if err != nil {
		return errs.Integrity("stored marking is invalid")
	}
	if _, err := b.guard.Check(ctx, c, action, "blob", id, &m, CheckOpts{}); err != nil {
		return err
	}
	if !shred {
		_, err := b.db.Exec(ctx, `UPDATE blobs SET state='deleted', deleted_at=now() WHERE id=$1`, id)
		return err
	}
	if _, err := b.db.Exec(ctx, `UPDATE blobs SET state='shredded', wrapped_dek=NULL, sealed_meta=''::bytea,
		shredded_at=now() WHERE id=$1`, id); err != nil {
		return err
	}
	return b.backend.Delete(ctx, r.storageKey)
}

// SweepPending removes uploads abandoned by a crashed process.
func (b *Blobs) SweepPending(ctx context.Context, olderThan time.Duration) (int, error) {
	rows, err := b.db.Query(ctx, `SELECT id, storage_key FROM blobs WHERE state='pending' AND created_at < $1`,
		time.Now().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	type item struct{ id, key string }
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.key); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	rows.Close()
	for _, it := range items {
		if err := b.backend.Delete(ctx, it.key); err != nil {
			return 0, err
		}
		if _, err := b.db.Exec(ctx, `DELETE FROM blobs WHERE id=$1`, it.id); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}
