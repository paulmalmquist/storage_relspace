package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Structured records in schema-validated collections.
//
// Encrypted collections (mandatory for CUI) store each document sealed under the collection's data key.
// The AAD binds collection, record id, marking and version, so swapping ciphertexts between rows,
// rolling a row back, or editing its marking in the database all fail authentication.
//
// Equality search on encrypted collections uses HMAC blind-index tokens over declared indexed_fields.
// Equal values produce equal tokens (frequency is visible to someone with database access); range and
// full-text search are not supported on encrypted data.

var (
	nameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}$`)
	fieldRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

const maxIndexedFields = 16

func collScope(name string) string { return "collection:" + name }

func recordAAD(coll, id string, m markings.Marking, version int) []byte {
	return []byte(fmt.Sprintf("strongbox/record/v1|%s|%s|%s|%d", coll, id, m.Banner(), version))
}

type Collection struct {
	Name          string
	Marking       markings.Marking
	Encrypted     bool
	IndexedFields []string
	JSONSchema    map[string]any
	IndexKeyID    *string
	Version       int
	CreatedBy     string
	CreatedAt     time.Time
}

func (c *Collection) JSON() map[string]any {
	return map[string]any{
		"name": c.Name, "marking": c.Marking.Banner(), "encrypted": c.Encrypted, "indexed_fields": nonNil(c.IndexedFields),
		"json_schema": c.JSONSchema, "version": c.Version, "created_by": c.CreatedBy,
		"created_at": c.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type Record struct {
	ID             string
	Collection     string
	Marking        markings.Marking
	Version        int
	Data           map[string]any
	Withheld       bool
	WithheldReason string
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedBy      string
	UpdatedAt      time.Time
}

func (r *Record) JSON() map[string]any {
	var data any
	if !r.Withheld {
		data = r.Data
	}
	out := map[string]any{
		"id": r.ID, "collection": r.Collection, "marking": r.Marking.Banner(), "version": r.Version, "data": data,
		"content_withheld": r.Withheld, "created_by": r.CreatedBy, "created_at": r.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updated_by": r.UpdatedBy, "updated_at": r.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if r.WithheldReason != "" {
		out["withheld_reason"] = r.WithheldReason
	}
	return out
}

type Records struct {
	db       *pgxpool.Pool
	keys     *Keys
	sealer   Sealer
	guard    *Guard
	MaxBytes int
	schemas  sync.Map // name@version -> *jsonschema.Schema
}

type CollectionInput struct {
	Name          string
	Marking       markings.Marking
	JSONSchema    map[string]any
	IndexedFields []string
	Encrypted     *bool
}

func compileSchema(name string, doc map[string]any) (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	url := "strongbox://collections/" + name + ".json"
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	return c.Compile(url)
}

func oneLine(err error, n int) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func (r *Records) CreateCollection(ctx context.Context, c Ctx, in CollectionInput) (*Collection, error) {
	if !nameRe.MatchString(in.Name) {
		return nil, errs.Invalid("collection name must match ^[a-z][a-z0-9_]{1,62}$")
	}
	seen := map[string]bool{}
	var fields []string
	for _, f := range in.IndexedFields {
		if !seen[f] {
			seen[f] = true
			fields = append(fields, f)
		}
	}
	if len(fields) > maxIndexedFields {
		return nil, errs.Invalid("indexed_fields: up to %d top-level field names", maxIndexedFields)
	}
	for _, f := range fields {
		if !fieldRe.MatchString(f) {
			return nil, errs.Invalid("indexed_fields: invalid field name %q", f)
		}
	}
	doc := in.JSONSchema
	if doc == nil {
		doc = map[string]any{"type": "object"}
	}
	if t, ok := doc["type"]; ok && t != "object" {
		return nil, errs.Invalid("collection schema must describe a JSON object")
	}
	if _, err := compileSchema(in.Name, doc); err != nil {
		return nil, errs.Invalid("invalid JSON Schema: %s", oneLine(err, 300))
	}
	enc := in.Marking.Controlled
	if in.Encrypted != nil {
		enc = *in.Encrypted
	}
	if in.Marking.Controlled && !enc {
		return nil, errs.Invalid("CUI collections must be encrypted")
	}
	if _, err := r.guard.Check(ctx, c, auth.CollectionCreate, "collection", in.Name, &in.Marking, CheckOpts{NoConceal: true}); err != nil {
		return nil, err
	}
	var indexKey *string
	if enc && len(fields) > 0 {
		id, _, err := r.keys.Active(ctx, collScope(in.Name), PurposeIndex)
		if err != nil {
			return nil, err
		}
		indexKey = &id
	}
	_, err := r.db.Exec(ctx, `INSERT INTO collections (name, marking, encrypted, indexed_fields, json_schema, index_key_id,
		created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`, in.Name, in.Marking.Banner(), enc, nonNil(fields), doc, indexKey, c.Principal.Subject)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, errs.Conflict("collection %s already exists", in.Name)
	}
	if err != nil {
		return nil, err
	}
	return r.collection(ctx, in.Name)
}

func (r *Records) collection(ctx context.Context, name string) (*Collection, error) {
	var col Collection
	var marking string
	err := r.db.QueryRow(ctx, `SELECT name, marking, encrypted, indexed_fields, json_schema, index_key_id, version,
		created_by, created_at FROM collections WHERE name=$1`, name).
		Scan(&col.Name, &marking, &col.Encrypted, &col.IndexedFields, &col.JSONSchema, &col.IndexKeyID, &col.Version,
			&col.CreatedBy, &col.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.NotFound("collection not found")
	}
	if err != nil {
		return nil, err
	}
	if col.Marking, err = markings.Parse(marking); err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	return &col, nil
}

func (r *Records) GetCollection(ctx context.Context, c Ctx, name string) (*Collection, error) {
	col, err := r.collection(ctx, name)
	if err != nil {
		return nil, err
	}
	if _, err := r.guard.Check(ctx, c, auth.CollectionRead, "collection", name, &col.Marking, CheckOpts{}); err != nil {
		return nil, err
	}
	return col, nil
}

func (r *Records) ListCollections(ctx context.Context, c Ctx) ([]*Collection, error) {
	if _, err := r.guard.Check(ctx, c, auth.CollectionRead, "collection", "", nil, CheckOpts{SkipAllowAudit: true}); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT name FROM collections ORDER BY name`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	var out []*Collection
	for _, n := range names {
		col, err := r.collection(ctx, n)
		if err != nil {
			return nil, err
		}
		if r.guard.Peek(c, auth.CollectionRead, &col.Marking).Allowed {
			out = append(out, col)
		}
	}
	return out, r.guard.Note(ctx, c, auth.CollectionRead, "collection", "", "allow", "listed collections", nil,
		map[string]any{"returned": len(out)})
}

// ---- helpers -------------------------------------------------------------------------------------

func (r *Records) validate(col *Collection, data map[string]any) error {
	if data == nil {
		return errs.Invalid("record data must be a JSON object")
	}
	raw, _ := json.Marshal(data)
	if len(raw) > r.MaxBytes {
		return errs.Invalid("record exceeds %d bytes", r.MaxBytes)
	}
	key := fmt.Sprintf("%s@%d", col.Name, col.Version)
	cached, ok := r.schemas.Load(key)
	if !ok {
		sch, err := compileSchema(col.Name, col.JSONSchema)
		if err != nil {
			return errs.Integrity("stored collection schema does not compile")
		}
		cached, _ = r.schemas.LoadOrStore(key, sch)
	}
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		return errs.Invalid("record data must be a JSON object")
	}
	if err := cached.(*jsonschema.Schema).Validate(inst); err != nil {
		return errs.Invalid("schema validation failed: %s", oneLine(err, 500))
	}
	return nil
}

func (r *Records) recordMarking(col *Collection, m *markings.Marking) (markings.Marking, error) {
	out := col.Marking
	if m != nil {
		out = *m
	}
	if !out.Dominates(col.Marking) {
		return out, errs.Invalid("record marking %s cannot be less restrictive than %s", out.Banner(), col.Marking.Banner())
	}
	return out, nil
}

type indexToken struct{ field, token string }

func (r *Records) tokens(ctx context.Context, col *Collection, data map[string]any) ([]indexToken, error) {
	var key []byte
	if col.IndexKeyID != nil {
		k, err := r.keys.Key(ctx, *col.IndexKeyID, collScope(col.Name))
		if err != nil {
			return nil, err
		}
		key = k
	}
	var out []indexToken
	for _, f := range col.IndexedFields {
		v, ok := data[f]
		if !ok {
			continue
		}
		var tok string
		var err error
		if key != nil {
			tok, err = BlindToken(key, col.Name, f, v)
		} else {
			tok, err = PlainToken(v)
		}
		if err != nil {
			return nil, errs.Invalid("indexed field %s: %v", f, err)
		}
		out = append(out, indexToken{f, tok})
	}
	return out, nil
}

type storage struct {
	plain  any
	sealed []byte
	keyID  *string
}

func (r *Records) storageValues(ctx context.Context, col *Collection, id string, data map[string]any, m markings.Marking, version int) (storage, error) {
	if !col.Encrypted {
		return storage{plain: data}, nil
	}
	keyID, sealed, err := r.sealer.SealJSON(ctx, collScope(col.Name), recordAAD(col.Name, id, m, version), data)
	return storage{sealed: sealed, keyID: &keyID}, err
}

type recordRow struct {
	id, marking, createdBy, updatedBy string
	plain                             []byte
	sealed                            []byte
	keyID                             *string
	version                           int
	createdAt, updatedAt              time.Time
}

const recordCols = `id, marking, data_plain, data_sealed, key_id, version, created_by, created_at, updated_by, updated_at`

func scanRecord(row pgx.Row) (*recordRow, error) {
	var rr recordRow
	err := row.Scan(&rr.id, &rr.marking, &rr.plain, &rr.sealed, &rr.keyID, &rr.version, &rr.createdBy, &rr.createdAt,
		&rr.updatedBy, &rr.updatedAt)
	return &rr, err
}

func (r *Records) row(ctx context.Context, coll, id string) (*recordRow, error) {
	rr, err := scanRecord(r.db.QueryRow(ctx, `SELECT `+recordCols+` FROM records WHERE id=$1 AND collection=$2
		AND deleted_at IS NULL`, id, coll))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.NotFound("record not found")
	}
	return rr, err
}

func (r *Records) view(ctx context.Context, col *Collection, rr *recordRow, include bool, reason string) (*Record, error) {
	m, err := markings.Parse(rr.marking)
	if err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	rec := &Record{ID: rr.id, Collection: col.Name, Marking: m, Version: rr.version, Withheld: !include,
		WithheldReason: reason, CreatedBy: rr.createdBy, CreatedAt: rr.createdAt, UpdatedBy: rr.updatedBy, UpdatedAt: rr.updatedAt}
	if !include {
		return rec, nil
	}
	var data map[string]any
	if rr.sealed != nil {
		if rr.keyID == nil {
			return nil, errs.Integrity("sealed record has no key")
		}
		err = r.sealer.OpenJSON(ctx, collScope(col.Name), *rr.keyID, recordAAD(col.Name, rr.id, m, rr.version), rr.sealed, &data)
	} else {
		err = decodeJSON(rr.plain, &data)
	}
	if err != nil {
		return nil, err
	}
	rec.Data = data
	return rec, nil
}

func (r *Records) contentAllowed(c Ctx, m markings.Marking) (bool, string) {
	d := r.guard.Peek(c, auth.RecordReadContent, &m)
	if d.Allowed {
		return true, ""
	}
	return false, d.Reason
}

func requestHash(data map[string]any, m markings.Marking) string {
	raw, _ := json.Marshal(map[string]any{"d": data, "m": m.Banner()})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ---- records -------------------------------------------------------------------------------------

func (r *Records) Create(ctx context.Context, c Ctx, coll string, data map[string]any, marking *markings.Marking, idemKey string) (*Record, error) {
	col, err := r.collection(ctx, coll)
	if err != nil {
		return nil, err
	}
	m, err := r.recordMarking(col, marking)
	if err != nil {
		return nil, err
	}
	if _, err := r.guard.Check(ctx, c, auth.RecordCreate, "record", "", &m, CheckOpts{SkipAllowAudit: true, NoConceal: true}); err != nil {
		return nil, err
	}
	if err := r.validate(col, data); err != nil {
		return nil, err
	}
	reqHash := requestHash(data, m)
	if idemKey != "" {
		if existing, err := r.idempotent(ctx, c, idemKey, reqHash); err != nil || existing != "" {
			if err != nil {
				return nil, err
			}
			return r.Get(ctx, c, coll, existing)
		}
	}
	id := store.NewID("rec")
	st, err := r.storageValues(ctx, col, id, data, m, 1)
	if err != nil {
		return nil, err
	}
	toks, err := r.tokens(ctx, col, data)
	if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO records (id, collection, marking, data_plain, data_sealed, key_id, version,
			created_by, updated_by) VALUES ($1,$2,$3,$4,$5,$6,1,$7,$7)`, id, col.Name, m.Banner(), st.plain, st.sealed, st.keyID,
			c.Principal.Subject); err != nil {
			return err
		}
		for _, t := range toks {
			if _, err := tx.Exec(ctx, `INSERT INTO record_index (collection, field, token, record_id) VALUES ($1,$2,$3,$4)`,
				col.Name, t.field, t.token, id); err != nil {
				return err
			}
		}
		if idemKey != "" {
			_, err := tx.Exec(ctx, `INSERT INTO idempotency_keys (principal, resource_type, key, resource_id, request_hash)
				VALUES ($1,'record',$2,$3,$4)`, c.Principal.Subject, idemKey, id, reqHash)
			return err
		}
		return nil
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && idemKey != "" {
		existing, ierr := r.idempotent(ctx, c, idemKey, reqHash)
		if ierr != nil {
			return nil, ierr
		}
		if existing != "" {
			return r.Get(ctx, c, coll, existing)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := r.guard.Note(ctx, c, auth.RecordCreate, "record", id, "allow", "record created", &m,
		map[string]any{"collection": col.Name}); err != nil {
		return nil, err
	}
	rr, err := r.row(ctx, col.Name, id)
	if err != nil {
		return nil, err
	}
	ok, reason := r.contentAllowed(c, m)
	return r.view(ctx, col, rr, ok, reason)
}

func (r *Records) idempotent(ctx context.Context, c Ctx, key, reqHash string) (string, error) {
	var id string
	var stored *string
	err := r.db.QueryRow(ctx, `SELECT resource_id, request_hash FROM idempotency_keys WHERE principal=$1
		AND resource_type='record' AND key=$2`, c.Principal.Subject, key).Scan(&id, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if stored == nil || *stored != reqHash {
		return "", errs.Conflict("idempotency key was already used with a different request")
	}
	return id, nil
}

func (r *Records) Get(ctx context.Context, c Ctx, coll, id string) (*Record, error) {
	col, err := r.collection(ctx, coll)
	if err != nil {
		return nil, err
	}
	rr, err := r.row(ctx, col.Name, id)
	if err != nil {
		return nil, err
	}
	m, err := markings.Parse(rr.marking)
	if err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	if _, err := r.guard.Check(ctx, c, auth.RecordRead, "record", id, &m, CheckOpts{SkipAllowAudit: true}); err != nil {
		return nil, err
	}
	d, err := r.guard.Check(ctx, c, auth.RecordReadContent, "record", id, &m, CheckOpts{})
	if err != nil {
		return nil, err
	}
	reason := ""
	if !d.Allowed {
		reason = d.Reason
	}
	return r.view(ctx, col, rr, d.Allowed, reason)
}

func (r *Records) Update(ctx context.Context, c Ctx, coll, id string, data map[string]any, expectedVersion int, marking *markings.Marking) (*Record, error) {
	col, err := r.collection(ctx, coll)
	if err != nil {
		return nil, err
	}
	rr, err := r.row(ctx, col.Name, id)
	if err != nil {
		return nil, err
	}
	current, err := markings.Parse(rr.marking)
	if err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	if _, err := r.guard.Check(ctx, c, auth.RecordUpdate, "record", id, &current, CheckOpts{}); err != nil {
		return nil, err
	}
	if marking == nil {
		marking = &current
	}
	next, err := r.recordMarking(col, marking)
	if err != nil {
		return nil, err
	}
	if !next.Dominates(current) {
		return nil, errs.Invalid("lowering a record's marking (decontrol) is not supported through this API")
	}
	if !next.Equal(current) {
		if _, err := r.guard.Check(ctx, c, auth.RecordUpdate, "record", id, &next, CheckOpts{NoConceal: true}); err != nil {
			return nil, err
		}
	}
	if rr.version != expectedVersion {
		return nil, errs.PreconditionFailed("record is at version %d, not %d", rr.version, expectedVersion)
	}
	if err := r.validate(col, data); err != nil {
		return nil, err
	}
	version := expectedVersion + 1
	st, err := r.storageValues(ctx, col, id, data, next, version)
	if err != nil {
		return nil, err
	}
	toks, err := r.tokens(ctx, col, data)
	if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE records SET marking=$3, data_plain=$4, data_sealed=$5, key_id=$6, version=$7,
			updated_by=$8, updated_at=now() WHERE id=$1 AND version=$2`, id, expectedVersion, next.Banner(), st.plain,
			st.sealed, st.keyID, version, c.Principal.Subject)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errs.PreconditionFailed("record was modified concurrently")
		}
		if _, err := tx.Exec(ctx, `DELETE FROM record_index WHERE record_id=$1`, id); err != nil {
			return err
		}
		for _, t := range toks {
			if _, err := tx.Exec(ctx, `INSERT INTO record_index (collection, field, token, record_id) VALUES ($1,$2,$3,$4)`,
				col.Name, t.field, t.token, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rr, err = r.row(ctx, col.Name, id)
	if err != nil {
		return nil, err
	}
	ok, reason := r.contentAllowed(c, next)
	return r.view(ctx, col, rr, ok, reason)
}

func (r *Records) Delete(ctx context.Context, c Ctx, coll, id string, expectedVersion *int, purge bool) error {
	col, err := r.collection(ctx, coll)
	if err != nil {
		return err
	}
	rr, err := r.row(ctx, col.Name, id)
	if err != nil {
		return err
	}
	m, err := markings.Parse(rr.marking)
	if err != nil {
		return errs.Integrity("stored marking is invalid")
	}
	if _, err := r.guard.Check(ctx, c, auth.RecordDelete, "record", id, &m, CheckOpts{Details: map[string]any{"purge": purge}}); err != nil {
		return err
	}
	if expectedVersion != nil && rr.version != *expectedVersion {
		return errs.PreconditionFailed("record is at version %d, not %d", rr.version, *expectedVersion)
	}
	return pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM record_index WHERE record_id=$1`, id); err != nil {
			return err
		}
		if purge {
			_, err := tx.Exec(ctx, `DELETE FROM records WHERE id=$1`, id)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE records SET deleted_at=now() WHERE id=$1`, id)
		return err
	})
}

func (r *Records) Query(ctx context.Context, c Ctx, coll string, filters map[string]any, limit int, cur string) ([]*Record, string, error) {
	col, err := r.collection(ctx, coll)
	if err != nil {
		return nil, "", err
	}
	if _, err := r.guard.Check(ctx, c, auth.RecordQuery, "collection", col.Name, &col.Marking, CheckOpts{SkipAllowAudit: true}); err != nil {
		return nil, "", err
	}
	indexed := map[string]bool{}
	for _, f := range col.IndexedFields {
		indexed[f] = true
	}
	var unknown []string
	for f := range filters {
		if !indexed[f] {
			unknown = append(unknown, f)
		}
	}
	if len(unknown) > 0 {
		return nil, "", errs.Invalid("can only filter on indexed fields %v; got %v", nonNil(col.IndexedFields), unknown)
	}
	n, err := ClampLimit(limit, 20)
	if err != nil {
		return nil, "", err
	}
	toks, err := r.tokens(ctx, col, filters)
	if err != nil {
		return nil, "", err
	}
	q := `SELECT ` + recordCols + ` FROM records WHERE collection=$1 AND deleted_at IS NULL`
	args := []any{col.Name}
	for _, t := range toks {
		args = append(args, t.field, t.token)
		q += fmt.Sprintf(` AND id IN (SELECT record_id FROM record_index WHERE collection=$1 AND field=$%d AND token=$%d)`,
			len(args)-1, len(args))
	}
	if cur != "" {
		t, cid, err := DecodeCursor(cur)
		if err != nil {
			return nil, "", err
		}
		args = append(args, t, cid)
		q += fmt.Sprintf(` AND (created_at < $%d OR (created_at = $%d AND id < $%d))`, len(args)-1, len(args)-1, len(args))
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT %d`, n+1)
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	var all []*recordRow
	for rows.Next() {
		rr, err := scanRecord(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		all = append(all, rr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	more := len(all) > n
	if more {
		all = all[:n]
	}
	var out []*Record
	withheld := 0
	for _, rr := range all {
		m, err := markings.Parse(rr.marking)
		if err != nil || !r.guard.Peek(c, auth.RecordRead, &m).Allowed {
			continue
		}
		ok, reason := r.contentAllowed(c, m)
		if !ok {
			withheld++
		}
		rec, err := r.view(ctx, col, rr, ok, reason)
		if err != nil {
			return nil, "", err
		}
		out = append(out, rec)
	}
	fields := make([]string, 0, len(filters))
	for f := range filters {
		fields = append(fields, f)
	}
	if err := r.guard.Note(ctx, c, auth.RecordQuery, "collection", col.Name, "allow", "queried records", &col.Marking,
		map[string]any{"filters": fields, "returned": len(out), "withheld": withheld, "scanned": len(all)}); err != nil {
		return nil, "", err
	}
	next := ""
	if more && len(all) > 0 {
		last := all[len(all)-1]
		next = EncodeCursor(last.createdAt, last.id)
	}
	return out, next, nil
}
