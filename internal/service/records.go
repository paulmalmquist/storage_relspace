package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/cache"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Structured records in schema-validated collections.
//
// Encrypted collections (mandatory for any controlled marking) store each document sealed under the
// collection's data key. The AAD binds app, collection, record id, marking and version, so swapping
// ciphertexts between rows or apps, rolling a row back, or editing its marking in the database all
// fail authentication. Unencrypted collections may hold UNCONTROLLED records only; the database
// enforces that with a CHECK constraint as well.
//
// Equality search on encrypted collections uses HMAC blind-index tokens over declared
// indexed_fields. Filtering on an indexed field is a content disclosure, so a filtered query only
// ever considers records whose content the caller may read (see Query).

var (
	nameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}$`)
	fieldRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

const (
	maxIndexedFields = 16
	maxSchemaBytes   = 64 * 1024
	maxSchemaDepth   = 32
	maxSchemaNodes   = 5000
)

func collScope(name string) string { return "collection:" + name }

// recordAAD: version 1 is the pre-app-scoping context, kept readable for legacy rows.
func recordAAD(aadVersion int, app, coll, id string, m markings.Marking, version int) []byte {
	if aadVersion == 1 {
		return []byte(fmt.Sprintf("strongbox/record/v1|%s|%s|%s|%d", coll, id, m.Banner(), version))
	}
	return []byte(fmt.Sprintf("strongbox/record/v2|%s|%s|%s|%s|%d", app, coll, id, m.Banner(), version))
}

type Collection struct {
	App           string
	Name          string
	Marking       markings.Marking
	Encrypted     bool
	IndexedFields []string
	JSONSchema    map[string]any
	IndexKeyID    *string
	TokenVersion  int
	Version       int
	HistoryLimit  int
	CreatedBy     string
	CreatedAt     time.Time
}

func (c *Collection) JSON() map[string]any {
	return map[string]any{
		"name": c.Name, "marking": c.Marking.Banner(), "encrypted": c.Encrypted, "indexed_fields": nonNil(c.IndexedFields),
		"json_schema": c.JSONSchema, "version": c.Version, "history_limit": c.HistoryLimit, "created_by": c.CreatedBy,
		"created_at": c.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

type Record struct {
	ID             string
	Collection     string
	Marking        markings.Marking
	Version        int
	Data           map[string]any
	Withheld       bool
	WithheldReason string
	Owner          string
	Visibility     string
	TeamID         string
	Deleted        bool
	Replayed       bool
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedBy      string
	UpdatedAt      time.Time
}

func (r *Record) JSON() map[string]any {
	var data any
	if !r.Withheld && !r.Deleted {
		data = r.Data
	}
	out := map[string]any{
		"id": r.ID, "collection": r.Collection, "marking": r.Marking.Banner(), "version": r.Version, "data": data,
		"content_withheld": r.Withheld, "owner": r.Owner, "visibility": r.Visibility, "team_id": optional(r.TeamID),
		"deleted": r.Deleted, "created_by": r.CreatedBy, "created_at": r.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updated_by": r.UpdatedBy, "updated_at": r.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if r.WithheldReason != "" {
		out["withheld_reason"] = r.WithheldReason
	}
	if r.Replayed {
		out["replayed"] = true
	}
	return out
}

// ETag is the version tag clients send back in If-Match.
func (r *Record) ETag() string { return fmt.Sprintf(`"v%d"`, r.Version) }

type Records struct {
	*Core
	keys             *Keys
	receipts         *receipts
	authz            Authorizer
	MaxBytes         int
	MaxResponseBytes int
	schemas          *cache.LRU[*jsonschema.Schema]
}

type CollectionInput struct {
	Name          string
	Marking       markings.Marking
	JSONSchema    map[string]any
	IndexedFields []string
	Encrypted     *bool
	HistoryLimit  int
}

// RecordInput is a create or update. Visibility and TeamID apply to create only; use Share to
// change them later.
type RecordInput struct {
	Data       map[string]any
	Marking    *markings.Marking
	Visibility string // private (default) | team | app
	TeamID     string
}

// ---- schema handling ----------------------------------------------------------------------------

// noRemoteRefs refuses every external reference: schemas are self-contained. Without it the
// compiler's default loader would read local files named in $ref.
type noRemoteRefs struct{}

func (noRemoteRefs) Load(string) (any, error) {
	return nil, errors.New("external $ref is not allowed; collection schemas must be self-contained")
}

func schemaComplexity(v any, depth int, nodes *int) error {
	*nodes++
	if depth > maxSchemaDepth {
		return errs.Invalid("schema nests deeper than %d levels", maxSchemaDepth)
	}
	if *nodes > maxSchemaNodes {
		return errs.Invalid("schema has more than %d nodes", maxSchemaNodes)
	}
	switch x := v.(type) {
	case map[string]any:
		for _, c := range x {
			if err := schemaComplexity(c, depth+1, nodes); err != nil {
				return err
			}
		}
	case []any:
		for _, c := range x {
			if err := schemaComplexity(c, depth+1, nodes); err != nil {
				return err
			}
		}
	}
	return nil
}

// compileSchema runs only after the caller is authorized. It bounds size and complexity, loads
// nothing from the network or filesystem, and returns sanitized errors.
func compileSchema(name string, doc map[string]any) (*jsonschema.Schema, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, errs.Invalid("schema is not JSON")
	}
	if len(raw) > maxSchemaBytes {
		return nil, errs.Invalid("schema exceeds %d bytes", maxSchemaBytes)
	}
	var generic any
	_ = decodeJSON(raw, &generic)
	nodes := 0
	if err := schemaComplexity(generic, 0, &nodes); err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(noRemoteRefs{})
	url := "strongbox:///collections/" + name + ".json"
	if err := c.AddResource(url, generic); err != nil {
		return nil, errs.Invalid("invalid JSON Schema")
	}
	sch, err := c.Compile(url)
	if err != nil {
		return nil, errs.Invalid("invalid JSON Schema: %s", sanitize(err, 200))
	}
	return sch, nil
}

// sanitize keeps the first line of an error, without control characters, bounded.
func sanitize(err error, n int) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

func (r *Records) schema(col *Collection) (*jsonschema.Schema, error) {
	return r.schemas.GetOrLoad(fmt.Sprintf("%s\x00%s\x00%d", col.App, col.Name, col.Version), func() (*jsonschema.Schema, error) {
		sch, err := compileSchema(col.Name, col.JSONSchema)
		if err != nil {
			return nil, errs.Integrity("stored collection schema does not compile")
		}
		return sch, nil
	})
}

// ---- collections ---------------------------------------------------------------------------------

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
	enc := in.Marking.Controlled
	if in.Encrypted != nil {
		enc = *in.Encrypted
	}
	if in.Marking.Controlled && !enc {
		return nil, errs.Invalid("CUI collections must be encrypted")
	}
	history := in.HistoryLimit
	if history == 0 {
		history = 100
	}
	if history < 1 || history > 10000 {
		return nil, errs.Invalid("history_limit must be between 1 and 10000")
	}
	doc := in.JSONSchema
	if doc == nil {
		doc = map[string]any{"type": "object"}
	}
	var out *Collection
	err := r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		// Authorize before touching the schema document.
		if !a.AtLeast("editor") {
			return r.deny(c, auth.CollectionCreate, "collection", in.Name, &in.Marking, "app role "+a.Role+" cannot define collections",
				errs.Forbidden("defining collections requires the editor or admin role in this app"))
		}
		if _, err := r.check(ctx, tx, c, auth.CollectionCreate, "collection", in.Name, &in.Marking, checkOpts{noConceal: true}); err != nil {
			return err
		}
		if t, ok := doc["type"]; ok && t != "object" {
			return errs.Invalid("collection schema must describe a JSON object")
		}
		if _, err := compileSchema(in.Name, doc); err != nil {
			return err
		}
		if op, err := r.receipts.claim(ctx, tx, c, Operation{Type: "collection.create", Target: in.Name, Marking: in.Marking.Banner(),
			Payload: map[string]any{"schema": doc, "indexed": nonNil(fields), "encrypted": enc, "history": history}}, 0, ""); err != nil || op != nil {
			if op != nil {
				out, err = r.collection(ctx, tx, c.App, in.Name)
			}
			return err
		}
		var indexKey *string
		if enc && len(fields) > 0 {
			id, _, err := r.keys.Active(ctx, tx, c.App, collScope(in.Name), PurposeIndex)
			if err != nil {
				return err
			}
			indexKey = &id
		}
		tag, err := tx.Exec(ctx, `INSERT INTO collections (app, name, marking, encrypted, indexed_fields, json_schema, index_key_id,
			created_by, token_version, history_limit) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,2,$9) ON CONFLICT DO NOTHING`,
			c.App, in.Name, in.Marking.Banner(), enc, nonNil(fields), doc, indexKey, c.Principal.Subject, history)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errs.Conflict("collection %s already exists", in.Name)
		}
		if err := r.receipts.complete(ctx, tx, c, "collection", in.Name, 1, nil); err != nil {
			return err
		}
		out, err = r.collection(ctx, tx, c.App, in.Name)
		return err
	})
	return out, err
}

func (r *Records) collection(ctx context.Context, tx pgx.Tx, app, name string) (*Collection, error) {
	col := Collection{App: app}
	var marking string
	err := tx.QueryRow(ctx, `SELECT name, marking, encrypted, indexed_fields, json_schema, index_key_id, token_version,
		version, history_limit, created_by, created_at FROM collections WHERE app = $1 AND name = $2`, app, name).
		Scan(&col.Name, &marking, &col.Encrypted, &col.IndexedFields, &col.JSONSchema, &col.IndexKeyID, &col.TokenVersion,
			&col.Version, &col.HistoryLimit, &col.CreatedBy, &col.CreatedAt)
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

// readableCollection loads a collection and checks the caller may see it.
func (r *Records) readableCollection(ctx context.Context, tx pgx.Tx, c Ctx, name string, audit bool) (*Collection, error) {
	col, err := r.collection(ctx, tx, c.App, name)
	if err != nil {
		return nil, err
	}
	_, err = r.check(ctx, tx, c, auth.CollectionRead, "collection", name, &col.Marking, checkOpts{skipAllow: !audit})
	return col, err
}

func (r *Records) GetCollection(ctx context.Context, c Ctx, name string) (*Collection, error) {
	var out *Collection
	err := r.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		col, err := r.readableCollection(ctx, tx, c, name, true)
		out = col
		return err
	})
	return out, err
}

func (r *Records) ListCollections(ctx context.Context, c Ctx) ([]*Collection, error) {
	var out []*Collection
	err := r.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		if _, err := r.check(ctx, tx, c, auth.CollectionRead, "collection", "", nil, checkOpts{skipAllow: true}); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT name FROM collections WHERE app = $1 ORDER BY name`, c.App)
		if err != nil {
			return err
		}
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, n := range names {
			col, err := r.collection(ctx, tx, c.App, n)
			if err != nil {
				return err
			}
			if r.Policy.Evaluate(c.Principal, auth.CollectionRead, &col.Marking).Allowed {
				out = append(out, col)
			}
		}
		return r.note(ctx, tx, c, auth.CollectionRead, "collection", "", "allow", "listed collections", nil,
			map[string]any{"returned": len(out)})
	})
	return out, err
}

// ---- helpers -------------------------------------------------------------------------------------

func (r *Records) validate(col *Collection, data map[string]any) error {
	if data == nil {
		return errs.Invalid("record data must be a JSON object")
	}
	raw, _ := json.Marshal(data)
	if len(raw) > r.MaxBytes {
		return errs.PayloadTooLarge("record exceeds %d bytes", r.MaxBytes)
	}
	sch, err := r.schema(col)
	if err != nil {
		return err
	}
	var inst any
	if err := decodeJSON(raw, &inst); err != nil {
		return errs.Invalid("record data must be a JSON object")
	}
	if err := sch.Validate(inst); err != nil {
		return errs.Invalid("schema validation failed: %s", sanitize(err, 500))
	}
	return nil
}

// recordMarking applies the collection default and the storage rules for markings.
func recordMarking(col *Collection, m *markings.Marking) (markings.Marking, error) {
	out := col.Marking
	if m != nil {
		out = *m
	}
	if !out.Dominates(col.Marking) {
		return out, errs.Invalid("record marking %s cannot be less restrictive than %s", out.Banner(), col.Marking.Banner())
	}
	if out.Controlled && !col.Encrypted {
		return out, errs.Invalid("controlled record (%s) in an unencrypted collection; controlled content is never stored in plaintext", out.Banner())
	}
	return out, nil
}

// sharing validates create-time visibility.
func sharing(a *Access, visibility, team string) (string, *string, error) {
	switch visibility {
	case "", "private":
		if team != "" {
			return "", nil, errs.Invalid("team_id applies only to team visibility")
		}
		return "private", nil, nil
	case "app":
		if team != "" {
			return "", nil, errs.Invalid("team_id applies only to team visibility")
		}
		return "app", nil, nil
	case "team":
		if _, ok := a.Teams[team]; !ok {
			return "", nil, errs.Invalid("team_id must name a team you belong to")
		}
		return "team", &team, nil
	}
	return "", nil, errs.Invalid("visibility must be private, team or app")
}

type indexToken struct{ field, token string }

func (r *Records) tokens(ctx context.Context, tx pgx.Tx, col *Collection, data map[string]any) ([]indexToken, error) {
	var key []byte
	if col.IndexKeyID != nil {
		k, err := r.keys.Key(ctx, tx, col.App, *col.IndexKeyID, collScope(col.Name))
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
			tok, err = BlindToken(key, col.TokenVersion, col.App, col.Name, f, v)
		} else if col.Encrypted {
			return nil, errs.Integrity("encrypted collection has no index key")
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

func (r *Records) writeIndex(ctx context.Context, tx pgx.Tx, col *Collection, id string, toks []indexToken) error {
	if _, err := tx.Exec(ctx, `DELETE FROM record_index WHERE app = $1 AND record_id = $2`, col.App, id); err != nil {
		return err
	}
	for _, t := range toks {
		if _, err := tx.Exec(ctx, `INSERT INTO record_index (app, collection, field, token, record_id) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT DO NOTHING`, col.App, col.Name, t.field, t.token, id); err != nil {
			return err
		}
	}
	return nil
}

type content struct {
	plain  any
	sealed []byte
	keyID  *string
	size   int
}

func (r *Records) seal(ctx context.Context, tx pgx.Tx, col *Collection, id string, data map[string]any, m markings.Marking, version int) (content, error) {
	raw, _ := json.Marshal(data)
	if !col.Encrypted {
		return content{plain: data, size: len(raw)}, nil
	}
	keyID, sealed, err := r.keys.SealJSON(ctx, tx, col.App, collScope(col.Name), recordAAD(2, col.App, col.Name, id, m, version), data)
	return content{sealed: sealed, keyID: &keyID, size: len(raw)}, err
}

type recordRow struct {
	id, collection, marking, createdBy, updatedBy, owner, visibility string
	teamID                                                           *string
	plain, sealed                                                    []byte
	keyID                                                            *string
	version, aadVersion                                              int
	createdAt, updatedAt                                             time.Time
	deletedAt                                                        *time.Time
}

const recordCols = `id, collection, marking, data_plain, data_sealed, key_id, version, aad_version, owner, visibility, team_id,
	created_by, created_at, updated_by, updated_at, deleted_at`

func scanRecord(row pgx.Row) (*recordRow, error) {
	var rr recordRow
	err := row.Scan(&rr.id, &rr.collection, &rr.marking, &rr.plain, &rr.sealed, &rr.keyID, &rr.version, &rr.aadVersion,
		&rr.owner, &rr.visibility, &rr.teamID, &rr.createdBy, &rr.createdAt, &rr.updatedBy, &rr.updatedAt, &rr.deletedAt)
	return &rr, err
}

func (rr *recordRow) resource() Resource {
	r := Resource{Kind: "record", ID: rr.id, Owner: rr.owner, Visibility: rr.visibility}
	if rr.teamID != nil {
		r.TeamID = *rr.teamID
	}
	return r
}

// row reads a record visible to the caller (RLS). includeDeleted is for history and restore.
func (r *Records) row(ctx context.Context, tx pgx.Tx, app, coll, id string, includeDeleted bool) (*recordRow, error) {
	q := `SELECT ` + recordCols + ` FROM records WHERE app = $1 AND collection = $2 AND id = $3`
	if !includeDeleted {
		q += ` AND deleted_at IS NULL`
	}
	rr, err := scanRecord(tx.QueryRow(ctx, q, app, coll, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.NotFound("record not found")
	}
	return rr, err
}

func (r *Records) open(ctx context.Context, tx pgx.Tx, col *Collection, id string, m markings.Marking, version, aadVersion int,
	plain, sealed []byte, keyID *string) (map[string]any, error) {
	var data map[string]any
	if sealed != nil {
		if keyID == nil {
			return nil, errs.Integrity("sealed record has no key")
		}
		err := r.keys.OpenJSON(ctx, tx, col.App, collScope(col.Name), *keyID, recordAAD(aadVersion, col.App, col.Name, id, m, version), sealed, &data)
		return data, err
	}
	return data, decodeJSON(plain, &data)
}

// view builds the response for a row. Content is included only when the policy allows reading it.
func (r *Records) view(ctx context.Context, tx pgx.Tx, c Ctx, col *Collection, rr *recordRow) (*Record, error) {
	m, err := markings.Parse(rr.marking)
	if err != nil {
		return nil, errs.Integrity("stored marking is invalid")
	}
	rec := &Record{ID: rr.id, Collection: col.Name, Marking: m, Version: rr.version, Owner: rr.owner, Visibility: rr.visibility,
		Deleted: rr.deletedAt != nil, CreatedBy: rr.createdBy, CreatedAt: rr.createdAt, UpdatedBy: rr.updatedBy, UpdatedAt: rr.updatedAt}
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
	rec.Data, err = r.open(ctx, tx, col, rr.id, m, rr.version, rr.aadVersion, rr.plain, rr.sealed, rr.keyID)
	return rec, err
}

// writable loads a live record and checks the caller may edit it.
func (r *Records) writable(ctx context.Context, tx pgx.Tx, c Ctx, a *Access, col *Collection, id string, need Perm, action auth.Action, includeDeleted bool) (*recordRow, markings.Marking, error) {
	rr, err := r.row(ctx, tx, c.App, col.Name, id, includeDeleted)
	if err != nil {
		return nil, markings.Marking{}, err
	}
	m, err := markings.Parse(rr.marking)
	if err != nil {
		return nil, m, errs.Integrity("stored marking is invalid")
	}
	if _, err := r.check(ctx, tx, c, auth.RecordRead, "record", id, &m, checkOpts{skipAllow: true}); err != nil {
		return nil, m, err
	}
	perm, why, err := r.authz.Permissions(ctx, tx, a, rr.resource())
	if err != nil {
		return nil, m, err
	}
	if !perm.Has(need) {
		return nil, m, r.deny(c, action, "record", id, &m, "sharing: "+strings.Join(why, ","),
			errs.Forbidden("you may read this record but not %s it", strings.TrimPrefix(string(action), "record.")))
	}
	return rr, m, nil
}

// ---- records -------------------------------------------------------------------------------------

func (r *Records) Create(ctx context.Context, c Ctx, coll string, in RecordInput) (*Record, error) {
	var out *Record
	err := r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		col, err := r.readableCollection(ctx, tx, c, coll, false)
		if err != nil {
			return err
		}
		m, err := recordMarking(col, in.Marking)
		if err != nil {
			return err
		}
		vis, team, err := sharing(a, in.Visibility, in.TeamID)
		if err != nil {
			return err
		}
		op := Operation{Type: "record.create", Target: coll, Marking: m.Banner(),
			Payload: map[string]any{"data": in.Data, "visibility": vis, "team_id": team}}
		if rc, err := r.receipts.claim(ctx, tx, c, op, 0, ""); err != nil || rc != nil {
			if rc != nil {
				out, err = r.replay(ctx, tx, c, col, rc)
			}
			return err
		}
		if !a.AtLeast("member") {
			return r.deny(c, auth.RecordCreate, "record", "", &m, "app role viewer", errs.Forbidden("viewers cannot create records"))
		}
		if _, err := r.check(ctx, tx, c, auth.RecordCreate, "record", "", &m, checkOpts{noConceal: true, skipAllow: true}); err != nil {
			return err
		}
		if err := r.validate(col, in.Data); err != nil {
			return err
		}
		id := store.NewID("rec")
		st, err := r.seal(ctx, tx, col, id, in.Data, m, 1)
		if err != nil {
			return err
		}
		toks, err := r.tokens(ctx, tx, col, in.Data)
		if err != nil {
			return err
		}
		rr, err := scanRecord(tx.QueryRow(ctx, `INSERT INTO records (app, id, collection, marking, data_plain, data_sealed, key_id,
			version, created_by, updated_by, owner, visibility, team_id, aad_version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$8,$8,$9,$10,2) RETURNING `+recordCols,
			c.App, id, col.Name, m.Banner(), st.plain, st.sealed, st.keyID, c.Principal.Subject, vis, team))
		if err != nil {
			return err
		}
		if err := r.writeIndex(ctx, tx, col, id, toks); err != nil {
			return err
		}
		if err := r.revision(ctx, tx, c, col, rr, "create", st.size); err != nil {
			return err
		}
		if err := r.receipts.complete(ctx, tx, c, "record", id, 1, map[string]any{"collection": col.Name}); err != nil {
			return err
		}
		if err := r.note(ctx, tx, c, auth.RecordCreate, "record", id, "allow", "record stored", &m,
			map[string]any{"collection": col.Name, "version": 1}); err != nil {
			return err
		}
		out, err = r.view(ctx, tx, c, col, rr)
		return err
	})
	return out, err
}

func (r *Records) Get(ctx context.Context, c Ctx, coll, id string) (*Record, error) {
	var out *Record
	err := r.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		col, err := r.readableCollection(ctx, tx, c, coll, false)
		if err != nil {
			return err
		}
		rr, err := r.row(ctx, tx, c.App, coll, id, false)
		if err != nil {
			return err
		}
		m, err := markings.Parse(rr.marking)
		if err != nil {
			return errs.Integrity("stored marking is invalid")
		}
		d, err := r.check(ctx, tx, c, auth.RecordRead, "record", id, &m, checkOpts{skipAllow: true})
		if err != nil {
			return err
		}
		cd := r.Policy.Evaluate(c.Principal, auth.RecordReadContent, &m)
		reason, action := d.Reason, auth.RecordReadContent
		if !cd.Allowed {
			reason, action = cd.Reason, auth.RecordRead
		}
		if err := r.note(ctx, tx, c, action, "record", id, "allow", reason, &m, nil); err != nil {
			return err
		}
		out, err = r.view(ctx, tx, c, col, rr)
		return err
	})
	return out, err
}

// Update replaces a record's data with compare-and-swap on expectedVersion. The returned record is
// exactly the version this call wrote, authorized for this caller.
func (r *Records) Update(ctx context.Context, c Ctx, coll, id string, in RecordInput, expectedVersion int) (*Record, error) {
	var out *Record
	err := r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		col, err := r.readableCollection(ctx, tx, c, coll, false)
		if err != nil {
			return err
		}
		marking := ""
		if in.Marking != nil {
			marking = in.Marking.Banner()
		}
		op := Operation{Type: "record.update", Target: coll + "/" + id, ExpectedVersion: expectedVersion, Marking: marking,
			Payload: map[string]any{"data": in.Data}}
		if rc, err := r.receipts.claim(ctx, tx, c, op, 0, ""); err != nil || rc != nil {
			if rc != nil {
				out, err = r.replay(ctx, tx, c, col, rc)
			}
			return err
		}
		rr, old, err := r.writable(ctx, tx, c, a, col, id, PermWrite, auth.RecordUpdate, false)
		if err != nil {
			return err
		}
		if rr.version != expectedVersion {
			return errs.PreconditionFailed("record is at version %d, not %d", rr.version, expectedVersion)
		}
		m := old
		if in.Marking != nil {
			m = *in.Marking
		}
		if m, err = recordMarking(col, &m); err != nil {
			return err
		}
		for _, mk := range []markings.Marking{old, m} {
			if _, err := r.check(ctx, tx, c, auth.RecordUpdate, "record", id, &mk, checkOpts{noConceal: true, skipAllow: true}); err != nil {
				return err
			}
		}
		if err := r.validate(col, in.Data); err != nil {
			return err
		}
		next := expectedVersion + 1
		st, err := r.seal(ctx, tx, col, id, in.Data, m, next)
		if err != nil {
			return err
		}
		toks, err := r.tokens(ctx, tx, col, in.Data)
		if err != nil {
			return err
		}
		// Compare-and-swap: concurrent writers serialize on the row lock and the loser's WHERE fails.
		nr, err := scanRecord(tx.QueryRow(ctx, `UPDATE records SET marking=$5, data_plain=$6, data_sealed=$7, key_id=$8,
			version=$9, aad_version=2, updated_by=$10, updated_at=now()
			WHERE app=$1 AND collection=$2 AND id=$3 AND version=$4 AND deleted_at IS NULL RETURNING `+recordCols,
			c.App, col.Name, id, expectedVersion, m.Banner(), st.plain, st.sealed, st.keyID, next, c.Principal.Subject))
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.PreconditionFailed("record changed concurrently; it is no longer at version %d", expectedVersion)
		}
		if err != nil {
			return err
		}
		if err := r.writeIndex(ctx, tx, col, id, toks); err != nil {
			return err
		}
		if err := r.revision(ctx, tx, c, col, nr, "update", st.size); err != nil {
			return err
		}
		if err := r.receipts.complete(ctx, tx, c, "record", id, next, map[string]any{"collection": col.Name}); err != nil {
			return err
		}
		if err := r.note(ctx, tx, c, auth.RecordUpdate, "record", id, "allow", "record updated", &m,
			map[string]any{"collection": col.Name, "version": next, "previous_marking": old.Banner()}); err != nil {
			return err
		}
		out, err = r.view(ctx, tx, c, col, nr)
		return err
	})
	return out, err
}

// Delete soft-deletes with compare-and-swap. The live row keeps no content; history keeps prior
// versions until history expiry or purge. expectedVersion nil deletes whatever version is current,
// still atomically. purge removes the row and its history.
func (r *Records) Delete(ctx context.Context, c Ctx, coll, id string, expectedVersion *int, purge bool) error {
	return r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		col, err := r.readableCollection(ctx, tx, c, coll, false)
		if err != nil {
			return err
		}
		ev := -1
		if expectedVersion != nil {
			ev = *expectedVersion
		}
		if rc, err := r.receipts.claim(ctx, tx, c, Operation{Type: "record.delete", Target: coll + "/" + id, ExpectedVersion: ev,
			Payload: map[string]any{"purge": purge}}, 0, ""); err != nil || rc != nil {
			return err // a replayed delete succeeded before
		}
		rr, m, err := r.writable(ctx, tx, c, a, col, id, PermManage, auth.RecordDelete, false)
		if err != nil {
			return err
		}
		if expectedVersion != nil && rr.version != *expectedVersion {
			return errs.PreconditionFailed("record is at version %d, not %d", rr.version, *expectedVersion)
		}
		if _, err := r.check(ctx, tx, c, auth.RecordDelete, "record", id, &m, checkOpts{noConceal: true, skipAllow: true}); err != nil {
			return err
		}
		if purge {
			tag, err := tx.Exec(ctx, `DELETE FROM records WHERE app=$1 AND collection=$2 AND id=$3 AND version=$4`,
				c.App, col.Name, id, rr.version)
			if err == nil && tag.RowsAffected() != 1 {
				err = errs.PreconditionFailed("record changed concurrently")
			}
			if err != nil {
				return err
			}
		} else {
			nr, err := scanRecord(tx.QueryRow(ctx, `UPDATE records SET deleted_at=now(), version=version+1, data_plain=NULL,
				data_sealed=NULL, key_id=NULL, updated_by=$5, updated_at=now()
				WHERE app=$1 AND collection=$2 AND id=$3 AND version=$4 AND deleted_at IS NULL RETURNING `+recordCols,
				c.App, col.Name, id, rr.version, c.Principal.Subject))
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.PreconditionFailed("record changed concurrently")
			}
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM record_index WHERE app=$1 AND record_id=$2`, c.App, id); err != nil {
				return err
			}
			if err := r.revision(ctx, tx, c, col, nr, "delete", 0); err != nil {
				return err
			}
		}
		if err := r.receipts.complete(ctx, tx, c, "record", id, rr.version+1, map[string]any{"deleted": true, "purged": purge}); err != nil {
			return err
		}
		reason := "record deleted"
		if purge {
			reason = "record and history purged"
		}
		return r.note(ctx, tx, c, auth.RecordDelete, "record", id, "allow", reason, &m, map[string]any{"collection": col.Name, "purge": purge})
	})
}

// Query lists records newest first, optionally filtered by equality on indexed fields.
//
// Disclosure rules: a record whose metadata the caller may not see is excluded in SQL, before
// LIMIT, so page sizes and cursors reveal nothing about it. A filter is an assertion about content,
// so a filtered query considers only records whose content the caller may read; an agent denied
// content cannot test candidate values. Results stop early at MaxResponseBytes.
func (r *Records) Query(ctx context.Context, c Ctx, coll string, filters map[string]any, limit int, cur string) ([]*Record, string, error) {
	n, err := ClampLimit(limit, 20)
	if err != nil {
		return nil, "", err
	}
	var out []*Record
	var next string
	err = r.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		col, err := r.readableCollection(ctx, tx, c, coll, false)
		if err != nil {
			return err
		}
		if _, err := r.check(ctx, tx, c, auth.RecordQuery, "collection", col.Name, &col.Marking, checkOpts{skipAllow: true}); err != nil {
			return err
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
			return errs.Invalid("can only filter on indexed fields %v; got %v", nonNil(col.IndexedFields), unknown)
		}
		need := auth.RecordRead
		if len(filters) > 0 {
			need = auth.RecordReadContent
		}
		allowed, err := r.allowedMarkings(ctx, tx, c, col, need)
		if err != nil {
			return err
		}
		toks, err := r.tokens(ctx, tx, col, filters)
		if err != nil {
			return err
		}
		q := `SELECT ` + recordCols + ` FROM records WHERE app=$1 AND collection=$2 AND deleted_at IS NULL AND marking = ANY($3)`
		args := []any{c.App, col.Name, allowed}
		for _, t := range toks {
			args = append(args, t.field, t.token)
			q += fmt.Sprintf(` AND id IN (SELECT record_id FROM record_index WHERE app=$1 AND collection=$2 AND field=$%d AND token=$%d)`,
				len(args)-1, len(args))
		}
		if cur != "" {
			t, cid, err := DecodeCursor(cur, c.App, "records/"+col.Name)
			if err != nil {
				return err
			}
			args = append(args, t, cid)
			q += fmt.Sprintf(` AND (created_at, id) < ($%d, $%d)`, len(args)-1, len(args))
		}
		q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT %d`, n+1)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*recordRow, error) { return scanRecord(row) })
		if err != nil {
			return err
		}
		more := len(all) > n
		if more {
			all = all[:n]
		}
		withheld, bytes := 0, 0
		for i, rr := range all {
			rec, err := r.view(ctx, tx, c, col, rr)
			if err != nil {
				return err
			}
			if rec.Withheld {
				withheld++
			}
			size := len(rr.plain) + len(rr.sealed)
			if i > 0 && bytes+size > r.MaxResponseBytes {
				more, all = true, all[:i]
				break
			}
			bytes += size
			out = append(out, rec)
		}
		if more && len(all) > 0 {
			last := all[len(all)-1]
			next = EncodeCursor(c.App, "records/"+col.Name, last.createdAt, last.id)
		}
		return r.note(ctx, tx, c, auth.RecordQuery, "collection", col.Name, "allow", "query", &col.Marking,
			map[string]any{"filters": sortedKeys(filters), "returned": len(out), "content_withheld": withheld})
	})
	return out, next, err
}

// allowedMarkings returns the markings that occur in the collection (from the marking catalog, so
// no table scan) for which the caller passes the policy for action. The set is used inside SQL, so
// excluded records never reach LIMIT.
func (r *Records) allowedMarkings(ctx context.Context, tx pgx.Tx, c Ctx, col *Collection, action auth.Action) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT marking FROM marking_catalog WHERE app = $1 AND scope = $2`, c.App, "collection:"+col.Name)
	if err != nil {
		return nil, err
	}
	present, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, banner := range present {
		m, err := markings.Parse(banner)
		if err == nil && r.Policy.Evaluate(c.Principal, action, &m).Allowed {
			out = append(out, banner)
		}
	}
	return out, nil
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
