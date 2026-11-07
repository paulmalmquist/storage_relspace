package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// ContractInput is a new version of a collection's contract.
type ContractInput struct {
	JSONSchema      map[string]any
	IndexedFields   []string
	UniqueFields    []string
	Defaults        map[string]any // set on records that lack the field, by the migration job
	ExpectedVersion int            // the version the caller is changing (compare-and-swap)
}

// ContractChange reports what a change did: took effect at once, or started a migration.
type ContractChange struct {
	Collection *Collection
	Version    int
	Immediate  bool
	Reason     string
	Migration  *Migration
}

type MigrationFailure struct {
	RecordID string `json:"record_id"`
	Reason   string `json:"reason"`
}

type Migration struct {
	ID          string             `json:"id"`
	Collection  string             `json:"collection"`
	FromVersion int                `json:"from_version"`
	ToVersion   int                `json:"to_version"`
	State       string             `json:"state"`
	Processed   int64              `json:"processed"`
	Rewritten   int64              `json:"rewritten"`
	Failures    []MigrationFailure `json:"failures"`
	CreatedBy   string             `json:"created_by"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	FinishedAt  *time.Time         `json:"finished_at"`
}

type ContractVersion struct {
	Version       int            `json:"version"`
	JSONSchema    map[string]any `json:"json_schema"`
	IndexedFields []string       `json:"indexed_fields"`
	UniqueFields  []string       `json:"unique_fields"`
	CreatedBy     string         `json:"created_by"`
	CreatedAt     time.Time      `json:"created_at"`
	Current       bool           `json:"current"`
	Pending       bool           `json:"pending"`
}

const migrationCols = `id, collection, from_version, to_version, state, processed, rewritten, failures, created_by, created_at,
	updated_at, finished_at`

func scanMigration(row pgx.Row) (*Migration, error) {
	var m Migration
	err := row.Scan(&m.ID, &m.Collection, &m.FromVersion, &m.ToVersion, &m.State, &m.Processed, &m.Rewritten, &m.Failures,
		&m.CreatedBy, &m.CreatedAt, &m.UpdatedAt, &m.FinishedAt)
	if m.Failures == nil {
		m.Failures = []MigrationFailure{}
	}
	return &m, err
}

func normalizeFields(fields []string) ([]string, error) {
	out := union(fields, nil)
	if len(out) > maxIndexedFields {
		return nil, errs.Invalid("indexed_fields: up to %d top-level field names", maxIndexedFields)
	}
	for _, f := range out {
		if !fieldRe.MatchString(f) {
			return nil, errs.Invalid("invalid field name %q", f)
		}
	}
	return out, nil
}

func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// ChangeContract stages a new contract version. A change that provably accepts every record the
// old contract accepted, adds no index or uniqueness and declares no defaults takes effect in this
// transaction. Anything else starts a migration job; the collection keeps its current version
// until the job has validated (and, with defaults, rewritten) every live record.
func (r *Records) ChangeContract(ctx context.Context, c Ctx, name string, in ContractInput) (*ContractChange, error) {
	indexed, err := normalizeFields(in.IndexedFields)
	if err != nil {
		return nil, err
	}
	unique, err := uniqueFields(in.UniqueFields, indexed)
	if err != nil {
		return nil, err
	}
	doc := in.JSONSchema
	if doc == nil {
		return nil, errs.Invalid("json_schema is required")
	}
	if t, ok := doc["type"]; ok && t != "object" {
		return nil, errs.Invalid("collection schema must describe a JSON object")
	}
	for f := range in.Defaults {
		if !fieldRe.MatchString(f) {
			return nil, errs.Invalid("defaults: invalid field name %q", f)
		}
	}
	var out *ContractChange
	err = r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if err := lockContract(ctx, tx, c.App, name, true); err != nil {
			return err
		}
		col, err := r.readableCollection(ctx, tx, c, name, false)
		if err != nil {
			return err
		}
		if !a.AtLeast("editor") {
			return r.deny(c, auth.CollectionCreate, "collection", name, &col.Marking, "app role "+a.Role+" cannot change contracts",
				errs.Forbidden("changing a collection's contract requires the editor or admin role in this app"))
		}
		if _, err := r.check(ctx, tx, c, auth.CollectionCreate, "collection", name, &col.Marking, checkOpts{noConceal: true, skipAllow: true}); err != nil {
			return err
		}
		if _, err := compileSchema(name, doc); err != nil {
			return err
		}
		if rc, err := r.receipts.claim(ctx, tx, c, Operation{Type: "collection.contract", Target: name, ExpectedVersion: in.ExpectedVersion,
			Payload: map[string]any{"schema": doc, "indexed": nonNil(indexed), "unique": nonNil(unique), "defaults": in.Defaults}}, 0, ""); err != nil || rc != nil {
			if rc != nil {
				out = &ContractChange{Version: rc.ResourceVersion}
				out.Collection, err = r.collection(ctx, tx, c.App, name)
			}
			return err
		}
		if col.Pending != nil {
			return errs.Coded(409, "migration_in_progress", "version %d is still being migrated to; cancel it or wait", col.Pending.Version)
		}
		if col.Version != in.ExpectedVersion {
			return errs.PreconditionFailed("collection contract is at version %d, not %d", col.Version, in.ExpectedVersion)
		}
		var next int
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) + 1 FROM collection_versions WHERE app = $1 AND collection = $2`,
			c.App, name).Scan(&next); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO collection_versions (app, collection, version, json_schema, indexed_fields, unique_fields, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, c.App, name, next, doc, nonNil(indexed), nonNil(unique), c.Principal.Subject); err != nil {
			return err
		}
		reason, immediate := "", true
		switch {
		case len(in.Defaults) > 0:
			reason, immediate = "declares defaults to apply to existing records", false
		case !subset(indexed, col.IndexedFields):
			reason, immediate = "adds indexed fields that existing records need tokens for", false
		case !subset(unique, col.UniqueFields):
			reason, immediate = "adds unique fields that existing records must be checked against", false
		default:
			if why := widens(col.JSONSchema, doc, "$"); why != "" {
				reason, immediate = why, false
			}
		}
		out = &ContractChange{Version: next, Immediate: immediate, Reason: reason}
		if immediate {
			if _, err := tx.Exec(ctx, `UPDATE collections SET version = $3, json_schema = $4, indexed_fields = $5, unique_fields = $6,
				updated_at = now() WHERE app = $1 AND name = $2`, c.App, name, next, doc, nonNil(indexed), nonNil(unique)); err != nil {
				return err
			}
		} else {
			if col.Encrypted && len(indexed) > 0 && col.IndexKeyID == nil {
				id, _, err := r.keys.Active(ctx, tx, c.App, collScope(name), PurposeIndex)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE collections SET index_key_id = $3 WHERE app = $1 AND name = $2`, c.App, name, id); err != nil {
					return err
				}
			}
			// Fields becoming unique start from nothing: rows left from an earlier contract are stale.
			if added := without(unique, col.UniqueFields); len(added) > 0 {
				if _, err := tx.Exec(ctx, `DELETE FROM record_unique WHERE app = $1 AND collection = $2 AND field = ANY($3)`,
					c.App, name, added); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE collections SET pending_version = $3 WHERE app = $1 AND name = $2`, c.App, name, next); err != nil {
				return err
			}
			defaults := in.Defaults
			if defaults == nil {
				defaults = map[string]any{}
			}
			m, err := scanMigration(tx.QueryRow(ctx, `INSERT INTO collection_migrations (app, id, collection, from_version, to_version,
				defaults, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+migrationCols,
				c.App, store.NewID("mig"), name, col.Version, next, defaults, c.Principal.Subject))
			if err != nil {
				return err
			}
			out.Migration = m
		}
		if err := r.receipts.complete(ctx, tx, c, "collection", name, next, nil); err != nil {
			return err
		}
		detail := map[string]any{"version": next, "immediate": immediate}
		if !immediate {
			detail["reason"] = reason
			detail["migration"] = out.Migration.ID
		}
		if err := r.note(ctx, tx, c, auth.CollectionCreate, "collection", name, "allow", "contract changed", &col.Marking, detail); err != nil {
			return err
		}
		out.Collection, err = r.collection(ctx, tx, c.App, name)
		return err
	})
	return out, err
}

func without(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// ContractVersions lists every version of a collection's contract, newest first.
func (r *Records) ContractVersions(ctx context.Context, c Ctx, name string) ([]ContractVersion, error) {
	var out []ContractVersion
	err := r.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		col, err := r.readableCollection(ctx, tx, c, name, false)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT version, json_schema, indexed_fields, unique_fields, created_by, created_at
			FROM collection_versions WHERE app = $1 AND collection = $2 ORDER BY version DESC LIMIT 200`, c.App, name)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractVersion, error) {
			var v ContractVersion
			err := row.Scan(&v.Version, &v.JSONSchema, &v.IndexedFields, &v.UniqueFields, &v.CreatedBy, &v.CreatedAt)
			v.Current = v.Version == col.Version
			v.Pending = col.Pending != nil && v.Version == col.Pending.Version
			return v, err
		})
		return err
	})
	return out, err
}

// GetMigration reports a migration's progress.
func (r *Records) GetMigration(ctx context.Context, c Ctx, name, id string) (*Migration, error) {
	var out *Migration
	err := r.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		if _, err := r.readableCollection(ctx, tx, c, name, false); err != nil {
			return err
		}
		m, err := scanMigration(tx.QueryRow(ctx, `SELECT `+migrationCols+` FROM collection_migrations WHERE app = $1 AND collection = $2 AND id = $3`,
			c.App, name, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFound("migration not found")
		}
		out = m
		return err
	})
	return out, err
}

// CancelMigration abandons a running migration; the collection stays at its current version.
func (r *Records) CancelMigration(ctx context.Context, c Ctx, name, id string) (*Migration, error) {
	var out *Migration
	err := r.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if err := lockContract(ctx, tx, c.App, name, true); err != nil {
			return err
		}
		col, err := r.readableCollection(ctx, tx, c, name, false)
		if err != nil {
			return err
		}
		if !a.AtLeast("editor") {
			return errs.Forbidden("cancelling a migration requires the editor or admin role in this app")
		}
		if _, err := r.check(ctx, tx, c, auth.CollectionCreate, "collection", name, &col.Marking, checkOpts{noConceal: true, skipAllow: true}); err != nil {
			return err
		}
		if out, err = r.endMigration(ctx, tx, col, id, "cancelled"); err != nil {
			return err
		}
		return r.note(ctx, tx, c, auth.CollectionCreate, "collection", name, "allow", "contract migration cancelled", &col.Marking,
			map[string]any{"migration": id})
	})
	return out, err
}

// endMigration finishes a running migration without switching versions (failed or cancelled).
// The caller holds the contract lock exclusively.
func (r *Records) endMigration(ctx context.Context, tx pgx.Tx, col *Collection, id, state string) (*Migration, error) {
	m, err := scanMigration(tx.QueryRow(ctx, `UPDATE collection_migrations SET state = $4, updated_at = now(), finished_at = now()
		WHERE app = $1 AND collection = $2 AND id = $3 AND state = 'running' RETURNING `+migrationCols, col.App, col.Name, id, state))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.Coded(409, "migration_finished", "migration %s is not running", id)
	}
	if err != nil {
		return nil, err
	}
	if col.Pending != nil {
		if added := without(col.Pending.UniqueFields, col.UniqueFields); len(added) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM record_unique WHERE app = $1 AND collection = $2 AND field = ANY($3)`,
				col.App, col.Name, added); err != nil {
				return nil, err
			}
		}
	}
	_, err = tx.Exec(ctx, `UPDATE collections SET pending_version = NULL WHERE app = $1 AND name = $2`, col.App, col.Name)
	return m, err
}

// ---- the migration job ---------------------------------------------------------------------------

const migrationBatch = 200
const maxMigrationFailures = 100

// migrateBatch advances one running migration by at most migrationBatch records, in worker mode,
// and finishes it when the scan is complete. Progress (the cursor) commits with each batch, so a
// crash resumes where the last batch ended.
func (r *Records) migrateBatch(ctx context.Context, db *store.DB, scope store.Scope, app string, m *Migration, auditLog *audit.Log) (bool, error) {
	done := false
	err := db.Run(ctx, scope, func(tx pgx.Tx) error {
		col, err := r.collection(ctx, tx, app, m.Collection)
		if err != nil {
			return err
		}
		var cursor string
		var defaults map[string]any
		var failures []MigrationFailure
		if err := tx.QueryRow(ctx, `SELECT cursor, defaults, failures FROM collection_migrations WHERE app = $1 AND id = $2 AND state = 'running'
			FOR UPDATE`, app, m.ID).Scan(&cursor, &defaults, &failures); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				done = true
				return nil
			}
			return err
		}
		if col.Pending == nil || col.Pending.Version != m.ToVersion {
			done = true
			return nil // superseded; endMigration below is not needed
		}
		target := col.Pending
		rows, err := tx.Query(ctx, `SELECT `+recordCols+` FROM records WHERE app = $1 AND collection = $2 AND id > $3
			AND deleted_at IS NULL ORDER BY id LIMIT $4 FOR UPDATE`, app, col.Name, cursor, migrationBatch)
		if err != nil {
			return err
		}
		batch, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*recordRow, error) { return scanRecord(row) })
		if err != nil {
			return err
		}
		var rewritten int64
		for _, rr := range batch {
			cursor = rr.id
			mk, err := markings.Parse(rr.marking)
			if err != nil {
				failures = append(failures, MigrationFailure{rr.id, "stored marking is invalid"})
				continue
			}
			data, err := r.open(ctx, tx, col, rr.id, mk, rr.version, rr.aadVersion, rr.plain, rr.sealed, rr.keyID)
			if err != nil {
				failures = append(failures, MigrationFailure{rr.id, "could not decrypt"})
				continue
			}
			changed := false
			for f, v := range defaults {
				if _, ok := data[f]; !ok {
					data[f] = v
					changed = true
				}
			}
			if err := r.validate(target, data); err != nil {
				failures = append(failures, MigrationFailure{rr.id, sanitize(err, 300)})
				continue
			}
			version := rr.version
			if changed {
				version++
				st, err := r.seal(ctx, tx, col, rr.id, data, mk, version)
				if err != nil {
					return err
				}
				nr, err := scanRecord(tx.QueryRow(ctx, `UPDATE records SET data_plain = $4, data_sealed = $5, key_id = $6, version = $7,
					aad_version = 2, schema_version = $8, updated_by = $9, updated_at = now()
					WHERE app = $1 AND id = $2 AND version = $3 RETURNING `+recordCols,
					app, rr.id, rr.version, st.plain, st.sealed, st.keyID, version, target.Version, workerSubject))
				if err != nil {
					return err
				}
				if err := r.revision(ctx, tx, Ctx{Principal: &auth.Principal{Subject: workerSubject}}, col, nr, "migrate", st.size); err != nil {
					return err
				}
				rewritten++
			} else if _, err := tx.Exec(ctx, `UPDATE records SET schema_version = $3 WHERE app = $1 AND id = $2`, app, rr.id, target.Version); err != nil {
				return err
			}
			toks, err := r.tokens(ctx, tx, col, data)
			if err != nil {
				failures = append(failures, MigrationFailure{rr.id, sanitize(err, 300)})
				continue
			}
			if field, err := r.writeTokens(ctx, tx, col, rr.id, toks, true); err != nil {
				return err
			} else if field != "" {
				failures = append(failures, MigrationFailure{rr.id, "another record already has this " + field})
			}
		}
		if len(failures) > maxMigrationFailures {
			failures = failures[:maxMigrationFailures]
		}
		if _, err := tx.Exec(ctx, `UPDATE collection_migrations SET cursor = $3, processed = processed + $4, rewritten = rewritten + $5,
			failures = $6, updated_at = now() WHERE app = $1 AND id = $2`, app, m.ID, cursor, len(batch), rewritten, failures); err != nil {
			return err
		}
		done = len(batch) < migrationBatch || len(failures) >= maxMigrationFailures
		return nil
	})
	if err != nil || !done {
		return done, err
	}
	// Finish: switch versions (or give up) under the exclusive contract lock, so no writer is
	// between reading the old contract and committing.
	err = db.Run(ctx, scope, func(tx pgx.Tx) error {
		if err := lockContract(ctx, tx, app, m.Collection, true); err != nil {
			return err
		}
		col, err := r.collection(ctx, tx, app, m.Collection)
		if err != nil {
			return err
		}
		var failures []MigrationFailure
		var state string
		if err := tx.QueryRow(ctx, `SELECT state, failures FROM collection_migrations WHERE app = $1 AND id = $2 FOR UPDATE`, app, m.ID).
			Scan(&state, &failures); err != nil || state != "running" {
			return err
		}
		entry := audit.Entry{App: app, Anonymous: workerSubject, Action: "collection.contract", ResourceType: "collection",
			ResourceID: m.Collection, Marking: col.Marking.Banner(), Decision: "allow",
			Details: map[string]any{"migration": m.ID, "version": m.ToVersion, "failures": len(failures)}}
		if len(failures) > 0 || col.Pending == nil || col.Pending.Version != m.ToVersion {
			if _, err := r.endMigration(ctx, tx, col, m.ID, "failed"); err != nil {
				return err
			}
			entry.Decision, entry.Reason = "error", fmt.Sprintf("contract migration failed: %d records do not satisfy version %d", len(failures), m.ToVersion)
			_, err := auditLog.Append(ctx, tx, entry)
			return err
		}
		p := col.Pending
		if _, err := tx.Exec(ctx, `UPDATE collections SET version = $3, json_schema = $4, indexed_fields = $5, unique_fields = $6,
			pending_version = NULL, updated_at = now() WHERE app = $1 AND name = $2`,
			app, col.Name, p.Version, p.JSONSchema, nonNil(p.IndexedFields), nonNil(p.UniqueFields)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE collection_migrations SET state = 'succeeded', updated_at = now(), finished_at = now()
			WHERE app = $1 AND id = $2`, app, m.ID); err != nil {
			return err
		}
		entry.Reason = fmt.Sprintf("contract version %d active", m.ToVersion)
		_, err = auditLog.Append(ctx, tx, entry)
		return err
	})
	return true, err
}

// ---- compatibility --------------------------------------------------------------------------------

// widens reports why newSchema might reject a document oldSchema accepted, or "" when every
// document valid under oldSchema is provably valid under newSchema. It understands a common subset
// of JSON Schema (type, properties, required, additionalProperties, items, enum, const and numeric
// and length bounds) and is conservative: anything else that differs needs a migration, which
// checks real records instead of reasoning about schemas.
func widens(oldS, newS any, path string) string {
	if reflect.DeepEqual(oldS, newS) {
		return ""
	}
	o, ok1 := oldS.(map[string]any)
	n, ok2 := newS.(map[string]any)
	if !ok1 || !ok2 {
		if b, ok := newS.(bool); ok && b {
			return ""
		}
		return path + ": schema changed in a way that cannot be compared"
	}
	if len(n) == 0 {
		return "" // {} accepts everything
	}
	known := map[string]bool{"type": true, "properties": true, "required": true, "additionalProperties": true, "items": true,
		"enum": true, "const": true, "minimum": true, "maximum": true, "exclusiveMinimum": true, "exclusiveMaximum": true,
		"minLength": true, "maxLength": true, "minItems": true, "maxItems": true, "title": true, "description": true,
		"$comment": true, "examples": true, "default": true, "$schema": true, "format": true}
	for _, key := range union(keys(o), keys(n)) {
		if !known[key] && !reflect.DeepEqual(o[key], n[key]) {
			return fmt.Sprintf("%s: %q changed", path, key)
		}
	}
	if why := widerType(o["type"], n["type"]); why != "" {
		return path + ": " + why
	}
	if nr, _ := n["required"].([]any); len(nr) > 0 {
		or, _ := o["required"].([]any)
		for _, f := range nr {
			if !slices.Contains(or, f) {
				return fmt.Sprintf("%s: %v became required", path, f)
			}
		}
	}
	op, _ := o["properties"].(map[string]any)
	np, _ := n["properties"].(map[string]any)
	oAdd, nAdd := o["additionalProperties"], n["additionalProperties"]
	for name, ns := range np {
		os, existed := op[name]
		switch {
		case existed:
			if why := widens(os, ns, path+"."+name); why != "" {
				return why
			}
		case oAdd == false:
			// No existing document has this property.
		default:
			if why := widens(orTrue(oAdd), ns, path+"."+name); why != "" {
				return fmt.Sprintf("%s.%s: new property constrains values existing records may hold", path, name)
			}
		}
	}
	for name, os := range op {
		if _, still := np[name]; still {
			continue
		}
		if why := widens(os, orTrue(nAdd), path+"."+name); why != "" {
			return fmt.Sprintf("%s.%s: removed property is no longer allowed", path, name)
		}
	}
	if oAdd != nil || nAdd != nil {
		if why := widens(orTrue(oAdd), orTrue(nAdd), path+".additionalProperties"); why != "" && oAdd != false {
			return why
		}
	}
	if o["items"] != nil || n["items"] != nil {
		if why := widens(orTrue(o["items"]), orTrue(n["items"]), path+"[]"); why != "" {
			return why
		}
	}
	if ne, ok := n["enum"].([]any); ok {
		oe, ok := o["enum"].([]any)
		if !ok {
			return path + ": enum added"
		}
		for _, v := range oe {
			if !slices.ContainsFunc(ne, func(x any) bool { return reflect.DeepEqual(x, v) }) {
				return fmt.Sprintf("%s: enum value %v removed", path, v)
			}
		}
	}
	if !reflect.DeepEqual(o["const"], n["const"]) && n["const"] != nil {
		return path + ": const changed"
	}
	if !reflect.DeepEqual(o["format"], n["format"]) && n["format"] != nil {
		return path + ": format changed"
	}
	lower := []string{"minimum", "exclusiveMinimum", "minLength", "minItems"}
	upper := []string{"maximum", "exclusiveMaximum", "maxLength", "maxItems"}
	for _, k := range lower {
		if why := bound(o[k], n[k], func(oldV, newV float64) bool { return newV <= oldV }); why != "" {
			return fmt.Sprintf("%s: %s %s", path, k, why)
		}
	}
	for _, k := range upper {
		if why := bound(o[k], n[k], func(oldV, newV float64) bool { return newV >= oldV }); why != "" {
			return fmt.Sprintf("%s: %s %s", path, k, why)
		}
	}
	return ""
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func orTrue(v any) any {
	if v == nil {
		return true
	}
	return v
}

func types(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "number" {
			return []string{"number", "integer"}
		}
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, types(x)...)
		}
		return out
	}
	return nil
}

func widerType(o, n any) string {
	if n == nil {
		return ""
	}
	if o == nil {
		return "type added"
	}
	nt := types(n)
	for _, t := range types(o) {
		if !slices.Contains(nt, t) {
			return "type " + t + " no longer allowed"
		}
	}
	return ""
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

func bound(o, n any, ok func(oldV, newV float64) bool) string {
	if n == nil {
		return ""
	}
	nv, nok := number(n)
	ov, ook := number(o)
	if !nok || !ook || o == nil {
		return "added or tightened"
	}
	if !ok(ov, nv) {
		return "tightened"
	}
	return ""
}
