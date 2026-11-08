// Package backup exports one app to a directory, validates an export offline, and restores it
// into a separate database.
//
// An export is ciphertext: sealed records, KMS-wrapped data keys and encrypted objects, with each
// app-bound encryption context intact. It is only readable with access to the same KMS key, and
// only under the same app identity, because the app is bound into every AAD. Restoring therefore
// keeps the app's identity. Copying an app under a new identity (a clone) is a different
// operation: every ciphertext would have to be re-sealed under the new context, which this package
// does not do.
//
// Legacy format (format_version 1); format 2 encrypts tables and authenticates the manifest:
//
//	manifest.json             what follows, with row counts and SHA-256 digests
//	tables/<table>.ndjson     one JSON object per row (to_jsonb), in dependency order
//	objects.ndjson            {key, bytes, sha256} for each object copied
//	objects/<storage key>     the encrypted objects, byte for byte
package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

const (
	Format        = "strongbox-export"
	FormatVersion = 2
)

// table is exported with where (bound to $1 = app) and restored in list order.
type table struct {
	name, where, order string
	merge              bool // insert missing rows only (global rows shared with other apps)
}

var tables = []table{
	{name: "apps", where: "app = $1"},
	{name: "principals", merge: true, where: `subject IN (SELECT subject FROM app_members WHERE app = $1
		UNION SELECT subject FROM app_clients WHERE app = $1 UNION SELECT subject FROM team_members WHERE app = $1
		UNION SELECT subject FROM resource_grants WHERE app = $1 AND subject IS NOT NULL)`},
	{name: "app_members", where: "app = $1"},
	{name: "app_clients", where: "app = $1"},
	{name: "teams", where: "app = $1"},
	{name: "team_members", where: "app = $1"},
	{name: "data_keys", where: "app = $1", order: "created_at, id"},
	{name: "collections", where: "app = $1", order: "name"},
	{name: "collection_versions", where: "app = $1", order: "collection, version"},
	{name: "records", where: "app = $1", order: "id"},
	{name: "record_revisions", where: "app = $1", order: "record_id, version"},
	{name: "record_index", where: "app = $1"},
	{name: "record_unique", where: "app = $1"},
	{name: "blobs", where: "app = $1", order: "id"},
	{name: "blob_parts", where: "app = $1", order: "blob_id, part_number"},
	{name: "resource_grants", where: "app = $1"},
	{name: "app_quotas", where: "app = $1"},
	{name: "collection_migrations", where: "app = $1"},
	{name: "audit_heads", where: "app = $1", order: "chain"},
	{name: "audit_events", where: "chain IN (SELECT chain FROM audit_heads WHERE app = $1)", order: "chain, seq"},
}

// Format 1 deliberately omitted transient state. Sealed format 2 also preserves durable
// idempotency outcomes and unfinished outside effects. Outbox IDs are target-local identities.
func formatTables(version int) []table {
	if version == 1 {
		return tables
	}
	out := append([]table(nil), tables...)
	return append(out, table{name: "operation_receipts", where: "app=$1", order: "subject,actor,op_id"}, table{name: "outbox", where: "app=$1 AND status<>'done'", order: "id"})
}

type TableEntry struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	Rows      int64  `json:"rows"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes,omitempty"`
	SealedKey []byte `json:"sealed_key,omitempty"`
}

type ObjectEntry struct {
	Key    string `json:"key"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Format        string       `json:"format"`
	FormatVersion int          `json:"format_version"`
	App           string       `json:"app"`
	CreatedAt     time.Time    `json:"created_at"`
	CreatedBy     string       `json:"created_by"`
	Build         string       `json:"build"`
	SchemaVersion int          `json:"schema_version"`
	Source        Source       `json:"source"`
	SnapshotAt    time.Time    `json:"snapshot_at"`
	Tables        []TableEntry `json:"tables"`
	Objects       struct {
		File   string `json:"file"`
		Count  int64  `json:"count"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"objects"`
	KEKs        []string          `json:"kek_ids"`
	Notes       string            `json:"notes"`
	Encryption  *ExportEncryption `json:"encryption,omitempty"`
	rawManifest []byte
}

type Source struct {
	Database         string                 `json:"database"`
	Schema           string                 `json:"schema"`
	SystemIdentifier string                 `json:"system_identifier,omitempty"`
	Objects          *store.ObjectNamespace `json:"objects,omitempty"`
}

func identity(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (Source, error) {
	var s Source
	if err := q.QueryRow(ctx, `SELECT current_database(), current_schema()`).Scan(&s.Database, &s.Schema); err != nil {
		return s, err
	}
	var id int64
	if err := q.QueryRow(ctx, `SELECT system_identifier FROM pg_control_system()`).Scan(&id); err != nil {
		return s, fmt.Errorf("database identity unavailable: %w", err)
	}
	s.SystemIdentifier = fmt.Sprint(id)
	return s, nil
}

// ownerTx runs fn in one transaction as strongbox_owner. Read-only exports use REPEATABLE READ, so
// every table comes from the same snapshot.
func ownerTx(ctx context.Context, pool *pgxpool.Pool, opts pgx.TxOptions, fn func(pgx.Tx) error) error {
	return pgx.BeginTxFunc(ctx, pool, opts, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+store.OwnerRole); err != nil {
			return err
		}
		return fn(tx)
	})
}

type hashingFile struct {
	f      *os.File
	w      *bufio.Writer
	h      io.Writer
	sum    func() string
	rows   int64
	sealed *crypto.StreamEncryptor
}

func create(path string) (*hashingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	return &hashingFile{f: f, w: bufio.NewWriter(io.MultiWriter(f, h)), h: h, sum: func() string { return hex.EncodeToString(h.Sum(nil)) }}, nil
}

func (h *hashingFile) write(p []byte) error {
	for len(p) > 0 {
		n := min(len(p), 64<<10)
		piece := p[:n]
		p = p[n:]
		if h.sealed != nil {
			var err error
			piece, err = h.sealed.Update(piece)
			if err != nil {
				return err
			}
		}
		if _, err := h.w.Write(piece); err != nil {
			return err
		}
	}
	return nil
}
func (h *hashingFile) line(b []byte) error {
	h.rows++
	if err := h.write(b); err != nil {
		return err
	}
	return h.write([]byte{'\n'})
}

func (h *hashingFile) close() error {
	if h.sealed != nil {
		tail, err := h.sealed.Finalize()
		if err == nil {
			_, err = h.w.Write(tail)
		}
		if err != nil {
			_ = h.f.Close()
			return err
		}
	}
	if err := h.w.Flush(); err != nil {
		_ = h.f.Close()
		return err
	}
	if err := h.f.Sync(); err != nil {
		_ = h.f.Close()
		return err
	}
	return h.f.Close()
}

// Export writes app to dir (which must not exist or be empty). A key provider selects sealed
// format 2 and supports every collection. Omitting it preserves the legacy format-1 writer for
// compatibility tests; that path refuses plaintext-bearing apps. The CLI always supplies KMS.
func Export(ctx context.Context, pool *pgxpool.Pool, backend store.Backend, app, dir, actor, build string, providers ...crypto.KeyProvider) (*Manifest, error) {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty", dir)
	}
	if len(providers) > 1 {
		return nil, errors.New("one export key provider is required")
	}
	format := 1
	var key []byte
	if len(providers) == 1 {
		if providers[0] == nil {
			return nil, errors.New("export key provider is nil")
		}
		format = FormatVersion
		key = crypto.NewDataKey()
		defer clear(key)
	}
	m := &Manifest{Format: Format, FormatVersion: format, App: app, CreatedAt: time.Now().UTC(), CreatedBy: actor, Build: build,
		Notes: "Ciphertext only. Readable with access to the KMS keys listed in kek_ids and only under this app's identity."}
	if format == 2 {
		m.Notes = "Encrypted table streams and encrypted objects. Manifest/inventory expose operational metadata only. Offline validation checks transport integrity; restore authenticates the manifest and every table."
		m.Encryption = &ExportEncryption{ID: store.NewID("ex")}
		wrapped, err := providers[0].Wrap(ctx, key, exportAAD(m, "key"))
		if err != nil {
			return nil, err
		}
		m.Encryption.KEKID = wrapped.KEKID
		m.Encryption.WrappedKey = wrapped.Ciphertext
	}
	var objects []ObjectEntry
	source, err := identity(ctx, pool)
	if err != nil {
		return nil, err
	}
	err = ownerTx(ctx, pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM apps WHERE app = $1)`, app).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("app %s not found", app)
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&m.SchemaVersion); err != nil {
			return err
		}
		m.Source = source
		if format == 2 {
			namespace, err := store.Namespace(backend)
			if err != nil {
				return err
			}
			m.Source.Objects = &namespace
		}
		if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&m.SnapshotAt); err != nil {
			return err
		}
		// Format 1 preserves database ciphertext; it cannot safely export plaintext collections.
		// Refuse before creating any files, including plaintext historical/index values.
		var plain bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM records WHERE app=$1 AND data_plain IS NOT NULL)
            OR EXISTS(SELECT 1 FROM record_revisions WHERE app=$1 AND data_plain IS NOT NULL)`, app).Scan(&plain); err != nil {
			return err
		}
		if plain && format == 1 {
			return errors.New("format 1 export refuses plaintext record data; use encrypted collections")
		}
		for _, t := range formatTables(m.FormatVersion) {
			expression := `to_jsonb(t)`
			if t.name == "outbox" {
				expression = `jsonb_set(to_jsonb(t)-'id'-'lease_owner'-'lease_expires','{status}',to_jsonb(CASE WHEN status='leased' THEN 'pending' ELSE status END))`
			}
			q := `SELECT ` + expression + ` FROM ` + t.name + ` t WHERE ` + t.where
			if t.order != "" {
				q += ` ORDER BY ` + t.order
			}
			rows, err := tx.Query(ctx, q, app)
			if err != nil {
				return fmt.Errorf("%s: %w", t.name, err)
			}
			file := tableFile(m.FormatVersion, t.name)
			out, err := create(filepath.Join(dir, file))
			if err != nil {
				rows.Close()
				return err
			}
			defer out.f.Close() // bounded by the fixed table inventory; covers early query/encryption errors
			entry := TableEntry{Name: t.name, File: file}
			if format == 2 {
				fileKey := crypto.NewDataKey()
				entry.SealedKey, err = crypto.Seal(key, fileKey, exportAAD(m, "file-key/"+file))
				if err == nil {
					out.sealed, err = crypto.NewStreamEncryptor(fileKey, exportAAD(m, file), 64<<10)
				}
				clear(fileKey)
				if err == nil {
					_, err = out.w.Write(out.sealed.Header())
				}
				if err != nil {
					rows.Close()
					_ = out.f.Close()
					return err
				}
			}
			for rows.Next() {
				var raw json.RawMessage
				if err := rows.Scan(&raw); err != nil {
					rows.Close()
					return err
				}
				if err := out.line(raw); err != nil {
					rows.Close()
					return err
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("%s: %w", t.name, err)
			}
			if err := out.close(); err != nil {
				return err
			}
			entry.Rows, entry.SHA256 = out.rows, out.sum()
			if format == 2 {
				st, err := os.Stat(filepath.Join(dir, file))
				if err != nil {
					return err
				}
				entry.Bytes = st.Size()
			}
			m.Tables = append(m.Tables, entry)
		}
		// Objects of every blob that still has them: single objects and parts.
		rows, err := tx.Query(ctx, `SELECT storage_key,state='active' AS required FROM blobs WHERE app = $1 AND layout = 'single' AND state IN ('active', 'deleted', 'shredded')
			UNION ALL SELECT p.storage_key,b.state IN ('active','pending') FROM blob_parts p JOIN blobs b ON b.app = p.app AND b.id = p.blob_id
			WHERE p.app = $1 AND b.state IN ('pending', 'active', 'deleted', 'shredded') ORDER BY 1`, app)
		if err != nil {
			return err
		}
		type objectRef struct {
			key      string
			required bool
		}
		keys, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (objectRef, error) { var o objectRef; return o, r.Scan(&o.key, &o.required) })
		if err != nil {
			return err
		}
		for _, ref := range keys {
			key := ref.key
			o, err := copyOut(ctx, backend, key, dir)
			if errors.Is(err, os.ErrNotExist) && !ref.required {
				continue // deleted or shredded and already purged from the store
			}
			if err != nil {
				return fmt.Errorf("object %s: %w", key, err)
			}
			objects = append(objects, o)
		}
		rows, err = tx.Query(ctx, `SELECT DISTINCT kek_id FROM data_keys WHERE app = $1 UNION SELECT DISTINCT kek_id FROM blobs WHERE app = $1 ORDER BY 1`, app)
		if err != nil {
			return err
		}
		m.KEKs, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		return nil, err
	}
	out, err := create(filepath.Join(dir, "objects.ndjson"))
	if err != nil {
		return nil, err
	}
	for _, o := range objects {
		b, _ := json.Marshal(o)
		if err := out.line(b); err != nil {
			return nil, err
		}
		m.Objects.Bytes += o.Bytes
	}
	if err := out.close(); err != nil {
		return nil, err
	}
	m.Objects.File, m.Objects.Count, m.Objects.SHA256 = "objects.ndjson", out.rows, out.sum()
	if format == 2 {
		m.KEKs = append(m.KEKs, m.Encryption.KEKID)
		slices.Sort(m.KEKs)
		m.KEKs = slices.Compact(m.KEKs)
		aad, err := manifestAAD(m)
		if err != nil {
			return nil, err
		}
		m.Encryption.Auth, err = crypto.Seal(key, nil, aad)
		if err != nil {
			return nil, err
		}
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	return m, os.WriteFile(filepath.Join(dir, "manifest.json"), append(raw, '\n'), 0o600)
}

func objectPath(dir, key string) (string, error) {
	clean := filepath.Clean(key)
	if !filepath.IsLocal(key) || filepath.ToSlash(clean) != key || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("object key %q escapes the export", key)
	}
	return filepath.Join(dir, "objects", clean), nil
}

func copyOut(ctx context.Context, backend store.Backend, key, dir string) (ObjectEntry, error) {
	src, err := backend.Read(ctx, key)
	if err != nil {
		if errs.Is(err, "not_found") {
			return ObjectEntry{}, os.ErrNotExist // validation reports it if an active blob needed it
		}
		return ObjectEntry{}, err
	}
	defer src.Close()
	path, err := objectPath(dir, key)
	if err != nil {
		return ObjectEntry{}, err
	}
	out, err := create(path)
	if err != nil {
		return ObjectEntry{}, err
	}
	defer out.f.Close()
	n, err := io.Copy(out.w, src)
	if err == nil {
		err = out.close()
	}
	if err != nil {
		return ObjectEntry{}, err
	}
	return ObjectEntry{Key: key, Bytes: n, SHA256: out.sum()}, nil
}

// ---- validation ------------------------------------------------------------------------------------

type Report struct {
	App           string   `json:"app"`
	Tables        int      `json:"tables"`
	Rows          int64    `json:"rows"`
	Objects       int64    `json:"objects"`
	Bytes         int64    `json:"bytes"`
	Problems      []string `json:"problems"`
	Level         string   `json:"level"`
	Authenticated bool     `json:"authenticated"`
}

func (r *Report) OK() bool { return len(r.Problems) == 0 }

func (r *Report) addf(f string, a ...any) {
	if len(r.Problems) < 200 {
		r.Problems = append(r.Problems, fmt.Sprintf(f, a...))
	}
}

func digestFile(path string) (string, int64, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()
	h := sha256.New()
	var lines int64
	r := bufio.NewReader(io.TeeReader(f, h))
	var size int64
	for {
		b, err := r.ReadSlice('\n')
		size += int64(len(b))
		if len(b) > 0 && b[len(b)-1] == '\n' {
			lines++
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", 0, 0, err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), lines, size, nil
}

func readManifest(dir string) (*Manifest, error) {
	f, err := os.Open(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	_ = f.Close()
	if len(raw) > 1<<20 {
		return nil, errors.New("manifest exceeds 1 MiB")
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if _, err := decodeRow(raw); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Format != Format {
		return nil, fmt.Errorf("not a Strongbox export (format %q)", m.Format)
	}
	if m.FormatVersion != 1 && m.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("export format_version %d is not supported by this build (supports %d)", m.FormatVersion, FormatVersion)
	}
	if m.FormatVersion == 2 && (m.Encryption == nil || !exportIDPattern.MatchString(m.Encryption.ID) || len(m.Encryption.WrappedKey) == 0 || len(m.Encryption.Auth) == 0) {
		return nil, errors.New("missing or invalid export encryption metadata")
	}
	if m.FormatVersion == 1 && m.Encryption != nil {
		return nil, errors.New("mixed export format versions")
	}
	m.rawManifest = raw
	return &m, nil
}

func eachLine(path string, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return scanLines(f, fn)
}
func scanLines(src io.Reader, fn func([]byte) error) error {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Validate checks an export without a database: manifest, every file's digest and row count, every
// object's digest, and that every blob's objects are present and match the digests recorded in
// its rows.
func Validate(dir string) (*Manifest, *Report, error) {
	m, err := readManifest(dir)
	if err != nil {
		return nil, nil, err
	}
	if m.FormatVersion == 2 {
		return validateTransport(dir, m)
	}
	rep, err := validateContent(dir, m, tableReader(dir, m, nil))
	return m, rep, err
}

type readTable func(name string, fn func([]byte) error) error

func validateContent(dir string, m *Manifest, read readTable) (*Report, error) {
	var err error
	rep := &Report{App: m.App, Level: "structural", Authenticated: m.FormatVersion == 2}
	if rep.Authenticated {
		rep.Level = "authenticated"
	}
	if !store.ValidApp(m.App) {
		rep.addf("invalid app identity")
	}
	known := map[string]bool{}
	for _, t := range formatTables(m.FormatVersion) {
		known[t.name] = true
	}
	seen := map[string]bool{}
	referenced := map[string]bool{}
	type attachmentRef struct{ id, owner string }
	links := map[attachmentRef]struct{}{}
	for _, t := range m.Tables {
		if !known[t.Name] {
			rep.addf("table %s is not part of format_version %d", t.Name, FormatVersion)
			continue
		}
		if seen[t.Name] || t.File != tableFile(m.FormatVersion, t.Name) {
			rep.addf("duplicate table or noncanonical file for %s", t.Name)
			continue
		}
		seen[t.Name] = true
		sum, rows, _, err := digestFile(filepath.Join(dir, t.File))
		switch {
		case err != nil:
			rep.addf("%s: %v", t.File, err)
		case sum != t.SHA256:
			rep.addf("%s: digest mismatch", t.File)
		case m.FormatVersion == 1 && rows != t.Rows:
			rep.addf("%s: %d rows, manifest says %d", t.File, rows, t.Rows)
		}
		rep.Tables++
		rep.Rows += t.Rows
		var count int64
		if err := read(t.Name, func(raw []byte) error {
			count++
			if err := rowScope(t.Name, m.App, raw); err != nil {
				return err
			}
			if t.Name == "records" {
				var rec struct {
					Attachment *string    `json:"attachment_id"`
					Owner      string     `json:"owner"`
					Deleted    *time.Time `json:"deleted_at"`
				}
				if err := json.Unmarshal(raw, &rec); err != nil {
					return err
				}
				if rec.Attachment != nil {
					if rec.Deleted != nil {
						return errors.New("deleted record has an active attachment")
					}
					links[attachmentRef{*rec.Attachment, rec.Owner}] = struct{}{}
				}
			}
			if t.Name == "blobs" || t.Name == "blob_parts" {
				row, _ := decodeRow(raw)
				referenced[stringColumn(row, "storage_key")] = true
			}
			return nil
		}); err != nil {
			rep.addf("%s: %v", t.File, err)
		}
		if count != t.Rows {
			rep.addf("%s: decrypted row count mismatch", t.File)
		}
	}
	for _, t := range formatTables(m.FormatVersion) {
		if !seen[t.name] {
			rep.addf("missing table %s", t.name)
		}
	}
	if m.Objects.File != "objects.ndjson" {
		rep.addf("noncanonical object inventory file")
		return rep, nil
	}
	sum, _, _, err := digestFile(filepath.Join(dir, m.Objects.File))
	if err != nil || sum != m.Objects.SHA256 {
		rep.addf("%s: missing or digest mismatch", m.Objects.File)
		return rep, nil
	}
	objects := map[string]ObjectEntry{}
	err = eachLine(filepath.Join(dir, m.Objects.File), func(b []byte) error {
		var o ObjectEntry
		if err := json.Unmarshal(b, &o); err != nil {
			return err
		}
		if !referenced[o.Key] {
			rep.addf("object %s is not referenced by this app", o.Key)
			return nil
		}
		if _, exists := objects[o.Key]; exists {
			rep.addf("duplicate object %s", o.Key)
			return nil
		}
		path, err := objectPath(dir, o.Key)
		if err != nil {
			rep.addf("%v", err)
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			rep.addf("object %s: missing", o.Key)
			return nil
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		_ = f.Close()
		if err != nil || n != o.Bytes || hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
			rep.addf("object %s: size or digest mismatch", o.Key)
		}
		objects[o.Key] = o
		rep.Objects++
		rep.Bytes += n
		return nil
	})
	if err != nil {
		return rep, err
	}
	if rep.Objects != m.Objects.Count || rep.Bytes != m.Objects.Bytes {
		rep.addf("object inventory count/bytes do not match manifest")
	}
	// Cross-check blob rows against objects.
	type part struct {
		BlobID      string `json:"blob_id"`
		Key         string `json:"storage_key"`
		SHA         string `json:"ciphertext_sha256"`
		Number      int    `json:"part_number"`
		Size        int64  `json:"size_bytes"`
		CipherBytes int64  `json:"cipher_bytes"`
	}
	parts := map[string][]part{}
	if err := read("blob_parts", func(b []byte) error {
		var p part
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		parts[p.BlobID] = append(parts[p.BlobID], p)
		return nil
	}); err != nil {
		return rep, err
	}
	err = read("blobs", func(b []byte) error {
		var bl struct {
			Owner    string  `json:"owner"`
			ID       string  `json:"id"`
			App      string  `json:"app"`
			State    string  `json:"state"`
			Layout   string  `json:"layout"`
			Key      string  `json:"storage_key"`
			SHA      *string `json:"ciphertext_sha256"`
			Declared int64   `json:"declared_size"`
			PartSize int64   `json:"part_size"`
		}
		if err := json.Unmarshal(b, &bl); err != nil {
			return err
		}
		if bl.App != m.App {
			rep.addf("blob %s belongs to %s, not %s", bl.ID, bl.App, m.App)
		}
		if bl.State != "active" && bl.State != "pending" {
			return nil
		}
		if bl.State == "active" && bl.App == m.App {
			delete(links, attachmentRef{bl.ID, bl.Owner})
		}
		if bl.Layout == "parts" {
			if bl.PartSize <= 0 || bl.Declared < 0 {
				rep.addf("blob %s: invalid multipart size", bl.ID)
				return nil
			}
			count := max(int64(1), (bl.Declared+bl.PartSize-1)/bl.PartSize)
			pp := parts[bl.ID]
			slices.SortFunc(pp, func(a, b part) int { return a.Number - b.Number })
			if bl.State == "active" && int64(len(pp)) != count {
				rep.addf("blob %s: incomplete part list", bl.ID)
			}
			aggregate := sha256.New()
			seen := map[int]bool{}
			for i, p := range pp {
				want := bl.PartSize
				if int64(p.Number) == count {
					want = bl.Declared - int64(p.Number-1)*bl.PartSize
				}
				if p.Number < 1 || int64(p.Number) > count || seen[p.Number] || p.Size != want || bl.State == "active" && p.Number != i+1 {
					rep.addf("blob %s: invalid part number or size", bl.ID)
				}
				seen[p.Number] = true
				digest, e := hex.DecodeString(p.SHA)
				if e != nil || len(digest) != sha256.Size {
					rep.addf("blob %s: invalid part digest", bl.ID)
				}
				aggregate.Write(digest)
				if o, ok := objects[p.Key]; !ok || o.SHA256 != p.SHA || o.Bytes != p.CipherBytes {
					rep.addf("blob %s: part %s missing or does not match its digest/size", bl.ID, p.Key)
				}
			}
			if bl.State == "active" && (bl.SHA == nil || hex.EncodeToString(aggregate.Sum(nil)) != *bl.SHA) {
				rep.addf("blob %s: part-list digest mismatch", bl.ID)
			}
			return nil
		}
		if bl.State == "pending" {
			return nil
		}

		if o, ok := objects[bl.Key]; !ok || bl.SHA == nil || o.SHA256 != *bl.SHA {
			rep.addf("blob %s: object missing or does not match its digest", bl.ID)
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	if len(links) > 0 {
		rep.addf("%d live attachment references have no matching active blob and owner", len(links))
	}
	return rep, nil
}

// ---- restore ---------------------------------------------------------------------------------------

type RestoreReport struct {
	App      string           `json:"app"`
	DryRun   bool             `json:"dry_run"`
	Rows     map[string]int64 `json:"rows"`
	Objects  int64            `json:"objects"`
	Problems []string         `json:"problems,omitempty"`
}

// Restore loads an export into the target database (pool: its migration login) and object store.
// The target must be a different database from the export's source, migrated to the current
// schema, and must not already contain the app. With dryRun, every row is inserted and every
// constraint checked inside a transaction that is then rolled back, and no object is written.
func Restore(ctx context.Context, pool *pgxpool.Pool, backend store.Backend, dir string, dryRun bool, providers ...crypto.KeyProvider) (*RestoreReport, error) {
	m, rep, err := Validate(dir)
	if err != nil {
		return nil, err
	}
	var key []byte
	if m.FormatVersion == 2 && rep.OK() {
		if len(providers) != 1 || providers[0] == nil {
			return nil, errors.New("sealed restore requires one key provider")
		}
		key, err = unlock(ctx, m, providers[0])
		if err != nil {
			return nil, err
		}
		defer clear(key)
		rep, err = validateContent(dir, m, tableReader(dir, m, key))
		if err != nil {
			return nil, err
		}
	}
	read := tableReader(dir, m, key)
	out := &RestoreReport{App: m.App, DryRun: dryRun, Rows: map[string]int64{}}
	if !rep.OK() {
		out.Problems = rep.Problems
		return out, errors.New("export failed validation; nothing restored")
	}
	applied, embedded, err := store.MigrationVersion(ctx, pool)
	if err != nil {
		return nil, err
	}
	if applied != embedded {
		return nil, fmt.Errorf("target schema is at version %d; run `strongbox init` (version %d) first", applied, embedded)
	}
	if m.SchemaVersion > applied {
		return nil, fmt.Errorf("export is from schema version %d, newer than this target (%d)", m.SchemaVersion, applied)
	}
	target, err := identity(ctx, pool)
	if err != nil {
		return nil, err
	}
	if m.Source.SystemIdentifier == "" || m.Source.Database == "" {
		return nil, errors.New("export has no stable source database identity")
	}
	if target.SystemIdentifier == m.Source.SystemIdentifier && target.Database == m.Source.Database {
		return nil, errors.New("the target is the export's source database; restore only into a separate database")
	}

	if m.FormatVersion == 2 {
		namespace, err := store.Namespace(backend)
		if err != nil {
			return nil, err
		}
		if m.Source.Objects == nil {
			return nil, errors.New("sealed export has no source storage namespace")
		}
		if m.Source.Objects.Overlaps(namespace) {
			return nil, errors.New("target object storage overlaps the source; use a separate bucket/prefix or directory")
		}
	}

	errRollback := errors.New("dry run")
	err = ownerTx(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM apps WHERE app = $1)`, m.App).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("the target already has app %s; restore only into a database without it", m.App)
		}
		// The registry is global security policy. An app backup must not introduce
		// new clearances or platform administrators into a populated installation.
		// A genuinely empty recovery target may recover its original registry.
		var populated bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM principals)
			OR EXISTS (SELECT 1 FROM apps WHERE app <> '_legacy')`).Scan(&populated); err != nil {
			return err
		}
		if populated {
			if err := read("principals", func(raw []byte) error {
				row, err := decodeRow(raw)
				if err != nil {
					return err
				}
				var exists bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM principals WHERE subject=$1)`,
					stringColumn(row, "subject")).Scan(&exists); err != nil {
					return err
				}
				if !exists {
					return errors.New("shared target requires every source principal to be pre-provisioned by its operator")
				}
				return nil
			}); err != nil {
				return err
			}
		}
		byName := map[string]TableEntry{}
		for _, t := range m.Tables {
			byName[t.Name] = t
		}
		for _, t := range formatTables(m.FormatVersion) {
			e, ok := byName[t.name]
			if !ok {
				continue
			}
			n, err := load(ctx, tx, t, m.App, func(fn func([]byte) error) error { return read(e.Name, fn) })
			if err != nil {
				return fmt.Errorf("%s: %w", t.name, err)
			}
			out.Rows[t.name] = n
		}
		// Surface deferred foreign-key violations here rather than at COMMIT.
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
			return err
		}
		if !dryRun {
			// The app and every row have passed validation. Objects are copied before
			// COMMIT, so readers never see rows pointing at objects not yet copied.
			err := eachLine(filepath.Join(dir, m.Objects.File), func(b []byte) error {
				var o ObjectEntry
				if err := json.Unmarshal(b, &o); err != nil {
					return err
				}
				path, err := objectPath(dir, o.Key)
				if err != nil {
					return err
				}
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()
				w, err := backend.OpenWriter(ctx, o.Key)
				if err != nil {
					return err
				}
				h := sha256.New()
				n, err := io.Copy(io.MultiWriter(w, h), f)
				if err != nil || n != o.Bytes || hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
					_ = w.Abort()
					if err != nil {
						return err
					}
					return errors.New("object changed during restore")
				}
				out.Objects++
				return w.Commit()
			})
			if err != nil {
				return fmt.Errorf("copying objects: %w", err)
			}
		}

		if dryRun {
			return errRollback
		}
		return nil
	})
	if errors.Is(err, errRollback) {
		err = nil
	}
	return out, err
}

func columns(ctx context.Context, tx pgx.Tx, table string) (map[string]bool, error) {
	rows, err := tx.Query(ctx, `SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1`, table)
	if err != nil {
		return nil, err
	}
	cols, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := map[string]bool{}
	for _, c := range cols {
		out[c] = true
	}
	return out, err
}

// load inserts a table file in batches. Columns missing from the export (an older schema) take
// their defaults; a column the target lacks (a newer schema) is an error.
func load(ctx context.Context, tx pgx.Tx, t table, app string, read func(func([]byte) error) error) (int64, error) {
	have, err := columns(ctx, tx, t.name)
	if err != nil {
		return 0, err
	}
	var batch []json.RawMessage
	var cols []string
	var n int64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		quoted := make([]string, len(cols))
		for i, c := range cols {
			quoted[i] = pgx.Identifier{c}.Sanitize()
		}
		list := strings.Join(quoted, ", ")
		q := `INSERT INTO ` + pgx.Identifier{t.name}.Sanitize() + ` (` + list + `) SELECT ` + list +
			` FROM jsonb_populate_recordset(NULL::` + pgx.Identifier{t.name}.Sanitize() + `, $1)`
		if t.merge {
			q += ` ON CONFLICT DO NOTHING`
		}
		arr, _ := json.Marshal(batch)
		tag, err := tx.Exec(ctx, q, string(arr))
		n += tag.RowsAffected()
		batch = batch[:0]
		return err
	}
	batchBytes := 0
	err = read(func(b []byte) error {
		if err := rowScope(t.name, app, b); err != nil {
			return err
		}
		row, err := decodeRow(b)
		if err != nil {
			return err
		}
		for c := range row {
			if !have[c] {
				return fmt.Errorf("export has column %s that this schema lacks; upgrade the target", c)
			}
		}
		if cols != nil {
			if len(row) != len(cols) {
				return errors.New("inconsistent row columns")
			}
			for _, c := range cols {
				if _, ok := row[c]; !ok {
					return errors.New("inconsistent row columns")
				}
			}
		}
		if cols == nil {
			var row map[string]json.RawMessage
			if err := json.Unmarshal(b, &row); err != nil {
				return err
			}
			for c := range row {
				if !have[c] {
					return fmt.Errorf("export has column %s that this schema lacks; upgrade the target", c)
				}
				cols = append(cols, c)
			}
			slices.Sort(cols)
		}
		batch = append(batch, append(json.RawMessage(nil), b...))
		batchBytes += len(b)
		if len(batch) == 500 || batchBytes >= 8<<20 {
			batchBytes = 0
			return flush()
		}
		return nil
	})
	if err != nil {
		return n, err
	}
	return n, flush()
}
