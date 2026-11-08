package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
)

var ErrInventoryUnsupported = errors.New("backend does not support inventory and conditional deletion")
var ErrObjectChanged = errors.New("object generation changed")

const InventoryPageSize = 200
const OrphanGrace = 24 * time.Hour

type ObjectInfo struct {
	Key     string    `json:"key"`
	Size    int64     `json:"size"`
	Updated time.Time `json:"updated"`
	Version string    `json:"version"`
}

// Inventory is privileged maintenance, deliberately absent from the request Backend interface.
// after is an exclusive keyset cursor. Only a live generation is listed; retained versions are
// governed by the bucket's own retention policy. Deletion never falls back to an unconditional call.
type Inventory interface {
	ListObjects(ctx context.Context, prefix, after string, limit int) ([]ObjectInfo, string, error)
	StatObject(ctx context.Context, key string) (ObjectInfo, error)
	DeleteVersion(ctx context.Context, object ObjectInfo) error
}

func AppObjectPrefix(app string) (string, error) {
	if !ValidApp(app) {
		return "", errors.New("invalid app scope")
	}
	return "apps/" + strings.ReplaceAll(app, ":", "/") + "/", nil
}
func objectPrefix(prefix string) error {
	if !strings.HasSuffix(prefix, "/") || !ValidStorageKey(strings.TrimSuffix(prefix, "/")) {
		return errors.New("invalid inventory prefix")
	}
	return nil
}
func pageLimit(n int) (int, error) {
	if n < 1 || n > InventoryPageSize {
		return 0, errors.New("inventory page size must be 1-200")
	}
	return n, nil
}

// ObjectReferenced protects committed references and every attempt of any pending upload. The
// latter includes ciphertext written before its part row commits, lease takeovers and expired
// sessions awaiting the worker. Purged blobs intentionally no longer retain their object files.
func ObjectReferenced(ctx context.Context, tx pgx.Tx, app, key string) (bool, error) {
	prefix, err := AppObjectPrefix(app)
	if err != nil {
		return false, err
	}
	if !ValidStorageKey(key) || !strings.HasPrefix(key, prefix) {
		return false, errors.New("object outside app scope")
	}
	var yes bool
	blobID, _, _ := strings.Cut(strings.TrimPrefix(key, prefix), "/")
	err = tx.QueryRow(ctx, `SELECT
        EXISTS(SELECT 1 FROM blobs WHERE app=$1 AND state<>'purged' AND storage_key=$2)
        OR EXISTS(SELECT 1 FROM blobs WHERE app=$1 AND id=$3 AND state='pending')
        OR EXISTS(SELECT 1 FROM blob_parts p JOIN blobs b ON b.app=p.app AND b.id=p.blob_id
            WHERE p.app=$1 AND p.storage_key=$2 AND b.state<>'purged')`, app, key, blobID).Scan(&yes)
	return yes, err
}

// localVersion includes inode and change time as well as mtime/size. Production GCS uses provider
// generation/metageneration. Local mutations take a filesystem directory lock across processes.
func localInfo(key string, st fs.FileInfo) (ObjectInfo, error) {
	if !st.Mode().IsRegular() {
		return ObjectInfo{}, errors.New("object is not a regular file")
	}
	stamp := sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%v", st.ModTime().UnixNano(), st.Size(), st.Sys())))
	version := hex.EncodeToString(stamp[:])
	return ObjectInfo{Key: key, Size: st.Size(), Updated: st.ModTime().UTC(), Version: version}, nil
}
func (l *Local) StatObject(ctx context.Context, key string) (ObjectInfo, error) {
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	path, err := l.path(key)
	if err != nil {
		return ObjectInfo{}, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return ObjectInfo{}, err
	}
	return localInfo(key, st)
}
func (l *Local) ListObjects(ctx context.Context, prefix, after string, limit int) ([]ObjectInfo, string, error) {
	if err := objectPrefix(prefix); err != nil {
		return nil, "", err
	}
	if _, err := pageLimit(limit); err != nil {
		return nil, "", err
	}
	if after != "" && (!strings.HasPrefix(after, prefix) || !ValidStorageKey(after)) {
		return nil, "", errors.New("cursor outside inventory prefix")
	}
	root := filepath.Join(l.root, filepath.FromSlash(prefix))
	var out []ObjectInfo
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in inventory scope")
		}
		if d.IsDir() {
			return nil
		}
		key, err := filepath.Rel(l.root, path)
		if err != nil {
			return err
		}
		key = filepath.ToSlash(key)
		if !ValidStorageKey(key) {
			return nil
		} // incomplete .upload-* files are not committed objects
		if key <= after {
			return nil
		}
		st, err := d.Info()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		info, err := localInfo(key, st)
		if err != nil {
			return err
		}
		out = append(out, info)
		// WalkDir is component-ordered, which differs from full-key ordering when
		// names include punctuation. Keep the smallest page across the complete walk.
		if len(out) > limit+1 {
			slices.SortFunc(out, func(a, b ObjectInfo) int { return strings.Compare(a.Key, b.Key) })
			out = out[:limit+1]
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	slices.SortFunc(out, func(a, b ObjectInfo) int { return strings.Compare(a.Key, b.Key) })
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Key
	}
	return out, next, nil
}

func (l *Local) DeleteVersion(ctx context.Context, o ObjectInfo) error {
	if !localConditionsSupported {
		return ErrInventoryUnsupported
	}
	if o.Version == "" {
		return errors.New("conditional deletion requires an object generation")
	}
	path, err := l.path(o.Key)
	if err != nil {
		return err
	}
	err = localLock(ctx, path, func() error {
		current, err := l.StatObject(ctx, o.Key)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != o.Version {
			return ErrObjectChanged
		}
		return os.Remove(path)
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type objectInventory interface {
	listObjects(context.Context, string, string, int) ([]ObjectInfo, string, error)
	statObject(context.Context, string) (ObjectInfo, error)
	deleteVersion(context.Context, ObjectInfo) error
}

func (r *Remote) inventory() (objectInventory, error) {
	i, ok := r.api.(objectInventory)
	if !ok {
		return nil, ErrInventoryUnsupported
	}
	return i, nil
}
func (r *Remote) StatObject(ctx context.Context, key string) (ObjectInfo, error) {
	if err := checkKey(key); err != nil {
		return ObjectInfo{}, err
	}
	i, err := r.inventory()
	if err != nil {
		return ObjectInfo{}, err
	}
	o, err := i.statObject(ctx, r.prefix+key)
	if err == nil {
		o.Key = key
	}
	return o, err
}
func (r *Remote) ListObjects(ctx context.Context, prefix, after string, limit int) ([]ObjectInfo, string, error) {
	if err := objectPrefix(prefix); err != nil {
		return nil, "", err
	}
	if _, err := pageLimit(limit); err != nil {
		return nil, "", err
	}
	if after != "" && (!strings.HasPrefix(after, prefix) || !ValidStorageKey(after)) {
		return nil, "", errors.New("cursor outside inventory prefix")
	}
	i, err := r.inventory()
	if err != nil {
		return nil, "", err
	}
	start := ""
	if after != "" {
		start = r.prefix + after
	}
	objects, next, err := i.listObjects(ctx, r.prefix+prefix, start, limit)
	if err != nil {
		return nil, "", err
	}
	for j := range objects {
		if !strings.HasPrefix(objects[j].Key, r.prefix+prefix) {
			return nil, "", errors.New("provider returned object outside scope")
		}
		objects[j].Key = strings.TrimPrefix(objects[j].Key, r.prefix)
	}
	if next != "" {
		if !strings.HasPrefix(next, r.prefix+prefix) {
			return nil, "", errors.New("provider returned cursor outside scope")
		}
		next = strings.TrimPrefix(next, r.prefix)
	}
	return objects, next, nil
}
func (r *Remote) DeleteVersion(ctx context.Context, o ObjectInfo) error {
	if err := checkKey(o.Key); err != nil {
		return err
	}
	if o.Version == "" {
		return errors.New("conditional deletion requires generation")
	}
	i, err := r.inventory()
	if err != nil {
		return err
	}
	o.Key = r.prefix + o.Key
	return i.deleteVersion(ctx, o)
}
func gcsInfo(o *storage.ObjectAttrs) ObjectInfo {
	return ObjectInfo{Key: o.Name, Size: o.Size, Updated: o.Updated.UTC(), Version: fmt.Sprintf("%d:%d", o.Generation, o.Metageneration)}
}
func (g gcsAPI) statObject(ctx context.Context, key string) (ObjectInfo, error) {
	o, err := g.bucket.Object(key).Attrs(ctx)
	if err != nil {
		return ObjectInfo{}, err
	}
	return gcsInfo(o), nil
}
func (g gcsAPI) listObjects(ctx context.Context, prefix, after string, limit int) ([]ObjectInfo, string, error) {
	it := g.bucket.Objects(ctx, &storage.Query{Prefix: prefix, StartOffset: after})
	var out []ObjectInfo
	for len(out) <= limit {
		o, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, "", err
		}
		if o.Name <= after {
			continue
		}
		out = append(out, gcsInfo(o))
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Key
	}
	return out, next, nil
}
func (g gcsAPI) deleteVersion(ctx context.Context, o ObjectInfo) error {
	generation, meta, ok := strings.Cut(o.Version, ":")
	if !ok {
		return errors.New("invalid GCS generation")
	}
	gen, err := strconv.ParseInt(generation, 10, 64)
	if err != nil || gen <= 0 {
		return errors.New("invalid GCS generation")
	}
	met, err := strconv.ParseInt(meta, 10, 64)
	if err != nil || met <= 0 {
		return errors.New("invalid GCS metageneration")
	}
	err = g.bucket.Object(o.Key).If(storage.Conditions{GenerationMatch: gen, MetagenerationMatch: met}).Delete(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil
	}
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == 412 {
		return ErrObjectChanged
	}
	return err
}
