package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/cache"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Data keys (DEKs) are per app and scope, wrapped by the KMS key-encryption key. The wrap AAD binds
// app, key id, scope and purpose, so a wrapped key copied to another app or scope will not unwrap.
// Data keys rotate on age; blind-index keys never rotate (tokens must stay comparable) and receipt
// keys never rotate (fingerprints must stay comparable for the receipt's lifetime).

const (
	PurposeData    = "data"
	PurposeIndex   = "index"
	PurposeReceipt = "receipt"
)

// wrapAAD: version 1 is the pre-app-scoping context, kept readable for legacy keys.
func wrapAAD(version int, app, id, scope, purpose string) []byte {
	if version == 1 {
		return []byte(fmt.Sprintf("strongbox/datakey/v1|%s|%s|%s", id, scope, purpose))
	}
	return []byte(fmt.Sprintf("strongbox/datakey/v2|%s|%s|%s|%s", app, id, scope, purpose))
}

type cachedKey struct {
	scope string
	key   []byte
}

// Keys is safe for concurrent use. The cache is bounded and coalesces concurrent misses, so a burst
// of requests for one cold key makes one KMS call.
type Keys struct {
	kms      crypto.KeyProvider
	Rotation time.Duration
	cache    *cache.LRU[cachedKey]
	// OnUnwrap observes KMS unwrap latency and outcome (metrics).
	OnUnwrap func(d time.Duration, err error)
}

func NewKeys(kms crypto.KeyProvider, rotation, ttl time.Duration, maxEntries int) *Keys {
	return &Keys{kms: kms, Rotation: rotation, cache: cache.New[cachedKey](maxEntries, ttl)}
}

// Active returns the current key for (app, scope, purpose), creating or rotating it in tx.
func (k *Keys) Active(ctx context.Context, tx pgx.Tx, app, scope, purpose string) (string, []byte, error) {
	var id string
	var created time.Time
	err := tx.QueryRow(ctx, `SELECT id, created_at FROM data_keys WHERE app = $1 AND scope = $2 AND purpose = $3
		AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1`, app, scope, purpose).Scan(&id, &created)
	switch {
	case err == nil && (purpose != PurposeData || time.Since(created) < k.Rotation):
		key, err := k.Key(ctx, tx, app, id, scope)
		return id, key, err
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return "", nil, err
	}
	return k.create(ctx, tx, app, scope, purpose)
}

func (k *Keys) create(ctx context.Context, tx pgx.Tx, app, scope, purpose string) (string, []byte, error) {
	id := store.NewID("dk")
	dek := crypto.NewDataKey()
	w, err := k.kms.Wrap(ctx, dek, wrapAAD(2, app, id, scope, purpose))
	if err != nil {
		return "", nil, kmsError(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO data_keys (app, id, scope, purpose, kek_id, wrapped_key, aad_version)
		VALUES ($1,$2,$3,$4,$5,$6,2)`, app, id, scope, purpose, w.KEKID, w.Ciphertext); err != nil {
		return "", nil, err
	}
	// Cached only by (app, id): if tx rolls back, nothing will ever reference this id.
	k.cache.Put(app+"\x00"+id, cachedKey{scope: scope, key: dek})
	return id, dek, nil
}

// Key returns an unwrapped key of app, verifying it belongs to expectedScope. The row is read in tx
// (under RLS) on a cache miss.
func (k *Keys) Key(ctx context.Context, tx pgx.Tx, app, id, expectedScope string) ([]byte, error) {
	ck, err := k.cache.GetOrLoad(app+"\x00"+id, func() (cachedKey, error) {
		var scope, purpose, kekID string
		var wrapped []byte
		var version int
		err := tx.QueryRow(ctx, `SELECT scope, purpose, kek_id, wrapped_key, aad_version FROM data_keys
			WHERE app = $1 AND id = $2`, app, id).Scan(&scope, &purpose, &kekID, &wrapped, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return cachedKey{}, errs.Integrity("data key %s not found", id)
		}
		if err != nil {
			return cachedKey{}, err
		}
		start := time.Now()
		dek, err := k.kms.Unwrap(ctx, crypto.WrappedKey{KEKID: kekID, Ciphertext: wrapped}, wrapAAD(version, app, id, scope, purpose))
		if k.OnUnwrap != nil {
			k.OnUnwrap(time.Since(start), err)
		}
		if err != nil {
			return cachedKey{}, kmsError(err)
		}
		return cachedKey{scope: scope, key: dek}, nil
	})
	if err != nil {
		return nil, err
	}
	if ck.scope != expectedScope {
		return nil, errs.Integrity("data key belongs to a different scope")
	}
	return ck.key, nil
}

// kmsError keeps integrity failures (wrong AAD, tampered wrap) distinct from KMS outages, which
// callers may retry.
func kmsError(err error) error {
	if errs.Is(err, "integrity_violation") {
		return err
	}
	if _, ok := errs.As(err); ok {
		return err
	}
	return errs.Unavailable("key management unavailable").Wrap(err)
}

// ClearCache drops unwrapped keys (tests, key-rotation drills).
func (k *Keys) ClearCache() { k.cache.Clear() }

// CacheStats reports cache effectiveness (metrics).
func (k *Keys) CacheStats() (entries int, hits, misses, evictions int64) {
	return k.cache.Len(), k.cache.Hits, k.cache.Misses, k.cache.Evictions
}

// SealJSON seals v under the scope's active data key.
func (k *Keys) SealJSON(ctx context.Context, tx pgx.Tx, app, scope string, aad []byte, v any) (string, []byte, error) {
	id, key, err := k.Active(ctx, tx, app, scope, PurposeData)
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", nil, err
	}
	sealed, err := crypto.Seal(key, raw, aad)
	return id, sealed, err
}

// OpenJSON opens a value sealed by SealJSON.
func (k *Keys) OpenJSON(ctx context.Context, tx pgx.Tx, app, scope, keyID string, aad, sealed []byte, out any) error {
	key, err := k.Key(ctx, tx, app, keyID, scope)
	if err != nil {
		return err
	}
	raw, err := crypto.Open(key, sealed, aad)
	if err != nil {
		return err
	}
	return decodeJSON(raw, out)
}

// CanonicalScalar renders an indexable value. Numbers are normalized so 4 and 4.0 match.
func CanonicalScalar(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		return strconv.FormatBool(x), nil
	case string:
		b, err := json.Marshal(x)
		return string(b), err
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return strconv.FormatInt(i, 10), nil
		}
		f, err := x.Float64()
		if err != nil {
			return "", err
		}
		return strconv.FormatFloat(f, 'g', -1, 64), nil
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	default:
		return "", errors.New("only scalar values (string, number, boolean, null) can be indexed or filtered")
	}
}

// BlindToken is an HMAC-SHA-256 token: equality-searchable without revealing the value. Version 2
// binds the app as well as collection and field; version 1 tokens (legacy collections) do not.
func BlindToken(indexKey []byte, version int, app, collection, field string, v any) (string, error) {
	c, err := CanonicalScalar(v)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, indexKey)
	if version >= 2 {
		m.Write([]byte(app + "\x1f"))
	}
	m.Write([]byte(collection + "\x1f" + field + "\x1f" + c))
	return "b:" + hex.EncodeToString(m.Sum(nil)), nil
}

// PlainToken indexes UNCONTROLLED values of unencrypted collections.
func PlainToken(v any) (string, error) {
	c, err := CanonicalScalar(v)
	if err != nil {
		return "", err
	}
	if len(c) <= 120 {
		return "p:" + c, nil
	}
	sum := sha256.Sum256([]byte(c))
	return "h:" + hex.EncodeToString(sum[:]), nil
}
