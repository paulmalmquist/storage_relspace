// Package service holds the domain services. Every path into stored data goes through them, so
// policy and audit cannot be skipped by the API or the MCP server.
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
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Data keys for small values (records, sealed blob metadata) and blind indexes.
//
// Blobs get a fresh data key per object. Small values would cost one KMS round trip each that way, so
// they use per-scope data keys instead: wrapped by the KEK, stored in data_keys, unwrapped on demand,
// cached in memory for a short TTL, and rotated on a schedule. Old keys stay available for decryption.
// Blind-index keys never rotate, because tokens must stay comparable.

const (
	PurposeData  = "data"
	PurposeIndex = "index"
)

func wrapAAD(id, scope, purpose string) []byte {
	return []byte(fmt.Sprintf("strongbox/datakey/v1|%s|%s|%s", id, scope, purpose))
}

type cachedKey struct {
	key     []byte
	scope   string
	expires time.Time
}

type Keys struct {
	db       *pgxpool.Pool
	kms      crypto.KeyProvider
	Rotation time.Duration
	ttl      time.Duration
	mu       sync.Mutex
	cache    map[string]cachedKey
}

func NewKeys(db *pgxpool.Pool, kms crypto.KeyProvider, rotation, ttl time.Duration) *Keys {
	return &Keys{db: db, kms: kms, Rotation: rotation, ttl: ttl, cache: map[string]cachedKey{}}
}

// Active returns the current key for a scope, creating or rotating it as needed.
func (k *Keys) Active(ctx context.Context, scope, purpose string) (string, []byte, error) {
	var id string
	var created time.Time
	err := k.db.QueryRow(ctx, `SELECT id, created_at FROM data_keys WHERE scope = $1 AND purpose = $2
		AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1`, scope, purpose).Scan(&id, &created)
	switch {
	case err == nil && (purpose == PurposeIndex || time.Since(created) < k.Rotation):
		key, err := k.Key(ctx, id, scope)
		return id, key, err
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return "", nil, err
	}
	return k.create(ctx, scope, purpose)
}

func (k *Keys) create(ctx context.Context, scope, purpose string) (string, []byte, error) {
	id := store.NewID("dk")
	dek := crypto.NewDataKey()
	w, err := k.kms.Wrap(ctx, dek, wrapAAD(id, scope, purpose))
	if err != nil {
		return "", nil, err
	}
	if _, err := k.db.Exec(ctx, `INSERT INTO data_keys (id, scope, purpose, kek_id, wrapped_key) VALUES ($1,$2,$3,$4,$5)`,
		id, scope, purpose, w.KEKID, w.Ciphertext); err != nil {
		return "", nil, err
	}
	k.remember(id, scope, dek)
	return id, dek, nil
}

// Key returns an unwrapped key, verifying it belongs to expectedScope.
func (k *Keys) Key(ctx context.Context, id, expectedScope string) ([]byte, error) {
	k.mu.Lock()
	hit, ok := k.cache[id]
	k.mu.Unlock()
	if ok && time.Now().Before(hit.expires) {
		if hit.scope != expectedScope {
			return nil, errs.Integrity("data key belongs to a different scope")
		}
		return hit.key, nil
	}
	var scope, purpose, kekID string
	var wrapped []byte
	err := k.db.QueryRow(ctx, `SELECT scope, purpose, kek_id, wrapped_key FROM data_keys WHERE id = $1`, id).
		Scan(&scope, &purpose, &kekID, &wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.Integrity("data key %s not found", id)
	}
	if err != nil {
		return nil, err
	}
	if scope != expectedScope {
		return nil, errs.Integrity("data key belongs to a different scope")
	}
	dek, err := k.kms.Unwrap(ctx, crypto.WrappedKey{KEKID: kekID, Ciphertext: wrapped}, wrapAAD(id, scope, purpose))
	if err != nil {
		return nil, err
	}
	k.remember(id, scope, dek)
	return dek, nil
}

func (k *Keys) remember(id, scope string, key []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cache[id] = cachedKey{key: key, scope: scope, expires: time.Now().Add(k.ttl)}
}

func (k *Keys) ClearCache() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cache = map[string]cachedKey{}
}

// Sealer seals JSON values under a scope's active data key.
type Sealer struct{ keys *Keys }

func (s Sealer) SealJSON(ctx context.Context, scope string, aad []byte, v any) (string, []byte, error) {
	id, key, err := s.keys.Active(ctx, scope, PurposeData)
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

func (s Sealer) OpenJSON(ctx context.Context, scope, keyID string, aad, sealed []byte, out any) error {
	key, err := s.keys.Key(ctx, keyID, scope)
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

// BlindToken is an HMAC-SHA-256 token: equality-searchable without revealing the value.
func BlindToken(indexKey []byte, collection, field string, v any) (string, error) {
	c, err := CanonicalScalar(v)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, indexKey)
	m.Write([]byte(collection + "\x1f" + field + "\x1f" + c))
	return "b:" + hex.EncodeToString(m.Sum(nil)), nil
}

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
