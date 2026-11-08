package service_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

// Drop the server's COMMIT acknowledgement after PostgreSQL has committed. This
// reproduces an ambiguous commit without assuming that an error means rollback.
type reviewDropCommitConn struct {
	net.Conn
	reader  *bufio.Reader
	pending []byte
	armed   *atomic.Bool
}

func (c *reviewDropCommitConn) Read(p []byte) (int, error) {
	if len(c.pending) == 0 {
		var h [5]byte
		if _, err := io.ReadFull(c.reader, h[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint32(h[1:])) - 4
		if n < 0 || n > 16<<20 {
			return 0, errors.New("invalid PostgreSQL message length")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(c.reader, body); err != nil {
			return 0, err
		}
		if h[0] == 'C' && string(body) == "COMMIT\x00" && c.armed.CompareAndSwap(true, false) {
			_ = c.Conn.Close()
			return 0, io.EOF
		}
		c.pending = append(h[:], body...)
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func TestReviewUnknownBlobCommitPreservesCommittedObject(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	cfg, err := pgxpool.ParseConfig(env.RuntimeURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.TLSConfig = nil
	cfg.ConnConfig.Fallbacks = nil
	cfg.ConnConfig.RuntimeParams["search_path"] = env.Schema
	cfg.MaxConns = 1
	var armed atomic.Bool
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &reviewDropCommitConn{Conn: c, reader: bufio.NewReader(c), armed: &armed}, nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	c, err := service.Build(ctx, env.C.Config, service.Overrides{Pool: pool, Backend: env.C.Backend, KMS: env.C.KMS})
	if err != nil {
		t.Fatal(err)
	}
	user := env.Ctx(t, "engineer@rel.test")
	user.OpID = "review-ambiguous-upload"
	body := []byte("committed blob must survive lost commit acknowledgement")
	u, replay, err := c.Blobs.Begin(ctx, user, service.BlobInput{Marking: cuiExpt, DeclaredSize: int64(len(body))})
	if err != nil || replay != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := u.Write(body); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	if _, err := u.Commit(); !errors.Is(err, store.ErrCommitUnknown) {
		t.Fatalf("want unknown commit, got %v", err)
	}
	var state string
	if err := env.Migrator.QueryRow(ctx, `SELECT state FROM blobs WHERE id=$1`, u.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Fatalf("test did not commit the row: %s", state)
	}
	_, got, err := env.C.Blobs.ReadAll(ctx, user, u.ID)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("unknown COMMIT destroyed a committed object's ciphertext: %v, body %q", err, got)
	}
}

type reviewArmBackend struct {
	store.Backend
	armed *atomic.Bool
}
type reviewArmWriter struct {
	store.Writer
	armed *atomic.Bool
}

func (b *reviewArmBackend) OpenWriter(ctx context.Context, key string) (store.Writer, error) {
	w, err := b.Backend.OpenWriter(ctx, key)
	if err != nil {
		return nil, err
	}
	return &reviewArmWriter{Writer: w, armed: b.armed}, nil
}
func (w *reviewArmWriter) Commit() error {
	if err := w.Writer.Commit(); err != nil {
		return err
	}
	w.armed.Store(true)
	return nil
}

func TestReviewUnknownPartCommitPreservesCommittedObject(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	cfg, err := pgxpool.ParseConfig(env.RuntimeURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.TLSConfig = nil
	cfg.ConnConfig.Fallbacks = nil
	cfg.ConnConfig.RuntimeParams["search_path"] = env.Schema
	cfg.MaxConns = 1
	var armed atomic.Bool
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &reviewDropCommitConn{Conn: c, reader: bufio.NewReader(c), armed: &armed}, nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	c, err := service.Build(ctx, env.C.Config, service.Overrides{Pool: pool, KMS: env.C.KMS, Backend: &reviewArmBackend{Backend: env.C.Backend, armed: &armed}})
	if err != nil {
		t.Fatal(err)
	}
	user := env.Ctx(t, "engineer@rel.test")
	body := []byte("committed upload part")
	sess, err := c.Blobs.CreateSession(ctx, user, service.BlobInput{Marking: cuiExpt, DeclaredSize: int64(len(body))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Blobs.PutPart(ctx, user, sess.ID, 1, bytes.NewReader(body)); !errors.Is(err, store.ErrCommitUnknown) {
		t.Fatalf("want unknown commit, got %v", err)
	}
	var count int
	if err := env.Migrator.QueryRow(ctx, `SELECT count(*) FROM blob_parts WHERE blob_id=$1`, sess.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("test did not commit part: %d", count)
	}
	if _, err := env.C.Blobs.CompleteSession(ctx, user, sess.ID); err != nil {
		t.Fatal(err)
	}
	_, got, err := env.C.Blobs.ReadAll(ctx, user, sess.ID)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("unknown COMMIT destroyed a referenced part: %v, body %q", err, got)
	}
}
