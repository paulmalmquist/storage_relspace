package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestReviewWorkerRejectsCrossAppObjectDelete(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	other := env.CtxIn(t, testenv.Other, "admin@rel.test")
	body := []byte("the other application's attachment")
	blob := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, other, body, service.BlobInput{Marking: cuiExpt}))
	var key string
	if err := env.Migrator.QueryRow(ctx, `SELECT storage_key FROM blobs WHERE app=$1 AND id=$2`, testenv.Other, blob.ID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	// A valid app transaction can enqueue this malformed payload: the SQL boundary
	// constrains outbox.app, but the worker must independently constrain its effects.
	payload, _ := json.Marshal(map[string]any{"blob_id": blob.ID, "keys": []string{key}})
	err := env.C.DB.Run(ctx, store.Scope{App: testenv.App, Subject: "engineer@rel.test", Actor: "engineer@rel.test", Mode: store.ModeApp}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox(app,kind,payload) VALUES($1,'object.delete',$2)`, testenv.App, payload)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	_, got, err := env.C.Blobs.ReadAll(ctx, other, blob.ID)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("app A's outbox deleted app B's ciphertext: %v, body %q", err, got)
	}
}
