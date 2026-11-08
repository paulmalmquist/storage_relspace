package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

func (w *Worker) deleteOrphan(ctx context.Context, j job) error {
	var object store.ObjectInfo
	if err := json.Unmarshal(j.Payload, &object); err != nil {
		return err
	}
	prefix, err := store.AppObjectPrefix(j.App)
	if err != nil {
		return err
	}
	if !store.ValidStorageKey(object.Key) || len(object.Key) <= len(prefix) || object.Key[:len(prefix)] != prefix || object.Version == "" {
		return errors.New("orphan deletion outside app scope or without a generation")
	}
	inventory, ok := w.Backend.(store.Inventory)
	if !ok {
		return store.ErrInventoryUnsupported
	}
	referenced := true
	if err := w.core.DB.Run(ctx, w.worker(j.App), func(tx pgx.Tx) error {
		var err error
		referenced, err = store.ObjectReferenced(ctx, tx, j.App, object.Key)
		return err
	}); err != nil {
		return err
	}
	if referenced {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	current, err := inventory.StatObject(call, object.Key)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, storage.ErrObjectNotExist) || errs.Is(err, "not_found") {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Version != object.Version || current.Updated.IsZero() || current.Updated.After(time.Now().Add(-store.OrphanGrace)) {
		return nil
	}
	err = inventory.DeleteVersion(call, object)
	if errors.Is(err, store.ErrObjectChanged) {
		return nil
	}
	return err
}
