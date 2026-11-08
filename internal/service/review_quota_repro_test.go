package service_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestReviewRecordQuotaOvershootIsAtMostSeven(t *testing.T) {
	env := testenv.New(t)
	notes(t, env)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env.C.DB.MaxConnsPerApp = 8
	env.Admin(t, `INSERT INTO app_quotas(app,max_records,updated_by) VALUES($1,10,'review')`, testenv.App)
	env.Admin(t, `INSERT INTO record_usage(app,shard) SELECT $1,g FROM generate_series(0,7) g`, testenv.App)
	env.Admin(t, `INSERT INTO marking_catalog(app,scope,marking) VALUES($1,'collection:notes','UNCONTROLLED')`, testenv.App)
	ids := make([][]string, 8)
	for i := 0; ; i++ {
		id := fmt.Sprintf("review-quota-%06d", i)
		sum := sha256.Sum256([]byte(id))
		shard := int(sum[0] % 8)
		if len(ids[shard]) < 10 {
			ids[shard] = append(ids[shard], id)
		}
		n := 0
		for _, set := range ids {
			n += len(set)
		}
		if n == 80 {
			break
		}
	}
	prepared := make(chan struct{}, 8)
	release := make(chan struct{})
	done := make(chan error, 8)
	for shard := 0; shard < 8; shard++ {
		go func(shard int) {
			done <- env.C.DB.Run(ctx, store.Scope{App: testenv.App, Subject: "engineer@rel.test", Actor: "engineer@rel.test", Mode: store.ModeApp}, func(tx pgx.Tx) error {
				for _, id := range ids[shard] {
					if _, err := tx.Exec(ctx, `INSERT INTO records(app,id,collection,marking,data_plain,version,created_by,updated_by,owner,visibility,aad_version)
                    VALUES($1,$2,'notes','UNCONTROLLED','{}',1,'engineer@rel.test','engineer@rel.test','engineer@rel.test','private',2)`, testenv.App, id); err != nil {
						return err
					}
				}
				prepared <- struct{}{}
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}(shard)
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	waiting := true
	for n := 0; n < 8 && waiting; n++ {
		select {
		case <-prepared:
		case <-timer.C:
			waiting = false
		}
	}
	close(release)
	for n := 0; n < 8; n++ {
		<-done
	}
	var count int
	if err := env.Migrator.QueryRow(ctx, `SELECT count(*) FROM records WHERE app=$1 AND deleted_at IS NULL`, testenv.App).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > 17 {
		t.Fatalf("max_records=10 admitted %d records; overshoot %d exceeds seven", count, count-10)
	}
}
