package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/pkg/client"
)

// Probe the same records at the same scheduled rate in both phases. Disabling SDK
// retries makes each rejection visible. Deadline overruns count even after queueing.
func (r *runner) fairness(ctx context.Context, duration, budget time.Duration, output string) error {
	const interval = 200 * time.Millisecond
	if duration < time.Second || duration > 10*time.Minute {
		return errors.New("fairness duration must be between 1 second and 10 minutes")
	}
	apps := []string{quietApp, probeApp, noisyApp}
	type target struct {
		app                  *client.App
		name, collection, id string
	}
	targets := make([]target, len(apps))
	for i, name := range apps {
		coll, err := r.collection(ctx, name, "probes")
		if err != nil {
			return err
		}
		tok, err := auth.MintDevToken(r.secret, user(1), "strongbox", time.Hour)
		if err != nil {
			return err
		}
		app := client.New(r.url, client.StaticToken(tok), client.WithRetries(0)).App(name)
		rec, err := app.CreateRecord(ctx, coll, client.RecordInput{Data: map[string]any{"probe": name}, Visibility: "app"})
		if err != nil {
			return err
		}
		targets[i] = target{app, name, coll, rec.ID}
	}
	samples := int(duration / interval)
	probe := func(t target, start time.Time) *Workload {
		w := &Workload{Name: t.name, Mode: "open", Offered: 5}
		for n := range samples {
			due := start.Add(time.Duration(n) * interval)
			time.Sleep(time.Until(due))
			request, cancel := context.WithDeadline(ctx, due.Add(budget))
			record, err := t.app.GetRecord(request, t.collection, t.id)
			if err == nil && (record.ID != t.id || record.Data["probe"] != t.name) {
				err = errors.New("wrong record")
			}
			cancel()
			w.record(time.Since(due), err)
		}
		w.finish(max(time.Since(start), time.Duration(samples)*interval))
		return w
	}
	run := func() []*Workload {
		results := make([]*Workload, 2)
		var wg sync.WaitGroup
		start := time.Now()
		for i := range results {
			wg.Go(func() { results[i] = probe(targets[i], start) })
		}
		wg.Wait()
		return results
	}
	baseline := run()
	noisy := &Workload{Name: noisyApp}
	noiseCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		n := targets[2]
		elapsed := closed(noiseCtx, r.users, duration+budget+time.Second, noisy, func(c context.Context, _ int) error {
			_, err := n.app.GetRecord(c, n.collection, n.id)
			once.Do(func() { close(started) })
			return err
		})
		noisy.finish(elapsed)
	}()
	select {
	case <-started:
	case <-time.After(budget):
		stop()
		<-done
		return errors.New("noisy app could not start")
	}
	loaded := run()
	stop()
	<-done
	passed := true
	for _, phase := range [][]*Workload{baseline, loaded} {
		for _, w := range phase {
			passed = passed && w.Ops == int64(samples) && len(w.Errors) == 0 && w.Max <= float64(budget.Milliseconds())
			fmt.Println(w.Line())
		}
	}
	var throttled int64
	for code, n := range noisy.Errors {
		if strings.HasPrefix(code, "429 ") {
			throttled += int64(n)
		} else {
			passed = false
		}
	}
	passed = passed && throttled > 0 && noisy.Ops > throttled
	report := struct {
		Scope    string      `json:"scope"`
		Users    int         `json:"noisy_concurrency"`
		Samples  int         `json:"scheduled_reads_per_quiet_app_per_phase"`
		Deadline string      `json:"probe_deadline"`
		Baseline []*Workload `json:"baseline"`
		Loaded   []*Workload `json:"under_load"`
		Noise    *Workload   `json:"noisy_app"`
		Passed   bool        `json:"passed"`
	}{"synthetic / one API instance and PostgreSQL / no client retries", r.users, samples, budget.String(), baseline, loaded, noisy, passed}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if output != "" {
		if err = os.WriteFile(output, append(raw, '\n'), 0644); err != nil {
			return err
		}
	} else {
		fmt.Println(string(raw))
	}
	if !passed {
		return errors.New("fairness check failed; see probe deadlines, error codes and noisy-app rejections")
	}
	return nil
}
