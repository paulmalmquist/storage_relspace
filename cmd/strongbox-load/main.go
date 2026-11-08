// Command strongbox-load drives synthetic workloads against a running Strongbox and reports latency
// percentiles, error codes and an independent check of the final state.
//
// Every number it prints describes the machine it ran on (one API process, one PostgreSQL, local
// keys and blobs, client and server sharing CPUs). It is SYNTHETIC: it shows how the service
// behaves under contention and overload, not what a production deployment can sustain.
//
//	strongbox-load -setup            # provision principals and apps (uses STRONGBOX_* config, migration login)
//	strongbox-load -url http://127.0.0.1:8080 -secret $STRONGBOX_DEV_JWT_SECRET -out results.json
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/pkg/client"
)

const (
	quietApp = "loadq"
	noisyApp = "loadn"
	probeApp = "loadp"
)

func user(i int) string { return fmt.Sprintf("load-%03d@example.com", i) }

func main() {
	url := flag.String("url", "http://127.0.0.1:8080", "API base URL")
	secret := flag.String("secret", os.Getenv("STRONGBOX_DEV_JWT_SECRET"), "dev JWT secret (development deployments only)")
	users := flag.Int("users", 32, "virtual users")
	dur := flag.Duration("duration", 15*time.Second, "duration of each closed-loop workload")
	sweep := flag.String("sweep", "25,50,100,200,400", "open-loop arrival rates (requests/s) for the sweep")
	step := flag.Duration("step", 10*time.Second, "duration of each sweep step")
	out := flag.String("out", "", "write results JSON here")
	setup := flag.Bool("setup", false, "provision principals and apps, then exit")
	fairness := flag.Bool("fairness-only", false, "compare fixed-rate reads in two apps with and without a third app under overload")
	probeBudget := flag.Duration("probe-deadline", 2*time.Second, "per-probe latency budget for the fairness check")
	flag.Parse()
	if *users < 1 || *users > 256 || *dur <= 0 || *probeBudget <= 0 {
		fmt.Fprintln(os.Stderr, "invalid load parameters")
		os.Exit(2)
	}
	ctx := context.Background()
	if *setup {
		if err := provision(ctx, *users); err != nil {
			fmt.Fprintln(os.Stderr, "setup:", err)
			os.Exit(1)
		}
		return
	}
	r := &runner{url: *url, secret: *secret, users: *users}
	if *fairness {
		if err := r.fairness(ctx, *dur, *probeBudget, *out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	res := Results{Label: "SYNTHETIC: one host, one API process, one PostgreSQL; not a production capacity estimate",
		StartedAt: time.Now().UTC(), Host: fmt.Sprintf("%s/%s, %d CPUs", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()),
		Users: *users, Duration: dur.String()}
	steps := []struct {
		name string
		fn   func(context.Context, time.Duration) (*Workload, error)
	}{
		{"private-state", r.privateState},
		{"shared-record", r.sharedRecord},
		{"blobs", r.blobs},
		{"quiet-alone", r.quietAlone},
		{"quiet-beside-noisy", r.quietBesideNoisy},
	}
	for _, s := range steps {
		w, err := s.fn(ctx, *dur)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.name, err)
			os.Exit(1)
		}
		w.Name = s.name
		res.Workloads = append(res.Workloads, w)
		fmt.Println(w.Line())
	}
	for _, f := range strings.Split(*sweep, ",") {
		var rate float64
		if _, err := fmt.Sscan(strings.TrimSpace(f), &rate); err != nil || rate <= 0 {
			continue
		}
		w, err := r.openLoop(ctx, rate, *step)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sweep:", err)
			os.Exit(1)
		}
		res.Sweep = append(res.Sweep, w)
		fmt.Println(w.Line())
	}
	if *out != "" {
		raw, _ := json.MarshalIndent(res, "", "  ")
		if err := os.WriteFile(*out, raw, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	for _, w := range append(res.Workloads, res.Sweep...) {
		if w.FinalState != "" && !strings.HasPrefix(w.FinalState, "ok") {
			os.Exit(2)
		}
	}
}

// ---- provisioning ----------------------------------------------------------------------------------

func provision(ctx context.Context, n int) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pool, err := store.Open(ctx, cfg.MigrationDatabaseURL, store.Options{Schema: cfg.DBSchema, MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	reg := auth.NewRegistry(pool)
	for i := range n + 1 {
		if err := reg.PutWith(ctx, pool, auth.Spec{Subject: user(i), Kind: auth.KindUser, Scopes: []string{"*"}, USPerson: true,
			CUIAccess: true, CUICategories: []string{"*"}}); err != nil {
			return err
		}
	}
	a := &admin.Admin{Pool: pool, Actor: "strongbox-load", Stripes: cfg.AuditStripes}
	for _, app := range []string{quietApp, noisyApp, probeApp} {
		scope := app + ":" + cfg.AppEnv
		if err := a.CreateApp(ctx, scope, app, user(0)); err != nil && !strings.Contains(err.Error(), "exists") && !strings.Contains(err.Error(), "duplicate") {
			return err
		}
		for i := 1; i <= n; i++ {
			if err := a.SetMember(ctx, scope, user(i), "editor"); err != nil {
				return err
			}
		}
	}
	fmt.Printf("provisioned %d users in %s, %s and %s (%s)\n", n+1, quietApp, noisyApp, probeApp, cfg.AppEnv)
	return nil
}

// ---- measurement -----------------------------------------------------------------------------------

type Results struct {
	Label     string      `json:"label"`
	StartedAt time.Time   `json:"started_at"`
	Host      string      `json:"host"`
	Users     int         `json:"users"`
	Duration  string      `json:"duration"`
	Workloads []*Workload `json:"workloads"`
	Sweep     []*Workload `json:"open_loop_sweep"`
}

type Workload struct {
	Name       string         `json:"name"`
	Mode       string         `json:"mode"` // closed (N users, back to back) | open (fixed arrival rate)
	Offered    float64        `json:"offered_per_s,omitempty"`
	Ops        int64          `json:"ops"`
	Throughput float64        `json:"ops_per_s"`
	P50        float64        `json:"p50_ms"`
	P95        float64        `json:"p95_ms"`
	P99        float64        `json:"p99_ms"`
	Max        float64        `json:"max_ms"`
	Errors     map[string]int `json:"errors"`
	Conflicts  int64          `json:"conflict_retries,omitempty"`
	FinalState string         `json:"final_state,omitempty"`

	mu  sync.Mutex
	lat []float64
}

func (w *Workload) record(d time.Duration, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Ops++
	w.lat = append(w.lat, float64(d.Microseconds())/1000)
	if err != nil {
		if w.Errors == nil {
			w.Errors = map[string]int{}
		}
		code := "transport"
		var ae *client.APIError
		if errors.As(err, &ae) {
			code = fmt.Sprintf("%d %s", ae.Status, ae.Code)
		}
		w.Errors[code]++
	}
}

func (w *Workload) finish(elapsed time.Duration) {
	slices.Sort(w.lat)
	pct := func(p float64) float64 {
		if len(w.lat) == 0 {
			return 0
		}
		i := int(math.Ceil(p*float64(len(w.lat)))) - 1
		return math.Round(w.lat[max(0, i)]*10) / 10
	}
	w.P50, w.P95, w.P99, w.Max = pct(0.50), pct(0.95), pct(0.99), pct(1)
	w.Throughput = math.Round(float64(w.Ops)/elapsed.Seconds()*10) / 10
}

func (w *Workload) Line() string {
	s := fmt.Sprintf("%-22s %-6s ops=%-6d %7.1f/s  p50=%6.1fms p95=%6.1fms p99=%6.1fms max=%7.1fms", w.Name, w.Mode, w.Ops,
		w.Throughput, w.P50, w.P95, w.P99, w.Max)
	if w.Offered > 0 {
		s += fmt.Sprintf(" offered=%.0f/s", w.Offered)
	}
	if len(w.Errors) > 0 {
		s += fmt.Sprintf(" errors=%v", w.Errors)
	}
	if w.Conflicts > 0 {
		s += fmt.Sprintf(" conflict-retries=%d", w.Conflicts)
	}
	if w.FinalState != "" {
		s += " final-state=" + w.FinalState
	}
	return s
}

// ---- workloads -------------------------------------------------------------------------------------

type runner struct {
	url, secret string
	users       int
	seq         atomic.Int64
}

func (r *runner) app(i int, app string) *client.App {
	tok, err := auth.MintDevToken(r.secret, user(i), "strongbox", 2*time.Hour)
	if err != nil {
		panic(err)
	}
	return client.New(r.url, client.StaticToken(tok), client.WithRetries(4)).App(app)
}

func (r *runner) collection(ctx context.Context, app, prefix string) (string, error) {
	name := fmt.Sprintf("%s_%d_%d", prefix, time.Now().Unix()%100000, r.seq.Add(1))
	_, err := r.app(0, app).CreateCollection(ctx, client.CollectionSpec{Name: name, Marking: "CUI//SP-EXPT", IndexedFields: []string{"owner"}})
	return name, err
}

// closed runs fn for each user back to back until d has passed.
func closed(ctx context.Context, n int, d time.Duration, w *Workload, fn func(ctx context.Context, i int) error) time.Duration {
	w.Mode = "closed"
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				t := time.Now()
				err := fn(ctx, i)
				if ctx.Err() != nil && err != nil {
					return // cut off by the deadline, not a result
				}
				w.record(time.Since(t), err)
			}
		}()
	}
	wg.Wait()
	return time.Since(start)
}

// privateState: each user owns one record and keeps updating it (load-save cycles of personal
// state). Check: each record's version equals 1 + that user's successful updates.
func (r *runner) privateState(ctx context.Context, d time.Duration) (*Workload, error) {
	coll, err := r.collection(ctx, quietApp, "private")
	if err != nil {
		return nil, err
	}
	ids := make([]string, r.users+1)
	ok := make([]atomic.Int64, r.users+1)
	for i := 1; i <= r.users; i++ {
		rec, err := r.app(i, quietApp).CreateRecord(ctx, coll, client.RecordInput{Data: map[string]any{"owner": user(i), "n": 0}})
		if err != nil {
			return nil, err
		}
		ids[i] = rec.ID
	}
	w := &Workload{}
	apps := make([]*client.App, r.users+1)
	for i := range apps {
		apps[i] = r.app(i, quietApp)
	}
	elapsed := closed(ctx, r.users, d, w, func(ctx context.Context, i int) error {
		_, err := apps[i].Mutate(ctx, coll, ids[i], 3, func(m map[string]any) (map[string]any, error) {
			m["n"] = num(m["n"]) + 1
			return m, nil
		})
		if err == nil {
			ok[i].Add(1)
		}
		return err
	})
	w.finish(elapsed)
	// Independent check through a fresh client (and the owner's own view).
	bad := 0
	for i := 1; i <= r.users; i++ {
		rec, err := r.app(i, quietApp).GetRecord(ctx, coll, ids[i])
		if err != nil || int64(rec.Version) != 1+ok[i].Load() || int64(num(rec.Data["n"])) != ok[i].Load() {
			bad++
		}
	}
	w.FinalState = finalState(bad, r.users, "records match their owners' successful updates")
	return w, nil
}

// sharedRecord: every user increments one app-visible counter with compare-and-swap. Conflicts are
// expected; the check is that the counter equals the number of increments that reported success.
func (r *runner) sharedRecord(ctx context.Context, d time.Duration) (*Workload, error) {
	coll, err := r.collection(ctx, quietApp, "shared")
	if err != nil {
		return nil, err
	}
	rec, err := r.app(0, quietApp).CreateRecord(ctx, coll, client.RecordInput{Data: map[string]any{"owner": "all", "n": 0}, Visibility: "app"})
	if err != nil {
		return nil, err
	}
	w := &Workload{}
	var success, conflicts atomic.Int64
	apps := make([]*client.App, r.users+1)
	for i := range apps {
		apps[i] = r.app(i, quietApp)
	}
	elapsed := closed(ctx, r.users, d, w, func(ctx context.Context, i int) error {
		cur, err := apps[i].GetRecord(ctx, coll, rec.ID)
		if err != nil {
			return err
		}
		_, err = apps[i].UpdateRecord(ctx, coll, rec.ID, cur.Version, client.RecordInput{Data: map[string]any{"owner": "all", "n": num(cur.Data["n"]) + 1}})
		switch {
		case err == nil:
			success.Add(1)
		case client.IsConflict(err):
			conflicts.Add(1)
			return nil // an expected outcome of CAS, not an error
		}
		return err
	})
	w.finish(elapsed)
	w.Conflicts = conflicts.Load()
	final, err := r.app(0, quietApp).GetRecord(ctx, coll, rec.ID)
	if err != nil {
		return nil, err
	}
	n := int64(num(final.Data["n"]))
	if n == success.Load() && int64(final.Version) == 1+n {
		w.FinalState = fmt.Sprintf("ok: counter %d = successful increments, no lost update", n)
	} else {
		w.FinalState = fmt.Sprintf("MISMATCH: counter %d (v%d), %d increments reported success", n, final.Version, success.Load())
	}
	return w, nil
}

// blobs: 64 KiB uploads followed by a read of the same blob; check: every stored blob reads back.
func (r *runner) blobs(ctx context.Context, d time.Duration) (*Workload, error) {
	w := &Workload{}
	type stored struct {
		app  *client.App
		id   string
		data []byte
	}
	var mu sync.Mutex
	var all []stored
	apps := make([]*client.App, r.users+1)
	for i := range apps {
		apps[i] = r.app(i, quietApp)
	}
	elapsed := closed(ctx, r.users, d, w, func(ctx context.Context, i int) error {
		data := make([]byte, 64*1024)
		_, _ = rand.Read(data)
		b, err := apps[i].PutBlob(ctx, data, client.BlobOptions{Marking: "CUI//SP-EXPT"})
		if err != nil {
			return err
		}
		got, _, err := apps[i].ReadBlob(ctx, b.ID, 0)
		if err == nil && !bytes.Equal(got, data) {
			err = errors.New("content mismatch")
		}
		mu.Lock()
		all = append(all, stored{apps[i], b.ID, data})
		mu.Unlock()
		return err
	})
	w.finish(elapsed)
	bad := 0
	for _, s := range all {
		got, _, err := s.app.ReadBlob(ctx, s.id, 0)
		if err != nil || !bytes.Equal(got, s.data) {
			bad++
		}
	}
	w.FinalState = finalState(bad, len(all), "blobs read back intact")
	return w, nil
}

func (r *runner) quietLoop(ctx context.Context, coll string, ids []string, users int, d time.Duration) *Workload {
	w := &Workload{}
	apps := make([]*client.App, users+1)
	for i := range apps {
		apps[i] = r.app(i, quietApp)
	}
	elapsed := closed(ctx, users, d, w, func(ctx context.Context, i int) error {
		_, err := apps[i].GetRecord(ctx, coll, ids[i])
		return err
	})
	w.finish(elapsed)
	return w
}

func (r *runner) quietSetup(ctx context.Context, users int) (string, []string, error) {
	coll, err := r.collection(ctx, quietApp, "quiet")
	if err != nil {
		return "", nil, err
	}
	ids := make([]string, users+1)
	for i := 1; i <= users; i++ {
		rec, err := r.app(i, quietApp).CreateRecord(ctx, coll, client.RecordInput{Data: map[string]any{"owner": user(i)}})
		if err != nil {
			return "", nil, err
		}
		ids[i] = rec.ID
	}
	return coll, ids, nil
}

// quietAlone is the baseline for quietBesideNoisy: 4 users reading their own records.
func (r *runner) quietAlone(ctx context.Context, d time.Duration) (*Workload, error) {
	coll, ids, err := r.quietSetup(ctx, 4)
	if err != nil {
		return nil, err
	}
	return r.quietLoop(ctx, coll, ids, 4, d), nil
}

// quietBesideNoisy: the same quiet workload while another app writes with every remaining user.
// The noisy app's per-app in-flight cap and rate limits are what keep the quiet app's latency.
func (r *runner) quietBesideNoisy(ctx context.Context, d time.Duration) (*Workload, error) {
	coll, ids, err := r.quietSetup(ctx, 4)
	if err != nil {
		return nil, err
	}
	ncoll, err := r.collection(ctx, noisyApp, "noisy")
	if err != nil {
		return nil, err
	}
	noisy := &Workload{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		users := r.users * 3 // more than the app's in-flight cap
		apps := make([]*client.App, users+1)
		for i := range apps {
			apps[i] = r.app(1+i%r.users, noisyApp)
		}
		closed(ctx, users, d, noisy, func(ctx context.Context, i int) error {
			_, err := apps[i].CreateRecord(ctx, ncoll, client.RecordInput{Data: map[string]any{"owner": "noisy", "pad": strings.Repeat("x", 2000)}})
			return err
		})
	}()
	time.Sleep(time.Second) // let the noise build
	w := r.quietLoop(ctx, coll, ids, 4, d-time.Second)
	<-done
	w.FinalState = ""
	noisy.finish(d)
	w.Errors = mergeErrors(w.Errors, nil)
	w.Name = "quiet-beside-noisy"
	fmt.Println("  (noisy app alongside: " + strings.TrimSpace(noisy.Line()) + ")")
	return w, nil
}

func mergeErrors(a, b map[string]int) map[string]int {
	if a == nil && b == nil {
		return nil
	}
	out := map[string]int{}
	for k, v := range a {
		out[k] += v
	}
	for k, v := range b {
		out[k] += v
	}
	return out
}

// openLoop issues requests at a fixed rate regardless of how fast they complete, so queueing shows
// up in latency (measured from the scheduled start) instead of hiding as reduced load. Each
// request is a create followed by nothing else; latency includes client-side waiting for a slot.
func (r *runner) openLoop(ctx context.Context, rate float64, d time.Duration) (*Workload, error) {
	coll, err := r.collection(ctx, quietApp, "sweep")
	if err != nil {
		return nil, err
	}
	w := &Workload{Name: fmt.Sprintf("open-loop %.0f/s", rate), Mode: "open", Offered: rate}
	apps := make([]*client.App, r.users+1)
	for i := range apps {
		apps[i] = r.app(i, quietApp)
	}
	interval := time.Duration(float64(time.Second) / rate)
	start := time.Now()
	var wg sync.WaitGroup
	var created atomic.Int64
	for k := 0; ; k++ {
		at := start.Add(time.Duration(k) * interval)
		if at.Sub(start) >= d {
			break
		}
		time.Sleep(time.Until(at))
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			_, err := apps[1+k%r.users].CreateRecord(cctx, coll, client.RecordInput{Data: map[string]any{"owner": "sweep", "k": k}, Visibility: "app"})
			if err == nil {
				created.Add(1)
			}
			w.record(time.Since(at), err)
		}(k)
	}
	wg.Wait()
	w.finish(time.Since(start))
	// Check: the collection holds exactly the creates that reported success.
	var n int64
	for rec, err := range queryAll(ctx, r.app(0, quietApp), coll) {
		if err != nil {
			return nil, err
		}
		_ = rec
		n++
	}
	if n == created.Load() {
		w.FinalState = fmt.Sprintf("ok: %d records = successful creates", n)
	} else {
		w.FinalState = fmt.Sprintf("MISMATCH: %d records, %d creates reported success", n, created.Load())
	}
	return w, nil
}

func queryAll(ctx context.Context, a *client.App, coll string) func(func(client.Record, error) bool) {
	return func(yield func(client.Record, error) bool) {
		cursor := ""
		for {
			page, err := a.Query(ctx, coll, nil, 200, cursor)
			if err != nil {
				yield(client.Record{}, err)
				return
			}
			for _, r := range page.Items {
				if !yield(r, nil) {
					return
				}
			}
			if page.NextCursor == nil {
				return
			}
			cursor = *page.NextCursor
		}
	}
}

func finalState(bad, total int, what string) string {
	if bad == 0 {
		return fmt.Sprintf("ok: %d/%d %s", total, total, what)
	}
	return fmt.Sprintf("MISMATCH: %d/%d failed the check (%s)", bad, total, what)
}

// num reads a JSON number whether the SDK decoded it as float64 or json.Number.
func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return math.NaN()
}
