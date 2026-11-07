// Package audit is a tamper-evident decision log: one SHA-256 hash chain per (app, stripe) plus a
// global chain for events outside any app.
//
// Events are appended inside the caller's transaction, so a mutation and its audit event commit or
// roll back together. Within a chain, sequence order equals commit order: the head row is locked
// FOR UPDATE until the writing transaction commits, so the next writer cannot take a sequence
// number before the previous one is durable. That makes "deliver everything after seq N" a correct
// cursor for exporting committed events (see Deliver).
//
// Stripes bound write contention: a busy app's mutations spread over N independent chains instead
// of serializing on one head row.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

const (
	Genesis     = "0000000000000000000000000000000000000000000000000000000000000000"
	GlobalChain = "global"
	formatV2    = 2 // canonical form includes chain and app
)

type Event struct {
	Chain        string         `json:"chain"`
	App          *string        `json:"app"`
	Seq          int64          `json:"seq"`
	TS           string         `json:"ts"`
	RequestID    *string        `json:"request_id"`
	Actor        string         `json:"actor"`
	ActorKind    string         `json:"actor_kind"`
	OnBehalfOf   *string        `json:"on_behalf_of"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   *string        `json:"resource_id"`
	Marking      *string        `json:"marking"`
	Decision     string         `json:"decision"`
	Reason       string         `json:"reason"`
	Details      map[string]any `json:"details"`
	Format       int            `json:"format"`
	PrevHash     string         `json:"prev_hash,omitempty"`
	Hash         string         `json:"hash,omitempty"`
}

// canonical is the hashed form: sorted keys, no HTML escaping, chain linkage excluded.
// Format 1 (events written before app scoping) predates the chain and app fields.
func canonical(e Event) []byte {
	m := map[string]any{
		"seq": e.Seq, "ts": e.TS, "request_id": e.RequestID, "actor": e.Actor, "actor_kind": e.ActorKind,
		"on_behalf_of": e.OnBehalfOf, "action": e.Action, "resource_type": e.ResourceType,
		"resource_id": e.ResourceID, "marking": e.Marking, "decision": e.Decision, "reason": e.Reason,
		"details": normalize(e.Details),
	}
	if e.Format >= formatV2 {
		m["chain"], m["app"], m["format"] = e.Chain, e.App, e.Format
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// normalize round-trips details through JSON so values hash identically before and after storage.
func normalize(d map[string]any) map[string]any {
	if d == nil {
		return map[string]any{}
	}
	raw, _ := json.Marshal(d)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func link(prev string, e Event) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(canonical(e))
	return hex.EncodeToString(h.Sum(nil))
}

// Entry is what callers record. App selects the chain; empty means the global chain.
type Entry struct {
	App          string
	Principal    *auth.Principal // nil for unauthenticated callers
	Anonymous    string          // subject to record when Principal is nil
	Action       string
	ResourceType string
	ResourceID   string
	Marking      string
	Decision     string // allow | deny | error
	Reason       string
	RequestID    string
	Details      map[string]any
}

type Log struct {
	db      *store.DB
	stripes int
}

func New(db *store.DB, stripes int) *Log { return &Log{db: db, stripes: max(1, stripes)} }

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ChainFor picks the stripe for an event. Events about one resource share a stripe, so a
// resource's history reads in commit order from one chain.
func (l *Log) ChainFor(app, key string) string {
	if app == "" {
		return GlobalChain
	}
	h := fnv.New32a()
	h.Write([]byte(key))
	return fmt.Sprintf("app:%s:%d", app, int(h.Sum32()%uint32(l.stripes)))
}

func (l *Log) event(in Entry) Event {
	e := Event{
		App: optional(in.App), RequestID: optional(in.RequestID), Action: in.Action, ResourceType: in.ResourceType,
		ResourceID: optional(in.ResourceID), Marking: optional(in.Marking), Decision: in.Decision,
		Reason: truncate(in.Reason, 512), Details: normalize(in.Details), Format: formatV2,
	}
	e.Chain = l.ChainFor(in.App, firstNonEmpty(in.ResourceID, in.RequestID))
	switch p := in.Principal; {
	case p == nil:
		e.Actor, e.ActorKind = truncate(firstNonEmpty(in.Anonymous, "anonymous"), 255), "anonymous"
	case p.Actor != "":
		e.Actor, e.ActorKind, e.OnBehalfOf = p.Actor, string(p.Kind), optional(p.Subject)
	default:
		e.Actor, e.ActorKind = p.Subject, string(p.Kind)
	}
	return e
}

// Append writes one event inside tx. The transaction's scope must match the entry: an app chain in
// app or worker mode for that app, the global chain in global mode. RLS enforces it.
func (l *Log) Append(ctx context.Context, tx pgx.Tx, in Entry) (Event, error) {
	e := l.event(in)
	var seq int64
	var head string
	err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_heads WHERE chain = $1 FOR UPDATE`, e.Chain).Scan(&seq, &head)
	if errors.Is(err, pgx.ErrNoRows) {
		// First event on this chain. ON CONFLICT covers a concurrent first writer; then lock it.
		if _, err = tx.Exec(ctx, `INSERT INTO audit_heads (chain, app, seq, hash) VALUES ($1, $2, 0, $3)
			ON CONFLICT (chain) DO NOTHING`, e.Chain, e.App, Genesis); err != nil {
			return e, err
		}
		err = tx.QueryRow(ctx, `SELECT seq, hash FROM audit_heads WHERE chain = $1 FOR UPDATE`, e.Chain).Scan(&seq, &head)
	}
	if err != nil {
		return e, err
	}
	e.Seq = seq + 1
	e.TS = time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00")
	e.PrevHash = head
	e.Hash = link(head, e)
	details, _ := json.Marshal(e.Details)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events (chain, app, format, seq, ts, request_id, actor, actor_kind,
		on_behalf_of, action, resource_type, resource_id, marking, decision, reason, details, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		e.Chain, e.App, e.Format, e.Seq, e.TS, e.RequestID, e.Actor, e.ActorKind, e.OnBehalfOf, e.Action,
		e.ResourceType, e.ResourceID, e.Marking, e.Decision, e.Reason, details, e.PrevHash, e.Hash); err != nil {
		return e, err
	}
	_, err = tx.Exec(ctx, `UPDATE audit_heads SET seq = $1, hash = $2 WHERE chain = $3`, e.Seq, e.Hash, e.Chain)
	return e, err
}

// Standalone records an event in its own transaction: denials and errors, whose request
// transaction rolls back. It detaches from request cancellation so a client disconnect cannot
// leave a decision unrecorded. An app that does not exist is recorded on the global chain.
func (l *Log) Standalone(ctx context.Context, in Entry) error {
	ctx = context.WithoutCancel(ctx)
	subject, actor := "anonymous", "anonymous"
	if in.Principal != nil {
		subject, actor = in.Principal.Subject, firstNonEmpty(in.Principal.Actor, in.Principal.Subject)
	}
	if in.App != "" && store.ValidApp(in.App) {
		err := l.db.Run(ctx, store.Scope{App: in.App, Subject: subject, Actor: actor, Mode: store.ModeApp}, func(tx pgx.Tx) error {
			_, err := l.Append(ctx, tx, in)
			return err
		})
		var pg *pgconn.PgError
		if err == nil || !errors.As(err, &pg) || pg.Code != "23503" {
			return err
		}
	}
	if in.App != "" {
		in.Details = withDetail(in.Details, "requested_app", in.App)
		in.App = ""
	}
	return l.db.Run(ctx, store.Scope{Subject: subject, Actor: actor, Mode: store.ModeGlobal}, func(tx pgx.Tx) error {
		_, err := l.Append(ctx, tx, in)
		return err
	})
}

func withDetail(d map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for kk, vv := range d {
		out[kk] = vv
	}
	out[k] = v
	return out
}

type ChainResult struct {
	Chain           string `json:"chain"`
	OK              bool   `json:"ok"`
	Checked         int64  `json:"checked"`
	HeadSeq         int64  `json:"head_seq"`
	FirstInvalidSeq *int64 `json:"first_invalid_seq"`
}

type VerifyResult struct {
	OK     bool          `json:"ok"`
	Chains []ChainResult `json:"chains"`
}

// Verify walks every chain visible in tx's scope (one app's stripes, or the global chain) and
// checks each against its head row.
func (l *Log) Verify(ctx context.Context, tx pgx.Tx) (VerifyResult, error) {
	rows, err := tx.Query(ctx, `SELECT chain, seq, hash FROM audit_heads ORDER BY chain`)
	if err != nil {
		return VerifyResult{}, err
	}
	type head struct {
		chain, hash string
		seq         int64
	}
	heads, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (head, error) {
		var h head
		return h, r.Scan(&h.chain, &h.seq, &h.hash)
	})
	if err != nil {
		return VerifyResult{}, err
	}
	out := VerifyResult{OK: true, Chains: []ChainResult{}}
	for _, h := range heads {
		r, err := verifyChain(ctx, tx, h.chain, h.seq, h.hash)
		if err != nil {
			return out, err
		}
		out.OK = out.OK && r.OK
		out.Chains = append(out.Chains, r)
	}
	return out, nil
}

// VerifyChain checks one chain against its head row.
func VerifyChain(ctx context.Context, tx pgx.Tx, chain string) (ChainResult, error) {
	var seq int64
	var hash string
	if err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_heads WHERE chain = $1`, chain).Scan(&seq, &hash); err != nil {
		return ChainResult{}, err
	}
	return verifyChain(ctx, tx, chain, seq, hash)
}

func verifyChain(ctx context.Context, tx pgx.Tx, chain string, headSeq int64, headHash string) (ChainResult, error) {
	prev, last, checked := Genesis, int64(0), int64(0)
	bad := func(seq int64) (ChainResult, error) {
		return ChainResult{Chain: chain, Checked: checked, HeadSeq: headSeq, FirstInvalidSeq: &seq}, nil
	}
	for {
		events, err := List(ctx, tx, chain, last, 1000)
		if err != nil {
			return ChainResult{}, err
		}
		if len(events) == 0 {
			break
		}
		for _, e := range events {
			if e.Seq != last+1 || e.PrevHash != prev || link(prev, e) != e.Hash {
				return bad(e.Seq)
			}
			prev, last = e.Hash, e.Seq
			checked++
		}
	}
	if last != headSeq || prev != headHash {
		return bad(last + 1)
	}
	return ChainResult{Chain: chain, OK: true, Checked: checked, HeadSeq: headSeq}, nil
}

// List returns events of one chain after afterSeq, in order.
func List(ctx context.Context, tx pgx.Tx, chain string, afterSeq int64, limit int) ([]Event, error) {
	limit = max(1, min(limit, 1000))
	rows, err := tx.Query(ctx, `SELECT chain, app, format, seq, ts, request_id, actor, actor_kind, on_behalf_of, action,
		resource_type, resource_id, marking, decision, reason, details, prev_hash, hash FROM audit_events
		WHERE chain = $1 AND seq > $2 ORDER BY seq LIMIT $3`, chain, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Event, error) {
		var e Event
		err := r.Scan(&e.Chain, &e.App, &e.Format, &e.Seq, &e.TS, &e.RequestID, &e.Actor, &e.ActorKind, &e.OnBehalfOf,
			&e.Action, &e.ResourceType, &e.ResourceID, &e.Marking, &e.Decision, &e.Reason, &e.Details, &e.PrevHash, &e.Hash)
		return e, err
	})
}

// Chains lists the chains visible in tx's scope.
func Chains(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT chain FROM audit_heads ORDER BY chain`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Deliver exports committed events of one chain to the structured log (Cloud Logging) and advances
// the chain's delivery cursor in the same transaction. Delivery is at-least-once: a crash after
// logging and before commit re-emits the batch. tx must be scoped to the chain's app (worker mode)
// or global mode for the global chain. Returns the number of events emitted.
func Deliver(ctx context.Context, tx pgx.Tx, chain string, app *string, limit int) (int, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO audit_delivery (chain, app, delivered_seq) VALUES ($1, $2, 0)
		ON CONFLICT (chain) DO NOTHING`, chain, app); err != nil {
		return 0, err
	}
	var delivered int64
	err := tx.QueryRow(ctx, `SELECT delivered_seq FROM audit_delivery WHERE chain = $1 FOR UPDATE SKIP LOCKED`, chain).Scan(&delivered)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil // another worker holds this chain
	}
	if err != nil {
		return 0, err
	}
	events, err := List(ctx, tx, chain, delivered, limit)
	if err != nil || len(events) == 0 {
		return 0, err
	}
	for _, e := range events {
		slog.Info("audit", "audit", true, "chain", e.Chain, "app", e.App, "seq", e.Seq, "ts", e.TS, "actor", e.Actor,
			"on_behalf_of", e.OnBehalfOf, "action", e.Action, "resource_type", e.ResourceType, "resource_id", e.ResourceID,
			"marking", e.Marking, "decision", e.Decision, "reason", e.Reason, "request_id", e.RequestID, "hash", e.Hash)
	}
	_, err = tx.Exec(ctx, `UPDATE audit_delivery SET delivered_seq = $1, updated_at = now() WHERE chain = $2`,
		events[len(events)-1].Seq, chain)
	return len(events), err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
