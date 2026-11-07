// Package audit is a tamper-evident audit log (NIST SP 800-171 3.3.1, 3.3.2, 3.3.8).
//
// Every authorization decision, including denials and authentication failures, becomes one event.
// Events form a SHA-256 hash chain: each event's hash covers the previous hash and the event's
// canonical JSON, so editing, deleting or reordering stored events breaks Verify from that point on.
// Events are also logged as structured JSON (audit=true) for an independent copy in Cloud Logging.
//
// Events carry identifiers and markings only, never CUI content, filenames or metadata values.
// Writes are fail-closed: if the event cannot be written, the request fails.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
)

const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

type Event struct {
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
	PrevHash     string         `json:"prev_hash,omitempty"`
	Hash         string         `json:"hash,omitempty"`
}

// canonical is the hashed form: sorted keys, no HTML escaping, chain fields excluded.
func canonical(e Event) []byte {
	m := map[string]any{
		"seq": e.Seq, "ts": e.TS, "request_id": e.RequestID, "actor": e.Actor, "actor_kind": e.ActorKind,
		"on_behalf_of": e.OnBehalfOf, "action": e.Action, "resource_type": e.ResourceType,
		"resource_id": e.ResourceID, "marking": e.Marking, "decision": e.Decision, "reason": e.Reason,
		"details": normalize(e.Details),
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

func chain(prev string, e Event) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(canonical(e))
	return hex.EncodeToString(h.Sum(nil))
}

type Entry struct {
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

type Log struct{ db *pgxpool.Pool }

func New(db *pgxpool.Pool) *Log { return &Log{db: db} }

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Record appends one event. The chain head row is locked (SELECT ... FOR UPDATE), so concurrent
// writers across replicas serialize correctly.
func (l *Log) Record(ctx context.Context, in Entry) (int64, error) {
	e := Event{
		RequestID: optional(in.RequestID), Action: in.Action, ResourceType: in.ResourceType,
		ResourceID: optional(in.ResourceID), Marking: optional(in.Marking), Decision: in.Decision,
		Reason: truncate(in.Reason, 512), Details: normalize(in.Details),
	}
	switch p := in.Principal; {
	case p == nil:
		e.Actor, e.ActorKind = truncate(firstNonEmpty(in.Anonymous, "anonymous"), 255), "anonymous"
	case p.Actor != "":
		e.Actor, e.ActorKind, e.OnBehalfOf = p.Actor, string(p.Kind), optional(p.Subject)
	default:
		e.Actor, e.ActorKind = p.Subject, string(p.Kind)
	}
	// Detach from request cancellation: a client disconnect must not leave a decision unrecorded.
	ctx = context.WithoutCancel(ctx)
	err := pgx.BeginFunc(ctx, l.db, func(tx pgx.Tx) error {
		var seq int64
		var head string
		if err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_head WHERE id = 1 FOR UPDATE`).Scan(&seq, &head); err != nil {
			return err
		}
		e.Seq = seq + 1
		e.TS = time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00")
		e.PrevHash = head
		e.Hash = chain(head, e)
		details, _ := json.Marshal(e.Details)
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events (seq, ts, request_id, actor, actor_kind, on_behalf_of,
			action, resource_type, resource_id, marking, decision, reason, details, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			e.Seq, e.TS, e.RequestID, e.Actor, e.ActorKind, e.OnBehalfOf, e.Action, e.ResourceType,
			e.ResourceID, e.Marking, e.Decision, e.Reason, details, e.PrevHash, e.Hash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE audit_head SET seq = $1, hash = $2 WHERE id = 1`, e.Seq, e.Hash)
		return err
	})
	if err != nil {
		return 0, err
	}
	slog.Info("audit", "audit", true, "seq", e.Seq, "actor", e.Actor, "on_behalf_of", e.OnBehalfOf,
		"action", e.Action, "resource_type", e.ResourceType, "resource_id", e.ResourceID, "marking", e.Marking,
		"decision", e.Decision, "reason", e.Reason, "request_id", e.RequestID, "hash", e.Hash)
	return e.Seq, nil
}

type VerifyResult struct {
	OK              bool   `json:"ok"`
	Checked         int64  `json:"checked"`
	HeadSeq         int64  `json:"head_seq"`
	FirstInvalidSeq *int64 `json:"first_invalid_seq"`
}

// Verify walks the whole chain and checks it against the head row.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	var headSeq int64
	var headHash string
	if err := l.db.QueryRow(ctx, `SELECT seq, hash FROM audit_head WHERE id = 1`).Scan(&headSeq, &headHash); err != nil {
		return VerifyResult{}, err
	}
	prev, last, checked := Genesis, int64(0), int64(0)
	bad := func(seq int64) (VerifyResult, error) {
		return VerifyResult{OK: false, Checked: checked, HeadSeq: headSeq, FirstInvalidSeq: &seq}, nil
	}
	for {
		events, err := l.List(ctx, last, 1000)
		if err != nil {
			return VerifyResult{}, err
		}
		if len(events) == 0 {
			break
		}
		for _, e := range events {
			if e.Seq != last+1 || e.PrevHash != prev || chain(prev, e) != e.Hash {
				return bad(e.Seq)
			}
			prev, last = e.Hash, e.Seq
			checked++
		}
	}
	if last != headSeq || prev != headHash {
		return bad(last + 1)
	}
	return VerifyResult{OK: true, Checked: checked, HeadSeq: headSeq}, nil
}

func (l *Log) List(ctx context.Context, afterSeq int64, limit int) ([]Event, error) {
	limit = max(1, min(limit, 1000))
	rows, err := l.db.Query(ctx, `SELECT seq, ts, request_id, actor, actor_kind, on_behalf_of, action, resource_type,
		resource_id, marking, decision, reason, details, prev_hash, hash FROM audit_events
		WHERE seq > $1 ORDER BY seq LIMIT $2`, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Seq, &e.TS, &e.RequestID, &e.Actor, &e.ActorKind, &e.OnBehalfOf, &e.Action,
			&e.ResourceType, &e.ResourceID, &e.Marking, &e.Decision, &e.Reason, &e.Details, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
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
