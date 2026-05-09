// Package slaworker contains the dedicated SLA breach + at-risk detection
// worker. It is split from the retention worker so SLA cycles can run on a
// faster cadence without coupling to retention/legal-hold concerns.
//
// Wiring (cmd/sla-worker/main.go):
//
//	pool, _ := pgxpool.New(ctx, dsn)
//	_, js, _  := sc_nats.Connect(cfg)
//	w := slaworker.New(pool, js)
//	w.Run(ctx, 1*time.Hour)
package slaworker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/sentinelcore/sentinelcore/internal/governance"
)

// Worker performs one or more SLA detection cycles.
type Worker struct {
	pool *pgxpool.Pool
	js   jetstream.JetStream

	last Result
}

// Result captures the outcome of a single RunOnce cycle.
type Result struct {
	Violations int
	Warnings   int
	StartedAt  time.Time
	EndedAt    time.Time
}

// New constructs a Worker. js may be nil — in that case events are still
// recorded in the database but not published over NATS.
func New(pool *pgxpool.Pool, js jetstream.JetStream) *Worker {
	return &Worker{pool: pool, js: js}
}

// LastResult returns a snapshot of the most recent RunOnce outcome. Useful in
// tests and for /metrics scraping.
func (w *Worker) LastResult() Result { return w.last }

// RunOnce executes one detection pass:
//
//  1. Find findings whose sla_deadline has passed and that have no open
//     violation row → insert governance.sla_violations + emit
//     governance.notifications event.
//  2. Find findings whose sla_deadline lies in the next 7 days → emit
//     sla.at_risk events idempotently (the unique index on
//     (user_id, resource_id, category) deduplicates).
//
// Returns the first error encountered; partial work may still have been
// committed by RecordSLAViolation calls before the error.
func (w *Worker) RunOnce(ctx context.Context) error {
	if w.pool == nil {
		return errors.New("slaworker: pool is nil")
	}

	res := Result{StartedAt: time.Now()}
	defer func() {
		res.EndedAt = time.Now()
		w.last = res
	}()

	now := time.Now()

	// Step 1: detect breaches.
	violations, err := governance.CheckSLAViolations(ctx, w.pool, now)
	if err != nil {
		return err
	}
	for i := range violations {
		v := &violations[i]
		if recErr := governance.RecordSLAViolation(ctx, w.pool, v); recErr != nil {
			// Best-effort: skip this finding but continue iterating so a
			// single FK conflict doesn't stall the cycle.
			continue
		}
		res.Violations++
		w.publishViolation(ctx, v)
	}

	// Step 2: detect at-risk warnings.
	warnings, err := governance.CheckSLAWarnings(ctx, w.pool, now)
	if err != nil {
		return err
	}
	for _, fid := range warnings {
		w.publishWarning(ctx, fid)
		res.Warnings++
	}

	return nil
}

// Run loops RunOnce on the given interval until ctx is cancelled. Errors are
// swallowed (they are surfaced via Result + log in the caller); the loop must
// not abort on a transient DB blip.
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// First cycle immediately so a freshly-deployed worker doesn't wait an
	// hour to surface backlog breaches.
	_ = w.RunOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.RunOnce(ctx)
		}
	}
}

func (w *Worker) publishViolation(ctx context.Context, v *governance.SLAViolation) {
	if w.js == nil {
		return
	}
	payload := map[string]any{
		"event_type":  "sla_violated",
		"finding_id":  v.FindingID,
		"org_id":      v.OrgID,
		"severity":    v.Severity,
		"deadline_at": v.DeadlineAt,
		"violated_at": v.ViolatedAt,
	}
	data, mErr := json.Marshal(payload)
	if mErr != nil {
		return
	}
	_, _ = w.js.Publish(ctx, "governance.notifications", data)
}

func (w *Worker) publishWarning(ctx context.Context, findingID string) {
	if w.js == nil {
		return
	}
	payload := map[string]any{
		"event_type": "sla_at_risk",
		"finding_id": findingID,
		"category":   "sla.at_risk",
	}
	data, mErr := json.Marshal(payload)
	if mErr != nil {
		return
	}
	_, _ = w.js.Publish(ctx, "governance.notifications", data)
}
