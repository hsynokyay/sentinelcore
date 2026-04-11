package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
)

// DebounceWindow is the per-project window during which additional
// scan.completed events are absorbed into the same run.
const DebounceWindow = 30 * time.Second

// MinRebuildInterval is a minimum gap between consecutive runs for the
// same project. Events arriving inside this window are dropped.
const MinRebuildInterval = 10 * time.Second

// Worker subscribes to scan.status.update, debounces per project, and
// invokes the correlator.
type Worker struct {
	js         jetstream.JetStream
	correlator *Correlator
	logger     zerolog.Logger

	mu         sync.Mutex
	pending    map[string]*time.Timer // projectID -> firing timer
	lastRunEnd map[string]time.Time
}

// NewWorker wires a worker against a NATS JetStream context and a correlator.
func NewWorker(js jetstream.JetStream, pool *pgxpool.Pool, logger zerolog.Logger) *Worker {
	return &Worker{
		js:         js,
		correlator: NewCorrelator(NewStore(pool), logger),
		logger:     logger.With().Str("component", "risk-worker").Logger(),
		pending:    make(map[string]*time.Timer),
		lastRunEnd: make(map[string]time.Time),
	}
}

// Run subscribes to scan.status.update and blocks until ctx is cancelled.
// Events are filtered: only status=completed triggers a rebuild.
func (w *Worker) Run(ctx context.Context) error {
	cons, err := w.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "risk-correlation",
		FilterSubject: "scan.status.update",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}

	w.logger.Info().Msg("risk worker subscribed to scan.status.update")

	for {
		select {
		case <-ctx.Done():
			w.logger.Info().Msg("risk worker shutting down")
			return nil
		default:
		}

		msgs, err := cons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}
		for msg := range msgs.Messages() {
			w.handleMessage(ctx, msg)
		}
	}
}

// handleMessage parses the scan status payload and schedules a debounced
// rebuild if status == "completed".
func (w *Worker) handleMessage(ctx context.Context, msg jetstream.Msg) {
	defer msg.Ack()

	var payload struct {
		ScanJobID string `json:"scan_job_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(msg.Data(), &payload); err != nil {
		w.logger.Error().Err(err).Msg("invalid scan.status.update payload")
		return
	}
	if payload.Status != "completed" {
		return
	}

	projectID, err := w.projectForScan(ctx, payload.ScanJobID)
	if err != nil {
		w.logger.Error().Err(err).Str("scan_job_id", payload.ScanJobID).Msg("cannot resolve project for scan")
		return
	}

	w.schedule(projectID, &payload.ScanJobID)
}

// schedule debounces: if a timer is already pending for this project,
// reset it; otherwise create a new one. Drops if the last run completed
// less than MinRebuildInterval ago.
func (w *Worker) schedule(projectID string, scanID *string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if last, ok := w.lastRunEnd[projectID]; ok && time.Since(last) < MinRebuildInterval {
		w.logger.Debug().Str("project_id", projectID).Msg("dropping event (last run too recent)")
		return
	}

	if t, ok := w.pending[projectID]; ok {
		t.Reset(DebounceWindow)
		return
	}
	t := time.AfterFunc(DebounceWindow, func() {
		w.fireRebuild(projectID, scanID)
	})
	w.pending[projectID] = t
}

// fireRebuild runs the correlator and records the completion time for the
// MinRebuildInterval gate.
func (w *Worker) fireRebuild(projectID string, scanID *string) {
	w.mu.Lock()
	delete(w.pending, projectID)
	w.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := w.correlator.RebuildProject(ctx, projectID, "scan_completed", scanID); err != nil {
		w.logger.Error().Err(err).Str("project_id", projectID).Msg("risk rebuild failed")
		return
	}
	w.mu.Lock()
	w.lastRunEnd[projectID] = time.Now()
	w.mu.Unlock()
}

// projectForScan resolves scan_job_id to project_id via a direct DB lookup.
// Needed because the scan.status.update payload does not carry the project.
func (w *Worker) projectForScan(ctx context.Context, scanJobID string) (string, error) {
	var projectID string
	err := w.correlator.store.Pool().QueryRow(ctx,
		`SELECT project_id::text FROM scans.scan_jobs WHERE id = $1`, scanJobID).Scan(&projectID)
	return projectID, err
}

// RebuildProjectManually bypasses the debouncer. Used by the API's
// manual-recompute endpoint.
func (w *Worker) RebuildProjectManually(ctx context.Context, projectID string) error {
	err := w.correlator.RebuildProject(ctx, projectID, "manual", nil)
	if err == nil {
		w.mu.Lock()
		w.lastRunEnd[projectID] = time.Now()
		w.mu.Unlock()
	}
	return err
}
