// Package exportworker drives the governance.export_jobs state machine.
//
// Lifecycle:
//
//	queued -> running -> completed
//	             |-> failed
//
// On RunOnce, the worker claims the oldest queued job per org (UPDATE ...
// WHERE status='queued' RETURNING ...), builds the evidence pack via
// internal/export/evidence.BuildPack, uploads to the configured BlobClient,
// then transitions the row to 'completed' with artifact_ref / artifact_hash
// / artifact_size populated.
//
// Failures along the way flip the row to 'failed' with the error captured
// in the error column. The worker is deliberately quiet about retries —
// each invocation processes one job and returns; the cron driver in
// cmd/export-worker schedules recurrent invocations.
package exportworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/export/evidence"
)

// Worker drives the export-job state machine.
type Worker struct {
	pool *pgxpool.Pool
	blob evidence.BlobClient
}

// New constructs a Worker. Both arguments are required.
func New(pool *pgxpool.Pool, blob evidence.BlobClient) *Worker {
	return &Worker{pool: pool, blob: blob}
}

// Result captures the outcome of one RunOnce invocation.
type Result struct {
	JobID     uuid.UUID
	Processed bool   // true if a job was claimed (regardless of success)
	Status    string // resulting status: "completed" | "failed" | ""
	Error     string // only populated on failure
}

// RunOnce claims and processes a single queued job. Returns Processed=false
// when the queue is empty.
func (w *Worker) RunOnce(ctx context.Context) (Result, error) {
	jobID, orgID, requestedBy, scope, format, err := w.claim(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, nil
		}
		return Result{}, fmt.Errorf("claim: %w", err)
	}

	// From here on, every error path must transition the job to 'failed'
	// so we never leave a row stuck in 'running'.
	res, runErr := w.run(ctx, jobID, orgID, requestedBy, scope, format)
	if runErr != nil {
		_ = w.markFailed(ctx, jobID, runErr.Error())
		return Result{
			JobID:     jobID,
			Processed: true,
			Status:    "failed",
			Error:     runErr.Error(),
		}, nil
	}
	return res, nil
}

// claim atomically picks the oldest queued job and flips it to running.
// Returns pgx.ErrNoRows when the queue is empty.
func (w *Worker) claim(ctx context.Context) (id uuid.UUID, orgID, requestedBy uuid.UUID, scopeRaw []byte, format string, err error) {
	const q = `
		UPDATE governance.export_jobs SET
		    status = 'running',
		    started_at = now()
		WHERE id = (
		    SELECT id FROM governance.export_jobs
		     WHERE status = 'queued'
		     ORDER BY created_at
		     LIMIT 1
		     FOR UPDATE SKIP LOCKED
		)
		RETURNING id, org_id, requested_by, scope, format`
	row := w.pool.QueryRow(ctx, q)
	err = row.Scan(&id, &orgID, &requestedBy, &scopeRaw, &format)
	return
}

// run is the happy path: build pack, upload, mark completed.
func (w *Worker) run(ctx context.Context, jobID, orgID, requestedBy uuid.UUID, scopeRaw []byte, format string) (Result, error) {
	var scope evidence.Scope
	if len(scopeRaw) > 0 {
		if err := json.Unmarshal(scopeRaw, &scope); err != nil {
			return Result{}, fmt.Errorf("scope unmarshal: %w", err)
		}
	}

	// Build the pack into an in-memory buffer first. Worker memory is the
	// natural limit for pack size; a 5k-finding pack with full audit log
	// fits comfortably under 128MB. Streaming directly to the blob backend
	// is a future refinement — we'd need a multipart writer + fail-rollback
	// path.
	buf := &bytes.Buffer{}
	meta, err := evidence.BuildPack(ctx, evidence.BuildInput{
		DB:      w.pool,
		OrgID:   orgID,
		BuiltBy: requestedBy,
		Scope:   scope,
		Format:  format,
		Writer:  buf,
	})
	if err != nil {
		return Result{}, fmt.Errorf("build pack: %w", err)
	}

	key := fmt.Sprintf("org/%s/exports/%s.zip", orgID, jobID)
	size, putErr := w.blob.Put(key, bytes.NewReader(buf.Bytes()))
	if putErr != nil {
		return Result{}, fmt.Errorf("blob put: %w", putErr)
	}

	// Defensive guardrail — the byte counter inside BuildPack and the blob
	// upload should agree. A mismatch usually indicates a partial network
	// flush, so we fail the job rather than ship a corrupt pack.
	if size != meta.Size {
		return Result{}, fmt.Errorf("size mismatch: built=%d uploaded=%d", meta.Size, size)
	}

	if err := w.markCompleted(ctx, jobID, key, meta.SHA256, meta.Size); err != nil {
		return Result{}, fmt.Errorf("mark completed: %w", err)
	}
	return Result{JobID: jobID, Processed: true, Status: "completed"}, nil
}

func (w *Worker) markCompleted(ctx context.Context, jobID uuid.UUID, ref, hash string, size int64) error {
	_, err := w.pool.Exec(ctx, `
		UPDATE governance.export_jobs SET
		    status = 'completed',
		    artifact_ref = $2,
		    artifact_hash = $3,
		    artifact_size = $4,
		    completed_at = now()
		WHERE id = $1`,
		jobID, ref, hash, size)
	return err
}

func (w *Worker) markFailed(ctx context.Context, jobID uuid.UUID, errStr string) error {
	// Truncate so a runaway error message doesn't blow out a TEXT column.
	if len(errStr) > 4000 {
		errStr = errStr[:4000]
	}
	_, err := w.pool.Exec(ctx, `
		UPDATE governance.export_jobs SET
		    status = 'failed',
		    error = $2,
		    completed_at = now()
		WHERE id = $1`,
		jobID, errStr)
	return err
}

// EnqueueExport inserts a new queued export-job row. Helper used by the
// HTTP handler so the SQL stays in one place.
func EnqueueExport(ctx context.Context, pool *pgxpool.Pool, orgID, requestedBy uuid.UUID, kind string, scopeRaw []byte, format string) (uuid.UUID, time.Time, error) {
	var id uuid.UUID
	var createdAt time.Time
	err := pool.QueryRow(ctx, `
		INSERT INTO governance.export_jobs (org_id, requested_by, kind, scope, format)
		VALUES ($1, $2, $3, $4::jsonb, $5)
		RETURNING id, created_at`,
		orgID, requestedBy, kind, scopeRaw, format).Scan(&id, &createdAt)
	return id, createdAt, err
}
