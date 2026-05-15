// Command forensics-cleanup-worker enforces a fixed retention window on the
// envelope-encrypted screenshots that internal/authbroker/replay's Forensics
// captures into MinIO. On every tick it walks dast_replay_failures rows
// older than OLDER_THAN, removes the referenced MinIO objects, and clears
// the screenshot_refs JSONB column.
//
// Defaults: 1h tick, 168h (7 day) retention, bucket "dast-forensics".
//
// Plan #6, PR C, Task C.3 (spec §5).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// minioRemover is the slice of *minio.Client behaviour the worker needs.
// Defined as an interface so unit tests can substitute a fake.
type minioRemover interface {
	RemoveObject(ctx context.Context, bucket, object string, opts minio.RemoveObjectOptions) error
}

// rowQuerier is the slice of *pgxpool.Pool the worker needs. Two methods so
// unit tests can substitute fakes without dragging in a real pgx connection.
type rowQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconnTag, error)
}

// pgconnTag mirrors pgconn.CommandTag's Stringer-only surface so we don't
// import pgconn just for the test fake. The real pgxpool returns
// pgconn.CommandTag which satisfies this trivially.
type pgconnTag interface {
	String() string
}

// poolAdapter wraps a *pgxpool.Pool to satisfy rowQuerier without needing
// the test code to know about pgconn.
type poolAdapter struct{ p *pgxpool.Pool }

func (a poolAdapter) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return a.p.Query(ctx, sql, args...)
}
func (a poolAdapter) Exec(ctx context.Context, sql string, args ...any) (pgconnTag, error) {
	tag, err := a.p.Exec(ctx, sql, args...)
	return tag, err
}

func main() {
	interval := envDuration("INTERVAL", time.Hour)
	olderThan := envDuration("OLDER_THAN", 7*24*time.Hour)
	bucket := envString("FORENSICS_BUCKET", "dast-forensics")

	pool, err := pgxpool.New(context.Background(), envString("DATABASE_URL", ""))
	if err != nil {
		log.Fatalf("forensics-cleanup-worker: pgxpool.New: %v", err)
	}
	defer pool.Close()

	mc, err := minio.New(envString("MINIO_ENDPOINT", "minio:9000"), &minio.Options{
		Creds:  credentials.NewStaticV4(envString("MINIO_ACCESS_KEY", ""), envString("MINIO_SECRET_KEY", ""), ""),
		Secure: envString("MINIO_SECURE", "false") == "true",
	})
	if err != nil {
		log.Fatalf("forensics-cleanup-worker: minio.New: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("forensics-cleanup-worker: tick=%s retention=%s bucket=%s", interval, olderThan, bucket)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	q := poolAdapter{p: pool}
	if err := runOnce(ctx, q, mc, bucket, olderThan); err != nil {
		log.Printf("forensics-cleanup-worker: initial run: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			log.Printf("forensics-cleanup-worker: shutting down")
			return
		case <-ticker.C:
			if err := runOnce(ctx, q, mc, bucket, olderThan); err != nil {
				log.Printf("forensics-cleanup-worker: tick: %v", err)
			}
		}
	}
}

// runOnce performs a single cleanup pass: rows older than olderThan have
// their referenced MinIO objects removed and screenshot_refs cleared. Any
// per-object RemoveObject errors are logged but do not abort the row update
// — best-effort cleanup is preferable to a stuck queue.
func runOnce(ctx context.Context, q rowQuerier, mc minioRemover, bucket string, olderThan time.Duration) error {
	rows, err := q.Query(ctx, `
		SELECT bundle_id, screenshot_refs
		FROM dast_replay_failures
		WHERE last_failure_at < NOW() - $1::interval
		  AND jsonb_array_length(screenshot_refs) > 0`,
		fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	type victim struct {
		bundleID uuid.UUID
		refs     []string
	}
	var victims []victim
	for rows.Next() {
		var bundleID uuid.UUID
		var refsJSON []byte
		if err := rows.Scan(&bundleID, &refsJSON); err != nil {
			rows.Close()
			return fmt.Errorf("scan: %w", err)
		}
		var refs []string
		if err := json.Unmarshal(refsJSON, &refs); err != nil {
			log.Printf("forensics-cleanup-worker: skip bundle %s: invalid JSONB: %v", bundleID, err)
			continue
		}
		victims = append(victims, victim{bundleID: bundleID, refs: refs})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("rows: %w", err)
	}
	rows.Close()

	for _, v := range victims {
		for _, key := range v.refs {
			if err := mc.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{}); err != nil {
				log.Printf("forensics-cleanup-worker: RemoveObject bundle=%s key=%s: %v", v.bundleID, key, err)
			}
		}
		if _, err := q.Exec(ctx,
			`UPDATE dast_replay_failures SET screenshot_refs = '[]'::jsonb WHERE bundle_id = $1`,
			v.bundleID); err != nil {
			return fmt.Errorf("update bundle %s: %w", v.bundleID, err)
		}
	}
	return nil
}

func envString(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("forensics-cleanup-worker: bad %s=%q, using %s: %v", k, v, def, err)
		return def
	}
	return d
}
