package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/sentinelcore/sentinelcore/internal/controlplane/api"
	"github.com/sentinelcore/sentinelcore/internal/sast/engine"
	csfrontend "github.com/sentinelcore/sentinelcore/internal/sast/frontend/csharp"
	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/java"
	jsfrontend "github.com/sentinelcore/sentinelcore/internal/sast/frontend/js"
	pyfrontend "github.com/sentinelcore/sentinelcore/internal/sast/frontend/python"
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/pkg/archive"
	"github.com/sentinelcore/sentinelcore/pkg/db"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

func main() {
	logger := observability.NewLogger("sast-worker")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Database
	pool, err := db.NewPool(ctx, db.Config{
		Host:     env("DB_HOST", "localhost"),
		Port:     envInt("DB_PORT", 5432),
		Database: env("DB_NAME", "sentinelcore"),
		User:     env("DB_USER", "sentinelcore"),
		Password: env("DB_PASSWORD", "dev-password"),
		MaxConns: envInt("DB_MAX_CONNS", 5),
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("database connect failed")
	}
	defer pool.Close()
	logger.Info().Msg("connected to PostgreSQL")

	// NATS
	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: env("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("NATS connect failed")
	}
	defer nc.Close()
	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure streams")
	}
	logger.Info().Msg("connected to NATS")

	// SAST engine
	eng, err := engine.NewFromBuiltins()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize SAST engine")
	}
	logger.Info().Int("rules", eng.RuleCount()).Msg("SAST engine initialized")

	// Metrics endpoint — Prometheus exposition on container-localhost
	// only. External scrape goes via `docker exec` from the host cron
	// job; container 127.0.0.1 is unreachable from other containers and
	// from the public Hetzner IP. See AUDIT-2026-05-11 HK-4.
	go startMetricsServer(ctx)

	signingKey := []byte(env("MSG_SIGNING_KEY", "dev-signing-key-change-me"))
	artifactRoot := env("ARTIFACT_STORAGE_ROOT", "/app/artifacts")

	// Consumer
	cons, err := js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "sast-engine-worker",
		FilterSubject: "scan.sast.dispatch",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create NATS consumer")
	}

	logger.Info().Msg("SAST worker waiting for scan jobs...")

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("shutting down")
			return
		default:
		}

		msgs, err := cons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}

		for msg := range msgs.Messages() {
			var job scanJob
			if err := json.Unmarshal(msg.Data(), &job); err != nil {
				logger.Error().Err(err).Msg("invalid scan job message")
				msg.Ack()
				continue
			}

			logger.Info().
				Str("scan_id", job.ScanID).
				Str("project_id", job.ProjectID).
				Str("artifact_id", job.SourceArtifactID).
				Msg("processing SAST scan")

			processJob(ctx, eng, pool, js, signingKey, artifactRoot, job)
			msg.Ack()
		}
	}
}

type scanJob struct {
	ScanID           string `json:"scan_id"`
	ProjectID        string `json:"project_id"`
	TargetID         string `json:"target_id,omitempty"`
	SourceArtifactID string `json:"source_artifact_id,omitempty"`
	ScanType         string `json:"scan_type"`
}

func processJob(
	ctx context.Context,
	eng *engine.Engine,
	pool *pgxpool.Pool,
	js jetstream.JetStream,
	signingKey []byte,
	artifactRoot string,
	job scanJob,
) {
	log := observability.NewLogger("sast-worker")

	publishStatus := func(status, errMsg string) {
		data, _ := json.Marshal(map[string]string{
			"scan_job_id": job.ScanID,
			"status":      status,
			"error":       errMsg,
		})
		js.Publish(ctx, "scan.status.update", data)
	}

	// Update status: running
	publishStatus("running", "")

	// Update scan_jobs row
	pool.Exec(ctx, `UPDATE scans.scan_jobs SET status = 'running', started_at = now(), updated_at = now(), progress = '{"phase":"analyzing","percent":10}'::jsonb WHERE id = $1`, job.ScanID)

	// Resolve source
	if job.SourceArtifactID == "" {
		publishStatus("failed", "no source_artifact_id provided")
		pool.Exec(ctx, `UPDATE scans.scan_jobs SET status = 'failed', error_message = 'no source artifact', updated_at = now() WHERE id = $1`, job.ScanID)
		return
	}

	artifactPath := filepath.Join(artifactRoot, job.SourceArtifactID+".zip")
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		publishStatus("failed", "artifact file not found: "+job.SourceArtifactID)
		pool.Exec(ctx, `UPDATE scans.scan_jobs SET status = 'failed', error_message = 'artifact file not found', updated_at = now() WHERE id = $1`, job.ScanID)
		return
	}

	// Validate ZIP
	if _, err := archive.ValidateZipFile(artifactPath, archive.DefaultLimits()); err != nil {
		publishStatus("failed", "artifact validation failed: "+err.Error())
		pool.Exec(ctx, `UPDATE scans.scan_jobs SET status = 'failed', error_message = $2, updated_at = now() WHERE id = $1`, job.ScanID, err.Error())
		return
	}

	// Extract to temp dir
	workDir, err := os.MkdirTemp("", "sast-scan-*")
	if err != nil {
		publishStatus("failed", err.Error())
		return
	}
	defer os.RemoveAll(workDir)

	srcDir := filepath.Join(workDir, "src")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		publishStatus("failed", err.Error())
		return
	}

	// Extract
	if err := extractZip(artifactPath, srcDir); err != nil {
		publishStatus("failed", "extract failed: "+err.Error())
		pool.Exec(ctx, `UPDATE scans.scan_jobs SET status = 'failed', error_message = $2, updated_at = now() WHERE id = $1`, job.ScanID, err.Error())
		return
	}

	pool.Exec(ctx, `UPDATE scans.scan_jobs SET progress = '{"phase":"parsing","percent":30}'::jsonb, updated_at = now() WHERE id = $1`, job.ScanID)

	// Find and parse Java files
	javaFiles, err := java.WalkJavaFiles(srcDir)
	if err != nil {
		publishStatus("failed", "walk failed: "+err.Error())
		return
	}

	// Also find JS/TS, Python, and C# files.
	jsFiles, _ := jsfrontend.WalkJSFiles(srcDir)
	pyFiles, _ := pyfrontend.WalkPythonFiles(srcDir)
	csFiles, _ := csfrontend.WalkCSharpFiles(srcDir)

	if len(javaFiles) == 0 && len(jsFiles) == 0 && len(pyFiles) == 0 && len(csFiles) == 0 {
		publishStatus("completed", "")
		pool.Exec(ctx, `UPDATE scans.scan_jobs SET status = 'completed', completed_at = now(), progress = '{"phase":"completed","percent":100}'::jsonb, updated_at = now() WHERE id = $1`, job.ScanID)
		log.Info().Str("scan_id", job.ScanID).Msg("no source files found in artifact")
		return
	}

	var modules []*ir.Module
	for _, absPath := range javaFiles {
		relPath, _ := filepath.Rel(srcDir, absPath)
		mod, parseErr := java.ParseFile(absPath, relPath)
		if parseErr != nil {
			log.Error().Err(parseErr).Str("file", relPath).Msg("parse error (skipping)")
			continue
		}
		modules = append(modules, mod)
	}
	for _, absPath := range jsFiles {
		relPath, _ := filepath.Rel(srcDir, absPath)
		mod, parseErr := jsfrontend.ParseFile(absPath, relPath)
		if parseErr != nil {
			log.Error().Err(parseErr).Str("file", relPath).Msg("parse error (skipping)")
			continue
		}
		modules = append(modules, mod)
	}
	for _, absPath := range pyFiles {
		relPath, _ := filepath.Rel(srcDir, absPath)
		mod, parseErr := pyfrontend.ParseFile(absPath, relPath)
		if parseErr != nil {
			log.Error().Err(parseErr).Str("file", relPath).Msg("parse error (skipping)")
			continue
		}
		modules = append(modules, mod)
	}
	for _, absPath := range csFiles {
		relPath, _ := filepath.Rel(srcDir, absPath)
		mod, parseErr := csfrontend.ParseFile(absPath, relPath)
		if parseErr != nil {
			log.Error().Err(parseErr).Str("file", relPath).Msg("parse error (skipping)")
			continue
		}
		modules = append(modules, mod)
	}

	pool.Exec(ctx, `UPDATE scans.scan_jobs SET progress = '{"phase":"analyzing","percent":60}'::jsonb, updated_at = now() WHERE id = $1`, job.ScanID)

	// Run engine
	findings := eng.AnalyzeAll(modules)

	pool.Exec(ctx, `UPDATE scans.scan_jobs SET progress = '{"phase":"persisting","percent":85}'::jsonb, updated_at = now() WHERE id = $1`, job.ScanID)

	// Persist findings
	for _, f := range findings {
		msg := engine.ToMessage(f, job.ScanID, job.ProjectID)
		findingID := uuid.New().String()

		// Check if this fingerprint already exists (dedup across scans).
		var existingID string
		err := pool.QueryRow(ctx,
			`SELECT id FROM findings.findings WHERE fingerprint = $1`, msg.Fingerprint,
		).Scan(&existingID)
		if err == nil {
			// Existing finding — update last_seen and scan_count.
			findingID = existingID
			pool.Exec(ctx,
				`UPDATE findings.findings SET last_seen_at = now(), scan_count = scan_count + 1, scan_job_id = $2, updated_at = now() WHERE id = $1`,
				findingID, msg.ScanJobID,
			)
		} else {
			// New finding — insert with rule_id for remediation lookup.
			_, insertErr := pool.Exec(ctx,
				`INSERT INTO findings.findings
					(id, project_id, scan_job_id, finding_type, fingerprint, title, description,
					 cwe_id, severity, confidence, file_path, line_start, line_end, status, rule_id)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'new', $14)`,
				findingID, msg.ProjectID, msg.ScanJobID, msg.FindingType, msg.Fingerprint,
				msg.Title, msg.Description, msg.CWEID, msg.Severity, msg.Confidence,
				msg.FilePath, msg.LineStart, nullIfZero(msg.LineEnd), msg.RuleID,
			)
			if insertErr != nil {
				log.Error().Err(insertErr).Str("fingerprint", msg.Fingerprint).Msg("finding insert failed")
				continue
			}
		}

		// Insert taint paths
		rows := engine.ToTaintPathRows(f, findingID)
		if tpErr := engine.InsertTaintPaths(ctx, pool, rows); tpErr != nil {
			log.Error().Err(tpErr).Str("finding_id", findingID).Msg("taint path insert failed")
		}

		// Publish to NATS for correlation engine
		resultData, _ := json.Marshal(msg)
		sig := sc_nats.SignMessage(signingKey, resultData)
		natsMsg := &nats.Msg{
			Subject: "scan.results.sast",
			Data:    resultData,
			Header:  nats.Header{"X-Signature": []string{sig}},
		}
		js.PublishMsg(ctx, natsMsg)
	}

	// Complete
	publishStatus("completed", "")
	pool.Exec(ctx,
		`UPDATE scans.scan_jobs SET status = 'completed', completed_at = now(), progress = '{"phase":"completed","percent":100}'::jsonb, updated_at = now() WHERE id = $1`,
		job.ScanID,
	)

	// Dispatch webhooks for scan completion.
	api.DispatchScanWebhooks(ctx, pool, log, job.ScanID)

	// Metrics.
	observability.ScanCompleted.WithLabelValues("sast", "completed").Inc()
	observability.FindingsProduced.WithLabelValues("sast").Observe(float64(len(findings)))
	observability.WorkerJobsProcessed.WithLabelValues("sast", "completed").Inc()

	log.Info().
		Str("scan_id", job.ScanID).
		Int("java_files", len(javaFiles)).
		Int("js_files", len(jsFiles)).
		Int("py_files", len(pyFiles)).
		Int("cs_files", len(csFiles)).
		Int("modules", len(modules)).
		Int("findings", len(findings)).
		Msg("SAST scan completed")
}

func extractZip(zipPath, destDir string) error {
	// Reuse the safe extraction from the existing SAST worker
	if _, err := archive.ValidateZipFile(zipPath, archive.DefaultLimits()); err != nil {
		return err
	}

	zr, err := archive.OpenZipForExtraction(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, f := range zr.File {
		target := filepath.Join(destDir, f.Name)
		absTarget, _ := filepath.Abs(target)
		absDest, _ := filepath.Abs(destDir)
		if !strings.HasPrefix(absTarget, absDest+string(os.PathSeparator)) && absTarget != absDest {
			return fmt.Errorf("path traversal in zip: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(absTarget, 0o750)
			continue
		}
		os.MkdirAll(filepath.Dir(absTarget), 0o750)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(absTarget)
		if err != nil {
			rc.Close()
			return err
		}
		buf := make([]byte, 32*1024)
		for {
			n, readErr := rc.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if readErr != nil {
				break
			}
		}
		rc.Close()
		out.Close()
	}
	return nil
}

func nullIfZero(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// metricsMux returns the HTTP mux that exposes Prometheus metrics on
// /metrics. Factored out so the endpoint can be tested without binding
// a real port.
func metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", observability.MetricsHandler())
	return mux
}

// startMetricsServer binds the metrics HTTP listener on
// 127.0.0.1:${METRICS_PORT:-9090} and serves Prometheus exposition.
// Binding to container-localhost keeps the surface unreachable from
// other containers on the docker network and from the public host IP;
// host scrape uses `docker exec ... wget` against the container's loopback.
// The server shuts down gracefully when the parent ctx is cancelled.
func startMetricsServer(ctx context.Context) {
	log := observability.NewLogger("sast-worker-metrics")
	addr := "127.0.0.1:" + env("METRICS_PORT", "9090")

	srv := &http.Server{
		Addr:              addr,
		Handler:           metricsMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		log.Info().Str("addr", addr).Msg("metrics server listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("metrics server failed")
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Info().Msg("metrics server stopped")
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return fallback
}
