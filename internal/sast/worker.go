package sast

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
)

// ScanJob represents an incoming SAST scan request.
type ScanJob struct {
	ScanJobID string    `json:"scan_job_id"`
	ProjectID string    `json:"project_id"`
	SourceRef SourceRef `json:"source_ref"`
}

// SourceRef identifies the source code to scan.
type SourceRef struct {
	RepoURL string `json:"repo_url"`
	Branch  string `json:"branch"`
}

// Worker consumes SAST scan jobs from NATS JetStream and publishes findings.
type Worker struct {
	js         jetstream.JetStream
	analyzer   *Analyzer
	signingKey []byte
	logger     zerolog.Logger
}

// NewWorker creates a new SAST worker.
func NewWorker(js jetstream.JetStream, analyzer *Analyzer, signingKey []byte, logger zerolog.Logger) *Worker {
	return &Worker{js: js, analyzer: analyzer, signingKey: signingKey, logger: logger}
}

// Start begins consuming scan jobs from NATS. It blocks until the context is cancelled.
func (w *Worker) Start(ctx context.Context) error {
	cons, err := w.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "sast-worker",
		FilterSubject: "scan.sast.dispatch",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}

	w.logger.Info().Msg("SAST worker waiting for scan jobs...")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		msgs, err := cons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}

		for msg := range msgs.Messages() {
			var job ScanJob
			if err := json.Unmarshal(msg.Data(), &job); err != nil {
				w.logger.Error().Err(err).Msg("invalid scan job")
				msg.Ack()
				continue
			}

			w.logger.Info().Str("scan_id", job.ScanJobID).Str("repo", job.SourceRef.RepoURL).Msg("processing scan")
			w.processScan(ctx, job)
			msg.Ack()
		}
	}
}

func (w *Worker) processScan(ctx context.Context, job ScanJob) {
	// Create temp working directory
	workDir, err := os.MkdirTemp("", "sast-scan-*")
	if err != nil {
		w.publishStatus(ctx, job.ScanJobID, "failed", err.Error())
		return
	}
	defer os.RemoveAll(workDir)

	w.publishStatus(ctx, job.ScanJobID, "running", "")

	// Git clone
	branch := job.SourceRef.Branch
	if branch == "" {
		branch = "main"
	}
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", "--branch", branch, job.SourceRef.RepoURL, workDir+"/src")
	if output, err := cmd.CombinedOutput(); err != nil {
		w.logger.Error().Err(err).Str("output", string(output)).Msg("git clone failed")
		w.publishStatus(ctx, job.ScanJobID, "failed", "git clone failed: "+err.Error())
		return
	}

	// Analyze
	findings, err := w.analyzer.AnalyzeDirectory(workDir + "/src")
	if err != nil {
		w.publishStatus(ctx, job.ScanJobID, "failed", err.Error())
		return
	}

	w.logger.Info().Str("scan_id", job.ScanJobID).Int("findings", len(findings)).Msg("analysis complete")

	// Publish findings
	for _, f := range findings {
		result := map[string]any{
			"scan_job_id":  job.ScanJobID,
			"project_id":   job.ProjectID,
			"finding_type": "sast",
			"rule_id":      f.RuleID,
			"title":        f.Title,
			"description":  f.Description,
			"cwe_id":       f.CWEID,
			"severity":     f.Severity,
			"confidence":   f.Confidence,
			"file_path":    f.FilePath,
			"line_start":   f.LineStart,
			"line_end":     f.LineEnd,
			"code_snippet": f.CodeSnippet,
			"fingerprint":  f.Fingerprint,
		}
		data, _ := json.Marshal(result)
		sig := sc_nats.SignMessage(w.signingKey, data)
		// Publish with signature header
		msg := &nats.Msg{
			Subject: "scan.results.sast",
			Data:    data,
			Header:  nats.Header{"X-Signature": []string{sig}},
		}
		w.js.PublishMsg(ctx, msg)
	}

	w.publishStatus(ctx, job.ScanJobID, "completed", "")
}

func (w *Worker) publishStatus(ctx context.Context, scanID, status, errorMsg string) {
	data, _ := json.Marshal(map[string]string{
		"scan_job_id": scanID,
		"status":      status,
		"error":       errorMsg,
	})
	w.js.Publish(ctx, "scan.status.update", data)
}
