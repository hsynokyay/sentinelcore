package sast

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/pkg/archive"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
)

// ArtifactStorageRoot mirrors the controlplane constant. Both services mount
// the same volume at /app/artifacts.
func ArtifactStorageRoot() string {
	if v := os.Getenv("ARTIFACT_STORAGE_ROOT"); v != "" {
		return v
	}
	return "/app/artifacts"
}

// ScanJob represents an incoming SAST scan request. It may carry either a
// git source reference (legacy) or an artifact_id pointing to a bundle under
// the shared artifact storage root.
type ScanJob struct {
	ScanJobID        string    `json:"scan_id"`
	ProjectID        string    `json:"project_id"`
	SourceRef        SourceRef `json:"source_ref"`
	SourceArtifactID string    `json:"source_artifact_id,omitempty"`
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

	srcDir := workDir + "/src"
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		w.publishStatus(ctx, job.ScanJobID, "failed", err.Error())
		return
	}

	// Source selection: artifact bundle if provided, else legacy git clone.
	if job.SourceArtifactID != "" {
		artifactPath := filepath.Join(ArtifactStorageRoot(), job.SourceArtifactID+".zip")
		if err := extractArtifactSafely(artifactPath, srcDir); err != nil {
			w.logger.Error().Err(err).Str("artifact", job.SourceArtifactID).Msg("artifact extract failed")
			w.publishStatus(ctx, job.ScanJobID, "failed", "artifact extract failed: "+err.Error())
			return
		}
	} else if job.SourceRef.RepoURL != "" {
		branch := job.SourceRef.Branch
		if branch == "" {
			branch = "main"
		}
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", "--branch", branch, job.SourceRef.RepoURL, srcDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			w.logger.Error().Err(err).Str("output", string(output)).Msg("git clone failed")
			w.publishStatus(ctx, job.ScanJobID, "failed", "git clone failed: "+err.Error())
			return
		}
	} else {
		w.publishStatus(ctx, job.ScanJobID, "failed", "scan job has neither repo_url nor source_artifact_id")
		return
	}

	// Analyze
	findings, err := w.analyzer.AnalyzeDirectory(srcDir)
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

// extractArtifactSafely validates the zip at path against DefaultLimits and
// then extracts its contents under destDir. Symlinks, absolute paths, parent
// traversal, and oversized entries are all rejected upfront by
// archive.ValidateZipFile, so this function only needs to do the happy-path
// extraction — but we still re-check each entry's final resolved path to
// guarantee we stay inside destDir.
func extractArtifactSafely(archivePath, destDir string) error {
	if _, err := archive.ValidateZipFile(archivePath, archive.DefaultLimits()); err != nil {
		return err
	}
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()

	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}

	for _, f := range zr.File {
		target := filepath.Join(absDest, f.Name)
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(absTarget, absDest+string(os.PathSeparator)) && absTarget != absDest {
			return fmt.Errorf("archive entry escapes root: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(absTarget, 0o750); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(absTarget), 0o750); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(absTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			rc.Close()
			return err
		}
		// archive.ValidateZipFile already enforced MaxEntryBytes, so this copy
		// is bounded.
		if _, err := io.Copy(out, rc); err != nil {
			rc.Close()
			out.Close()
			return err
		}
		rc.Close()
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) publishStatus(ctx context.Context, scanID, status, errorMsg string) {
	data, _ := json.Marshal(map[string]string{
		"scan_job_id": scanID,
		"status":      status,
		"error":       errorMsg,
	})
	w.js.Publish(ctx, "scan.status.update", data)
}
