package dast

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// ScanJob represents a DAST scan job received from the orchestrator.
type ScanJob struct {
	ID            string     `json:"id"`
	TargetBaseURL string     `json:"target_base_url"`
	AllowedHosts  []string   `json:"allowed_hosts"`
	PinnedIPs     []string   `json:"pinned_ips"` // from orchestrator DNS resolution
	Endpoints     []Endpoint `json:"endpoints"`
	AuthConfig    *authbroker.AuthConfig `json:"auth_config,omitempty"`
	ScopeConfig   scope.Config `json:"-"`
	Concurrency   int        `json:"concurrency"`
	RequestDelay  time.Duration `json:"request_delay"`
}

// ScanResult contains the outcome of a DAST scan.
type ScanResult struct {
	ScanJobID       string     `json:"scan_job_id"`
	WorkerID        string     `json:"worker_id"`
	Status          string     `json:"status"` // completed, failed, aborted
	Findings        []Finding  `json:"findings"`
	TotalRequests   int        `json:"total_requests"`
	FailedRequests  int        `json:"failed_requests"`
	ScopeViolations int64      `json:"scope_violations"`
	Duration        time.Duration `json:"duration"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     time.Time  `json:"completed_at"`
	Error           string     `json:"error,omitempty"`
}

// Finding represents a discovered vulnerability.
type Finding struct {
	ID         string    `json:"id"`
	RuleID     string    `json:"rule_id"`
	Title      string    `json:"title"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	Confidence string    `json:"confidence"`
	URL        string    `json:"url"`
	Method     string    `json:"method"`
	Parameter  string    `json:"parameter,omitempty"`
	Evidence   *Evidence `json:"evidence,omitempty"`
	MatchDetail string   `json:"match_detail"`
	FoundAt    time.Time `json:"found_at"`
}

// WorkerConfig configures a DAST worker instance.
type WorkerConfig struct {
	WorkerID       string
	MaxConcurrency int
	RequestTimeout time.Duration
}

// Worker executes DAST scan jobs.
type Worker struct {
	cfg       WorkerConfig
	broker    *authbroker.Broker
	logger    zerolog.Logger
	running   atomic.Bool
}

// NewWorker creates a DAST worker.
func NewWorker(cfg WorkerConfig, broker *authbroker.Broker, logger zerolog.Logger) *Worker {
	if cfg.WorkerID == "" {
		cfg.WorkerID = "dast-" + uuid.New().String()[:8]
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 10
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}

	return &Worker{
		cfg:    cfg,
		broker: broker,
		logger: logger.With().Str("component", "dast-worker").Str("worker_id", cfg.WorkerID).Logger(),
	}
}

// ExecuteScan runs a complete DAST scan job.
func (w *Worker) ExecuteScan(ctx context.Context, job ScanJob) (*ScanResult, error) {
	if !w.running.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("worker %s is already running a scan", w.cfg.WorkerID)
	}
	defer w.running.Store(false)

	result := &ScanResult{
		ScanJobID: job.ID,
		WorkerID:  w.cfg.WorkerID,
		StartedAt: time.Now(),
	}

	w.logger.Info().
		Str("scan_job_id", job.ID).
		Str("target", job.TargetBaseURL).
		Int("endpoints", len(job.Endpoints)).
		Msg("starting DAST scan")

	// Set up scope enforcer
	enforcer := scope.NewEnforcer(job.ScopeConfig, w.logger)
	if err := enforcer.PinHosts(ctx); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("scope pin failed: %v", err)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	// Set up auth session if configured
	var session *authbroker.Session
	if job.AuthConfig != nil {
		var err error
		session, err = w.broker.CreateSession(ctx, job.ID, *job.AuthConfig)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("auth failed: %v", err)
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			return result, nil
		}
		defer w.broker.RevokeScanSessions(job.ID)
	}

	// Generate test cases
	testCases := GenerateTestCases(job.Endpoints)
	w.logger.Info().Int("test_cases", len(testCases)).Msg("generated test cases")

	// Set up scheduler
	concurrency := job.Concurrency
	if concurrency <= 0 {
		concurrency = w.cfg.MaxConcurrency
	}
	scheduler := NewScheduler(SchedulerConfig{
		Concurrency:    concurrency,
		RequestDelay:   job.RequestDelay,
		RequestTimeout: w.cfg.RequestTimeout,
		ScanJobID:      job.ID,
	}, enforcer, session, w.logger)

	// Execute and collect results
	for res := range scheduler.Execute(ctx, testCases) {
		result.TotalRequests++

		if res.Error != nil {
			result.FailedRequests++
			RecordScanRequest("error", res.Duration.Seconds())
			w.logger.Debug().Err(res.Error).Str("test_id", res.TestCase.ID).Msg("test case failed")
			continue
		}

		RecordScanRequest("success", res.Duration.Seconds())
		if res.Evidence != nil {
			RecordEvidenceCaptured()
		}

		// Check for finding using pre-read body (avoids double-consumption)
		if res.TestCase.Matcher != nil && res.Response != nil {
			matched, detail := res.TestCase.Matcher.Match(res.Response, res.RespBody)
			if matched {
				finding := Finding{
					ID:          uuid.New().String(),
					RuleID:      res.TestCase.RuleID,
					Title:       res.TestCase.Name,
					Category:    res.TestCase.Category,
					Severity:    res.TestCase.Severity,
					Confidence:  res.TestCase.Confidence,
					URL:         res.TestCase.URL,
					Method:      res.TestCase.Method,
					Evidence:    res.Evidence,
					MatchDetail: detail,
					FoundAt:     time.Now(),
				}
				result.Findings = append(result.Findings, finding)
				RecordFinding(finding.Severity, finding.Category)
				w.logger.Info().
					Str("rule_id", finding.RuleID).
					Str("severity", finding.Severity).
					Str("url", finding.URL).
					Msg("finding detected")
			}
		}
	}

	result.ScopeViolations = enforcer.ViolationCount()
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	if enforcer.IsAborted() {
		result.Status = "aborted"
		result.Error = "scan aborted due to scope violations"
	} else if ctx.Err() != nil {
		result.Status = "failed"
		result.Error = "context cancelled"
	} else {
		result.Status = "completed"
	}
	RecordScanCompleted(result.Status)

	w.logger.Info().
		Str("status", result.Status).
		Int("findings", len(result.Findings)).
		Int("total_requests", result.TotalRequests).
		Int("failed_requests", result.FailedRequests).
		Int64("scope_violations", result.ScopeViolations).
		Dur("duration", result.Duration).
		Msg("DAST scan completed")

	return result, nil
}

// MarshalResult serializes a scan result to JSON.
func MarshalResult(result *ScanResult) ([]byte, error) {
	return json.Marshal(result)
}
