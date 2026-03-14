package dast

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// RequestResult holds the outcome of a scheduled scan request.
type RequestResult struct {
	TestCase   TestCase
	Request    *http.Request
	Response   *http.Response
	Evidence   *Evidence
	Duration   time.Duration
	Error      error
}

// SchedulerConfig controls request dispatch behavior.
type SchedulerConfig struct {
	// Concurrency is the number of parallel requests. Default 10.
	Concurrency int

	// RequestDelay is the minimum delay between requests to the same host.
	RequestDelay time.Duration

	// Timeout per individual request.
	RequestTimeout time.Duration

	// ScanJobID for evidence tagging.
	ScanJobID string
}

// Scheduler dispatches test cases through a scope-enforced, rate-limited pipeline.
type Scheduler struct {
	cfg       SchedulerConfig
	enforcer  *scope.Enforcer
	session   *authbroker.Session
	client    *http.Client
	logger    zerolog.Logger
}

// NewScheduler creates a request scheduler with scope enforcement.
func NewScheduler(cfg SchedulerConfig, enforcer *scope.Enforcer, session *authbroker.Session, logger zerolog.Logger) *Scheduler {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}

	client := scope.NewScopedClient(enforcer, cfg.RequestTimeout)

	return &Scheduler{
		cfg:      cfg,
		enforcer: enforcer,
		session:  session,
		client:   client,
		logger:   logger.With().Str("component", "dast-scheduler").Logger(),
	}
}

// Execute runs all test cases and streams results to the returned channel.
// It respects context cancellation and scope enforcement auto-abort.
func (s *Scheduler) Execute(ctx context.Context, testCases []TestCase) <-chan RequestResult {
	results := make(chan RequestResult, s.cfg.Concurrency)
	sem := make(chan struct{}, s.cfg.Concurrency)

	go func() {
		defer close(results)

		var wg sync.WaitGroup
		for i, tc := range testCases {
			// Check abort conditions
			if ctx.Err() != nil {
				s.logger.Info().Msg("context cancelled, stopping scheduler")
				break
			}
			if s.enforcer.IsAborted() {
				s.logger.Error().Msg("scope enforcer aborted, stopping scheduler")
				break
			}

			// Rate limiting
			if s.cfg.RequestDelay > 0 && i > 0 {
				select {
				case <-time.After(s.cfg.RequestDelay):
				case <-ctx.Done():
					break
				}
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(tc TestCase) {
				defer func() {
					<-sem
					wg.Done()
				}()

				result := s.executeTestCase(ctx, tc)
				select {
				case results <- result:
				case <-ctx.Done():
				}
			}(tc)
		}
		wg.Wait()
	}()

	return results
}

func (s *Scheduler) executeTestCase(ctx context.Context, tc TestCase) RequestResult {
	result := RequestResult{TestCase: tc}

	req, err := tc.BuildRequest(ctx)
	if err != nil {
		result.Error = fmt.Errorf("build request: %w", err)
		return result
	}
	result.Request = req

	// Inject auth session credentials
	if s.session != nil {
		s.session.ApplyTo(req)
	}

	start := time.Now()
	resp, err := s.client.Do(req)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		return result
	}
	result.Response = resp

	// Capture evidence
	evidence, err := CaptureEvidence(req, resp, tc.RuleID, s.cfg.ScanJobID, result.Duration)
	if err != nil {
		s.logger.Warn().Err(err).Str("rule_id", tc.RuleID).Msg("evidence capture failed")
	} else {
		result.Evidence = evidence
	}

	return result
}

// Stats returns execution statistics.
type Stats struct {
	TotalRequests   int
	SuccessRequests int
	FailedRequests  int
	ScopeViolations int64
	TotalDuration   time.Duration
}
