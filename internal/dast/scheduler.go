package dast

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	RespBody   []byte // read once to prevent double-consumption
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
	cfg          SchedulerConfig
	enforcer     *scope.Enforcer
	session      *authbroker.Session
	client       *http.Client
	logger       zerolog.Logger
	bypassIssuer *BypassTokenIssuer
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

// SetBypassIssuer configures an optional BypassTokenIssuer. When non-nil, the
// scheduler injects a scanner bypass token into every outgoing request header.
// The field is intentionally nil by default — the feature remains inactive until
// a customer enables it and the issuer is wired in.
func (s *Scheduler) SetBypassIssuer(issuer *BypassTokenIssuer) {
	s.bypassIssuer = issuer
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

	// Inject scanner bypass token when the feature is enabled for this scan.
	if s.bypassIssuer != nil {
		host := req.URL.Host
		if tok, err := s.bypassIssuer.Issue(ctx, s.cfg.ScanJobID, host); err == nil {
			req.Header.Set(BypassTokenHeader, tok)
		} else {
			s.logger.Warn().Err(err).Msg("bypass token issue failed, continuing without header")
		}
	}

	start := time.Now()
	resp, err := s.client.Do(req)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		return result
	}

	// Read body once — prevents double-consumption between evidence capture and matchers.
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxEvidenceBodySize))
	resp.Body.Close()
	if readErr != nil {
		result.Error = fmt.Errorf("read response body: %w", readErr)
		return result
	}

	// Replace body with a re-readable copy so callers (matchers) can still access it.
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	result.Response = resp
	result.RespBody = respBody

	// Capture evidence from the already-read body
	evidence := captureEvidenceFromBytes(req, resp, respBody, tc.RuleID, s.cfg.ScanJobID, result.Duration)
	result.Evidence = evidence

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
