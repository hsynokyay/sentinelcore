// Package browser implements the security foundations for browser-based DAST scanning.
// This package provides Chrome lifecycle management, CDP scope enforcement,
// auth injection, and evidence capture — but NO crawler or scanner logic.
package browser

import (
	"strings"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/internal/dast"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// BrowserScanJob defines a browser-based DAST scan job.
type BrowserScanJob struct {
	ID            string                 `json:"id"`
	ProjectID     string                 `json:"project_id"`
	TargetBaseURL string                 `json:"target_base_url"`
	SeedURLs      []string               `json:"seed_urls"`
	AllowedHosts  []string               `json:"allowed_hosts"`
	PinnedIPs     map[string][]string    `json:"pinned_ips"`
	AuthConfig    *authbroker.AuthConfig  `json:"auth_config,omitempty"`
	ScopeConfig   scope.Config           `json:"-"`
	MaxURLs       int                    `json:"max_urls"`
	MaxDepth      int                    `json:"max_depth"`
	MaxDuration   time.Duration          `json:"max_duration"`
	PageTimeout   time.Duration          `json:"page_timeout"`
}

// BrowserScanResult contains the outcome of a browser-based DAST scan.
type BrowserScanResult struct {
	ScanJobID       string        `json:"scan_job_id"`
	WorkerID        string        `json:"worker_id"`
	Status          string        `json:"status"` // completed, failed, aborted
	Findings        []dast.Finding `json:"findings"`
	PagesVisited    int           `json:"pages_visited"`
	ScopeViolations int64         `json:"scope_violations"`
	Duration        time.Duration `json:"duration"`
	StartedAt       time.Time     `json:"started_at"`
	CompletedAt     time.Time     `json:"completed_at"`
	Error           string        `json:"error,omitempty"`
}

// DestructiveKeywords contains words that indicate a form action is destructive.
// Even though the crawler is not yet implemented, this safety list is a security foundation.
var DestructiveKeywords = []string{
	"delete",
	"remove",
	"cancel",
	"unsubscribe",
	"pay",
	"purchase",
	"transfer",
	"send",
	"destroy",
	"drop",
	"terminate",
	"revoke",
}

// IsDestructiveAction checks if the given text contains any destructive keyword (case-insensitive).
func IsDestructiveAction(text string) bool {
	lower := strings.ToLower(text)
	for _, kw := range DestructiveKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
