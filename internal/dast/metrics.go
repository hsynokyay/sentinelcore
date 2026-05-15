package dast

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Scope enforcement metrics
	scopeViolationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "dast",
		Name:      "scope_violations_total",
		Help:      "Total number of scope enforcement violations by type.",
	}, []string{"type"})

	scopeChecksTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "dast",
		Name:      "scope_checks_total",
		Help:      "Total number of scope enforcement checks performed.",
	})

	// Scan metrics
	scanRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "dast",
		Name:      "scan_requests_total",
		Help:      "Total DAST scan requests by status.",
	}, []string{"status"})

	scanRequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "sentinelcore",
		Subsystem: "dast",
		Name:      "scan_request_duration_seconds",
		Help:      "Duration of individual DAST scan requests.",
		Buckets:   prometheus.DefBuckets,
	})

	findingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "dast",
		Name:      "findings_total",
		Help:      "Total DAST findings by severity.",
	}, []string{"severity", "category"})

	scansCompleted = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "dast",
		Name:      "scans_completed_total",
		Help:      "Total completed DAST scans by status.",
	}, []string{"status"})

	// Auth broker metrics
	authSessionsCreated = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "auth_broker",
		Name:      "sessions_created_total",
		Help:      "Total auth sessions created by strategy.",
	}, []string{"strategy"})

	authSessionFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "auth_broker",
		Name:      "session_failures_total",
		Help:      "Total auth session creation failures by strategy.",
	}, []string{"strategy"})

	// Evidence metrics
	evidenceCaptured = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "dast",
		Name:      "evidence_captured_total",
		Help:      "Total evidence records captured.",
	})

	evidenceRedactions = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "sentinelcore",
		Subsystem: "dast",
		Name:      "evidence_redactions_total",
		Help:      "Total credential redactions applied in evidence.",
	})
)

// RecordScopeViolation increments the scope violation counter.
func RecordScopeViolation(violationType string) {
	scopeViolationsTotal.WithLabelValues(violationType).Inc()
}

// RecordEvidenceRedaction increments the credential-redaction counter.
// Called by the evidence pipeline whenever it strips secret-looking
// tokens from a response body before persisting evidence.
func RecordEvidenceRedaction() { evidenceRedactions.Inc() }

// RecordScopeCheck increments the scope check counter.
func RecordScopeCheck() {
	scopeChecksTotal.Inc()
}

// RecordScanRequest records a scan request outcome.
func RecordScanRequest(status string, durationSecs float64) {
	scanRequestsTotal.WithLabelValues(status).Inc()
	scanRequestDuration.Observe(durationSecs)
}

// RecordFinding records a discovered finding.
func RecordFinding(severity, category string) {
	findingsTotal.WithLabelValues(severity, category).Inc()
}

// RecordScanCompleted records a completed scan.
func RecordScanCompleted(status string) {
	scansCompleted.WithLabelValues(status).Inc()
}

// RecordAuthSession records auth session creation.
func RecordAuthSession(strategy string, success bool) {
	if success {
		authSessionsCreated.WithLabelValues(strategy).Inc()
	} else {
		authSessionFailures.WithLabelValues(strategy).Inc()
	}
}

// RecordEvidenceCaptured records evidence capture.
func RecordEvidenceCaptured() {
	evidenceCaptured.Inc()
}
