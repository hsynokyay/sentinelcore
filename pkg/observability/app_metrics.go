package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// SentinelCore application metrics. All metrics are registered via promauto
// which handles registration + collection automatically with the default
// Prometheus registry (served by MetricsHandler).

// --- Scan metrics ---

var ScanCreated = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_scan_created_total",
	Help: "Total scans created, labeled by type and trigger.",
}, []string{"scan_type", "trigger_type"})

var ScanCompleted = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_scan_completed_total",
	Help: "Total scans completed, labeled by type and status.",
}, []string{"scan_type", "status"})

var ScanDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "sentinelcore_scan_duration_seconds",
	Help:    "Scan execution duration in seconds.",
	Buckets: prometheus.ExponentialBuckets(1, 2, 12), // 1s to ~68m
}, []string{"scan_type"})

var FindingsProduced = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "sentinelcore_findings_per_scan",
	Help:    "Number of findings produced per scan.",
	Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1 to 512
}, []string{"scan_type"})

// --- Worker metrics ---

var WorkerJobsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_worker_jobs_processed_total",
	Help: "Total jobs processed by scan workers.",
}, []string{"worker_type", "status"})

var WorkerQueueLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "sentinelcore_worker_queue_latency_seconds",
	Help:    "Time from scan creation to worker pickup.",
	Buckets: prometheus.ExponentialBuckets(0.1, 2, 12),
}, []string{"worker_type"})

// --- Export metrics ---

var ExportRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_export_requests_total",
	Help: "Total export requests by format.",
}, []string{"format", "scope"})

// --- Webhook metrics ---

var WebhookDeliveries = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_webhook_deliveries_total",
	Help: "Total webhook delivery attempts.",
}, []string{"event", "status"})

var WebhookLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "sentinelcore_webhook_delivery_seconds",
	Help:    "Webhook delivery latency.",
	Buckets: prometheus.DefBuckets,
}, []string{"event"})

// --- API key metrics ---

var APIKeyAuths = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_apikey_auth_total",
	Help: "Total API key authentication attempts.",
}, []string{"status"})

// --- Audit integrity metrics ---

// AuditIntegrityChecks counts chain-verification outcomes per partition.
// A pass is expected every hour; a fail is pager-escalated in chunk 9.
var AuditIntegrityChecks = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_audit_integrity_check_total",
	Help: "Audit chain verification runs, by partition and outcome (pass|fail|partial|error).",
}, []string{"partition", "outcome"})

// AuditEventsIngested counts events successfully written to audit.audit_log.
// Bumped by the audit-service consumer on each commit.
var AuditEventsIngested = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_audit_events_ingested_total",
	Help: "Audit events persisted to audit.audit_log, by action domain.",
}, []string{"action_domain"})

// --- HTTP request metrics (general) ---

var HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_http_requests_total",
	Help: "Total HTTP requests.",
}, []string{"method", "path", "status"})

var HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "sentinelcore_http_request_duration_seconds",
	Help:    "HTTP request duration.",
	Buckets: prometheus.DefBuckets,
}, []string{"method", "path"})

// --- SAST metrics ---
//
// First entry in this section establishes the naming convention precedent
// for SAST observability: prefix `sentinelcore_sast_*`, `_total` suffix
// for counters, low-cardinality labels only. Per-rule labels are
// intentionally avoided where the emit site is rule-agnostic. Sprint 1.5
// housekeeping will formalize the convention in a dedicated document.

// SASTCallgraphOverloadCollisions counts overload collisions during call
// graph construction: the same FQN observed more than once because
// SentinelIR Function.FQN does not yet include parameter-type mangling
// (deferred to Sprint 4 frontend chunk per AUDIT-2026-05-11, P0-4).
// First-declared method wins; subsequent overloads are dropped from the
// graph and counted here so the impact surface is sized before committing
// to a full FQN-mangling redesign. Paired with a Debug-level log entry at
// the emit site that records which method displaced which.
var SASTCallgraphOverloadCollisions = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sentinelcore_sast_callgraph_overload_collisions_total",
	Help: "Callgraph overload collisions: same FQN reseen with different " +
		"parameter signature. First-declared method kept; subsequent " +
		"overloads dropped.",
}, []string{"language"})
