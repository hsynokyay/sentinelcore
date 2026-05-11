package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMetricsMux_ExposesCollisionCounter verifies the /metrics endpoint
// emits the PR-A2 callgraph collision counter in Prometheus exposition
// format. Covers AUDIT-2026-05-11 HK-4 acceptance criterion #1 (endpoint
// returns 200) and #2 (4 language label-sets present at idle).
func TestMetricsMux_ExposesCollisionCounter(t *testing.T) {
	// Exercise the same boot-time priming path the worker uses so the
	// CounterVec emits a sample line per supported language at idle.
	primeMetrics()

	mux := metricsMux()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status code: got %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Prometheus exposition format markers must be present.
	for _, marker := range []string{
		"# HELP sentinelcore_sast_callgraph_overload_collisions_total",
		"# TYPE sentinelcore_sast_callgraph_overload_collisions_total counter",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("missing prom format marker: %q", marker)
		}
	}

	// All four supported language label-sets must appear at idle —
	// guarantees stable label cardinality for Prometheus alert rules.
	for _, l := range supportedLanguages {
		needle := `sentinelcore_sast_callgraph_overload_collisions_total{language="` + l + `"}`
		if !strings.Contains(body, needle) {
			t.Errorf("missing metric line for language=%s", l)
		}
	}
}

// TestPrimeMetrics_Idempotent verifies primeMetrics can be called more
// than once without inflating counter values (Add(0) is no-op semantics).
// Guards against an accidental Inc()-instead-of-Add(0) regression that
// would silently double-count on boot.
func TestPrimeMetrics_Idempotent(t *testing.T) {
	primeMetrics()
	primeMetrics()
	primeMetrics()

	// Re-fetch /metrics; every language label must read 0.
	mux := metricsMux()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	body := rec.Body.String()

	for _, l := range supportedLanguages {
		// The metric line ends with the counter value; assert " 0" suffix.
		needle := `sentinelcore_sast_callgraph_overload_collisions_total{language="` + l + `"} 0`
		if !strings.Contains(body, needle) {
			t.Errorf("language=%s: counter not zero after triple-prime (priming is not idempotent)", l)
		}
	}
}

// TestMetricsMux_404OnOtherPaths guards against accidentally exposing
// a default handler — only /metrics should respond.
func TestMetricsMux_404OnOtherPaths(t *testing.T) {
	mux := metricsMux()

	for _, path := range []string{"/", "/healthz", "/admin"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Errorf("path %q: status %d, want 404", path, rec.Code)
		}
	}
}
