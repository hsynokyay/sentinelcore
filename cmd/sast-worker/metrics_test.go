package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/observability"
)

// TestMetricsMux_ExposesCollisionCounter verifies the /metrics endpoint
// emits the PR-A2 callgraph collision counter in Prometheus exposition
// format. Covers AUDIT-2026-05-11 HK-4 acceptance criterion #1 (endpoint
// returns 200) and #2 (4 language label-sets present after they have
// been touched).
func TestMetricsMux_ExposesCollisionCounter(t *testing.T) {
	// Touch each language so the CounterVec emits a sample line per label.
	// Add(0) is a no-op on the value but materializes the label set in the
	// underlying child map so promhttp.Handler emits it.
	for _, l := range []string{"java", "python", "javascript", "csharp"} {
		observability.SASTCallgraphOverloadCollisions.WithLabelValues(l).Add(0)
	}

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

	// All four language label-sets must appear after being touched.
	for _, l := range []string{"java", "python", "javascript", "csharp"} {
		needle := `sentinelcore_sast_callgraph_overload_collisions_total{language="` + l + `"}`
		if !strings.Contains(body, needle) {
			t.Errorf("missing metric line for language=%s", l)
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
