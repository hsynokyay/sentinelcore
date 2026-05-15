package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gather drains a Collector into a slice of dto.Metric for assertions.
func gather(t *testing.T, c prometheus.Collector) []*dto.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 32)
	c.Collect(ch)
	close(ch)
	out := []*dto.Metric{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("Write: %v", err)
		}
		out = append(out, &pb)
	}
	return out
}

func TestReplayTotalIncrements(t *testing.T) {
	// Use a fresh local registry so this test does not depend on global state
	// or the order in which the test binary executes other tests.
	r := prometheus.NewRegistry()
	if err := Register(r); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ReplayTotal.WithLabelValues("success").Inc()
	ReplayTotal.WithLabelValues("failure_circuit").Inc()
	ReplayTotal.WithLabelValues("failure_circuit").Inc()

	got := gather(t, ReplayTotal)
	if len(got) < 2 {
		t.Fatalf("expected at least 2 label sets, got %d", len(got))
	}

	// Build a label-value -> count map for assertions.
	counts := map[string]float64{}
	for _, m := range got {
		var label string
		for _, l := range m.GetLabel() {
			if l.GetName() == "result" {
				label = l.GetValue()
			}
		}
		counts[label] = m.GetCounter().GetValue()
	}
	if counts["success"] < 1 {
		t.Errorf("success counter not incremented: %v", counts)
	}
	if counts["failure_circuit"] < 2 {
		t.Errorf("failure_circuit counter not incremented twice: %v", counts)
	}
}

func TestCircuitStateGauge(t *testing.T) {
	CircuitState.WithLabelValues("bundle-a").Set(1)
	CircuitState.WithLabelValues("bundle-b").Set(0)

	got := gather(t, CircuitState)
	if len(got) < 2 {
		t.Fatalf("expected 2+ gauge samples, got %d", len(got))
	}

	values := map[string]float64{}
	for _, m := range got {
		var bundle string
		for _, l := range m.GetLabel() {
			if l.GetName() == "bundle_id" {
				bundle = l.GetValue()
			}
		}
		values[bundle] = m.GetGauge().GetValue()
	}
	if values["bundle-a"] != 1 {
		t.Errorf("bundle-a gauge expected 1, got %v", values["bundle-a"])
	}
	if values["bundle-b"] != 0 {
		t.Errorf("bundle-b gauge expected 0, got %v", values["bundle-b"])
	}
}

func TestPlainCountersIncrement(t *testing.T) {
	before := struct{ a, p, pr float64 }{
		a:  counterValue(t, AnomalyTotal),
		p:  counterValue(t, PostStateMismatchTotal),
		pr: counterValue(t, PrincipalMismatchTotal),
	}

	AnomalyTotal.Inc()
	PostStateMismatchTotal.Inc()
	PrincipalMismatchTotal.Inc()

	if got := counterValue(t, AnomalyTotal); got != before.a+1 {
		t.Errorf("AnomalyTotal: want %v, got %v", before.a+1, got)
	}
	if got := counterValue(t, PostStateMismatchTotal); got != before.p+1 {
		t.Errorf("PostStateMismatchTotal: want %v, got %v", before.p+1, got)
	}
	if got := counterValue(t, PrincipalMismatchTotal); got != before.pr+1 {
		t.Errorf("PrincipalMismatchTotal: want %v, got %v", before.pr+1, got)
	}
}

func TestCredentialLoadResults(t *testing.T) {
	CredentialLoadTotal.WithLabelValues("success").Inc()
	CredentialLoadTotal.WithLabelValues("not_found").Inc()
	CredentialLoadTotal.WithLabelValues("decrypt_error").Inc()
	CredentialLoadTotal.WithLabelValues("error").Inc()

	got := gather(t, CredentialLoadTotal)
	if len(got) < 4 {
		t.Errorf("expected at least 4 label sets across known results, got %d", len(got))
	}
}

func TestRegisterIsIdempotent(t *testing.T) {
	r := prometheus.NewRegistry()
	if err := Register(r); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := Register(r); err != nil {
		t.Fatalf("second Register must tolerate AlreadyRegisteredError: %v", err)
	}
}

func TestRegisterAllCollectors(t *testing.T) {
	// Ensure every collector named in the package is registered exactly once
	// when Register is called against a fresh registry.
	r := prometheus.NewRegistry()
	if err := Register(r); err != nil {
		t.Fatalf("Register: %v", err)
	}
	mfs, err := r.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]bool{
		"dast_replay_total":                    true,
		"dast_replay_circuit_state":            true,
		"dast_replay_anomaly_total":            true,
		"dast_replay_postate_mismatch_total":   true,
		"dast_replay_principal_mismatch_total": true,
		"dast_credential_load_total":           true,
	}
	seen := map[string]bool{}
	for _, mf := range mfs {
		seen[mf.GetName()] = true
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("metric %q was not registered", name)
		}
	}
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var pb dto.Metric
	if err := c.Write(&pb); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return pb.GetCounter().GetValue()
}
