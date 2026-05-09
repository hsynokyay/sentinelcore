// Package metrics defines DAST-specific Prometheus collectors for the
// SentinelCore replay subsystem.
//
// Metrics are constructed via prometheus.NewCounter/NewGauge (NOT promauto)
// so that callers can choose the registry — `Register(prometheus.DefaultRegisterer)`
// for the shared default registry that the existing controlplane /metrics
// endpoint serves, or a fresh `prometheus.NewRegistry()` for tests.
//
// Plan #6, PR B (spec §4.1–4.2). Emit-sites land alongside the replay
// engine code introduced by plan #5 (circuit breaker, anomaly detector,
// post-state hash, principal binding) and the credentials store; see
// `internal/authbroker/replay/replayer.go` and
// `internal/dast/credentials/store.go` once those land.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// ReplayTotal counts every Engine.Replay call by terminal result. The
// `result` label is one of:
//   - "success"
//   - "failure_circuit"   (circuit-open short-circuit)
//   - "failure_anomaly"   (anomaly detector tripped)
//   - "failure_postate"   (post-state hash mismatch)
//   - "failure_principal" (principal binding mismatch)
//   - "failure_ratelimit" (host rate-limit reject)
//   - "failure_host"      (host-mismatch reject)
//   - "failure_action"    (per-action chromedp / replay step error)
//   - "failure_other"     (uncategorised failure)
var ReplayTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "dast_replay_total",
	Help: "DAST replay attempts by result.",
}, []string{"result"})

// CircuitState reports the current breaker state for each bundle.
// 0 == closed (replays allowed), 1 == open (replays short-circuited).
var CircuitState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "dast_replay_circuit_state",
	Help: "Replay circuit breaker state per bundle (0=closed, 1=open).",
}, []string{"bundle_id"})

// AnomalyTotal counts replay anomaly-detector trips. Always emitted
// alongside ReplayTotal{result="failure_anomaly"} for double-bookkeeping.
var AnomalyTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "dast_replay_anomaly_total",
	Help: "Replay anomaly-detector trips.",
})

// PostStateMismatchTotal counts replay post-state hash mismatches.
// Always emitted alongside ReplayTotal{result="failure_postate"}.
var PostStateMismatchTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "dast_replay_postate_mismatch_total",
	Help: "Replay post-state hash mismatches.",
})

// PrincipalMismatchTotal counts replay principal-binding mismatches.
// Always emitted alongside ReplayTotal{result="failure_principal"}.
var PrincipalMismatchTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "dast_replay_principal_mismatch_total",
	Help: "Replay principal-binding mismatches.",
})

// CredentialLoadTotal counts credential store Load calls by result.
// The `result` label is one of:
//   - "success"
//   - "not_found"      (bundle / row missing)
//   - "decrypt_error"  (envelope decrypt or AAD mismatch)
//   - "error"          (other I/O / db errors)
var CredentialLoadTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "dast_credential_load_total",
	Help: "Credential store Load attempts by result.",
}, []string{"result"})

// Register registers all DAST metrics with r. Tolerant of repeat-registration
// errors so test reruns and idempotent main() calls do not crash; any other
// error from r.Register is returned to the caller.
//
// Call once from controlplane main with prometheus.DefaultRegisterer to
// expose the metrics on the existing /metrics endpoint.
func Register(r prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		ReplayTotal,
		CircuitState,
		AnomalyTotal,
		PostStateMismatchTotal,
		PrincipalMismatchTotal,
		CredentialLoadTotal,
	} {
		if err := r.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				return err
			}
		}
	}
	return nil
}
