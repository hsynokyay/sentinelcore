package main

import "testing"

// TestGetEnv_Fallback ensures the env-helper used by main returns the fallback
// when no var is set. The integration test for the worker itself lives in
// internal/governance/slaworker.
func TestGetEnv_Fallback(t *testing.T) {
	t.Setenv("SLA_WORKER_TEST_VAR_UNSET", "")
	if v := getEnv("SLA_WORKER_TEST_VAR_UNSET", "fallback"); v != "fallback" {
		t.Errorf("expected fallback, got %q", v)
	}
	t.Setenv("SLA_WORKER_TEST_VAR_SET", "real")
	if v := getEnv("SLA_WORKER_TEST_VAR_SET", "fallback"); v != "real" {
		t.Errorf("expected real, got %q", v)
	}
}
