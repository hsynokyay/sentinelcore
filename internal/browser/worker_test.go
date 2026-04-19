package browser

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/internal/authbroker"
)

func TestNewBrowserWorker(t *testing.T) {
	broker := authbroker.NewBroker(zerolog.Nop())
	w := NewBrowserWorker("worker-1", broker, zerolog.Nop())

	if w.WorkerID != "worker-1" {
		t.Errorf("expected WorkerID 'worker-1', got %q", w.WorkerID)
	}
	if w.broker == nil {
		t.Error("expected broker to be set")
	}
}

func TestExecuteScan_NilJob(t *testing.T) {
	broker := authbroker.NewBroker(zerolog.Nop())
	w := NewBrowserWorker("worker-1", broker, zerolog.Nop())

	// Empty job should fail.
	result, err := w.ExecuteScan(nil, BrowserScanJob{})
	if err == nil {
		t.Error("expected error for empty job")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if result.Status != "failed" {
		t.Errorf("expected status 'failed', got %q", result.Status)
	}
}

func TestExecuteScan_MissingTarget(t *testing.T) {
	broker := authbroker.NewBroker(zerolog.Nop())
	w := NewBrowserWorker("worker-2", broker, zerolog.Nop())

	result, err := w.ExecuteScan(nil, BrowserScanJob{ID: "job-1"})
	if err == nil {
		t.Error("expected error for missing target URL")
	}
	if result.Status != "failed" {
		t.Errorf("expected status 'failed', got %q", result.Status)
	}
}
