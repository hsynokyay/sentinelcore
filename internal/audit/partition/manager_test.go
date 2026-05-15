package partition

import (
	"context"
	"testing"
	"time"
)

// Most of the manager is a thin wrapper around SQL. We unit-test only the
// argument-validation branches; the happy-path belongs in an integration
// test that needs a live postgres.

func TestEnsureRollingWindow_RejectsNegative(t *testing.T) {
	m := &Manager{}
	if _, err := m.EnsureRollingWindow(context.Background(), -1); err == nil {
		t.Fatal("expected error for negative monthsAhead")
	}
}

func TestRunDaily_RespectsContextCancel(t *testing.T) {
	// Ensure the loop exits promptly on ctx cancel. Nil pool means the
	// first run() call will panic on Exec, so we capture recoverable
	// crashes by running the blocking call in a goroutine with a tiny
	// deadline — the goal here is only to exercise the ticker-exit path.
	t.Skip("integration-gated; pool not available in unit tests")

	// Placeholder for future integration-style run with pool from env.
	_ = context.Background()
	_ = time.Second
}
