package replay

import (
	"context"
	"fmt"
	"time"
)

// CheckActionDuration returns an error if the observed duration exceeds 3x the
// recorded baseline. recordedMs <= 0 (legacy bundles without per-action
// duration) skips the check.
func CheckActionDuration(observed time.Duration, recordedMs int) error {
	if recordedMs <= 0 {
		return nil
	}
	limit := time.Duration(3*recordedMs) * time.Millisecond
	if observed > limit {
		return fmt.Errorf("anomaly: action ran %s, recorded baseline %dms (3x limit %s)", observed, recordedMs, limit)
	}
	return nil
}

// AggregateBudget returns a context whose deadline is now + 3x the sum of
// recorded action durations. recordedTotalMs <= 0 (legacy bundles) returns
// the parent context unchanged with a no-op cancel.
func AggregateBudget(parent context.Context, recordedTotalMs int) (context.Context, context.CancelFunc) {
	if recordedTotalMs <= 0 {
		return parent, func() {}
	}
	deadline := time.Now().Add(time.Duration(3*recordedTotalMs) * time.Millisecond)
	return context.WithDeadline(parent, deadline)
}
