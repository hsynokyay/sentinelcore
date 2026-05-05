package replay

import (
	"context"
	"testing"
	"time"
)

func TestCheckActionDuration_WithinThreshold(t *testing.T) {
	if err := CheckActionDuration(150*time.Millisecond, 100); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCheckActionDuration_AtThreshold(t *testing.T) {
	// Exactly 3x baseline should pass (only > limit returns error).
	if err := CheckActionDuration(300*time.Millisecond, 100); err != nil {
		t.Fatalf("unexpected at exact 3x: %v", err)
	}
}

func TestCheckActionDuration_Exceeds(t *testing.T) {
	if err := CheckActionDuration(400*time.Millisecond, 100); err == nil {
		t.Fatal("expected anomaly")
	}
}

func TestCheckActionDuration_LegacyZero(t *testing.T) {
	if err := CheckActionDuration(10*time.Second, 0); err != nil {
		t.Fatalf("legacy bundles must skip: %v", err)
	}
}

func TestCheckActionDuration_LegacyNegative(t *testing.T) {
	if err := CheckActionDuration(10*time.Second, -1); err != nil {
		t.Fatalf("negative recordedMs must skip: %v", err)
	}
}

func TestAggregateBudget_LegacyZeroReturnsParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	ctx, cancel := AggregateBudget(parent, 0)
	defer cancel()
	if ctx != parent {
		t.Fatal("expected parent context returned unchanged for recordedTotalMs<=0")
	}
}

func TestAggregateBudget_AppliesDeadline(t *testing.T) {
	parent := context.Background()
	ctx, cancel := AggregateBudget(parent, 100) // 3x = 300ms
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected deadline to be set")
	}
	d := time.Until(dl)
	if d <= 0 || d > 350*time.Millisecond {
		t.Fatalf("deadline outside expected window: %s", d)
	}
}
