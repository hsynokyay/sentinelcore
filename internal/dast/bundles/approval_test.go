package bundles

import (
	"testing"
)

func TestApproval_StateMachineCompiles(t *testing.T) {
	var _ BundleStore = &PostgresStore{}
	if ErrApprovalSelfRecorder == nil {
		t.Fatal("expected sentinel error to be defined")
	}
}
