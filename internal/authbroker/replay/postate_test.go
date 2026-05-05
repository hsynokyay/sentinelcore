package replay

import (
	"context"
	"testing"
)

func TestVerifyPostState_EmptyExpectedSkips(t *testing.T) {
	if err := VerifyPostState(context.Background(), ""); err != nil {
		t.Fatalf("legacy bundle must skip: %v", err)
	}
}
