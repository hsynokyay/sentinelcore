package replay

import (
	"context"
	"fmt"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/recording"
)

// VerifyPostState recomputes the post-state skeleton hash in the current
// chromedp context and compares it to the expected value. An empty expected
// hash (legacy bundles) skips the check.
func VerifyPostState(ctx context.Context, expected string) error {
	if expected == "" {
		return nil
	}
	got, err := recording.ComputePostStateHash(ctx)
	if err != nil {
		return fmt.Errorf("postate: compute: %w", err)
	}
	if got != expected {
		return fmt.Errorf("postate: skeleton hash mismatch (refresh_required): got %s, want %s", got, expected)
	}
	return nil
}
