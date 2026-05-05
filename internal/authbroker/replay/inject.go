package replay

import (
	"context"
	"errors"
	"fmt"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
)

// InjectFill loads the credential keyed by action.VaultKey from the credential
// store and types it into the field identified by action.Selector. The
// plaintext is overwritten in memory before this function returns so the
// secret is not retained on the heap longer than necessary.
//
// InjectFill is intended to be called from within an active chromedp context
// (typically the per-action timeoutCtx maintained by the Engine). Errors from
// the underlying store (including credentials.ErrNotFound) are wrapped with
// the prefix "inject: credential load:" so callers can identify the failure
// class via errors.Is.
func InjectFill(ctx context.Context, store credentials.Store, bundleID uuid.UUID, action bundles.Action) error {
	if action.Kind != bundles.ActionFill {
		return fmt.Errorf("inject: action kind %q is not fill", action.Kind)
	}
	if action.VaultKey == "" {
		return fmt.Errorf("inject: fill action has no vault_key")
	}
	if action.Selector == "" {
		return fmt.Errorf("inject: fill action has no selector")
	}
	if store == nil {
		return errors.New("inject: nil credential store")
	}

	plain, err := store.Load(ctx, bundleID, action.VaultKey)
	if err != nil {
		return fmt.Errorf("inject: credential load: %w", err)
	}
	defer zeroBytes(plain)

	return chromedp.Run(ctx, chromedp.SendKeys(action.Selector, string(plain), chromedp.ByQuery))
}

// zeroBytes overwrites every byte of b with 0. Best-effort scrubbing — Go's
// runtime may have copied the slice elsewhere, but this at least prevents the
// most obvious post-use leaks (e.g. memory dumps, reused buffers).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
