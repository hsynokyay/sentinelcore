package credentials

import "context"

// Event type constants for credential lifecycle. Defined here (rather than in
// internal/audit/dast_events.go) to keep this package self-contained — the
// CLI binary is the only writer that emits these and it injects an
// AuditWriter implementation at construction.
const (
	EventDASTCredentialAdded   = "dast.credential.added"
	EventDASTCredentialLoaded  = "dast.credential.loaded"
	EventDASTCredentialRemoved = "dast.credential.removed"
)

// AuditWriter writes a single audit event. We avoid importing internal/audit
// here so this package stays decoupled — CLI/controlplane wires the real
// writer at startup. This mirrors the pattern in internal/dast/bundles.
type AuditWriter interface {
	Write(ctx context.Context, eventType string, resourceID string, details map[string]any) error
}

// NoopAuditWriter is a no-op AuditWriter used when no writer is wired in.
type NoopAuditWriter struct{}

// Write implements AuditWriter as a no-op.
func (NoopAuditWriter) Write(_ context.Context, _, _ string, _ map[string]any) error {
	return nil
}

// EmitAdded records a dast.credential.added event. Errors from the writer are
// best-effort (audit failures must not break the CLI flow); callers may
// inspect the returned error if they want to log it.
func EmitAdded(ctx context.Context, w AuditWriter, bundleID, vaultKey string) error {
	if w == nil {
		return nil
	}
	return w.Write(ctx, EventDASTCredentialAdded, bundleID, map[string]any{
		"vault_key": vaultKey,
	})
}

// EmitLoaded records a dast.credential.loaded event.
func EmitLoaded(ctx context.Context, w AuditWriter, bundleID, vaultKey string) error {
	if w == nil {
		return nil
	}
	return w.Write(ctx, EventDASTCredentialLoaded, bundleID, map[string]any{
		"vault_key": vaultKey,
	})
}

// EmitRemoved records a dast.credential.removed event.
func EmitRemoved(ctx context.Context, w AuditWriter, bundleID, vaultKey string) error {
	if w == nil {
		return nil
	}
	return w.Write(ctx, EventDASTCredentialRemoved, bundleID, map[string]any{
		"vault_key": vaultKey,
	})
}
