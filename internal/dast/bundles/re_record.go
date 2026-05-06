package bundles

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrAlreadySuperseded indicates an attempt to re-record a bundle whose
// status is already 'superseded'. The caller should fetch the replacement
// (via the superseded_by column) and re-record from there if needed.
var ErrAlreadySuperseded = errors.New("bundles: source bundle is already superseded")

// ReRecordStore is the minimal subset of BundleStore methods plus the
// MarkSupersededBy helper needed by ReRecord. PostgresStore satisfies it.
//
// We keep this surface narrow so unit tests can inject a fake without
// re-implementing the entire BundleStore.
type ReRecordStore interface {
	Load(ctx context.Context, id, customerID string) (*Bundle, error)
	Save(ctx context.Context, b *Bundle, customerID string) (string, error)
	MarkSupersededBy(ctx context.Context, srcID, newID, customerID string) error
}

// ReRecord creates a fresh draft bundle that replaces an existing source
// bundle. The source is flipped to status='superseded' and its superseded_by
// column points at the new draft (still in pending_review) so the audit
// trail is preserved.
//
// Returns the new Bundle (with ID populated) on success. Errors:
//   - the underlying store error if Load fails (including ErrBundleNotFound).
//   - ErrAlreadySuperseded if the source row's status is already 'superseded'.
//   - any error returned by Save when persisting the draft.
//
// Ordering: we Save the draft FIRST (so the new ID exists), then atomically
// flip the source via MarkSupersededBy. If the link step fails, the draft
// remains visible as a fresh pending_review bundle and an operator can
// recover; if we instead flipped the source first and the Save failed we
// would leave the source orphaned with no replacement.
//
// The reason argument is currently audit-only (recorded as a metadata
// field on the new draft via metadata_jsonb is intentionally deferred to a
// follow-up: keeping the function signature stable matches plan #6 D.2).
func ReRecord(ctx context.Context, store ReRecordStore, oldID, callerUserID, callerOrgID, reason string) (*Bundle, error) {
	if store == nil {
		return nil, fmt.Errorf("re-record: nil store")
	}
	if oldID == "" {
		return nil, fmt.Errorf("re-record: old bundle id required")
	}
	if callerOrgID == "" {
		return nil, fmt.Errorf("re-record: caller org id required")
	}
	if callerUserID == "" {
		return nil, fmt.Errorf("re-record: caller user id required")
	}

	// 1. Load the source bundle (also verifies tenant ownership via Load's
	//    customer_id WHERE clause).
	src, err := store.Load(ctx, oldID, callerOrgID)
	if err != nil {
		return nil, fmt.Errorf("re-record: load source: %w", err)
	}

	// 2. Refuse to re-record an already-superseded bundle. The replacement
	//    chain should be followed by the operator instead.
	if src.Status == "superseded" {
		return nil, ErrAlreadySuperseded
	}

	// 3. Build the new draft. Empty actions + empty session — the operator
	//    fills it in via `dast record --bundle <new-id>` afterwards.
	now := time.Now().UTC()
	ttl := src.TTLSeconds
	if ttl <= 0 {
		ttl = 86400
	}
	draft := &Bundle{
		// SchemaVersion is overwritten by Save (always 1 today) but we
		// carry the source's value so any future bump is preserved.
		SchemaVersion:   src.SchemaVersion,
		ProjectID:       src.ProjectID,
		TargetHost:      src.TargetHost,
		TargetPrincipal: src.TargetPrincipal,
		PrincipalClaim:  src.PrincipalClaim,
		Type:            src.Type,
		// CapturedSession deliberately empty — the operator records anew.
		CapturedSession: SessionCapture{Headers: map[string]string{}},
		CreatedByUserID: callerUserID,
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Duration(ttl) * time.Second),
		TTLSeconds:      ttl,
	}

	// 4. Persist the draft. Save returns its assigned ID and inserts at
	//    status='pending_review' (set inline by the SQL).
	newID, err := store.Save(ctx, draft, callerOrgID)
	if err != nil {
		return nil, fmt.Errorf("re-record: save draft: %w", err)
	}
	draft.ID = newID

	// 5. Atomically flip the source row. If this fails the draft remains
	//    as an orphan pending_review bundle that an operator can use; the
	//    source is unchanged.
	if err := store.MarkSupersededBy(ctx, oldID, newID, callerOrgID); err != nil {
		return nil, fmt.Errorf("re-record: mark superseded: %w", err)
	}

	// 6. Reflect the link on the returned source state for callers that
	//    might pass the result to follow-on logging. The draft itself
	//    carries newID via .ID.
	_ = reason // reserved for future audit metadata wiring
	return draft, nil
}
