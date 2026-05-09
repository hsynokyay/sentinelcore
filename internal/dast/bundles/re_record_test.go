package bundles

import (
	"context"
	"errors"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// TestReRecord_HappyPath drives the supersede transition on a real Postgres
// instance. Skips without TEST_DATABASE_URL; the migration set must be
// up-to-date through 051_dast_bundle_supersede so the column + status
// constraint exist.
func TestReRecord_HappyPath(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()

	k := kms.NewLocalProvider([]byte("test-master-key-32-bytes-of-entropy!"))
	store := NewPostgresStore(pool, k, "test-hmac", "alias/test", InlineObjectStore{})

	customerID := "11111111-aaaa-aaaa-aaaa-111111111111"
	creator := "22222222-aaaa-aaaa-aaaa-222222222222"
	caller := "33333333-aaaa-aaaa-aaaa-333333333333"

	src := &Bundle{
		ProjectID:       "44444444-aaaa-aaaa-aaaa-444444444444",
		TargetHost:      "app.bank.tld",
		TargetPrincipal: "user@example.tld",
		PrincipalClaim:  "sub",
		Type:            "session_import",
		CreatedByUserID: creator,
		TTLSeconds:      3600,
		CapturedSession: SessionCapture{
			Cookies: []Cookie{{Name: "JSESSIONID", Value: "abc"}},
			Headers: map[string]string{"Authorization": "Bearer xyz"},
		},
	}
	srcID, err := store.Save(context.Background(), src, customerID)
	if err != nil {
		t.Fatalf("Save source: %v", err)
	}
	defer pool.Exec(context.Background(),
		`DELETE FROM dast_auth_bundles WHERE id = $1 OR superseded_by = $1 OR id = (SELECT superseded_by FROM dast_auth_bundles WHERE id = $1)`,
		srcID)

	draft, err := ReRecord(context.Background(), store, srcID, caller, customerID, "creds rotated")
	if err != nil {
		t.Fatalf("ReRecord: %v", err)
	}
	if draft == nil || draft.ID == "" {
		t.Fatal("ReRecord returned no draft")
	}
	if draft.ID == srcID {
		t.Fatal("ReRecord returned source ID — expected fresh draft ID")
	}

	// Source should now be superseded with superseded_by pointing at draft.
	var srcStatus string
	var srcSupersededBy *string
	err = pool.QueryRow(context.Background(),
		`SELECT status, superseded_by FROM dast_auth_bundles WHERE id = $1`,
		srcID).Scan(&srcStatus, &srcSupersededBy)
	if err != nil {
		t.Fatalf("query source row: %v", err)
	}
	if srcStatus != "superseded" {
		t.Errorf("source status = %q, want 'superseded'", srcStatus)
	}
	if srcSupersededBy == nil || *srcSupersededBy != draft.ID {
		got := "<nil>"
		if srcSupersededBy != nil {
			got = *srcSupersededBy
		}
		t.Errorf("source.superseded_by = %s, want %s", got, draft.ID)
	}

	// Draft should be pending_review with target metadata copied.
	var draftStatus, draftTargetHost, draftPrincipalClaim, draftType string
	var draftTTL int
	err = pool.QueryRow(context.Background(),
		`SELECT status, target_host, principal_claim, type, ttl_seconds FROM dast_auth_bundles WHERE id = $1`,
		draft.ID).Scan(&draftStatus, &draftTargetHost, &draftPrincipalClaim, &draftType, &draftTTL)
	if err != nil {
		t.Fatalf("query draft row: %v", err)
	}
	if draftStatus != "pending_review" {
		t.Errorf("draft status = %q, want 'pending_review'", draftStatus)
	}
	if draftTargetHost != src.TargetHost {
		t.Errorf("draft target_host = %q, want %q", draftTargetHost, src.TargetHost)
	}
	if draftPrincipalClaim != src.PrincipalClaim {
		t.Errorf("draft principal_claim = %q, want %q", draftPrincipalClaim, src.PrincipalClaim)
	}
	if draftType != src.Type {
		t.Errorf("draft type = %q, want %q", draftType, src.Type)
	}
	if draftTTL != src.TTLSeconds {
		t.Errorf("draft ttl_seconds = %d, want %d", draftTTL, src.TTLSeconds)
	}
}

// TestReRecord_Missing returns the underlying store error when the source
// id does not exist for the caller's tenant.
func TestReRecord_Missing(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()

	k := kms.NewLocalProvider([]byte("test-master-key-32-bytes-of-entropy!"))
	store := NewPostgresStore(pool, k, "test-hmac", "alias/test", InlineObjectStore{})

	_, err := ReRecord(context.Background(), store,
		"00000000-0000-0000-0000-000000000099",
		"55555555-aaaa-aaaa-aaaa-555555555555",
		"66666666-aaaa-aaaa-aaaa-666666666666",
		"")
	if err == nil {
		t.Fatal("expected error for missing source bundle")
	}
	if !errors.Is(err, ErrBundleNotFound) {
		t.Errorf("expected ErrBundleNotFound chain, got %v", err)
	}
}

// TestReRecord_AlreadySuperseded refuses a second re-record on a source
// that has already been flipped, preventing duplicate replacement chains.
func TestReRecord_AlreadySuperseded(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()

	k := kms.NewLocalProvider([]byte("test-master-key-32-bytes-of-entropy!"))
	store := NewPostgresStore(pool, k, "test-hmac", "alias/test", InlineObjectStore{})

	customerID := "77777777-aaaa-aaaa-aaaa-777777777777"
	creator := "88888888-aaaa-aaaa-aaaa-888888888888"
	caller := "99999999-aaaa-aaaa-aaaa-999999999999"

	src := &Bundle{
		ProjectID:       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		TargetHost:      "app.bank.tld",
		PrincipalClaim:  "sub",
		Type:            "session_import",
		CreatedByUserID: creator,
		TTLSeconds:      3600,
		CapturedSession: SessionCapture{Headers: map[string]string{}},
	}
	srcID, err := store.Save(context.Background(), src, customerID)
	if err != nil {
		t.Fatalf("Save source: %v", err)
	}
	defer pool.Exec(context.Background(),
		`DELETE FROM dast_auth_bundles WHERE id = $1 OR superseded_by = $1`, srcID)

	first, err := ReRecord(context.Background(), store, srcID, caller, customerID, "first")
	if err != nil {
		t.Fatalf("first ReRecord: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM dast_auth_bundles WHERE id = $1`, first.ID)

	_, err = ReRecord(context.Background(), store, srcID, caller, customerID, "second")
	if err == nil {
		t.Fatal("expected error on second re-record of already-superseded source")
	}
	// Load returns successfully (status 'superseded' is not in Load's
	// rejection set), so ReRecord catches it via the Status field check
	// and returns ErrAlreadySuperseded directly.
	if !errors.Is(err, ErrAlreadySuperseded) {
		t.Errorf("expected ErrAlreadySuperseded, got %v", err)
	}
}
