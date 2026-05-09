package replay

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
)

// fakeCredStore is a hand-rolled credentials.Store double for unit tests.
// It satisfies the full Store interface so it can substitute for a Postgres
// store in InjectFill / Engine tests that don't need real persistence.
type fakeCredStore struct {
	loadErr error
	value   []byte
}

func (f *fakeCredStore) Save(_ context.Context, _, _ uuid.UUID, _ string, _ []byte) error {
	return nil
}

func (f *fakeCredStore) Load(_ context.Context, _ uuid.UUID, _ string) ([]byte, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	// Return a fresh copy so callers can scrub without affecting the fixture.
	return append([]byte(nil), f.value...), nil
}

func (f *fakeCredStore) Delete(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

func (f *fakeCredStore) ListKeys(_ context.Context, _ uuid.UUID) ([]string, error) {
	return nil, nil
}

func TestInjectFill_RejectsNonFillKind(t *testing.T) {
	err := InjectFill(context.Background(), &fakeCredStore{}, uuid.New(),
		bundles.Action{Kind: bundles.ActionClick, Selector: "#x", VaultKey: "k"})
	if err == nil || !strings.Contains(err.Error(), "is not fill") {
		t.Fatalf("expected kind rejection, got %v", err)
	}
}

func TestInjectFill_MissingVaultKey(t *testing.T) {
	err := InjectFill(context.Background(), &fakeCredStore{}, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, Selector: "#x"})
	if err == nil || !strings.Contains(err.Error(), "vault_key") {
		t.Fatalf("expected vault_key rejection, got %v", err)
	}
}

func TestInjectFill_MissingSelector(t *testing.T) {
	err := InjectFill(context.Background(), &fakeCredStore{}, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, VaultKey: "k"})
	if err == nil || !strings.Contains(err.Error(), "selector") {
		t.Fatalf("expected selector rejection, got %v", err)
	}
}

func TestInjectFill_LoadErrorBubbles(t *testing.T) {
	err := InjectFill(context.Background(),
		&fakeCredStore{loadErr: errors.New("boom")}, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, Selector: "#x", VaultKey: "k"})
	if err == nil || !strings.Contains(err.Error(), "credential load") {
		t.Fatalf("expected credential load error, got %v", err)
	}
}

func TestInjectFill_NotFoundIsRecognisable(t *testing.T) {
	// Callers that want to distinguish "missing credential" from other store
	// failures rely on errors.Is — make sure the wrap chain preserves it.
	err := InjectFill(context.Background(),
		&fakeCredStore{loadErr: credentials.ErrNotFound}, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, Selector: "#x", VaultKey: "k"})
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("expected errors.Is(err, credentials.ErrNotFound), got %v", err)
	}
}

func TestInjectFill_NilStore(t *testing.T) {
	err := InjectFill(context.Background(), nil, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, Selector: "#x", VaultKey: "k"})
	if err == nil || !strings.Contains(err.Error(), "nil credential store") {
		t.Fatalf("expected nil-store rejection, got %v", err)
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte("secret")
	zeroBytes(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d not zero: %v", i, c)
		}
	}
}
