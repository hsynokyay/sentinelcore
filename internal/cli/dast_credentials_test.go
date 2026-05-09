package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
)

func TestParseBundleAndKey_Both(t *testing.T) {
	id, k, err := parseBundleAndKey([]string{
		"--bundle", "11111111-1111-1111-1111-111111111111",
		"--key", "pwd",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "pwd" {
		t.Fatalf("key: got %q, want %q", k, "pwd")
	}
	if id.String() != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("id: got %v", id)
	}
}

func TestParseBundleAndKey_BundleOnly(t *testing.T) {
	// list and other read-only ops should accept --bundle without --key.
	id, k, err := parseBundleAndKey([]string{
		"--bundle", "22222222-2222-2222-2222-222222222222",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "" {
		t.Fatalf("expected empty key, got %q", k)
	}
	if id.String() != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("id: got %v", id)
	}
}

func TestParseBundleAndKey_MissingBundle(t *testing.T) {
	_, _, err := parseBundleAndKey([]string{"--key", "pwd"})
	if err == nil {
		t.Fatal("expected error when --bundle missing")
	}
	if !strings.Contains(err.Error(), "--bundle") {
		t.Fatalf("error %q missing --bundle hint", err)
	}
}

func TestParseBundleAndKey_BadUUID(t *testing.T) {
	_, _, err := parseBundleAndKey([]string{"--bundle", "not-a-uuid"})
	if err == nil {
		t.Fatal("expected error for malformed UUID")
	}
	if !strings.Contains(err.Error(), "invalid bundle uuid") {
		t.Fatalf("error %q missing invalid-uuid hint", err)
	}
}

func TestParseBundleAndKey_FlagWithoutValue(t *testing.T) {
	// `--bundle` at end with no value — should be treated as empty bundle.
	_, _, err := parseBundleAndKey([]string{"--bundle"})
	if err == nil {
		t.Fatal("expected error when --bundle has no value")
	}
}

func TestRequireCustomerID_Missing(t *testing.T) {
	t.Setenv(CredentialsEnvCustomerID, "")
	_, err := requireCustomerID()
	if err == nil {
		t.Fatal("expected error when SENTINEL_CUSTOMER_ID unset")
	}
}

func TestRequireCustomerID_BadUUID(t *testing.T) {
	t.Setenv(CredentialsEnvCustomerID, "not-a-uuid")
	_, err := requireCustomerID()
	if err == nil {
		t.Fatal("expected error for malformed UUID")
	}
}

func TestRequireCustomerID_OK(t *testing.T) {
	t.Setenv(CredentialsEnvCustomerID, "33333333-3333-3333-3333-333333333333")
	id, err := requireCustomerID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.String() != "33333333-3333-3333-3333-333333333333" {
		t.Fatalf("id: got %v", id)
	}
}

// fakeStore is a credentials.Store implementation backed by an in-memory map,
// used to verify that the CLI dispatch wires arguments through correctly.
type fakeStore struct {
	saved   map[string][]byte
	deleted []string
	listed  []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{saved: map[string][]byte{}}
}

func (f *fakeStore) key(b uuid.UUID, k string) string { return b.String() + "/" + k }

func (f *fakeStore) Save(_ context.Context, _, b uuid.UUID, k string, plaintext []byte) error {
	f.saved[f.key(b, k)] = append([]byte(nil), plaintext...)
	return nil
}

func (f *fakeStore) Load(_ context.Context, b uuid.UUID, k string) ([]byte, error) {
	v, ok := f.saved[f.key(b, k)]
	if !ok {
		return nil, credentials.ErrNotFound
	}
	return v, nil
}

func (f *fakeStore) Delete(_ context.Context, b uuid.UUID, k string) error {
	f.deleted = append(f.deleted, f.key(b, k))
	delete(f.saved, f.key(b, k))
	return nil
}

func (f *fakeStore) ListKeys(_ context.Context, b uuid.UUID) ([]string, error) {
	return f.listed, nil
}

var _ credentials.Store = (*fakeStore)(nil)

func TestRunCredAdd_RequiresCustomerID(t *testing.T) {
	t.Setenv(CredentialsEnvCustomerID, "")
	store := newFakeStore()
	err := runCredAdd(
		[]string{"--bundle", "11111111-1111-1111-1111-111111111111", "--key", "pwd"},
		store,
		strings.NewReader("hunter2\n"),
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal("expected error when customer id missing")
	}
}

func TestRunCredAdd_RequiresKey(t *testing.T) {
	t.Setenv(CredentialsEnvCustomerID, "33333333-3333-3333-3333-333333333333")
	store := newFakeStore()
	err := runCredAdd(
		[]string{"--bundle", "11111111-1111-1111-1111-111111111111"},
		store,
		strings.NewReader("hunter2\n"),
		&bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "--key") {
		t.Fatalf("expected --key error; got %v", err)
	}
}

func TestRunCredAdd_RejectsEmptyValue(t *testing.T) {
	t.Setenv(CredentialsEnvCustomerID, "33333333-3333-3333-3333-333333333333")
	store := newFakeStore()
	// Empty stdin (immediate EOF) → empty password → reject.
	err := runCredAdd(
		[]string{"--bundle", "11111111-1111-1111-1111-111111111111", "--key", "pwd"},
		store,
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("expected empty-value error; got %v", err)
	}
}

func TestRunCredAdd_HappyPath(t *testing.T) {
	bundleStr := "11111111-1111-1111-1111-111111111111"
	t.Setenv(CredentialsEnvCustomerID, "33333333-3333-3333-3333-333333333333")
	store := newFakeStore()
	if err := runCredAdd(
		[]string{"--bundle", bundleStr, "--key", "pwd"},
		store,
		strings.NewReader("hunter2\n"),
		&bytes.Buffer{},
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bid, _ := uuid.Parse(bundleStr)
	got, ok := store.saved[store.key(bid, "pwd")]
	if !ok {
		t.Fatal("expected store.saved to contain pwd entry")
	}
	if string(got) != "hunter2" {
		t.Fatalf("plaintext: got %q, want %q", got, "hunter2")
	}
}

func TestRunCredList_PrintsKeys(t *testing.T) {
	store := newFakeStore()
	store.listed = []string{"api_key", "login_pwd"}
	var out bytes.Buffer
	if err := runCredList(
		[]string{"--bundle", "11111111-1111-1111-1111-111111111111"},
		store,
		&out,
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "api_key\nlogin_pwd\n"
	if out.String() != want {
		t.Fatalf("output: got %q, want %q", out.String(), want)
	}
}

func TestRunCredRemove_RequiresKey(t *testing.T) {
	store := newFakeStore()
	err := runCredRemove(
		[]string{"--bundle", "11111111-1111-1111-1111-111111111111"},
		store,
	)
	if err == nil || !strings.Contains(err.Error(), "--key") {
		t.Fatalf("expected --key error; got %v", err)
	}
}

func TestRunCredRemove_HappyPath(t *testing.T) {
	store := newFakeStore()
	if err := runCredRemove(
		[]string{"--bundle", "11111111-1111-1111-1111-111111111111", "--key", "pwd"},
		store,
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(store.deleted) != 1 {
		t.Fatalf("expected 1 delete call; got %d", len(store.deleted))
	}
}

func TestRunCredentialsCommand_UnknownSubcommand(t *testing.T) {
	store := newFakeStore()
	err := RunCredentialsCommand([]string{"bogus"}, store)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown-subcommand error; got %v", err)
	}
}

func TestRunCredentialsCommand_NoArgs(t *testing.T) {
	store := newFakeStore()
	err := RunCredentialsCommand(nil, store)
	if err == nil {
		t.Fatal("expected usage error with no args")
	}
}

// Ensure ErrNotFound is exported and usable in dispatch tests, e.g. for
// future `credentials get` subcommands.
func TestErrNotFound_Exported(t *testing.T) {
	store := newFakeStore()
	bid := uuid.New()
	_, err := store.Load(context.Background(), bid, "missing")
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}
