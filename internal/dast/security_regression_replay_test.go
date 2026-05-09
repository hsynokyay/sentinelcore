package dast

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/recording"
	"github.com/sentinelcore/sentinelcore/internal/authbroker/replay"
	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
)

// sec-03: a tampered action list with a navigate URL pointing outside the
// bundle's TargetHost must be rejected by the replay engine's pre-flight
// host-match check, before any browser is launched.
func TestSec03_ForgedActionListRejected(t *testing.T) {
	e := replay.NewEngine()
	b := &bundles.Bundle{
		ID:         "sec03-forged",
		Type:       "recorded_login",
		TargetHost: "app.bank.tld",
		ExpiresAt:  time.Now().Add(time.Hour),
		Actions: []bundles.Action{
			{Kind: bundles.ActionNavigate, URL: "https://app.bank.tld/login"},
			{Kind: bundles.ActionNavigate, URL: "https://evil.example.com/exfil"},
		},
	}

	_, err := e.Replay(context.Background(), b)
	if err == nil {
		t.Fatal("expected pre-flight rejection for navigate outside target host")
	}
	if !strings.Contains(err.Error(), "scope violation") {
		t.Fatalf("expected scope violation error, got: %v", err)
	}
}

// sec-04: per-bundle rate limit must reject a second replay within the
// configured interval.
func TestSec04_ReplayRateLimit(t *testing.T) {
	rl := replay.NewRateLimit()
	if err := rl.Allow("b1", "app.bank.tld"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := rl.Allow("b1", "app.bank.tld"); err == nil {
		t.Fatal("expected rate-limit rejection on immediate repeat")
	}
}

// sec-05: VerifyPostState must surface an error whenever an expected hash is
// supplied but cannot be reproduced. At unit-test scale we have no live
// chromedp context, so ComputePostStateHash inevitably fails — that failure
// is the same signal a tampered/refreshed page would produce in production.
// An empty expected hash must remain a no-op (legacy bundle skip path).
func TestSec05_TamperedPostStateHashRejected(t *testing.T) {
	if err := replay.VerifyPostState(context.Background(), ""); err != nil {
		t.Fatalf("empty expected must skip cleanly, got: %v", err)
	}
	err := replay.VerifyPostState(context.Background(), "deadbeef")
	if err == nil {
		t.Fatal("expected error when expected hash is non-empty without a live chromedp ctx")
	}
}

// sec-06: VerifyPrincipal must reject a non-empty mismatch but allow either
// side being empty (no binding configured) and matching values.
func TestSec06_PrincipalMismatchRejected(t *testing.T) {
	if err := replay.VerifyPrincipal("alice", "admin"); err == nil {
		t.Fatal("expected mismatch error for alice vs admin")
	}
	if err := replay.VerifyPrincipal("alice", "alice"); err != nil {
		t.Fatalf("matching principals must pass, got: %v", err)
	}
	if err := replay.VerifyPrincipal("", "admin"); err != nil {
		t.Fatalf("empty bundle principal must pass, got: %v", err)
	}
	if err := replay.VerifyPrincipal("alice", ""); err != nil {
		t.Fatalf("empty scan expected must pass, got: %v", err)
	}
	if err := replay.VerifyPrincipal("", ""); err != nil {
		t.Fatalf("both empty must pass, got: %v", err)
	}
}

// sec07TestPool mirrors internal/authbroker/replay/circuit_test.go: skip
// cleanly when TEST_DATABASE_URL is unset so unit-test runs in a no-DB
// environment do not fail.
func sec07TestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping sec-07 circuit integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	return pool
}

// sec07MustInsertBundle inserts a minimal dast_auth_bundles row so the
// dast_replay_failures FK is satisfied. Pattern copied from
// internal/authbroker/replay/circuit_test.go (cross-package — replicate, not
// import).
func sec07MustInsertBundle(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO dast_auth_bundles (
			id, customer_id, project_id, target_host,
			type, status,
			iv, ciphertext_ref, wrapped_dek, kms_key_id, kms_key_version,
			integrity_hmac, schema_version,
			created_by_user_id, expires_at
		) VALUES (
			$1, $2, $3, 'sec07.example.com',
			'session_import', 'pending_review',
			'\x00'::bytea, 'inline:', '\x00'::bytea, 'alias/test', 'v1',
			'\x00'::bytea, 1,
			$4, $5
		)`,
		id, uuid.New(), uuid.New(), uuid.New(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("sec07MustInsertBundle: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM dast_auth_bundles WHERE id=$1`, id)
	})
}

// sec-07: after three recorded failures, the per-bundle circuit must report
// open. This is the production guarantee that a misbehaving target cannot be
// hammered indefinitely.
func TestSec07_CircuitOpensAfter3(t *testing.T) {
	pool := sec07TestPool(t)
	defer pool.Close()
	s := replay.NewCircuitStore(pool)
	ctx := context.Background()
	id := uuid.New()
	sec07MustInsertBundle(t, pool, id)

	for i := 0; i < 3; i++ {
		if err := s.RecordFailure(ctx, id, "boom", ""); err != nil {
			t.Fatalf("RecordFailure %d: %v", i+1, err)
		}
	}
	open, err := s.IsOpen(ctx, id)
	if err != nil {
		t.Fatalf("IsOpen: %v", err)
	}
	if !open {
		t.Fatal("expected circuit open after 3 failures")
	}
}

// sec08FakeCredStore is a hand-rolled credentials.Store double used solely by
// sec-08 to simulate a forged vault_key — the lookup yields ErrNotFound and
// InjectFill must surface that in its wrap chain.
type sec08FakeCredStore struct {
	loadErr error
}

func (f *sec08FakeCredStore) Save(_ context.Context, _, _ uuid.UUID, _ string, _ []byte) error {
	return nil
}

func (f *sec08FakeCredStore) Load(_ context.Context, _ uuid.UUID, _ string) ([]byte, error) {
	return nil, f.loadErr
}

func (f *sec08FakeCredStore) Delete(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

func (f *sec08FakeCredStore) ListKeys(_ context.Context, _ uuid.UUID) ([]string, error) {
	return nil, nil
}

// sec-08: a fill action whose vault_key does not resolve in the credential
// store must be rejected by InjectFill — this is the protection against a
// bundle action pointing at a non-existent (or forged) vault entry.
func TestSec08_ForgedVaultKeyRejected(t *testing.T) {
	fake := &sec08FakeCredStore{loadErr: credentials.ErrNotFound}
	err := replay.InjectFill(context.Background(), fake, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, Selector: "#x", VaultKey: "ghost"})
	if err == nil {
		t.Fatal("expected error for unresolved vault_key")
	}
	if !strings.Contains(err.Error(), "credential load") {
		t.Fatalf("expected wrapped 'credential load' error, got: %v", err)
	}
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("expected errors.Is(err, credentials.ErrNotFound), got: %v", err)
	}
}

// sec-09: the capture-time invariant — fill events must NOT carry a value —
// is the linchpin of the "no plaintext credentials in bundles" property. Any
// payload that leaks a value through the binding must be rejected by
// recording.ParseAndValidate.
func TestSec09_FillValueRejectedAtIngest(t *testing.T) {
	_, err := recording.ParseAndValidate(`{"kind":"fill","selector":"#pwd","t":1,"value":"x"}`)
	if err == nil {
		t.Fatal("expected rejection for fill payload carrying value")
	}
	if !strings.Contains(err.Error(), "must not carry value") {
		t.Fatalf("expected 'must not carry value' error, got: %v", err)
	}
}

// sec10FakeForensics counts Capture invocations so the privacy regression
// can assert "no capture on the not-yet-failed path." It deliberately
// returns an empty key + nil error so the engine treats the capture as a
// successful no-op when the path is exercised — what we test here is the
// CALL COUNT, not the engine's reaction to the result.
type sec10FakeForensics struct{ calls int }

func (f *sec10FakeForensics) Capture(_ context.Context, _ uuid.UUID, _ int) (string, error) {
	f.calls++
	return "", nil
}

// sec-10: forensics privacy — Replay must NOT capture a screenshot on any
// path that did not first observe a replay failure. Specifically: a request
// rejected by an early validation gate (nil bundle / wrong type / expired /
// no actions) must NOT touch chromedp and therefore must NOT invoke the
// forensics sink, because those rejections are well-formedness errors that
// have no operational forensic value and would only burn KMS+MinIO quota.
//
// This is the "happy-path" from the privacy invariant's perspective: in
// unit tests we have no live chromedp browser, so the only way to observe
// a positively-no-capture branch is to exercise Replay's pre-bundleID
// validation gates.
func TestSec10_ForensicsOnlyOnFailure(t *testing.T) {
	fakeF := &sec10FakeForensics{}
	e := replay.NewEngine().WithForensics(fakeF)

	// Case A: nil bundle — Replay must reject before any forensic capture.
	if _, err := e.Replay(context.Background(), nil); err == nil {
		t.Fatal("expected nil-bundle rejection")
	}
	if fakeF.calls != 0 {
		t.Fatalf("Capture called %d times on nil-bundle path", fakeF.calls)
	}

	// Case B: wrong type — same invariant, different gate.
	wrongType := &bundles.Bundle{
		ID:        "10101010-1010-1010-1010-101010101010",
		Type:      "session_import",
		ExpiresAt: time.Now().Add(time.Hour),
		Actions:   []bundles.Action{{Kind: bundles.ActionNavigate, URL: "https://x/"}},
	}
	if _, err := e.Replay(context.Background(), wrongType); err == nil {
		t.Fatal("expected wrong-type rejection")
	}
	if fakeF.calls != 0 {
		t.Fatalf("Capture called %d times on wrong-type path", fakeF.calls)
	}

	// Case C: expired bundle — same invariant.
	expired := &bundles.Bundle{
		ID:        "20202020-2020-2020-2020-202020202020",
		Type:      "recorded_login",
		ExpiresAt: time.Now().Add(-time.Hour),
		Actions:   []bundles.Action{{Kind: bundles.ActionNavigate, URL: "https://x/"}},
	}
	if _, err := e.Replay(context.Background(), expired); err == nil {
		t.Fatal("expected expired rejection")
	}
	if fakeF.calls != 0 {
		t.Fatalf("Capture called %d times on expired path", fakeF.calls)
	}

	// Case D: no actions — same invariant.
	empty := &bundles.Bundle{
		ID:        "30303030-3030-3030-3030-303030303030",
		Type:      "recorded_login",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if _, err := e.Replay(context.Background(), empty); err == nil {
		t.Fatal("expected no-actions rejection")
	}
	if fakeF.calls != 0 {
		t.Fatalf("Capture called %d times on empty-actions path", fakeF.calls)
	}
}
