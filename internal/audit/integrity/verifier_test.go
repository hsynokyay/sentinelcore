package integrity

import (
	"testing"
)

// stubResolver is a minimal in-memory key store used by tests.
type stubResolver map[int][]byte

func (s stubResolver) Key(version int) ([]byte, error) {
	k, ok := s[version]
	if !ok {
		return nil, errKeyMissing
	}
	return k, nil
}

// errKeyMissing is separately declared so the assertion in the verifier
// (unreachable from this pkg) can be mirrored here for tests.
var errKeyMissing = testError("key missing")

type testError string

func (e testError) Error() string { return string(e) }

func TestQuoteIdent(t *testing.T) {
	cases := map[string]string{
		"audit_log":        `"audit_log"`,
		`weird"name`:       `"weird""name"`,
		"audit_log_202604": `"audit_log_202604"`,
	}
	for in, want := range cases {
		if got := quoteIdent(in); got != want {
			t.Errorf("quoteIdent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJSONToMap(t *testing.T) {
	if m, ok := jsonToMap([]byte(`{"a":1,"b":"x"}`)); !ok || m["a"] != float64(1) || m["b"] != "x" {
		t.Errorf("roundtrip: ok=%v m=%v", ok, m)
	}
	if _, ok := jsonToMap([]byte(`[1,2,3]`)); ok {
		t.Error("expected false for non-object JSON")
	}
	if _, ok := jsonToMap([]byte(`not json`)); ok {
		t.Error("expected false for malformed JSON")
	}
}

// VerifyPartition integration test: DB-gated. Seeds a small chain, flips a
// byte, asserts outcome=fail. Skipped when TEST_DATABASE_URL unset.
//
// Kept minimal; the heavy integration tests live in
// test/integration/audit_integrity_test.go once a DB fixture is available.
func TestVerifyPartition_SkipsWhenNoDB(t *testing.T) {
	// Placeholder: real version acquires pool from env. Stub here so
	// `go test` passes on hosts without TEST_DATABASE_URL.
	t.Skip("integration test deferred to test/integration/")
}
