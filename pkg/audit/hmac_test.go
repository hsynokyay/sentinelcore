package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHMACCompute_Deterministic(t *testing.T) {
	key := mustKey(t)
	e := AuditEvent{
		EventID: "id", Timestamp: "t", Action: "x.y", ActorType: "u",
		ActorID: "u", ResourceType: "r", ResourceID: "r", Result: "success",
	}
	a := HMACCompute(key, Canonical(e, "prev"))
	b := HMACCompute(key, Canonical(e, "prev"))
	if a != b {
		t.Fatalf("non-deterministic HMAC: %s vs %s", a, b)
	}
	// Hex form, 64 chars = 32 bytes.
	if len(a) != 64 {
		t.Fatalf("want 64-char hex, got %d: %s", len(a), a)
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("not hex: %v", err)
	}
}

func TestHMACCompute_DifferentKey(t *testing.T) {
	e := AuditEvent{
		EventID: "id", Timestamp: "t", Action: "x.y",
		ActorType: "u", ActorID: "u", ResourceType: "r", ResourceID: "r", Result: "success",
	}
	k1, k2 := mustKey(t), mustKey(t)
	if HMACCompute(k1, Canonical(e, "p")) == HMACCompute(k2, Canonical(e, "p")) {
		t.Fatal("two different keys produced identical HMAC (astronomically unlikely; likely bug)")
	}
}

func TestHMACCompute_PreviousHashInfluences(t *testing.T) {
	// The whole point of the chain: changing previous_hash must change the HMAC.
	key := mustKey(t)
	e := AuditEvent{
		EventID: "id", Timestamp: "t", Action: "x.y",
		ActorType: "u", ActorID: "u", ResourceType: "r", ResourceID: "r", Result: "success",
	}
	if HMACCompute(key, Canonical(e, "A")) == HMACCompute(key, Canonical(e, "B")) {
		t.Fatal("previous_hash not mixed into canonical/HMAC — chain is broken")
	}
}

func TestHMACVerify_HappyPath(t *testing.T) {
	key := mustKey(t)
	e := AuditEvent{
		EventID: "id", Timestamp: "t", Action: "x.y",
		ActorType: "u", ActorID: "u", ResourceType: "r", ResourceID: "r", Result: "success",
	}
	got := HMACCompute(key, Canonical(e, ""))
	if !HMACVerify(key, Canonical(e, ""), got) {
		t.Fatal("verify failed on freshly computed HMAC")
	}
}

func TestHMACVerify_Rejects_Tamper(t *testing.T) {
	key := mustKey(t)
	e := AuditEvent{
		EventID: "id", Timestamp: "t", Action: "x.y",
		ActorType: "u", ActorID: "u", ResourceType: "r", ResourceID: "r", Result: "success",
	}
	got := HMACCompute(key, Canonical(e, ""))
	// Flip one byte of the event.
	e.ActorID = "u2"
	if HMACVerify(key, Canonical(e, ""), got) {
		t.Fatal("verify accepted mutated event — tamper detection broken")
	}
}

func TestHMACVerify_ConstantTime(t *testing.T) {
	// Confirm we use subtle.ConstantTimeCompare semantics — not easy to test
	// side-channel-free, but we can at least verify rejects a near-miss.
	key := mustKey(t)
	canonical := "some-canonical"
	good := HMACCompute(key, canonical)
	// Flip last nibble.
	bad := []byte(good)
	if bad[len(bad)-1] == 'a' {
		bad[len(bad)-1] = 'b'
	} else {
		bad[len(bad)-1] = 'a'
	}
	if HMACVerify(key, canonical, string(bad)) {
		t.Fatal("accepted near-miss hash")
	}
}

func TestHMACCompute_RFC4231Vector(t *testing.T) {
	// RFC 4231 §4.2 test vector for HMAC-SHA256.
	key := bytes.Repeat([]byte{0x0b}, 20)
	data := "Hi There"
	got := HMACCompute(key, data)
	want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	if got != want {
		t.Fatalf("RFC 4231 vector mismatch:\n got:  %s\n want: %s", got, want)
	}
}
