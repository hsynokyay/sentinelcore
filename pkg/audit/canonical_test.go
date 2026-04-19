package audit

import "testing"

func TestCanonical_KeyOrdering(t *testing.T) {
	// RFC 8785-lite: keys at every level sorted lexicographically.
	e := AuditEvent{
		EventID: "id-1", Timestamp: "t", ActorType: "user",
		ActorID: "u", Action: "auth.login.succeeded",
		ResourceType: "user", ResourceID: "u", Result: "success",
		Details: map[string]any{
			"z": 1,
			"a": map[string]any{"y": 2, "b": 3},
			"m": "middle",
		},
	}
	got := Canonical(e, "prev-hash")
	// "a" before "m" before "z" at top; "b" before "y" inside a.
	// The canonical form inlines previous_hash at the end.
	wantContains := []string{
		`"a":{"b":3,"y":2}`,
		`"m":"middle"`,
		`"z":1`,
	}
	for _, w := range wantContains {
		if !contains(got, w) {
			t.Errorf("canonical missing %q\nfull: %s", w, got)
		}
	}
	// previous_hash must be at the tail of the buffer, separated by a delimiter.
	if !contains(got, "|prev-hash") {
		t.Errorf("missing trailing |previous_hash; got: %s", got)
	}
}

func TestCanonical_NoWhitespace(t *testing.T) {
	e := AuditEvent{
		EventID: "x", Timestamp: "t", ActorType: "user",
		ActorID: "u", Action: "x.y.z", ResourceType: "r",
		ResourceID: "rid", Result: "success",
		Details: map[string]any{"a": 1, "b": []any{2, 3}},
	}
	got := Canonical(e, "")
	for _, c := range []byte{' ', '\t', '\n', '\r'} {
		for i := 0; i < len(got); i++ {
			if got[i] == c {
				t.Fatalf("canonical contains whitespace %q at %d: %s", c, i, got)
			}
		}
	}
}

func TestCanonical_Deterministic(t *testing.T) {
	// Building the same event twice (different map iteration order) must produce identical output.
	e1 := AuditEvent{
		EventID: "id", Timestamp: "t", Action: "x", ActorType: "u", ActorID: "u",
		ResourceType: "r", ResourceID: "r", Result: "success",
		Details: map[string]any{"z": 9, "a": 1, "m": 5},
	}
	e2 := AuditEvent{
		EventID: "id", Timestamp: "t", Action: "x", ActorType: "u", ActorID: "u",
		ResourceType: "r", ResourceID: "r", Result: "success",
		Details: map[string]any{"a": 1, "m": 5, "z": 9},
	}
	for i := 0; i < 100; i++ {
		if Canonical(e1, "p") != Canonical(e2, "p") {
			t.Fatalf("canonical not deterministic at iter %d", i)
		}
	}
}

func TestCanonical_NilDetails(t *testing.T) {
	e := AuditEvent{
		EventID: "id", Timestamp: "t", Action: "x", ActorType: "u", ActorID: "u",
		ResourceType: "r", ResourceID: "r", Result: "success",
	}
	// Should not panic and should not emit a "details" key at all.
	got := Canonical(e, "")
	if contains(got, `"details"`) {
		t.Errorf("unexpected details key: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
