package recording

import "testing"

func TestCanonicalize_Stable(t *testing.T) {
	a := `{"path":"/dashboard","form":["user","pass","submit"],"h":["Welcome","Account"],"nav":["Home","Settings"]}`
	b := `{"path":"/dashboard","form":["submit","pass","user"],"h":["Account","Welcome"],"nav":["Settings","Home"]}`
	ha, hb := canonicalize(a), canonicalize(b)
	if ha != hb {
		t.Fatalf("expected stable hash regardless of slice order: %s != %s", ha, hb)
	}
	if len(ha) != 64 {
		t.Fatalf("expected 64-char hex digest, got %d (%q)", len(ha), ha)
	}
}

func TestCanonicalize_DifferentPathsDiffer(t *testing.T) {
	a := `{"path":"/dashboard","form":["user"],"h":[],"nav":[]}`
	b := `{"path":"/login","form":["user"],"h":[],"nav":[]}`
	if canonicalize(a) == canonicalize(b) {
		t.Fatal("expected distinct paths to produce distinct hashes")
	}
}

func TestCanonicalize_BadJSONFallback(t *testing.T) {
	got := canonicalize("not-json")
	if len(got) != 64 {
		t.Fatalf("expected 64-char hex digest from fallback, got %d (%q)", len(got), got)
	}
	// Verify hex chars only.
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("expected lowercase hex digest, got %q", got)
		}
	}
}
