package query

import (
	"strings"
	"testing"
	"time"
)

func TestBuild_Empty(t *testing.T) {
	b := Filter{}.Build()
	if b.Where != "" {
		t.Errorf("empty filter: expected no WHERE, got %q", b.Where)
	}
	if len(b.Args) != 0 {
		t.Errorf("empty filter: expected no args, got %v", b.Args)
	}
}

func TestBuild_Timestamps(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	b := Filter{From: &from, To: &to}.Build()
	if !strings.Contains(b.Where, "timestamp >= $1") {
		t.Errorf("missing from clause: %q", b.Where)
	}
	if !strings.Contains(b.Where, "timestamp < $2") {
		t.Errorf("missing to clause: %q", b.Where)
	}
	if len(b.Args) != 2 {
		t.Errorf("args: got %d want 2", len(b.Args))
	}
}

func TestBuild_ActionGlob(t *testing.T) {
	b := Filter{Actions: []string{"risk.*", "governance.*", "auth.login.succeeded"}}.Build()
	// literals go into ANY($n), globs become LIKE.
	if !strings.Contains(b.Where, "action = ANY") {
		t.Errorf("missing ANY for literals: %q", b.Where)
	}
	if !strings.Contains(b.Where, "action LIKE") {
		t.Errorf("missing LIKE for globs: %q", b.Where)
	}
	// Two globs = two LIKE bindings.
	if strings.Count(b.Where, "action LIKE") != 2 {
		t.Errorf("expected 2 LIKE clauses, got %q", b.Where)
	}
}

func TestBuild_KeysetPagination(t *testing.T) {
	ts := time.Now().UTC()
	id := int64(12345)
	b := Filter{AfterTimestamp: &ts, AfterID: &id}.Build()
	// Expect ($N < ts) OR (ts = $M AND id < $K) shape.
	if !strings.Contains(b.Where, "timestamp <") || !strings.Contains(b.Where, "id <") {
		t.Errorf("keyset clause missing: %q", b.Where)
	}
	if len(b.Args) != 3 {
		t.Errorf("expected 3 args (ts,ts,id), got %d: %v", len(b.Args), b.Args)
	}
}

func TestValidate_ReverseRange(t *testing.T) {
	earlier := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	f := Filter{From: &later, To: &earlier}
	if err := f.Validate(); err == nil {
		t.Fatal("expected error for reversed range")
	}
}

func TestValidate_BadResult(t *testing.T) {
	if err := (Filter{Result: "maybe"}).Validate(); err == nil {
		t.Fatal("expected error for invalid Result")
	}
}

func TestValidate_BadGlob(t *testing.T) {
	if err := (Filter{Actions: []string{"auth.*.succeeded"}}).Validate(); err == nil {
		t.Fatal("expected error for mid-glob")
	}
}

func TestValidate_OKGlob(t *testing.T) {
	if err := (Filter{Actions: []string{"risk.*"}}).Validate(); err != nil {
		t.Errorf("trailing .* should be valid: %v", err)
	}
}
