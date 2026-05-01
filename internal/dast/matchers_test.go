package dast

import (
	"net/http"
	"regexp"
	"testing"
)

func TestBodyRegexMatcher_Hit(t *testing.T) {
	m := &BodyRegexMatcher{
		Pattern: regexp.MustCompile(`root:[^:]*:0:0:`),
		Reason:  "etc/passwd contents detected",
	}
	hit, reason := m.Match(&http.Response{}, []byte("root:x:0:0:root:/root:/bin/bash"))
	if !hit {
		t.Fatalf("expected hit, got miss")
	}
	if reason != "etc/passwd contents detected" {
		t.Errorf("reason = %q", reason)
	}
}

func TestBodyRegexMatcher_Miss(t *testing.T) {
	m := &BodyRegexMatcher{Pattern: regexp.MustCompile(`evil`), Reason: "x"}
	hit, _ := m.Match(&http.Response{}, []byte("nothing here"))
	if hit {
		t.Fatalf("expected miss")
	}
}
