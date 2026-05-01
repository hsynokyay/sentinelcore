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

func TestHeaderContainsMatcher_Hit(t *testing.T) {
	m := &HeaderContainsMatcher{Name: "Set-Cookie", Substring: "pwn=1", Reason: "CRLF echo"}
	resp := &http.Response{Header: http.Header{"Set-Cookie": []string{"session=abc; pwn=1; path=/"}}}
	hit, reason := m.Match(resp, nil)
	if !hit || reason != "CRLF echo" {
		t.Fatalf("expected hit with reason 'CRLF echo', got hit=%v reason=%q", hit, reason)
	}
}

func TestHeaderContainsMatcher_Miss(t *testing.T) {
	m := &HeaderContainsMatcher{Name: "Set-Cookie", Substring: "pwn=1"}
	resp := &http.Response{Header: http.Header{"Set-Cookie": []string{"session=abc"}}}
	hit, _ := m.Match(resp, nil)
	if hit {
		t.Fatalf("expected miss")
	}
}

func TestHeaderContainsMatcher_NilResp(t *testing.T) {
	m := &HeaderContainsMatcher{Name: "X", Substring: "y"}
	hit, _ := m.Match(nil, nil)
	if hit {
		t.Fatalf("expected miss on nil response")
	}
}
