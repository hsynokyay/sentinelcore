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

func TestHeaderRegexMatcher_Hit(t *testing.T) {
	m := &HeaderRegexMatcher{
		Name:    "Location",
		Pattern: regexp.MustCompile(`https?://(evil|example)\.org`),
		Reason:  "open redirect",
	}
	resp := &http.Response{Header: http.Header{"Location": []string{"https://example.org/x"}}}
	hit, reason := m.Match(resp, nil)
	if !hit || reason != "open redirect" {
		t.Fatalf("hit=%v reason=%q", hit, reason)
	}
}

func TestHeaderRegexMatcher_Miss(t *testing.T) {
	m := &HeaderRegexMatcher{Name: "Location", Pattern: regexp.MustCompile(`evil`)}
	resp := &http.Response{Header: http.Header{"Location": []string{"/internal/path"}}}
	hit, _ := m.Match(resp, nil)
	if hit {
		t.Fatalf("expected miss")
	}
}

func TestStatusDiffMatcher_HitWhenBaselineDiffers(t *testing.T) {
	m := &StatusDiffMatcher{BaselineCode: 401, ProbeCode: 200, Reason: "auth bypass"}
	resp := &http.Response{StatusCode: 200}
	hit, reason := m.Match(resp, nil)
	if !hit || reason != "auth bypass" {
		t.Fatalf("hit=%v reason=%q", hit, reason)
	}
}

func TestStatusDiffMatcher_MissWhenSameAsBaseline(t *testing.T) {
	m := &StatusDiffMatcher{BaselineCode: 200, ProbeCode: 200}
	resp := &http.Response{StatusCode: 200}
	hit, _ := m.Match(resp, nil)
	if hit {
		t.Fatalf("expected miss when probe matches baseline")
	}
}

func TestStatusDiffMatcher_HitWithoutBaseline(t *testing.T) {
	// No baseline configured (zero value) → fire on ProbeCode alone
	m := &StatusDiffMatcher{ProbeCode: 200, Reason: "static probe"}
	resp := &http.Response{StatusCode: 200}
	hit, _ := m.Match(resp, nil)
	if !hit {
		t.Fatalf("expected hit when baseline is zero and probe matches")
	}
}
