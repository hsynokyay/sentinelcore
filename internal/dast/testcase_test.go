package dast

import (
	"context"
	"net/http"
	"testing"
)

func TestTestCase_BuildRequest_GET(t *testing.T) {
	tc := TestCase{
		Method:  "GET",
		URL:     "https://example.com/api/test?q=1",
		Headers: map[string]string{"Accept": "application/json"},
	}

	req, err := tc.BuildRequest(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Fatalf("unexpected method: %s", req.Method)
	}
	if req.URL.String() != "https://example.com/api/test?q=1" {
		t.Fatalf("unexpected URL: %s", req.URL)
	}
	if req.Header.Get("Accept") != "application/json" {
		t.Fatal("custom header not set")
	}
}

func TestTestCase_BuildRequest_POST(t *testing.T) {
	tc := TestCase{
		Method:      "POST",
		URL:         "https://example.com/api/login",
		Body:        `{"username":"test"}`,
		ContentType: "application/json",
	}

	req, err := tc.BuildRequest(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Fatalf("unexpected method: %s", req.Method)
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Fatal("Content-Type not set")
	}
	if req.Body == nil {
		t.Fatal("body should not be nil")
	}
}

func TestTestCase_BuildRequest_DefaultMethod(t *testing.T) {
	tc := TestCase{URL: "https://example.com"}
	req, err := tc.BuildRequest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "GET" {
		t.Fatalf("expected default GET, got %s", req.Method)
	}
}

func TestStatusCodeMatcher(t *testing.T) {
	m := &StatusCodeMatcher{Codes: []int{200, 201}}

	resp := &http.Response{StatusCode: 200}
	matched, detail := m.Match(resp, nil)
	if !matched {
		t.Fatal("expected match for 200")
	}
	if detail == "" {
		t.Fatal("expected non-empty detail")
	}

	resp.StatusCode = 404
	matched, _ = m.Match(resp, nil)
	if matched {
		t.Fatal("should not match 404")
	}
}

func TestBodyContainsMatcher(t *testing.T) {
	m := &BodyContainsMatcher{Patterns: []string{"SQL syntax", "error"}}

	matched, _ := m.Match(nil, []byte("You have an error in your SQL syntax"))
	if !matched {
		t.Fatal("expected match")
	}

	matched, _ = m.Match(nil, []byte("all good"))
	if matched {
		t.Fatal("should not match")
	}
}

func TestCompositeMatcher_OR(t *testing.T) {
	m := &CompositeMatcher{
		Mode: "or",
		Matchers: []ResponseMatcher{
			&StatusCodeMatcher{Codes: []int{500}},
			&BodyContainsMatcher{Patterns: []string{"error"}},
		},
	}

	resp := &http.Response{StatusCode: 200}
	matched, _ := m.Match(resp, []byte("an error occurred"))
	if !matched {
		t.Fatal("expected OR match on body")
	}
}

func TestCompositeMatcher_AND(t *testing.T) {
	m := &CompositeMatcher{
		Mode: "and",
		Matchers: []ResponseMatcher{
			&StatusCodeMatcher{Codes: []int{500}},
			&BodyContainsMatcher{Patterns: []string{"error"}},
		},
	}

	resp := &http.Response{StatusCode: 500}
	matched, _ := m.Match(resp, []byte("an error occurred"))
	if !matched {
		t.Fatal("expected AND match")
	}

	resp.StatusCode = 200
	matched, _ = m.Match(resp, []byte("an error occurred"))
	if matched {
		t.Fatal("AND should fail when status doesn't match")
	}
}
