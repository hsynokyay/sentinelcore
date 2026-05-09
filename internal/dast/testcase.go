package dast

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// TestCase represents a single DAST test to execute against a target endpoint.
type TestCase struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	Name        string            `json:"name"`
	Category    string            `json:"category"` // sqli, xss, path_traversal, ssrf, etc.
	Severity    string            `json:"severity"` // critical, high, medium, low, info
	Confidence  string            `json:"confidence"` // high, medium, low
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`

	// MinProfile is the minimum scan profile required for this test case
	// to run. Empty value means "standard" (the existing default).
	// Valid values: "passive", "standard", "aggressive".
	MinProfile string `json:"min_profile,omitempty"`

	// Matcher determines if the response indicates a vulnerability.
	Matcher ResponseMatcher `json:"-"`
}

// BuildRequest creates an http.Request from the test case definition.
func (tc *TestCase) BuildRequest(ctx context.Context) (*http.Request, error) {
	var bodyReader *strings.Reader
	if tc.Body != "" {
		bodyReader = strings.NewReader(tc.Body)
	}

	method := tc.Method
	if method == "" {
		method = http.MethodGet
	}

	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(ctx, method, tc.URL, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, tc.URL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	for k, v := range tc.Headers {
		req.Header.Set(k, v)
	}

	// Enable GetBody for evidence capture
	if tc.Body != "" {
		body := tc.Body
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(body)), nil
		}
	}

	return req, nil
}

// ResponseMatcher checks if a response indicates a vulnerability.
type ResponseMatcher interface {
	Match(resp *http.Response, body []byte) (bool, string)
}

// StatusCodeMatcher matches specific HTTP status codes.
type StatusCodeMatcher struct {
	Codes []int
}

func (m *StatusCodeMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	for _, code := range m.Codes {
		if resp.StatusCode == code {
			return true, fmt.Sprintf("matched status code %d", code)
		}
	}
	return false, ""
}

// BodyContainsMatcher matches response body content.
type BodyContainsMatcher struct {
	Patterns []string
}

func (m *BodyContainsMatcher) Match(_ *http.Response, body []byte) (bool, string) {
	bodyStr := string(body)
	for _, pattern := range m.Patterns {
		if strings.Contains(bodyStr, pattern) {
			return true, fmt.Sprintf("body contains %q", pattern)
		}
	}
	return false, ""
}

// CompositeMatcher combines multiple matchers with AND/OR logic.
type CompositeMatcher struct {
	Matchers []ResponseMatcher
	Mode     string // "and" or "or"
}

func (m *CompositeMatcher) Match(resp *http.Response, body []byte) (bool, string) {
	var reasons []string
	for _, matcher := range m.Matchers {
		matched, reason := matcher.Match(resp, body)
		if m.Mode == "or" && matched {
			return true, reason
		}
		if m.Mode == "and" && !matched {
			return false, ""
		}
		if matched {
			reasons = append(reasons, reason)
		}
	}
	if m.Mode == "and" && len(reasons) == len(m.Matchers) {
		return true, strings.Join(reasons, "; ")
	}
	return false, ""
}
