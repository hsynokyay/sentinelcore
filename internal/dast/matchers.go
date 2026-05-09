package dast

import (
	"net/http"
	"regexp"
	"strings"
)

// BodyRegexMatcher fires when the regex matches the response body.
type BodyRegexMatcher struct {
	Pattern *regexp.Regexp
	Reason  string
}

func (m *BodyRegexMatcher) Match(_ *http.Response, body []byte) (bool, string) {
	if m.Pattern != nil && m.Pattern.Match(body) {
		return true, m.Reason
	}
	return false, ""
}

// HeaderContainsMatcher fires when a named header value contains the substring.
type HeaderContainsMatcher struct {
	Name      string
	Substring string
	Reason    string
}

func (m *HeaderContainsMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil {
		return false, ""
	}
	for _, v := range resp.Header.Values(m.Name) {
		if strings.Contains(v, m.Substring) {
			return true, m.Reason
		}
	}
	return false, ""
}

// HeaderRegexMatcher fires when a named header value matches the regex.
type HeaderRegexMatcher struct {
	Name    string
	Pattern *regexp.Regexp
	Reason  string
}

func (m *HeaderRegexMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil || m.Pattern == nil {
		return false, ""
	}
	for _, v := range resp.Header.Values(m.Name) {
		if m.Pattern.MatchString(v) {
			return true, m.Reason
		}
	}
	return false, ""
}

// StatusDiffMatcher fires when the probe response status differs from a
// recorded baseline status. The matcher is configured with the expected
// success-of-attack status; the worker is responsible for setting
// BaselineCode before invoking the matcher (left zero if no baseline was
// captured, in which case the matcher fires on ProbeCode alone — useful
// for static thresholds).
type StatusDiffMatcher struct {
	BaselineCode int
	ProbeCode    int
	Reason       string
}

func (m *StatusDiffMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil {
		return false, ""
	}
	if resp.StatusCode != m.ProbeCode {
		return false, ""
	}
	if m.BaselineCode == 0 || m.BaselineCode != m.ProbeCode {
		return true, m.Reason
	}
	return false, ""
}
