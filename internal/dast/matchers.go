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

// HeaderMissingMatcher fires when a named response header is absent or empty.
// Used by passive security checks (CSP, HSTS, X-Frame-Options, etc.).
//
// HTTPSOnly=true skips the check on plain-HTTP responses where the header
// would not apply (e.g. HSTS only makes sense over HTTPS).
type HeaderMissingMatcher struct {
	Name      string
	HTTPSOnly bool
	Reason    string
}

func (m *HeaderMissingMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil {
		return false, ""
	}
	if m.HTTPSOnly && resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme != "https" {
		return false, ""
	}
	for _, v := range resp.Header.Values(m.Name) {
		if strings.TrimSpace(v) != "" {
			return false, ""
		}
	}
	return true, m.Reason
}

// HeaderPresentMatcher fires when a named response header IS present (used to
// flag information-disclosure headers like X-Powered-By).
type HeaderPresentMatcher struct {
	Name   string
	Reason string
}

func (m *HeaderPresentMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil {
		return false, ""
	}
	for _, v := range resp.Header.Values(m.Name) {
		if strings.TrimSpace(v) != "" {
			return true, m.Reason + ": " + v
		}
	}
	return false, ""
}

// CookieMissingFlagMatcher fires when at least one Set-Cookie response
// header is missing the named flag (Secure, HttpOnly, SameSite).
//
// HTTPSOnly=true skips the check on plain-HTTP (Secure flag is meaningful
// only when there's a TLS connection to bind to).
type CookieMissingFlagMatcher struct {
	Flag      string // "Secure", "HttpOnly", "SameSite"
	HTTPSOnly bool
	Reason    string
}

func (m *CookieMissingFlagMatcher) Match(resp *http.Response, _ []byte) (bool, string) {
	if resp == nil {
		return false, ""
	}
	if m.HTTPSOnly && resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme != "https" {
		return false, ""
	}
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return false, ""
	}
	flag := strings.ToLower(m.Flag)
	for _, raw := range cookies {
		lower := strings.ToLower(raw)
		// Match flag as a token surrounded by ; or end-of-string.
		// Avoids false-positives from cookie values that happen to contain "secure".
		hasFlag := false
		for _, part := range strings.Split(lower, ";") {
			part = strings.TrimSpace(part)
			if part == flag || strings.HasPrefix(part, flag+"=") {
				hasFlag = true
				break
			}
		}
		if !hasFlag {
			cookieName := strings.SplitN(strings.TrimSpace(raw), "=", 2)[0]
			return true, m.Reason + ": cookie " + cookieName
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
