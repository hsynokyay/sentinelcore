package dast

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"
)

func httpsResp(headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	u, _ := url.Parse("https://target.example/")
	return &http.Response{Header: headers, Request: &http.Request{URL: u}}
}

func httpResp(headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	u, _ := url.Parse("http://target.example/")
	return &http.Response{Header: headers, Request: &http.Request{URL: u}}
}

func TestHeaderMissingMatcher_HitWhenAbsent(t *testing.T) {
	m := &HeaderMissingMatcher{Name: "Content-Security-Policy", Reason: "CSP missing"}
	hit, reason := m.Match(httpsResp(nil), nil)
	if !hit || reason != "CSP missing" {
		t.Fatalf("expected hit, got hit=%v reason=%q", hit, reason)
	}
}

func TestHeaderMissingMatcher_MissWhenPresent(t *testing.T) {
	m := &HeaderMissingMatcher{Name: "Content-Security-Policy"}
	resp := httpsResp(http.Header{"Content-Security-Policy": []string{"default-src 'self'"}})
	if hit, _ := m.Match(resp, nil); hit {
		t.Fatalf("expected miss when header present")
	}
}

func TestHeaderMissingMatcher_MissWhenEmptyValue(t *testing.T) {
	m := &HeaderMissingMatcher{Name: "X-Frame-Options", Reason: "XFO missing"}
	resp := httpsResp(http.Header{"X-Frame-Options": []string{"   "}})
	if hit, _ := m.Match(resp, nil); !hit {
		t.Fatalf("empty header value should count as missing")
	}
}

func TestHeaderMissingMatcher_HTTPSOnly_SkipsOnPlainHTTP(t *testing.T) {
	m := &HeaderMissingMatcher{Name: "Strict-Transport-Security", HTTPSOnly: true, Reason: "HSTS missing"}
	if hit, _ := m.Match(httpResp(nil), nil); hit {
		t.Fatalf("HTTPSOnly matcher should skip plain HTTP responses")
	}
	if hit, _ := m.Match(httpsResp(nil), nil); !hit {
		t.Fatalf("HTTPSOnly matcher should fire on HTTPS when header missing")
	}
}

func TestHeaderPresentMatcher_FlagsDisclosureHeader(t *testing.T) {
	m := &HeaderPresentMatcher{Name: "X-Powered-By", Reason: "X-Powered-By disclosed"}
	resp := httpsResp(http.Header{"X-Powered-By": []string{"PHP/8.1.0"}})
	hit, reason := m.Match(resp, nil)
	if !hit {
		t.Fatalf("expected hit when header present")
	}
	if reason != "X-Powered-By disclosed: PHP/8.1.0" {
		t.Errorf("reason = %q", reason)
	}
}

func TestHeaderPresentMatcher_MissWhenAbsent(t *testing.T) {
	m := &HeaderPresentMatcher{Name: "X-Powered-By"}
	if hit, _ := m.Match(httpsResp(nil), nil); hit {
		t.Fatalf("expected miss when header absent")
	}
}

func TestCookieMissingFlagMatcher_FiresWhenSecureMissing(t *testing.T) {
	m := &CookieMissingFlagMatcher{Flag: "Secure", HTTPSOnly: true, Reason: "cookie not Secure"}
	resp := httpsResp(http.Header{"Set-Cookie": []string{"session=abc; Path=/; HttpOnly"}})
	hit, reason := m.Match(resp, nil)
	if !hit {
		t.Fatalf("expected hit when Secure flag missing")
	}
	if !regexp.MustCompile(`cookie not Secure: cookie session`).MatchString(reason) {
		t.Errorf("reason = %q", reason)
	}
}

func TestCookieMissingFlagMatcher_PassesWhenAllFlagsPresent(t *testing.T) {
	m := &CookieMissingFlagMatcher{Flag: "HttpOnly"}
	resp := httpsResp(http.Header{"Set-Cookie": []string{"session=abc; Path=/; HttpOnly; Secure"}})
	if hit, _ := m.Match(resp, nil); hit {
		t.Fatalf("expected miss when HttpOnly present")
	}
}

func TestCookieMissingFlagMatcher_DoesNotFalsePositiveOnValueMatching(t *testing.T) {
	// Cookie value happens to contain "secure" — must not be parsed as a flag.
	m := &CookieMissingFlagMatcher{Flag: "Secure", HTTPSOnly: true}
	resp := httpsResp(http.Header{"Set-Cookie": []string{"session=secure-token; Path=/"}})
	if hit, _ := m.Match(resp, nil); !hit {
		t.Fatalf("matcher should still fire — Secure flag is not actually set")
	}
}

func TestCookieMissingFlagMatcher_HTTPSOnlySkipsHTTP(t *testing.T) {
	m := &CookieMissingFlagMatcher{Flag: "Secure", HTTPSOnly: true}
	resp := httpResp(http.Header{"Set-Cookie": []string{"session=abc"}})
	if hit, _ := m.Match(resp, nil); hit {
		t.Fatalf("Secure check should skip plain-HTTP responses")
	}
}

func TestCookieMissingFlagMatcher_MissWhenNoCookies(t *testing.T) {
	m := &CookieMissingFlagMatcher{Flag: "HttpOnly"}
	if hit, _ := m.Match(httpsResp(nil), nil); hit {
		t.Fatalf("no Set-Cookie should never fire")
	}
}

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
