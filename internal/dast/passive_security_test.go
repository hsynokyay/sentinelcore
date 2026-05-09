package dast

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeneratePassiveSecurityChecks_EmitsAllRules(t *testing.T) {
	cases := generatePassiveSecurityChecks("https://target.example/")
	wantRules := []string{
		"DAST-HEAD-CSP-001",
		"DAST-HEAD-HSTS-001",
		"DAST-HEAD-XFO-001",
		"DAST-HEAD-XCTO-001",
		"DAST-HEAD-REFER-001",
		"DAST-HEAD-PERM-001",
		"DAST-HEAD-XPOWERED-001",
		"DAST-HEAD-SERVER-001",
		"DAST-COOKIE-SECURE-001",
		"DAST-COOKIE-HTTPONLY-001",
		"DAST-COOKIE-SAMESITE-001",
	}
	if len(cases) != len(wantRules) {
		t.Fatalf("got %d cases, want %d", len(cases), len(wantRules))
	}
	got := map[string]bool{}
	for _, tc := range cases {
		got[tc.RuleID] = true
		if tc.MinProfile != "passive" {
			t.Errorf("%s: MinProfile = %q, want passive", tc.RuleID, tc.MinProfile)
		}
		if tc.Matcher == nil {
			t.Errorf("%s: nil Matcher", tc.RuleID)
		}
		if tc.URL != "https://target.example/" {
			t.Errorf("%s: URL = %q, want base URL", tc.RuleID, tc.URL)
		}
		if tc.Method != "GET" {
			t.Errorf("%s: Method = %q, want GET", tc.RuleID, tc.Method)
		}
	}
	for _, want := range wantRules {
		if !got[want] {
			t.Errorf("missing rule %s", want)
		}
	}
}

func TestGeneratePassiveSecurityChecks_NoBaseURL_ReturnsNil(t *testing.T) {
	if cases := generatePassiveSecurityChecks(""); cases != nil {
		t.Errorf("empty base URL should return nil, got %d cases", len(cases))
	}
}

// TestPassiveChecks_TripOnInsecureSite spins up a deliberately-insecure
// httptest server (no headers, plain cookie) and verifies the matchers
// actually fire end-to-end against a real http.Response. This catches bugs
// that unit-level matcher tests can't (e.g. wrong header name casing, wrong
// matcher wiring).
func TestPassiveChecks_TripOnInsecureSite(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// Set just enough to trip every matcher.
		w.Header().Set("Server", "Apache/2.4.41")
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.Header().Set("Set-Cookie", "session=abc; Path=/") // missing all flags
		w.Write([]byte("hello"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	client := srv.Client()

	cases := generatePassiveSecurityChecks(srv.URL + "/")
	tripped := map[string]string{}
	for _, tc := range cases {
		req, err := tc.BuildRequest(t.Context())
		if err != nil {
			t.Fatalf("%s: build request: %v", tc.RuleID, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: do request: %v", tc.RuleID, err)
		}
		hit, reason := tc.Matcher.Match(resp, nil)
		resp.Body.Close()
		if hit {
			tripped[tc.RuleID] = reason
		}
	}

	wantTripped := []string{
		"DAST-HEAD-CSP-001",
		"DAST-HEAD-HSTS-001",
		"DAST-HEAD-XFO-001",
		"DAST-HEAD-XCTO-001",
		"DAST-HEAD-REFER-001",
		"DAST-HEAD-PERM-001",
		"DAST-HEAD-XPOWERED-001",
		"DAST-HEAD-SERVER-001",
		"DAST-COOKIE-SECURE-001",
		"DAST-COOKIE-HTTPONLY-001",
		"DAST-COOKIE-SAMESITE-001",
	}
	for _, want := range wantTripped {
		if _, ok := tripped[want]; !ok {
			t.Errorf("rule %s did not trip on insecure site", want)
		}
	}
}

// TestPassiveChecks_DontTripOnSecureSite verifies the inverse: when every
// header is set and cookies are flagged, no probe fires.
func TestPassiveChecks_DontTripOnSecureSite(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "geolocation=()")
		h.Set("Server", "nginx") // no version
		h.Set("Set-Cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
		w.Write([]byte("ok"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	client := srv.Client()

	cases := generatePassiveSecurityChecks(srv.URL + "/")
	var tripped []string
	for _, tc := range cases {
		req, err := tc.BuildRequest(t.Context())
		if err != nil {
			t.Fatalf("%s: %v", tc.RuleID, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.RuleID, err)
		}
		hit, reason := tc.Matcher.Match(resp, nil)
		resp.Body.Close()
		if hit {
			tripped = append(tripped, tc.RuleID+": "+reason)
		}
	}
	if len(tripped) != 0 {
		t.Errorf("expected zero findings against fully-secure site, got: %s", strings.Join(tripped, "; "))
	}
}

func TestGenerateTestCases_IncludesPassiveChecksOncePerScan(t *testing.T) {
	endpoints := []Endpoint{
		{Path: "/a", Method: "GET", BaseURL: "https://target.example"},
		{Path: "/b", Method: "GET", BaseURL: "https://target.example"},
		{Path: "/c", Method: "GET", BaseURL: "https://target.example"},
	}
	cases := GenerateTestCases(endpoints, "passive")
	csp := 0
	for _, tc := range cases {
		if tc.RuleID == "DAST-HEAD-CSP-001" {
			csp++
		}
	}
	if csp != 1 {
		t.Errorf("CSP probe emitted %d times, want exactly 1 per scan (not per endpoint)", csp)
	}
}
