package dast

import (
	"strings"
	"testing"
)

func TestTargetRow_AllowedHosts_FallsBackToBaseURL(t *testing.T) {
	cases := []struct {
		name           string
		row            targetRow
		wantFirstHost  string
	}{
		{
			name: "explicit allowed_domains wins",
			row: targetRow{
				BaseURL:        "https://app.example.com",
				AllowedDomains: []string{"api.example.com", "auth.example.com"},
			},
			wantFirstHost: "api.example.com",
		},
		{
			name: "empty allowed_domains falls back to base URL host",
			row: targetRow{
				BaseURL:        "https://app.example.com:8443/path",
				AllowedDomains: []string{},
			},
			wantFirstHost: "app.example.com:8443",
		},
		{
			name: "host without port",
			row: targetRow{
				BaseURL:        "http://localhost",
				AllowedDomains: nil,
			},
			wantFirstHost: "localhost",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts := tc.row.AllowedHosts()
			if len(hosts) == 0 || hosts[0] != tc.wantFirstHost {
				t.Errorf("AllowedHosts()[0] = %v, want %q", hosts, tc.wantFirstHost)
			}
		})
	}
}

func TestSurfaceFingerprint_DeterministicAndScoped(t *testing.T) {
	ep := Endpoint{Path: "/users", Method: "GET"}
	f1 := surfaceFingerprint("scan-1", ep)
	f2 := surfaceFingerprint("scan-1", ep)
	if f1 != f2 {
		t.Errorf("expected deterministic fingerprint, got %s vs %s", f1, f2)
	}
	if surfaceFingerprint("scan-2", ep) == f1 {
		t.Errorf("fingerprint should differ across scan_jobs (got %s for both)", f1)
	}
	if surfaceFingerprint("scan-1", Endpoint{Path: "/users", Method: "POST"}) == f1 {
		t.Errorf("fingerprint should differ across methods")
	}
}

func TestDastFingerprint_StableAcrossScans(t *testing.T) {
	f := Finding{
		RuleID:    "DAST-SQLI-001",
		URL:       "https://app.example.com/users?id=1",
		Method:    "GET",
		Parameter: "id",
	}
	a := dastFingerprint(f)
	b := dastFingerprint(f)
	if a != b {
		t.Errorf("expected stable fingerprint, got %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, "") || len(a) != 64 {
		t.Errorf("expected 64-char hex (sha256), got %d-char %q", len(a), a)
	}
}

func TestDastFingerprint_SensitiveToRuleAndLocation(t *testing.T) {
	base := Finding{RuleID: "DAST-SQLI-001", URL: "https://x/y", Method: "GET", Parameter: "p"}
	for _, mut := range []func(Finding) Finding{
		func(f Finding) Finding { f.RuleID = "DAST-XSS-001"; return f },
		func(f Finding) Finding { f.URL = "https://x/z"; return f },
		func(f Finding) Finding { f.Method = "POST"; return f },
		func(f Finding) Finding { f.Parameter = "q"; return f },
	} {
		mutated := mut(base)
		if dastFingerprint(base) == dastFingerprint(mutated) {
			t.Errorf("fingerprint should differ between %+v and %+v", base, mutated)
		}
	}
}
