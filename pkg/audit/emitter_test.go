package audit

import "testing"

func TestNormaliseIP(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"10.0.0.5":            "10.0.0.5",
		"10.0.0.5:58242":      "10.0.0.5",
		"[::1]:1234":          "::1",
		"::1":                 "::1",
		"2001:db8::1":         "2001:db8::1",
		"2001:db8::1:80":      "2001:db8::1:80", // valid IPv6, left unchanged
		"garbage":             "",
		"10.0.0.5:abc":        "10.0.0.5",
	}
	for in, want := range cases {
		if got := normaliseIP(in); got != want {
			t.Errorf("normaliseIP(%q) = %q, want %q", in, got, want)
		}
	}
}
