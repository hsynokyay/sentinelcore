package sso

import "testing"

func TestValidateReturnTo(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
	}{
		{"/dashboard", true},
		{"/findings/abc-123?tab=evidence", true},
		{"/settings#section", true},
		{"", false},
		{"//evil.com/x", false},
		{"/\\evil.com", false},
		{"http://evil.com/", false},
		{"https://evil.com/", false},
		{"javascript:alert(1)", false},
		{"//evil.com/a?x=y", false},
		{"/?foo=//evil.com", true},
		{"relative", false},
		{"/  ", false},
		{"/ok\nX-Header: pwn", false},
		{"/ok\r", false},
	}
	for _, tc := range cases {
		got := ValidateReturnTo(tc.in)
		if got != tc.wantOK {
			t.Errorf("ValidateReturnTo(%q) = %v, want %v", tc.in, got, tc.wantOK)
		}
	}
}
