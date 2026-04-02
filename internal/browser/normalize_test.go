package browser

import "testing"

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"basic https", "https://Example.COM/Page", "https://example.com/Page"},
		{"strip fragment", "https://example.com/page#section", "https://example.com/page"},
		{"strip trailing slash", "https://example.com/path/", "https://example.com/path"},
		{"keep root slash", "https://example.com/", "https://example.com/"},
		{"add root slash", "https://example.com", "https://example.com/"},
		{"strip default port 443", "https://example.com:443/page", "https://example.com/page"},
		{"strip default port 80", "http://example.com:80/page", "http://example.com/page"},
		{"keep non-default port", "https://example.com:8443/page", "https://example.com:8443/page"},
		{"sort query params", "https://example.com/page?z=1&a=2", "https://example.com/page?a=2&z=1"},
		{"ws scheme", "ws://example.com/socket", "ws://example.com/socket"},
		{"wss scheme", "wss://example.com/socket", "wss://example.com/socket"},
		{"reject ftp", "ftp://example.com/file", ""},
		{"reject javascript", "javascript:alert(1)", ""},
		{"reject data", "data:text/html,<h1>Hi</h1>", ""},
		{"reject empty", "", ""},
		{"reject mailto", "mailto:user@example.com", ""},
		{"lowercase host", "HTTPS://WWW.EXAMPLE.COM/PATH", "https://www.example.com/PATH"},
		{"duplicate query values sorted", "https://ex.com/?b=2&a=1&a=0", "https://ex.com/?a=0&a=1&b=2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeURL(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveURL(t *testing.T) {
	base := "https://example.com/app/page"
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"absolute", "https://example.com/other", "https://example.com/other"},
		{"relative path", "subpage", "https://example.com/app/subpage"},
		{"root relative", "/root", "https://example.com/root"},
		{"fragment only", "#section", "https://example.com/app/page#section"},
		{"query only", "?q=1", "https://example.com/app/page?q=1"},
		{"parent path", "../other", "https://example.com/other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveURL(tt.ref, base)
			if got != tt.want {
				t.Errorf("ResolveURL(%q, %q) = %q, want %q", tt.ref, base, got, tt.want)
			}
		})
	}
}
