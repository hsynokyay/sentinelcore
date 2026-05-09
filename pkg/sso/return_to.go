package sso

import "strings"

// ValidateReturnTo enforces the open-redirect guard on the return_to
// query parameter passed to /auth/sso/.../start. The value must be a
// same-origin path: starts with `/`, does not start with `//` (protocol-
// relative URL), contains no scheme indicator, no newlines (header
// injection), and no leading whitespace.
//
// Returns true iff the value is safe to store in Redis state and later
// use in a Location: header.
func ValidateReturnTo(s string) bool {
	if s == "" {
		return false
	}
	if s[0] != '/' {
		return false
	}
	if len(s) >= 2 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	if strings.ContainsAny(s, "\r\n") {
		return false
	}
	// Reject whitespace-only-content like "/  ".
	if strings.TrimSpace(s) == "/" && s != "/" {
		return false
	}
	// Reject scheme-looking paths: a `:` before any path/query/fragment
	// delimiter is a URI scheme. Check only the first 32 chars so that
	// legitimate `:` in deep query strings is fine.
	head := s
	if len(head) > 32 {
		head = s[:32]
	}
	if idx := strings.Index(head, ":"); idx > 0 {
		if !strings.ContainsAny(head[:idx], "/?#") {
			return false
		}
	}
	return true
}
