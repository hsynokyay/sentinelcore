package replay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ExtractPrincipal scans cookies for JWT-shaped values (three base64url
// segments separated by dots) and returns the value of the named claim from
// the first decodable payload. The signature is NOT verified — the goal is
// identity attribution, not authentication. claim defaults to "sub".
func ExtractPrincipal(cookies []*http.Cookie, claim string) (string, bool) {
	if claim == "" {
		claim = "sub"
	}
	for _, c := range cookies {
		if c == nil {
			continue
		}
		parts := strings.Split(c.Value, ".")
		if len(parts) != 3 {
			continue
		}
		payload, err := base64.RawURLEncoding.DecodeString(padBase64(parts[1]))
		if err != nil {
			// Try standard URL encoding as a fallback (some issuers pad).
			payload, err = base64.URLEncoding.DecodeString(padBase64(parts[1]))
			if err != nil {
				continue
			}
		}
		var m map[string]interface{}
		if err := json.Unmarshal(payload, &m); err != nil {
			continue
		}
		if v, ok := m[claim]; ok {
			return fmt.Sprint(v), true
		}
	}
	return "", false
}

// VerifyPrincipal returns nil when the bundle's recorded principal matches
// the scan job's expected principal, or when either side is empty (no
// binding configured). A non-empty mismatch returns an error.
func VerifyPrincipal(bundlePrincipal, scanExpected string) error {
	if bundlePrincipal == "" || scanExpected == "" {
		return nil
	}
	if bundlePrincipal != scanExpected {
		return fmt.Errorf("principal: bundle=%q scan=%q (mismatch)", bundlePrincipal, scanExpected)
	}
	return nil
}

func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}
