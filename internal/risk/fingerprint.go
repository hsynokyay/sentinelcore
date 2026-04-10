package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	uuidRegex  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	numRegex   = regexp.MustCompile(`^[0-9]+$`)
	alphaRegex = regexp.MustCompile(`[a-zA-Z]`)
	digitRegex = regexp.MustCompile(`[0-9]`)
)

// NormalizeRoute converts a raw URL (or path) into the canonical form used
// for DAST cluster fingerprinting. Applied in order:
//  1. strip scheme + host
//  2. strip query string
//  3. URL-decode path segments
//  4. lowercase the path
//  5. parameterize numeric / uuid / long-alnum segments positionally
//  6. rejoin, strip trailing slash except for root
func NormalizeRoute(raw string) string {
	if raw == "" {
		return ""
	}
	raw = strings.TrimSpace(raw)

	// Step 1+2: parse and keep only the path.
	path := raw
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			path = u.Path
		}
	} else if idx := strings.Index(raw, "?"); idx >= 0 {
		path = raw[:idx]
	}
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	if path == "" {
		path = "/"
	}

	// Step 3: URL-decode.
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}

	// Step 4: lowercase.
	path = strings.ToLower(path)

	// Step 5: parameterize segments.
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		segments[i] = classifySegment(seg)
	}
	path = strings.Join(segments, "/")

	// Step 6: strip trailing slash (but not for root).
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}
	if path == "" {
		path = "/"
	}
	return path
}

// classifySegment replaces a single path segment with a parameter token if
// it matches the numeric / uuid / long-alnum patterns.
func classifySegment(seg string) string {
	if numRegex.MatchString(seg) {
		return ":num"
	}
	if uuidRegex.MatchString(seg) {
		return ":uuid"
	}
	if len(seg) > 16 && alphaRegex.MatchString(seg) && digitRegex.MatchString(seg) {
		return ":token"
	}
	return seg
}

// NormalizeParam lowercases and trims a DAST parameter name.
func NormalizeParam(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// NormalizeFilePath canonicalizes a SAST file path: forward slashes, no
// leading "./", no absolute prefixes.
func NormalizeFilePath(path string) string {
	path = strings.ReplaceAll(path, `\`, "/")
	path = strings.TrimPrefix(path, "./")
	return path
}

// LocationGroup computes the SAST discriminator inside a file. Prefers the
// enclosing method name; falls back to a line-bucketed + CWE-keyed form.
// See spec §5.2.
func LocationGroup(functionName string, lineStart, cweID int) string {
	if fn := strings.TrimSpace(functionName); fn != "" {
		return "m:" + fn
	}
	return fmt.Sprintf("b:%d:cwe_%d", lineStart/25, cweID)
}

// ComputeFingerprint returns (fingerprint, kind, version) for a finding.
// The version is not included in the hash — it lives on the cluster row
// as an administrative scope.
func ComputeFingerprint(f *Finding) (fp string, kind string, version int16) {
	switch f.Type {
	case "dast":
		input := []string{
			f.ProjectID,
			"dast",
			strconv.Itoa(f.CWEID),
			strings.ToUpper(f.HTTPMethod),
			NormalizeRoute(f.URL),
			NormalizeParam(f.Parameter),
		}
		return sha256hex(strings.Join(input, "|")), "dast_route", FingerprintVersion
	case "sast":
		input := []string{
			f.ProjectID,
			"sast",
			strconv.Itoa(f.CWEID),
			strings.ToLower(f.Language),
			NormalizeFilePath(f.FilePath),
			LocationGroup(f.FunctionName, f.LineStart, f.CWEID),
		}
		return sha256hex(strings.Join(input, "|")), "sast_file", FingerprintVersion
	}
	return "", "", 0
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
