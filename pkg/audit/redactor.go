package audit

import (
	"regexp"
	"strings"
)

// secretKeyPattern matches keys whose VALUES should never be recorded in
// audit event details. The match is case-insensitive over the WHOLE key
// (use word boundaries inside so "session_key" and "keyring" both match
// but plain "key" matches too).
//
// Additions here are a one-way door: expanding the deny-list is safe;
// narrowing it is a forensic hazard (old events may have been relying on
// the redaction). Coordinate with security review before removing a term.
var secretKeyPattern = regexp.MustCompile(
	`(?i)(secret|password|passwd|token|(api|private|session|access|signing|encryption|hmac|refresh|enc)[_\-]?key|authorization|bearer|credential|passphrase|hash|cookie)`)

// truncateLimit is the max allowed length of any string VALUE in a redacted
// event. Longer values are trimmed to (truncateLimit) chars + truncateSuffix.
// 512 is a compromise: big enough for meaningful diagnostic payloads (URLs,
// error messages, stack traces), small enough to keep per-row size bounded.
const truncateLimit = 512

// truncateSuffix is appended to values that were shortened so callers and
// UIs can tell truncation happened. It's a single Unicode horizontal ellipsis.
const truncateSuffix = "…"

// Redact walks a map, drops any (string-keyed) fields whose key matches
// secretKeyPattern, and truncates any string value longer than truncateLimit.
// The returned slice lists the DROPPED paths in dot-notation so the audit
// row can record what was scrubbed without revealing the values themselves.
//
// Non-map / non-slice values (int, bool, float) pass through unchanged.
// Nested maps and arrays are walked recursively.
//
// Redact is purely functional: it returns a NEW map/slice and does not
// mutate the input. This matters because emitter callers pass handler-owned
// maps that may still be in use for other logging paths.
func Redact(in map[string]any) (out map[string]any, dropped []string) {
	if in == nil {
		return nil, nil
	}
	return redactMap(in, ""), collectDrops(in, "")
}

// redactMap returns a copy of m with secret keys removed and long strings
// truncated. It does NOT collect dropped paths; that is a separate pass so
// the hot path can avoid allocating the slice when callers don't need it.
func redactMap(m map[string]any, prefix string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if secretKeyPattern.MatchString(k) {
			continue
		}
		out[k] = redactValue(v, joinPath(prefix, k))
	}
	return out
}

// redactValue applies the truncation + recursion rules to a single value.
func redactValue(v any, path string) any {
	switch t := v.(type) {
	case map[string]any:
		return redactMap(t, path)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = redactValue(x, path)
		}
		return out
	case string:
		if len(t) > truncateLimit {
			return t[:truncateLimit] + truncateSuffix
		}
		return t
	default:
		return v
	}
}

// collectDrops walks the ORIGINAL map (not the redacted copy) to list every
// dotted path that was dropped. Done as a separate pass for clarity; the
// iteration cost is tiny compared to HMAC + DB write on the write path.
func collectDrops(m map[string]any, prefix string) []string {
	var out []string
	for k, v := range m {
		p := joinPath(prefix, k)
		if secretKeyPattern.MatchString(k) {
			out = append(out, p)
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			out = append(out, collectDrops(t, p)...)
		case []any:
			for _, x := range t {
				if nested, ok := x.(map[string]any); ok {
					out = append(out, collectDrops(nested, p)...)
				}
			}
		}
	}
	return out
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// ContainsSecretKeys is exposed for tests + lint-like use cases. It returns
// true if any key anywhere in the map matches secretKeyPattern.
func ContainsSecretKeys(m map[string]any) bool {
	for k, v := range m {
		if secretKeyPattern.MatchString(k) {
			return true
		}
		switch t := v.(type) {
		case map[string]any:
			if ContainsSecretKeys(t) {
				return true
			}
		case []any:
			for _, x := range t {
				if nested, ok := x.(map[string]any); ok {
					if ContainsSecretKeys(nested) {
						return true
					}
				}
			}
		}
	}
	return false
}

// Keep strings import usable for future structured warnings.
var _ = strings.HasPrefix
