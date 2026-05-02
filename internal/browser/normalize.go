package browser

import (
	"net/url"
	"sort"
	"strings"
)

// NormalizeURL canonicalizes a URL for deduplication.
// Strips fragments, lowercases scheme+host, sorts query params,
// removes trailing slashes, removes default ports.
// Returns empty string for invalid URLs.
func NormalizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Only allow http/https/ws/wss
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https", "ws", "wss":
		// ok
	default:
		return ""
	}

	// Lowercase host
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return ""
	}

	// Remove default ports
	port := parsed.Port()
	if (scheme == "http" || scheme == "ws") && port == "80" {
		port = ""
	}
	if (scheme == "https" || scheme == "wss") && port == "443" {
		port = ""
	}

	// Rebuild host with port
	hostPort := host
	if port != "" {
		hostPort = host + ":" + port
	}

	// Normalize path: remove trailing slash (except root)
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}

	// Sort query parameters for consistent dedup
	query := parsed.Query()
	sortedQuery := url.Values{}
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals := query[k]
		sort.Strings(vals)
		for _, v := range vals {
			sortedQuery.Add(k, v)
		}
	}

	// Strip fragment — fragments are client-side only
	result := scheme + "://" + hostPort + path
	if encoded := sortedQuery.Encode(); encoded != "" {
		result += "?" + encoded
	}

	return result
}

// ResolveURL resolves a potentially relative URL against a base URL.
// Returns the resolved absolute URL or empty string on failure.
func ResolveURL(rawURL, baseURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	return resolved.String()
}
