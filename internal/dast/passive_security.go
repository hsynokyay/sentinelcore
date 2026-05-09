package dast

import (
	"regexp"
)

// generatePassiveSecurityChecks emits one probe per passive header/cookie
// security check, all targeting the scan's base URL. These run regardless of
// scan profile (MinProfile=passive) and require no parameters — every site
// gets the same set of checks once per scan.
//
// Findings are deduplicated downstream by fingerprint(rule_id|method|url|param)
// so emitting them only against the base URL keeps results clean (no per-
// endpoint duplicates of the same site-wide policy issue).
func generatePassiveSecurityChecks(baseURL string) []TestCase {
	if baseURL == "" {
		return nil
	}

	cases := []TestCase{
		{
			RuleID:     "DAST-HEAD-CSP-001",
			Name:       "Missing Content-Security-Policy header",
			Category:   "security_misconfig",
			Severity:   "medium",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &HeaderMissingMatcher{
				Name:   "Content-Security-Policy",
				Reason: "response missing Content-Security-Policy — XSS / injection have no policy-level mitigation",
			},
		},
		{
			RuleID:     "DAST-HEAD-HSTS-001",
			Name:       "Missing Strict-Transport-Security header",
			Category:   "security_misconfig",
			Severity:   "medium",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &HeaderMissingMatcher{
				Name:      "Strict-Transport-Security",
				HTTPSOnly: true,
				Reason:    "response missing Strict-Transport-Security — clients can be downgraded to plain HTTP",
			},
		},
		{
			RuleID:     "DAST-HEAD-XFO-001",
			Name:       "Missing X-Frame-Options header",
			Category:   "security_misconfig",
			Severity:   "low",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &HeaderMissingMatcher{
				Name:   "X-Frame-Options",
				Reason: "response missing X-Frame-Options — page can be embedded in iframes (clickjacking risk)",
			},
		},
		{
			RuleID:     "DAST-HEAD-XCTO-001",
			Name:       "Missing X-Content-Type-Options header",
			Category:   "security_misconfig",
			Severity:   "low",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &HeaderMissingMatcher{
				Name:   "X-Content-Type-Options",
				Reason: "response missing X-Content-Type-Options: nosniff — browsers may MIME-sniff",
			},
		},
		{
			RuleID:     "DAST-HEAD-REFER-001",
			Name:       "Missing Referrer-Policy header",
			Category:   "security_misconfig",
			Severity:   "low",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &HeaderMissingMatcher{
				Name:   "Referrer-Policy",
				Reason: "response missing Referrer-Policy — full URLs may leak via Referer to third parties",
			},
		},
		{
			RuleID:     "DAST-HEAD-PERM-001",
			Name:       "Missing Permissions-Policy header",
			Category:   "security_misconfig",
			Severity:   "info",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &HeaderMissingMatcher{
				Name:   "Permissions-Policy",
				Reason: "response missing Permissions-Policy — sensitive browser features are not restricted",
			},
		},
		{
			RuleID:     "DAST-HEAD-XPOWERED-001",
			Name:       "Server framework disclosed via X-Powered-By header",
			Category:   "info_disclosure",
			Severity:   "low",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &HeaderPresentMatcher{
				Name:   "X-Powered-By",
				Reason: "X-Powered-By exposes runtime/framework",
			},
		},
		{
			RuleID:     "DAST-HEAD-SERVER-001",
			Name:       "Server software version disclosed via Server header",
			Category:   "info_disclosure",
			Severity:   "low",
			Confidence: "medium",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			// Match Server values that include a version (digits.digits) — bare
			// "nginx" or "cloudflare" are intentionally allowed.
			Matcher: &HeaderRegexMatcher{
				Name:    "Server",
				Pattern: regexp.MustCompile(`\d+\.\d+`),
				Reason:  "Server header discloses software version",
			},
		},
		{
			RuleID:     "DAST-COOKIE-SECURE-001",
			Name:       "Cookie set without Secure flag over HTTPS",
			Category:   "security_misconfig",
			Severity:   "medium",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &CookieMissingFlagMatcher{
				Flag:      "Secure",
				HTTPSOnly: true,
				Reason:    "cookie set without Secure — can leak to plain-HTTP",
			},
		},
		{
			RuleID:     "DAST-COOKIE-HTTPONLY-001",
			Name:       "Cookie set without HttpOnly flag",
			Category:   "security_misconfig",
			Severity:   "medium",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &CookieMissingFlagMatcher{
				Flag:   "HttpOnly",
				Reason: "cookie accessible to JavaScript (no HttpOnly)",
			},
		},
		{
			RuleID:     "DAST-COOKIE-SAMESITE-001",
			Name:       "Cookie set without SameSite attribute",
			Category:   "security_misconfig",
			Severity:   "low",
			Confidence: "high",
			Method:     "GET",
			URL:        baseURL,
			MinProfile: "passive",
			Matcher: &CookieMissingFlagMatcher{
				Flag:   "SameSite",
				Reason: "cookie has no SameSite attribute — CSRF protection is up to the browser default",
			},
		},
	}

	// Stamp deterministic IDs so test cases have the rule id baked in. This
	// is what the worker uses for evidence linkage.
	for i := range cases {
		cases[i].ID = cases[i].RuleID
	}
	return cases
}
