package dast

import (
	"fmt"
	"net/url"
	"strings"
)

// Endpoint represents a parsed API endpoint from an OpenAPI spec.
type Endpoint struct {
	Path        string
	Method      string
	Parameters  []Parameter
	RequestBody *RequestBodySpec
	BaseURL     string
	// CapturedJWT, when non-empty, is a JWT (compact serialization) that
	// the orchestrator captured from this endpoint's auth profile during
	// baseline crawl. Used by JWT-targeted probes. Empty means no JWT
	// was observed; JWT probes skip the endpoint silently.
	CapturedJWT string
}

// Parameter represents an API parameter.
type Parameter struct {
	Name     string
	In       string // path, query, header, cookie
	Type     string // string, integer, boolean, array
	Required bool
	Example  string
}

// RequestBodySpec describes expected request body.
type RequestBodySpec struct {
	ContentType string
	Schema      map[string]string // field → type
	Example     string
}

// profileRank ranks scan profiles for filtering. Higher = more permissive.
var profileRank = map[string]int{
	"passive":    0,
	"standard":   1,
	"aggressive": 2,
}

// GenerateTestCases creates DAST test cases for a set of API endpoints.
// `profile` is the scan profile ("passive", "standard", "aggressive");
// empty string defaults to "standard". Test cases whose MinProfile rank
// exceeds the requested profile are dropped.
func GenerateTestCases(endpoints []Endpoint, profile string) []TestCase {
	if profile == "" {
		profile = "standard"
	}
	requested, ok := profileRank[profile]
	if !ok {
		requested = profileRank["standard"]
	}

	var cases []TestCase
	for _, ep := range endpoints {
		fullURL := ep.BaseURL + ep.Path
		cases = append(cases, generateSQLiTests(ep, fullURL)...)
		cases = append(cases, generateXSSTests(ep, fullURL)...)
		cases = append(cases, generatePathTraversalTests(ep, fullURL)...)
		cases = append(cases, generateSSRFTests(ep, fullURL)...)
		cases = append(cases, generateIDORTests(ep, fullURL)...)
		cases = append(cases, generateHeaderInjectionTests(ep, fullURL)...)
	}

	// Filter by profile.
	filtered := cases[:0]
	for _, tc := range cases {
		min := tc.MinProfile
		if min == "" {
			min = "standard"
		}
		minRank, ok := profileRank[min]
		if !ok {
			minRank = profileRank["standard"]
		}
		if minRank <= requested {
			filtered = append(filtered, tc)
		}
	}
	return filtered
}

func generateSQLiTests(ep Endpoint, baseURL string) []TestCase {
	payloads := []string{
		"' OR '1'='1",
		"1; DROP TABLE users--",
		"' UNION SELECT NULL,NULL--",
		"1' AND SLEEP(5)--",
		"' OR 1=1#",
	}

	indicators := []string{
		"SQL syntax",
		"mysql_",
		"ORA-",
		"PostgreSQL",
		"sqlite3",
		"SQLSTATE",
		"unclosed quotation",
		"quoted string not properly terminated",
	}

	var cases []TestCase
	for _, param := range ep.Parameters {
		if param.In == "query" || param.In == "path" {
			for i, payload := range payloads {
				testURL := injectParam(baseURL, param, payload)
				cases = append(cases, TestCase{
					ID:         fmt.Sprintf("sqli-%s-%s-%d", ep.Method, param.Name, i),
					RuleID:     "DAST-SQLI-001",
					Name:       fmt.Sprintf("SQL Injection via %s param %q", param.In, param.Name),
					Category:   "sqli",
					Severity:   "critical",
					Confidence: "medium",
					Method:     ep.Method,
					URL:        testURL,
					Matcher:    &BodyContainsMatcher{Patterns: indicators},
				})
			}
		}
	}
	return cases
}

func generateXSSTests(ep Endpoint, baseURL string) []TestCase {
	payloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"'><script>alert(1)</script>",
	}

	var cases []TestCase
	for _, param := range ep.Parameters {
		if param.In == "query" {
			for i, payload := range payloads {
				testURL := injectParam(baseURL, param, payload)
				cases = append(cases, TestCase{
					ID:         fmt.Sprintf("xss-%s-%s-%d", ep.Method, param.Name, i),
					RuleID:     "DAST-XSS-001",
					Name:       fmt.Sprintf("Reflected XSS via %s param %q", param.In, param.Name),
					Category:   "xss",
					Severity:   "high",
					Confidence: "medium",
					Method:     ep.Method,
					URL:        testURL,
					Matcher:    &BodyContainsMatcher{Patterns: []string{payload}},
				})
			}
		}
	}
	return cases
}

func generatePathTraversalTests(ep Endpoint, baseURL string) []TestCase {
	payloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}

	indicators := []string{
		"root:x:",
		"[boot loader]",
		"[operating systems]",
	}

	var cases []TestCase
	for _, param := range ep.Parameters {
		if param.In == "path" || param.In == "query" {
			for i, payload := range payloads {
				testURL := injectParam(baseURL, param, payload)
				cases = append(cases, TestCase{
					ID:         fmt.Sprintf("pt-%s-%s-%d", ep.Method, param.Name, i),
					RuleID:     "DAST-PT-001",
					Name:       fmt.Sprintf("Path Traversal via %s param %q", param.In, param.Name),
					Category:   "path_traversal",
					Severity:   "high",
					Confidence: "medium",
					Method:     ep.Method,
					URL:        testURL,
					Matcher:    &BodyContainsMatcher{Patterns: indicators},
				})
			}
		}
	}
	return cases
}

func generateSSRFTests(ep Endpoint, baseURL string) []TestCase {
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:80/",
		"http://[::1]/",
		"http://0.0.0.0/",
		"http://metadata.google.internal/",
	}

	var cases []TestCase
	for _, param := range ep.Parameters {
		if param.Type == "string" && (param.In == "query" || param.In == "path") {
			for i, payload := range payloads {
				testURL := injectParam(baseURL, param, payload)
				cases = append(cases, TestCase{
					ID:         fmt.Sprintf("ssrf-%s-%s-%d", ep.Method, param.Name, i),
					RuleID:     "DAST-SSRF-001",
					Name:       fmt.Sprintf("SSRF via %s param %q", param.In, param.Name),
					Category:   "ssrf",
					Severity:   "critical",
					Confidence: "low",
					Method:     ep.Method,
					URL:        testURL,
					Matcher: &CompositeMatcher{
						Mode: "or",
						Matchers: []ResponseMatcher{
							&StatusCodeMatcher{Codes: []int{200}},
							&BodyContainsMatcher{Patterns: []string{"ami-", "instance-id", "meta-data"}},
						},
					},
				})
			}
		}
	}
	return cases
}

func generateIDORTests(ep Endpoint, baseURL string) []TestCase {
	idPayloads := []string{"1", "0", "-1", "999999", "admin"}

	var cases []TestCase
	for _, param := range ep.Parameters {
		if param.In == "path" && isIDParam(param.Name) {
			for i, payload := range idPayloads {
				testURL := injectParam(baseURL, param, payload)
				cases = append(cases, TestCase{
					ID:         fmt.Sprintf("idor-%s-%s-%d", ep.Method, param.Name, i),
					RuleID:     "DAST-IDOR-001",
					Name:       fmt.Sprintf("IDOR via %s param %q", param.In, param.Name),
					Category:   "idor",
					Severity:   "high",
					Confidence: "low",
					Method:     ep.Method,
					URL:        testURL,
					Matcher:    &StatusCodeMatcher{Codes: []int{200}},
				})
			}
		}
	}
	return cases
}

func generateHeaderInjectionTests(ep Endpoint, baseURL string) []TestCase {
	return []TestCase{
		{
			ID:       fmt.Sprintf("hi-%s-host", ep.Method),
			RuleID:   "DAST-HI-001",
			Name:     "Host Header Injection",
			Category: "header_injection",
			Severity: "medium",
			Confidence: "medium",
			Method:   ep.Method,
			URL:      baseURL,
			Headers:  map[string]string{"Host": "evil.com"},
			Matcher:  &BodyContainsMatcher{Patterns: []string{"evil.com"}},
		},
	}
}

func injectParam(baseURL string, param Parameter, payload string) string {
	if param.In == "path" {
		return strings.Replace(baseURL, "{"+param.Name+"}", url.PathEscape(payload), 1)
	}
	// query param
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	q.Set(param.Name, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

func isIDParam(name string) bool {
	lower := strings.ToLower(name)
	if lower == "id" {
		return true
	}
	if strings.HasSuffix(lower, "_id") {
		return true
	}
	// camelCase: userId, projectId — require uppercase I before d
	if len(name) > 2 && strings.HasSuffix(name, "Id") {
		return true
	}
	return false
}
