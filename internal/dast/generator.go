package dast

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
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
		cases = append(cases, generateXXETests(ep, fullURL)...)
		cases = append(cases, generateNoSQLITests(ep, fullURL)...)
		cases = append(cases, generateGraphQLIntrospectionTests(ep, fullURL)...)
		cases = append(cases, generateJWTAlgNoneTests(ep, fullURL)...)
		cases = append(cases, generateJWTWeakSecretTests(ep, fullURL)...)
		cases = append(cases, generateCRLFTests(ep, fullURL)...)
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

// generateXXETests probes endpoints accepting XML bodies for external-entity
// expansion. Payload includes a SYSTEM entity that resolves /etc/passwd; the
// matcher fires on a /etc/passwd-shaped response body.
func generateXXETests(ep Endpoint, baseURL string) []TestCase {
	if ep.RequestBody == nil ||
		!strings.Contains(strings.ToLower(ep.RequestBody.ContentType), "xml") {
		return nil
	}
	payload := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
		`<root>&xxe;</root>`
	return []TestCase{{
		ID:          fmt.Sprintf("xxe-%s", ep.Method),
		RuleID:      "DAST-XXE-001",
		Name:        "XXE via SYSTEM entity in XML body",
		Category:    "xxe",
		Severity:    "high",
		Confidence:  "medium",
		Method:      ep.Method,
		URL:         baseURL,
		ContentType: "application/xml",
		Body:        payload,
		MinProfile:  "standard",
		Matcher: &BodyRegexMatcher{
			Pattern: regexp.MustCompile(`root:[^:]*:0:0:`),
			Reason:  "external entity resolved /etc/passwd",
		},
	}}
}

// jwtWeakSecretCandidates is the small dictionary that the weak-secret probe
// brute-forces against captured HS256 tokens. Twelve entries — enough to
// catch the most common copy-paste secrets; a longer list would inflate the
// per-endpoint test count without much marginal coverage.
var jwtWeakSecretCandidates = []string{
	"secret", "key", "password", "123456", "admin", "jwt",
	"JWT", "your-256-bit-secret", "please-change-me", "s3cr3t", "", "secretkey",
}

// generateJWTWeakSecretTests cracks the captured token offline against the
// dictionary above. If a candidate verifies the HS256 signature, the probe
// emits a single TestCase that re-uses the original token with that secret —
// the active probe is just hitting the endpoint with the same token to flag
// the finding (the cracked secret is the actual evidence and lives in the
// finding's name/description).
func generateJWTWeakSecretTests(ep Endpoint, baseURL string) []TestCase {
	if ep.CapturedJWT == "" {
		return nil
	}
	parts := strings.Split(ep.CapturedJWT, ".")
	if len(parts) != 3 {
		return nil
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	if !strings.Contains(string(headerJSON), `"HS256"`) {
		return nil
	}
	signedInput := []byte(parts[0] + "." + parts[1])
	expected, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil
	}
	for _, secret := range jwtWeakSecretCandidates {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(signedInput)
		if hmac.Equal(mac.Sum(nil), expected) {
			return []TestCase{{
				ID:         fmt.Sprintf("jwt-weak-%s", ep.Method),
				RuleID:     "DAST-JWT-002",
				Name:       fmt.Sprintf("JWT signed with weak secret %q", secret),
				Category:   "jwt_weak_secret",
				Severity:   "high",
				Confidence: "high",
				Method:     ep.Method,
				URL:        baseURL,
				Headers:    map[string]string{"Authorization": "Bearer " + ep.CapturedJWT},
				MinProfile: "standard",
				Matcher:    &StatusCodeMatcher{Codes: []int{200}},
			}}
		}
	}
	return nil
}

// generateJWTAlgNoneTests re-signs a captured JWT with alg=none and an empty
// signature. The matcher fires when the modified token is accepted (probe
// returns 200 instead of the expected 401/403).
func generateJWTAlgNoneTests(ep Endpoint, baseURL string) []TestCase {
	if ep.CapturedJWT == "" {
		return nil
	}
	parts := strings.Split(ep.CapturedJWT, ".")
	if len(parts) != 3 {
		return nil
	}
	// Build header {"alg":"none","typ":"JWT"} as base64url (no padding).
	const noneHeaderB64 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	noneToken := noneHeaderB64 + "." + parts[1] + "."
	return []TestCase{{
		ID:         fmt.Sprintf("jwt-none-%s", ep.Method),
		RuleID:     "DAST-JWT-001",
		Name:       "JWT alg=none accepted",
		Category:   "jwt_alg_none",
		Severity:   "critical",
		Confidence: "high",
		Method:     ep.Method,
		URL:        baseURL,
		Headers:    map[string]string{"Authorization": "Bearer " + noneToken},
		MinProfile: "passive",
		Matcher:    &StatusCodeMatcher{Codes: []int{200}},
	}}
}

// generateGraphQLIntrospectionTests probes well-known GraphQL paths for an
// introspection-enabled endpoint. Sends an introspection query; the matcher
// fires when the response body advertises the schema.
func generateGraphQLIntrospectionTests(ep Endpoint, _ string) []TestCase {
	candidates := []string{"/graphql", "/api/graphql", "/v1/graphql"}
	matched := false
	for _, c := range candidates {
		if ep.Path == c {
			matched = true
			break
		}
	}
	if !matched {
		return nil
	}
	body := `{"query":"{__schema{types{name}}}"}`
	return []TestCase{{
		ID:          fmt.Sprintf("graphql-%s", ep.Method),
		RuleID:      "DAST-GRAPHQL-001",
		Name:        "GraphQL introspection enabled",
		Category:    "graphql_introspection",
		Severity:    "medium",
		Confidence:  "high",
		Method:      "POST",
		URL:         ep.BaseURL + ep.Path,
		ContentType: "application/json",
		Body:        body,
		MinProfile:  "passive",
		Matcher: &CompositeMatcher{
			Mode: "and",
			Matchers: []ResponseMatcher{
				&StatusCodeMatcher{Codes: []int{200}},
				&BodyContainsMatcher{Patterns: []string{`"__schema"`, `"types"`}},
			},
		},
	}}
}

// generateNoSQLITests probes JSON-bodied endpoints for NoSQL-operator injection.
// Substitutes operator objects into expected string fields and looks for a
// status code that signals authentication or authorization bypass.
func generateNoSQLITests(ep Endpoint, baseURL string) []TestCase {
	if ep.RequestBody == nil ||
		!strings.Contains(strings.ToLower(ep.RequestBody.ContentType), "json") ||
		ep.RequestBody.Schema == nil {
		return nil
	}
	operators := []string{
		`{"$ne": null}`,
		`{"$gt": ""}`,
		`{"$regex": ".*"}`,
	}
	var cases []TestCase
	for fieldName := range ep.RequestBody.Schema {
		for i, op := range operators {
			body := buildJSONWithOperator(ep.RequestBody.Schema, fieldName, op)
			cases = append(cases, TestCase{
				ID:          fmt.Sprintf("nosql-%s-%s-%d", ep.Method, fieldName, i),
				RuleID:      "DAST-NOSQL-001",
				Name:        fmt.Sprintf("NoSQL operator injection via field %q", fieldName),
				Category:    "nosql_injection",
				Severity:    "high",
				Confidence:  "low",
				Method:      ep.Method,
				URL:         baseURL,
				ContentType: "application/json",
				Body:        body,
				MinProfile:  "standard",
				Matcher: &StatusCodeMatcher{
					// 200 on a typical login endpoint = bypass; baseline diff
					// would refine this in a future iteration.
					Codes: []int{200},
				},
			})
		}
	}
	return cases
}

// buildJSONWithOperator constructs a JSON body where one field is replaced by
// a raw operator JSON snippet. Other fields get a placeholder string value.
func buildJSONWithOperator(schema map[string]string, target, opJSON string) string {
	var parts []string
	for k := range schema {
		if k == target {
			parts = append(parts, fmt.Sprintf(`%q: %s`, k, opJSON))
		} else {
			parts = append(parts, fmt.Sprintf(`%q: "probe"`, k))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// generateCRLFTests injects %0d%0a-encoded CR/LF into query parameters and
// expects the response to echo a forged Set-Cookie header.
func generateCRLFTests(ep Endpoint, baseURL string) []TestCase {
	payloads := []string{
		"%0d%0aSet-Cookie:%20pwn=1",
		"%0D%0ASet-Cookie:%20pwn=1",
		"\r\nSet-Cookie: pwn=1",
	}
	var cases []TestCase
	for _, param := range ep.Parameters {
		if param.In != "query" && param.In != "path" {
			continue
		}
		for i, payload := range payloads {
			// Build URL with raw query to preserve percent-encoded CR/LF literals.
			var testURL string
			if param.In == "query" {
				u, err := url.Parse(baseURL)
				if err != nil {
					testURL = baseURL
				} else {
					u.RawQuery = param.Name + "=" + payload
					testURL = u.String()
				}
			} else {
				testURL = injectParam(baseURL, param, payload)
			}
			cases = append(cases, TestCase{
				ID:         fmt.Sprintf("crlf-%s-%s-%d", ep.Method, param.Name, i),
				RuleID:     "DAST-CRLF-001",
				Name:       fmt.Sprintf("CRLF injection via %s param %q", param.In, param.Name),
				Category:   "crlf_injection",
				Severity:   "high",
				Confidence: "medium",
				Method:     ep.Method,
				URL:        testURL,
				MinProfile: "standard",
				Matcher: &HeaderContainsMatcher{
					Name:      "Set-Cookie",
					Substring: "pwn=1",
					Reason:    "injected Set-Cookie header echoed in response",
				},
			})
		}
	}
	return cases
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
