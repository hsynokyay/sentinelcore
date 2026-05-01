package dast

import (
	"strings"
	"testing"
)

func TestGenerateTestCases_SQLi(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/api/users/{id}",
			Method:  "GET",
			BaseURL: "https://target.com",
			Parameters: []Parameter{
				{Name: "id", In: "path", Type: "integer", Required: true},
			},
		},
	}

	cases := GenerateTestCases(endpoints, "standard")
	if len(cases) == 0 {
		t.Fatal("expected test cases to be generated")
	}

	// Check that SQLi cases exist
	var sqliCount int
	for _, tc := range cases {
		if tc.Category == "sqli" {
			sqliCount++
		}
	}
	if sqliCount == 0 {
		t.Fatal("expected SQL injection test cases")
	}
}

func TestGenerateTestCases_XSS(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/search",
			Method:  "GET",
			BaseURL: "https://target.com",
			Parameters: []Parameter{
				{Name: "q", In: "query", Type: "string"},
			},
		},
	}

	cases := GenerateTestCases(endpoints, "standard")
	var xssCount int
	for _, tc := range cases {
		if tc.Category == "xss" {
			xssCount++
		}
	}
	if xssCount == 0 {
		t.Fatal("expected XSS test cases")
	}
}

func TestGenerateTestCases_SSRF(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/api/fetch",
			Method:  "GET",
			BaseURL: "https://target.com",
			Parameters: []Parameter{
				{Name: "url", In: "query", Type: "string"},
			},
		},
	}

	cases := GenerateTestCases(endpoints, "standard")
	var ssrfCount int
	for _, tc := range cases {
		if tc.Category == "ssrf" {
			ssrfCount++
		}
	}
	if ssrfCount == 0 {
		t.Fatal("expected SSRF test cases")
	}
}

func TestGenerateTestCases_IDOR(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/api/users/{user_id}/profile",
			Method:  "GET",
			BaseURL: "https://target.com",
			Parameters: []Parameter{
				{Name: "user_id", In: "path", Type: "integer", Required: true},
			},
		},
	}

	cases := GenerateTestCases(endpoints, "standard")
	var idorCount int
	for _, tc := range cases {
		if tc.Category == "idor" {
			idorCount++
		}
	}
	if idorCount == 0 {
		t.Fatal("expected IDOR test cases")
	}
}

func TestGenerateTestCases_MultipleCategories(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/api/items/{id}",
			Method:  "GET",
			BaseURL: "https://target.com",
			Parameters: []Parameter{
				{Name: "id", In: "path", Type: "integer", Required: true},
				{Name: "filter", In: "query", Type: "string"},
			},
		},
	}

	cases := GenerateTestCases(endpoints, "standard")
	categories := make(map[string]int)
	for _, tc := range cases {
		categories[tc.Category]++
	}

	// Should have multiple categories
	if len(categories) < 3 {
		t.Fatalf("expected at least 3 categories, got %d: %v", len(categories), categories)
	}
}

func TestGenerateTestCases_NoEndpoints(t *testing.T) {
	cases := GenerateTestCases(nil, "standard")
	if len(cases) != 0 {
		t.Fatalf("expected 0 test cases for nil endpoints, got %d", len(cases))
	}
}

func TestInjectParam_Query(t *testing.T) {
	result := injectParam("https://example.com/search", Parameter{Name: "q", In: "query"}, "test payload")
	if result != "https://example.com/search?q=test+payload" {
		t.Fatalf("unexpected URL: %s", result)
	}
}

func TestInjectParam_Path(t *testing.T) {
	result := injectParam("https://example.com/users/{id}", Parameter{Name: "id", In: "path"}, "123")
	if result != "https://example.com/users/123" {
		t.Fatalf("unexpected URL: %s", result)
	}
}

func TestGenerateTestCases_XXE(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/parse",
			Method:  "POST",
			BaseURL: "http://target.local",
			RequestBody: &RequestBodySpec{
				ContentType: "application/xml",
			},
		},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var xxe []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-XXE-001" {
			xxe = append(xxe, c)
		}
	}
	if len(xxe) == 0 {
		t.Fatalf("expected at least 1 XXE test case, got 0")
	}
	if xxe[0].Category != "xxe" {
		t.Errorf("category = %q, want xxe", xxe[0].Category)
	}
	if xxe[0].Severity != "high" {
		t.Errorf("severity = %q, want high", xxe[0].Severity)
	}
	if xxe[0].ContentType != "application/xml" {
		t.Errorf("content_type = %q, want application/xml", xxe[0].ContentType)
	}
	if !strings.Contains(xxe[0].Body, "ENTITY") {
		t.Errorf("body should contain ENTITY declaration, got %q", xxe[0].Body)
	}
}

func TestGenerateTestCases_NoSQL(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/login",
			Method:  "POST",
			BaseURL: "http://target.local",
			RequestBody: &RequestBodySpec{
				ContentType: "application/json",
				Schema: map[string]string{
					"username": "string",
					"password": "string",
				},
			},
		},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var nosql []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-NOSQL-001" {
			nosql = append(nosql, c)
		}
	}
	if len(nosql) == 0 {
		t.Fatalf("expected at least 1 NoSQL test case, got 0")
	}
	if !strings.Contains(nosql[0].Body, "$ne") && !strings.Contains(nosql[0].Body, "$gt") {
		t.Errorf("expected $ne or $gt operator in body, got %q", nosql[0].Body)
	}
}

func TestGenerateTestCases_GraphQLIntrospection(t *testing.T) {
	endpoints := []Endpoint{
		{Path: "/graphql", Method: "POST", BaseURL: "http://target.local"},
	}
	cases := GenerateTestCases(endpoints, "passive")
	var gql []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-GRAPHQL-001" {
			gql = append(gql, c)
		}
	}
	if len(gql) == 0 {
		t.Fatalf("expected GraphQL probe, got 0")
	}
	if gql[0].MinProfile != "passive" {
		t.Errorf("min_profile = %q, want passive", gql[0].MinProfile)
	}
	if !strings.Contains(gql[0].Body, "__schema") {
		t.Errorf("body should contain __schema, got %q", gql[0].Body)
	}
}

func TestGenerateTestCases_JWTAlgNone(t *testing.T) {
	// Real-shaped HS256 token; payload contains no sensitive data.
	// Header decodes to: {"alg":"HS256","typ":"JWT"}
	// Payload decodes to: {"sub":"u","exp":99999999999}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1IiwiZXhwIjo5OTk5OTk5OTk5OX0.signature"
	endpoints := []Endpoint{
		{Path: "/me", Method: "GET", BaseURL: "http://target.local", CapturedJWT: jwt},
	}
	cases := GenerateTestCases(endpoints, "passive")
	var hits []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-JWT-001" {
			hits = append(hits, c)
		}
	}
	if len(hits) == 0 {
		t.Fatalf("expected DAST-JWT-001 case, got 0")
	}
	auth := hits[0].Headers["Authorization"]
	if !strings.HasPrefix(auth, "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.") {
		t.Errorf("Authorization header should carry an alg=none token, got %q", auth)
	}
	// Token must have empty signature (the trailing 3rd segment).
	if strings.HasSuffix(strings.TrimPrefix(auth, "Bearer "), ".signature") {
		t.Errorf("signature segment should be empty, got %q", auth)
	}
}

func TestGenerateTestCases_JWTAlgNone_NoTokenSkipped(t *testing.T) {
	endpoints := []Endpoint{
		{Path: "/me", Method: "GET", BaseURL: "http://target.local"},
	}
	cases := GenerateTestCases(endpoints, "passive")
	for _, c := range cases {
		if c.RuleID == "DAST-JWT-001" {
			t.Fatalf("expected JWT-001 to be skipped without CapturedJWT, but got %d cases", len(cases))
		}
	}
}

func TestGenerateTestCases_JWTWeakSecret(t *testing.T) {
	// Token signed with HS256 secret "secret":
	// header = {"alg":"HS256","typ":"JWT"}, payload = {"sub":"u"}
	// Signature verified: hmac-sha256("secret", header+"."+payload)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1In0.D9OYCASOic8f2se0l70pQbnYe4k4FisxamL3OAU6LCc"
	endpoints := []Endpoint{
		{Path: "/me", Method: "GET", BaseURL: "http://target.local", CapturedJWT: jwt},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var hit *TestCase
	for i, c := range cases {
		if c.RuleID == "DAST-JWT-002" {
			hit = &cases[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected DAST-JWT-002, got 0 cases")
	}
	if !strings.Contains(hit.Name, "secret") {
		t.Errorf("name should mention the cracked secret: %q", hit.Name)
	}
	if hit.MinProfile != "standard" {
		t.Errorf("min_profile = %q, want standard", hit.MinProfile)
	}
}

func TestGenerateTestCases_CRLF(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/track",
			Method:  "GET",
			BaseURL: "http://target.local",
			Parameters: []Parameter{
				{Name: "id", In: "query", Type: "string"},
			},
		},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var crlf []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-CRLF-001" {
			crlf = append(crlf, c)
		}
	}
	if len(crlf) == 0 {
		t.Fatalf("expected CRLF probe, got 0")
	}
	if !strings.Contains(crlf[0].URL, "%0d%0a") && !strings.Contains(crlf[0].URL, "%0D%0A") {
		t.Errorf("URL should encode CR/LF, got %q", crlf[0].URL)
	}
}

func TestGenerateTestCases_OpenRedirect(t *testing.T) {
	endpoints := []Endpoint{
		{
			Path:    "/login/callback",
			Method:  "GET",
			BaseURL: "http://target.local",
			Parameters: []Parameter{
				{Name: "next", In: "query", Type: "string"},
				{Name: "id", In: "query", Type: "integer"},
			},
		},
	}
	cases := GenerateTestCases(endpoints, "standard")
	var redirs []TestCase
	for _, c := range cases {
		if c.RuleID == "DAST-OPENREDIR-001" {
			redirs = append(redirs, c)
		}
	}
	if len(redirs) == 0 {
		t.Fatalf("expected open-redirect probes, got 0")
	}
	// Should target the "next" param, not "id"
	for _, c := range redirs {
		if !strings.Contains(c.URL, "next=") {
			t.Errorf("probe should target the redirect-shaped param, got URL %q", c.URL)
		}
	}
}

func TestIsIDParam(t *testing.T) {
	tests := []struct {
		name   string
		expect bool
	}{
		{"id", true},
		{"user_id", true},
		{"userId", true},
		{"projectId", true},
		{"name", false},
		{"filter", false},
		{"valid", false},
	}
	for _, tt := range tests {
		if isIDParam(tt.name) != tt.expect {
			t.Errorf("isIDParam(%q) = %v, want %v", tt.name, !tt.expect, tt.expect)
		}
	}
}
