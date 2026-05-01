package dast

import (
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
