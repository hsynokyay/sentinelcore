package sso

import "testing"

func TestResolveRole(t *testing.T) {
	mappings := []GroupMapping{
		{Group: "sec-engs", Role: "security_engineer", Priority: 10},
		{Group: "admins", Role: "admin", Priority: 1},
		{Group: "auditors", Role: "auditor", Priority: 100},
	}
	defaultRole := "developer"

	cases := []struct {
		name            string
		groups          []string
		want            string
		wantFromMapping bool
	}{
		{"no groups → default", nil, "developer", false},
		{"unrecognized group → default", []string{"random"}, "developer", false},
		{"single match: auditor", []string{"auditors"}, "auditor", true},
		{"two matches: priority wins", []string{"auditors", "sec-engs"}, "security_engineer", true},
		{"all three: admin wins by priority", []string{"auditors", "sec-engs", "admins"}, "admin", true},
		{"case-sensitive match", []string{"SEC-ENGS"}, "developer", false},
	}
	for _, tc := range cases {
		got, ok := ResolveRole(tc.groups, mappings, defaultRole)
		if got != tc.want || ok != tc.wantFromMapping {
			t.Errorf("%s: ResolveRole(%v) = (%q, %v), want (%q, %v)",
				tc.name, tc.groups, got, ok, tc.want, tc.wantFromMapping)
		}
	}

	// Tie-breaker: same priority, sort by Role ASC.
	tieMappings := []GroupMapping{
		{Group: "A", Role: "role_b", Priority: 5},
		{Group: "B", Role: "role_a", Priority: 5},
	}
	got, ok := ResolveRole([]string{"A", "B"}, tieMappings, "developer")
	if got != "role_a" || !ok {
		t.Errorf("tie broken ASC: got=%q ok=%v, want role_a/true", got, ok)
	}
}
