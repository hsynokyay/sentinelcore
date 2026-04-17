package sso

import "sort"

// GroupMapping is one row from auth.oidc_group_mappings.
// Lower Priority value wins; ties broken by Role ASC (for determinism).
type GroupMapping struct {
	Group    string
	Role     string
	Priority int
}

// ResolveRole picks the best role for an incoming set of IdP group
// claims. Returns (role, fromMapping); fromMapping=false means the
// default role was used.
//
// Algorithm:
//  1. Filter mappings to those whose Group appears in groups.
//  2. Sort by (Priority ASC, Role ASC) for deterministic tie-breaking.
//  3. Pick the first. If empty, return (defaultRole, false).
func ResolveRole(groups []string, mappings []GroupMapping, defaultRole string) (string, bool) {
	if len(groups) == 0 || len(mappings) == 0 {
		return defaultRole, false
	}
	inSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		inSet[g] = struct{}{}
	}
	matched := make([]GroupMapping, 0, len(mappings))
	for _, m := range mappings {
		if _, ok := inSet[m.Group]; ok {
			matched = append(matched, m)
		}
	}
	if len(matched) == 0 {
		return defaultRole, false
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Priority != matched[j].Priority {
			return matched[i].Priority < matched[j].Priority
		}
		return matched[i].Role < matched[j].Role
	})
	return matched[0].Role, true
}
