package apikeys

import "fmt"

// UnknownScopeError is returned when a requested scope is not a known
// permission in the auth.permissions catalog. The UI can suggest similar
// names by fuzzy-matching against the full catalog.
type UnknownScopeError struct {
	Scope string
}

func (e *UnknownScopeError) Error() string {
	return fmt.Sprintf("unknown scope: %q", e.Scope)
}

// PrivilegeEscalationError is returned when the requested scope is not in
// the creator's own permission set. The creator cannot grant permissions
// they do not themselves possess.
type PrivilegeEscalationError struct {
	Scope string
}

func (e *PrivilegeEscalationError) Error() string {
	return fmt.Sprintf("cannot grant scope you don't have: %q", e.Scope)
}

// EmptyScopesError — sentinel for requests with no scopes. Exposed as a
// value so handlers can errors.Is() it to 400 BAD_REQUEST.
var EmptyScopesError = fmt.Errorf("scopes must contain at least one permission")

// DuplicateScopeError is returned when the requested list contains the
// same scope twice. Also triggers 400 BAD_REQUEST at the handler.
type DuplicateScopeError struct {
	Scope string
}

func (e *DuplicateScopeError) Error() string {
	return fmt.Sprintf("duplicate scope: %q", e.Scope)
}

// ValidateScopes enforces four rules on an API-key scope list:
//  1. Must contain at least one scope.
//  2. No duplicates (case-sensitive).
//  3. Every scope must exist in the permissions catalog (known).
//  4. Every scope must be in the creator's own permission set.
//
// Returns one of the typed errors above so handlers can map each to the
// correct HTTP status without string-matching.
//
// known + creator are passed as sets for O(1) lookup. Typical callers
// obtain them from the RBAC cache.
func ValidateScopes(requested []string, creator, known map[string]struct{}) error {
	if len(requested) == 0 {
		return EmptyScopesError
	}

	seen := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		if _, dup := seen[scope]; dup {
			return &DuplicateScopeError{Scope: scope}
		}
		seen[scope] = struct{}{}

		if _, ok := known[scope]; !ok {
			return &UnknownScopeError{Scope: scope}
		}
		if _, ok := creator[scope]; !ok {
			return &PrivilegeEscalationError{Scope: scope}
		}
	}
	return nil
}
