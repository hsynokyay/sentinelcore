package vuln

import (
	"strconv"
	"strings"
)

// MatchVersion checks if a given version falls within a vulnerability's
// version range. It supports basic semver comparison for MVP.
// Range format examples: "< 4.17.21", ">= 1.0.0, < 2.0.0"
func MatchVersion(version, versionRange, ecosystem string) bool {
	version = strings.TrimSpace(version)
	versionRange = strings.TrimSpace(versionRange)

	if version == "" || versionRange == "" {
		return false
	}

	// Split on comma for compound ranges like ">= 1.0.0, < 2.0.0"
	parts := strings.Split(versionRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !matchSingleConstraint(version, part) {
			return false
		}
	}
	return true
}

func matchSingleConstraint(version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)

	var op, target string

	if strings.HasPrefix(constraint, ">=") {
		op = ">="
		target = strings.TrimSpace(constraint[2:])
	} else if strings.HasPrefix(constraint, "<=") {
		op = "<="
		target = strings.TrimSpace(constraint[2:])
	} else if strings.HasPrefix(constraint, "!=") {
		op = "!="
		target = strings.TrimSpace(constraint[2:])
	} else if strings.HasPrefix(constraint, ">") {
		op = ">"
		target = strings.TrimSpace(constraint[1:])
	} else if strings.HasPrefix(constraint, "<") {
		op = "<"
		target = strings.TrimSpace(constraint[1:])
	} else if strings.HasPrefix(constraint, "=") {
		op = "="
		target = strings.TrimSpace(constraint[1:])
	} else {
		// Exact match
		op = "="
		target = constraint
	}

	cmp := compareSemver(version, target)

	switch op {
	case "=":
		return cmp == 0
	case "!=":
		return cmp != 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	default:
		return false
	}
}

// compareSemver compares two version strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareSemver(a, b string) int {
	aParts := parseVersionParts(a)
	bParts := parseVersionParts(b)

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var av, bv int
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func parseVersionParts(v string) []int {
	// Strip leading 'v' if present
	v = strings.TrimPrefix(v, "v")
	// Strip pre-release suffix (anything after '-')
	if idx := strings.Index(v, "-"); idx >= 0 {
		v = v[:idx]
	}
	// Strip build metadata (anything after '+')
	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	result := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			result[i] = 0
		} else {
			result[i] = n
		}
	}
	return result
}
