// Package engine — dedup.go collapses semantic-duplicate findings.
//
// "Semantic duplicate" means two or more findings that describe the
// same vulnerability at the same source location, even when produced
// by different rules. The motivating case from Sprint 1.2 is the
// `Secrets.java:27` line that matches BOTH a generic
// hardcoded-credential rule (SC-JAVA-SECRET-001) AND a specialized
// JWT-secret rule (SC-JAVA-JWT-003). Both tag the same finding as
// HARDCODED_SECRET; the engine should report it once, not twice.
//
// This is distinct from the *fingerprint* dedup that already runs
// inside Engine.AnalyzeAll: fingerprint collapses identical re-runs of
// the same rule (e.g. inter-procedural pre-pass + main pass producing
// the same finding twice). Semantic dedup operates one level higher,
// across rules.
//
// Tie-break for "which rule survives in a group" is intentionally
// minimal — Sprint 1.3 will revisit once the severity policy YAML and
// per-rule confidence land. For now: highest severity wins, then
// alphabetically smallest rule_id (deterministic).

package engine

import (
	"sort"
)

// DedupReport accompanies a deduplicated finding slice and exposes
// audit information that the worker can persist into scan-job
// metadata or surface in operator-facing logs. It is intentionally
// detached from the Finding type itself: end-users only ever see the
// surviving findings, and the audit trail is for debugging.
type DedupReport struct {
	// Suppressed is the total number of findings that were folded into
	// surviving siblings — i.e. the difference between the input
	// length and the output length.
	Suppressed int

	// Audit is one entry per dedup group that had more than one
	// member. Single-member groups (the vast majority) are omitted.
	Audit []DedupAuditEntry
}

// DedupAuditEntry records one collapsed group: the surviving rule_id
// and which rule_ids it superseded at the same (file, line, vuln_class).
type DedupAuditEntry struct {
	ModulePath        string
	Line              int
	VulnClass         string
	KeptRuleID        string
	SuppressedRuleIDs []string
}

// severityRank returns a numeric ordering for rule severity. Higher
// number = more severe = preferred to keep during dedup. Unknown
// severities sort below "info" so a rule with a typo'd severity loses
// to any well-formed sibling rather than being silently kept.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info":
		return 0
	default:
		return -1
	}
}

// dedupKey is the canonical identity for "same vulnerability at same
// place". The order — file, line, then vuln_class — is for readability
// in audit logs; it has no functional significance because map lookup
// uses the whole tuple.
type dedupKey struct {
	module    string
	line      int
	vulnClass string
}

// Deduplicate folds semantic-duplicate findings and returns the
// surviving slice plus a report describing what was collapsed. Input
// order is preserved among survivors so callers (and snapshot tests)
// see a stable ordering.
//
// Findings with an empty VulnClass are NEVER deduplicated against any
// other finding — even another empty-VulnClass finding at the same
// location. An empty VulnClass means "I don't know what kind of
// vulnerability this is", and silently grouping unknowns would
// collapse semantically distinct findings. After Sprint 1.2's
// MigrateInPlace + InferVulnClass promotion this case should not
// occur in practice for builtin rules; the guard is here for
// robustness against externally-supplied rules and future test
// fixtures that hand-build Findings.
func Deduplicate(findings []Finding) ([]Finding, DedupReport) {
	if len(findings) == 0 {
		return findings, DedupReport{}
	}

	// Group indices by canonical key, preserving original order so
	// the surviving finding inherits its input position.
	groups := map[dedupKey][]int{}
	groupOrder := []dedupKey{} // insertion order = first-seen order
	for i, f := range findings {
		if f.VulnClass == "" {
			// See doc comment — never collapse unknown-class findings.
			// We model this by giving each one a unique synthetic key.
			key := dedupKey{f.ModulePath, f.Line, "__unkn__:" + f.RuleID + ":" + f.Fingerprint}
			groups[key] = append(groups[key], i)
			if len(groups[key]) == 1 {
				groupOrder = append(groupOrder, key)
			}
			continue
		}
		key := dedupKey{f.ModulePath, f.Line, f.VulnClass}
		if _, ok := groups[key]; !ok {
			groupOrder = append(groupOrder, key)
		}
		groups[key] = append(groups[key], i)
	}

	out := make([]Finding, 0, len(findings))
	report := DedupReport{}

	for _, key := range groupOrder {
		members := groups[key]
		if len(members) == 1 {
			out = append(out, findings[members[0]])
			continue
		}

		// Tie-break ordering — keep the highest severity; on tie keep
		// the alphabetically smallest rule_id. Stable so test
		// snapshots are reproducible.
		sort.SliceStable(members, func(a, b int) bool {
			fa, fb := findings[members[a]], findings[members[b]]
			ra, rb := severityRank(fa.Severity), severityRank(fb.Severity)
			if ra != rb {
				return ra > rb // higher rank first
			}
			return fa.RuleID < fb.RuleID
		})

		kept := findings[members[0]]
		out = append(out, kept)

		suppressed := make([]string, 0, len(members)-1)
		for _, idx := range members[1:] {
			suppressed = append(suppressed, findings[idx].RuleID)
		}
		report.Suppressed += len(suppressed)
		report.Audit = append(report.Audit, DedupAuditEntry{
			ModulePath:        kept.ModulePath,
			Line:              kept.Line,
			VulnClass:         kept.VulnClass,
			KeptRuleID:        kept.RuleID,
			SuppressedRuleIDs: suppressed,
		})
	}

	return out, report
}
