package risk

import "fmt"

// ScoreInputs bundles everything the scorer needs for a single cluster.
// The correlator populates it by inspecting cluster_findings, relations,
// and linked surface entries before calling ComputeScore.
type ScoreInputs struct {
	Severity         string
	FingerprintKind  string // 'sast_file' | 'dast_route'
	RuntimeConfirmed bool   // a runtime_confirmation relation with confidence >= 0.80 exists
	PublicExposure   bool   // any linked surface_entry has exposure='public'
	PublicSurfaceURL string // populated when PublicExposure is true
	SameRoute        bool   // DAST only: >1 findings share the cluster's canonical_route
	SameParam        bool   // DAST only: >1 findings share the cluster's canonical_param
	CanonicalRoute   string
	CanonicalParam   string
}

// ScoreResult is the deterministic output of ComputeScore. Total is the
// final risk_score (0..100). Evidence is ordered by SortOrder ascending
// and is suitable for direct insertion into risk.cluster_evidence.
type ScoreResult struct {
	Total    int
	Evidence []Evidence
}

// SeverityBase maps a severity label to the integer base contribution.
// Unknown severities return 0.
func SeverityBase(severity string) int {
	switch severity {
	case "critical":
		return 60
	case "high":
		return 45
	case "medium":
		return 30
	case "low":
		return 15
	case "info":
		return 5
	}
	return 0
}

// ComputeScore is the only scoring entry point. It is a pure function —
// no DB access, no side effects — so it is trivially testable and safe
// to call inside the correlator's transaction.
//
// The caller persists the returned Evidence rows with cluster_id and
// source_run_id filled in.
func ComputeScore(in ScoreInputs) ScoreResult {
	out := ScoreResult{Evidence: make([]Evidence, 0, 5)}

	// Base score — always emitted.
	base := SeverityBase(in.Severity)
	out.Total = base
	out.Evidence = append(out.Evidence, Evidence{
		Category:  "score_base",
		Code:      "SEVERITY_BASE",
		Label:     fmt.Sprintf("Base score from %s severity", in.Severity),
		Weight:    intPtr(base),
		SortOrder: 0,
		Metadata:  map[string]any{"severity": in.Severity},
	})

	// Runtime confirmation boost.
	if in.RuntimeConfirmed {
		out.Total += 20
		out.Evidence = append(out.Evidence, Evidence{
			Category:  "score_boost",
			Code:      "RUNTIME_CONFIRMED",
			Label:     "Confirmed at runtime by DAST",
			Weight:    intPtr(20),
			SortOrder: 10,
		})
	}

	// Public exposure boost.
	if in.PublicExposure {
		label := "Exposed on a public surface"
		if in.PublicSurfaceURL != "" {
			label = fmt.Sprintf("Exposed on public surface %s", in.PublicSurfaceURL)
		}
		out.Evidence = append(out.Evidence, Evidence{
			Category:  "score_boost",
			Code:      "PUBLIC_EXPOSURE",
			Label:     label,
			Weight:    intPtr(15),
			SortOrder: 20,
			RefType:   "surface_entry",
			Metadata:  map[string]any{"surface_url": in.PublicSurfaceURL},
		})
		out.Total += 15
	}

	// Same route/param — DAST clusters only.
	if in.FingerprintKind == "dast_route" {
		if in.SameRoute {
			out.Total += 5
			out.Evidence = append(out.Evidence, Evidence{
				Category:  "score_boost",
				Code:      "SAME_ROUTE",
				Label:     fmt.Sprintf("Multiple findings on route %s", in.CanonicalRoute),
				Weight:    intPtr(5),
				SortOrder: 30,
			})
		}
		if in.SameParam {
			out.Total += 5
			out.Evidence = append(out.Evidence, Evidence{
				Category:  "score_boost",
				Code:      "SAME_PARAM",
				Label:     fmt.Sprintf("Multiple findings on param %s", in.CanonicalParam),
				Weight:    intPtr(5),
				SortOrder: 40,
			})
		}
	}

	// Cap at 100.
	if out.Total > 100 {
		out.Total = 100
	}
	return out
}

func intPtr(i int) *int { return &i }
