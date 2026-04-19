package risk

import "fmt"

// ClassifyRelation returns the relation type, confidence, and rationale for
// a pair of clusters. Returns empty relType if the pair is unrelated.
//
// sharesSurface is a lookup the caller performs before invocation: it is
// true when both clusters are linked to at least one common surface_entry.
// The function itself does not query the database.
func ClassifyRelation(a, b *Cluster, sharesSurface bool) (relType string, confidence float64, rationale string) {
	// runtime_confirmation: SAST cluster + DAST cluster sharing a CWE.
	sastDast := (a.FingerprintKind == "sast_file" && b.FingerprintKind == "dast_route") ||
		(a.FingerprintKind == "dast_route" && b.FingerprintKind == "sast_file")
	if sastDast && a.CWEID != 0 && a.CWEID == b.CWEID {
		conf := 0.80
		if a.OWASPCategory != "" && a.OWASPCategory == b.OWASPCategory {
			conf += 0.10
		}
		if conf > 1.00 {
			conf = 1.00
		}
		return "runtime_confirmation", conf,
			fmt.Sprintf("SAST and DAST both detected CWE-%d (%s)", a.CWEID, nonEmpty(a.VulnClass, b.VulnClass))
	}

	// same_cwe: both same kind, same CWE (weaker signal).
	if a.FingerprintKind == b.FingerprintKind && a.CWEID != 0 && a.CWEID == b.CWEID {
		return "same_cwe", 0.30,
			fmt.Sprintf("Same vulnerability class (CWE-%d)", a.CWEID)
	}

	// related_surface: two DAST clusters touching the same surface entry.
	if a.FingerprintKind == "dast_route" && b.FingerprintKind == "dast_route" && sharesSurface {
		return "related_surface", 0.60, "Both clusters touch the same surface entry"
	}

	return "", 0, ""
}

// CanonicalizePair orders a pair of cluster IDs so the smaller is always
// the source. This satisfies the UNIQUE(source_cluster_id, target_cluster_id,
// relation_type) constraint without requiring the caller to remember which
// direction was previously inserted.
func CanonicalizePair(a, b string) (source, target string) {
	if a < b {
		return a, b
	}
	return b, a
}

// BoostThreshold is the minimum confidence at which a runtime_confirmation
// relation contributes the +20 RUNTIME_CONFIRMED score boost.
const BoostThreshold = 0.80

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
