package export

import "strings"

// ControlRef mirrors compliance.ControlRef as a flat, dependency-free
// shape so the exporter can stay decoupled from the DB-aware compliance
// package. The HTTP handler resolves controls (calling
// compliance.ResolveControls) and copies the result into
// FindingData.ControlRefs before invoking the formatter.
type ControlRef struct {
	CatalogCode string
	CatalogName string
	ControlID   string
	Title       string
	Confidence  string
}

// complianceTagPrefix returns the short tag prefix used in SARIF
// result.properties.tags entries. The prefix is the catalog code's
// first underscore-separated token, lowercased — so OWASP_TOP10_2021
// becomes "owasp", PCI_DSS_4_0 becomes "pci", etc.
func complianceTagPrefix(catalogCode string) string {
	if catalogCode == "" {
		return ""
	}
	parts := strings.SplitN(catalogCode, "_", 2)
	return strings.ToLower(parts[0])
}

// complianceTags converts a ControlRef slice into the slice of SARIF
// tag strings the result properties.tags array expects.
func complianceTags(refs []ControlRef) []string {
	if len(refs) == 0 {
		return nil
	}
	tags := make([]string, 0, len(refs))
	for _, r := range refs {
		prefix := complianceTagPrefix(r.CatalogCode)
		if prefix == "" || r.ControlID == "" {
			continue
		}
		tags = append(tags, prefix+":"+r.ControlID)
	}
	return tags
}
