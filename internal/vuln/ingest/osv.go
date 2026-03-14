package ingest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/vuln"
)

// OSVEntry represents a single OSV vulnerability record.
type OSVEntry struct {
	ID        string         `json:"id"`
	Summary   string         `json:"summary"`
	Details   string         `json:"details"`
	Aliases   []string       `json:"aliases"`
	Severity  []OSVSeverity  `json:"severity"`
	Affected  []OSVAffected  `json:"affected"`
	Published string         `json:"published"`
	Modified  string         `json:"modified"`
	References []OSVReference `json:"references"`
}

// OSVSeverity holds severity scoring.
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVAffected describes an affected package.
type OSVAffected struct {
	Package OSVPackage  `json:"package"`
	Ranges  []OSVRange  `json:"ranges"`
}

// OSVPackage identifies a package.
type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// OSVRange describes version ranges.
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

// OSVEvent is a version event (introduced, fixed, etc.).
type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// OSVReference is a reference link.
type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ParseOSV parses an OSV JSON record and returns normalized vulnerability records.
func ParseOSV(data []byte) ([]vuln.NormalizedVuln, error) {
	var entry OSVEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("ingest: parse OSV JSON: %w", err)
	}

	// Determine CVE ID from aliases or use the OSV ID
	cveID := entry.ID
	for _, alias := range entry.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveID = alias
			break
		}
	}

	nv := vuln.NormalizedVuln{
		CVEID:       cveID,
		Source:      "osv",
		Title:       entry.Summary,
		Description: entry.Details,
		PublishedAt: entry.Published,
		ModifiedAt:  entry.Modified,
	}

	// Extract CVSS v3.1 from severity
	for _, sev := range entry.Severity {
		if sev.Type == "CVSS_V3" {
			nv.CVSSv31Vector = sev.Score
			nv.CVSSv31Score = parseCVSSScore(sev.Score)
			break
		}
	}

	// Extract affected packages
	for _, aff := range entry.Affected {
		ecosystem := strings.ToLower(aff.Package.Ecosystem)
		for _, r := range aff.Ranges {
			ap := vuln.AffectedPackage{
				Ecosystem:   ecosystem,
				PackageName: aff.Package.Name,
			}

			var introduced, fixed string
			for _, ev := range r.Events {
				if ev.Introduced != "" {
					introduced = ev.Introduced
				}
				if ev.Fixed != "" {
					fixed = ev.Fixed
				}
			}

			if introduced != "" && fixed != "" {
				ap.VersionRange = fmt.Sprintf(">= %s, < %s", introduced, fixed)
			} else if fixed != "" {
				ap.VersionRange = fmt.Sprintf("< %s", fixed)
			} else if introduced != "" {
				ap.VersionRange = fmt.Sprintf(">= %s", introduced)
			}
			ap.FixedVersion = fixed

			nv.AffectedPackages = append(nv.AffectedPackages, ap)
		}
	}

	// Extract references
	for _, ref := range entry.References {
		nv.References = append(nv.References, ref.URL)
	}

	// Store raw data
	nv.RawData = data

	return []vuln.NormalizedVuln{nv}, nil
}

// parseCVSSScore extracts the base score from a CVSS v3.1 vector string.
// Vector format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
// This is a simplified parser; the actual score is not embedded in the vector.
// For OSV, we return 0 since the score is not provided separately.
func parseCVSSScore(vector string) float64 {
	// OSV typically only provides the vector string, not the computed score.
	// A full implementation would compute the score from the vector.
	// For MVP, return 0 and let the vector be used for display.
	return 0
}
