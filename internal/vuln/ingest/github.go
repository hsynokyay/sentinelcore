package ingest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/vuln"
)

// GitHubAdvisory represents a GitHub Security Advisory.
type GitHubAdvisory struct {
	GHSAID          string                   `json:"ghsaId"`
	CVEID           string                   `json:"cveId"`
	Summary         string                   `json:"summary"`
	Description     string                   `json:"description"`
	Severity        string                   `json:"severity"`
	CVSS            *GitHubCVSS              `json:"cvss,omitempty"`
	CWEs            *GitHubCWEConnection     `json:"cwes,omitempty"`
	Vulnerabilities GitHubVulnConnection     `json:"vulnerabilities"`
	References      []GitHubAdvisoryRef      `json:"references"`
	PublishedAt     string                   `json:"publishedAt"`
	UpdatedAt       string                   `json:"updatedAt"`
}

// GitHubCVSS holds the CVSS score from a GitHub Advisory.
type GitHubCVSS struct {
	Score        float64 `json:"score"`
	VectorString string  `json:"vectorString"`
}

// GitHubCWEConnection holds CWE data from a GitHub Advisory.
type GitHubCWEConnection struct {
	Nodes []GitHubCWENode `json:"nodes"`
}

// GitHubCWENode is a single CWE entry.
type GitHubCWENode struct {
	CWEID string `json:"cweId"`
}

// GitHubVulnConnection holds vulnerable package data.
type GitHubVulnConnection struct {
	Nodes []GitHubVulnNode `json:"nodes"`
}

// GitHubVulnNode represents a single vulnerable package entry.
type GitHubVulnNode struct {
	Package              GitHubPackage       `json:"package"`
	VulnerableVersionRange string            `json:"vulnerableVersionRange"`
	FirstPatchedVersion  *GitHubPatchVersion `json:"firstPatchedVersion"`
}

// GitHubPackage identifies a package.
type GitHubPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// GitHubPatchVersion holds the first patched version.
type GitHubPatchVersion struct {
	Identifier string `json:"identifier"`
}

// GitHubAdvisoryRef is a reference link.
type GitHubAdvisoryRef struct {
	URL string `json:"url"`
}

// ParseGitHubAdvisory parses a GitHub Security Advisory JSON and returns
// normalized vulnerability records.
func ParseGitHubAdvisory(data []byte) ([]vuln.NormalizedVuln, error) {
	var advisory GitHubAdvisory
	if err := json.Unmarshal(data, &advisory); err != nil {
		return nil, fmt.Errorf("ingest: parse GitHub Advisory JSON: %w", err)
	}

	// Use CVE ID if available, otherwise fall back to GHSA ID
	cveID := advisory.CVEID
	if cveID == "" {
		cveID = advisory.GHSAID
	}

	nv := vuln.NormalizedVuln{
		CVEID:       cveID,
		Source:      "github",
		Title:       advisory.Summary,
		Description: advisory.Description,
		PublishedAt: advisory.PublishedAt,
		ModifiedAt:  advisory.UpdatedAt,
	}

	// Extract CVSS
	if advisory.CVSS != nil {
		nv.CVSSv31Score = advisory.CVSS.Score
		nv.CVSSv31Vector = advisory.CVSS.VectorString
	}

	// Map severity string to rough CVSS score if no CVSS data
	if nv.CVSSv31Score == 0 {
		nv.CVSSv31Score = severityToScore(advisory.Severity)
	}

	// Extract CWE IDs
	if advisory.CWEs != nil {
		for _, node := range advisory.CWEs.Nodes {
			if id := parseCWEID(node.CWEID); id > 0 {
				nv.CWEIDs = append(nv.CWEIDs, id)
			}
		}
	}

	// Extract affected packages
	for _, node := range advisory.Vulnerabilities.Nodes {
		ap := vuln.AffectedPackage{
			Ecosystem:    strings.ToLower(node.Package.Ecosystem),
			PackageName:  node.Package.Name,
			VersionRange: node.VulnerableVersionRange,
		}
		if node.FirstPatchedVersion != nil {
			ap.FixedVersion = node.FirstPatchedVersion.Identifier
		}
		nv.AffectedPackages = append(nv.AffectedPackages, ap)
	}

	// Extract references
	for _, ref := range advisory.References {
		nv.References = append(nv.References, ref.URL)
	}

	// Store raw data
	nv.RawData = data

	return []vuln.NormalizedVuln{nv}, nil
}

// severityToScore maps a GitHub severity string to an approximate CVSS score.
func severityToScore(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 9.5
	case "HIGH":
		return 7.5
	case "MODERATE", "MEDIUM":
		return 5.5
	case "LOW":
		return 3.0
	default:
		return 0
	}
}
