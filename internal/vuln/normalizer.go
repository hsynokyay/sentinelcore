package vuln

// NormalizedVuln is the unified internal representation of a vulnerability
// from any feed source (NVD, OSV, GitHub Advisory).
type NormalizedVuln struct {
	CVEID             string            `json:"cve_id"`
	Source            string            `json:"source"` // nvd, osv, github
	Title             string            `json:"title"`
	Description       string            `json:"description"`
	CVSSv31Score      float64           `json:"cvss_v31_score"`
	CVSSv31Vector     string            `json:"cvss_v31_vector"`
	CWEIDs            []int             `json:"cwe_ids"`
	AffectedPackages  []AffectedPackage `json:"affected_packages"`
	ExploitAvailable  bool              `json:"exploit_available"`
	ActivelyExploited bool              `json:"actively_exploited"`
	PublishedAt       string            `json:"published_at"`
	ModifiedAt        string            `json:"modified_at"`
	References        []string          `json:"references"`
	RawData           []byte            `json:"-"`
}

// AffectedPackage represents a single package affected by a vulnerability.
type AffectedPackage struct {
	Ecosystem    string `json:"ecosystem"`     // npm, pypi, maven, go
	PackageName  string `json:"package_name"`
	VersionRange string `json:"version_range"` // e.g., ">= 0, < 4.17.21"
	FixedVersion string `json:"fixed_version"`
}
