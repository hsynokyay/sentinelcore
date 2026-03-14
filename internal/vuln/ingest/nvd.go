package ingest

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/vuln"
)

// NVDFeed represents the top-level NVD JSON 2.0 response.
type NVDFeed struct {
	Vulnerabilities []NVDItem `json:"vulnerabilities"`
}

// NVDItem wraps a single CVE entry in the NVD feed.
type NVDItem struct {
	CVE NVDCVE `json:"cve"`
}

// NVDCVE represents the CVE data within an NVD item.
type NVDCVE struct {
	ID           string          `json:"id"`
	Descriptions []NVDLangString `json:"descriptions"`
	Metrics      NVDMetrics      `json:"metrics"`
	Weaknesses   []NVDWeakness   `json:"weaknesses"`
	References   []NVDReference  `json:"references"`
	Published    string          `json:"published"`
	LastModified string          `json:"lastModified"`
}

// NVDLangString is a language-tagged string from the NVD API.
type NVDLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// NVDMetrics holds CVSS metric data.
type NVDMetrics struct {
	CvssMetricV31 []NVDCvssMetricV31 `json:"cvssMetricV31"`
}

// NVDCvssMetricV31 holds a single CVSS v3.1 metric.
type NVDCvssMetricV31 struct {
	CvssData NVDCvssData `json:"cvssData"`
}

// NVDCvssData holds the CVSS score and vector.
type NVDCvssData struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

// NVDWeakness represents a weakness (CWE) entry.
type NVDWeakness struct {
	Description []NVDLangString `json:"description"`
}

// NVDReference represents a reference URL.
type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// ParseNVD parses NVD JSON 2.0 format and returns normalized vulnerability records.
func ParseNVD(data []byte) ([]vuln.NormalizedVuln, error) {
	var feed NVDFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("ingest: parse NVD JSON: %w", err)
	}

	results := make([]vuln.NormalizedVuln, 0, len(feed.Vulnerabilities))

	for _, item := range feed.Vulnerabilities {
		cve := item.CVE

		nv := vuln.NormalizedVuln{
			CVEID:       cve.ID,
			Source:      "nvd",
			PublishedAt: cve.Published,
			ModifiedAt:  cve.LastModified,
		}

		// Extract English description
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				nv.Description = d.Value
				// Use first sentence as title (up to 120 chars)
				nv.Title = truncateTitle(d.Value)
				break
			}
		}

		// Extract CVSS v3.1 score
		if len(cve.Metrics.CvssMetricV31) > 0 {
			m := cve.Metrics.CvssMetricV31[0]
			nv.CVSSv31Score = m.CvssData.BaseScore
			nv.CVSSv31Vector = m.CvssData.VectorString
		}

		// Extract CWE IDs
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if id := parseCWEID(d.Value); id > 0 {
					nv.CWEIDs = append(nv.CWEIDs, id)
				}
			}
		}

		// Check references for exploit indicators
		for _, ref := range cve.References {
			nv.References = append(nv.References, ref.URL)
			for _, tag := range ref.Tags {
				lower := strings.ToLower(tag)
				if lower == "exploit" {
					nv.ExploitAvailable = true
				}
			}
		}

		// Store raw data
		raw, _ := json.Marshal(item)
		nv.RawData = raw

		results = append(results, nv)
	}

	return results, nil
}

// truncateTitle creates a short title from the description.
func truncateTitle(desc string) string {
	// Take first sentence
	if idx := strings.Index(desc, ". "); idx > 0 && idx < 120 {
		return desc[:idx+1]
	}
	if len(desc) > 120 {
		return desc[:120] + "..."
	}
	return desc
}

// parseCWEID extracts the numeric CWE ID from a string like "CWE-502".
func parseCWEID(s string) int {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "CWE-") {
		return 0
	}
	n, err := strconv.Atoi(s[4:])
	if err != nil {
		return 0
	}
	return n
}
