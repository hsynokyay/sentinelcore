package ingest

import (
	"testing"
)

const githubTestFixture = `{
  "ghsaId": "GHSA-jfh8-c2jp-5v3q",
  "cveId": "CVE-2021-23337",
  "summary": "Prototype Pollution in lodash",
  "description": "All versions of package lodash prior to 4.17.21 are vulnerable to Prototype Pollution via the template function.",
  "severity": "HIGH",
  "cvss": {
    "score": 7.2,
    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
  },
  "cwes": {
    "nodes": [
      {"cweId": "CWE-1321"}
    ]
  },
  "vulnerabilities": {
    "nodes": [
      {
        "package": {"ecosystem": "NPM", "name": "lodash"},
        "vulnerableVersionRange": ">= 0, < 4.17.21",
        "firstPatchedVersion": {"identifier": "4.17.21"}
      }
    ]
  },
  "references": [
    {"url": "https://github.com/lodash/lodash/pull/5116"},
    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}
  ],
  "publishedAt": "2021-02-19T00:00:00Z",
  "updatedAt": "2021-08-10T00:00:00Z"
}`

func TestParseGitHubAdvisory_Lodash(t *testing.T) {
	results, err := ParseGitHubAdvisory([]byte(githubTestFixture))
	if err != nil {
		t.Fatalf("ParseGitHubAdvisory failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	v := results[0]

	if v.CVEID != "CVE-2021-23337" {
		t.Errorf("expected CVE-2021-23337, got %s", v.CVEID)
	}

	if v.Source != "github" {
		t.Errorf("expected source github, got %s", v.Source)
	}

	if v.Title != "Prototype Pollution in lodash" {
		t.Errorf("unexpected title: %s", v.Title)
	}

	if v.CVSSv31Score != 7.2 {
		t.Errorf("expected CVSS score 7.2, got %f", v.CVSSv31Score)
	}

	if v.CVSSv31Vector != "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("unexpected CVSS vector: %s", v.CVSSv31Vector)
	}

	if len(v.CWEIDs) != 1 || v.CWEIDs[0] != 1321 {
		t.Errorf("expected CWE-1321, got %v", v.CWEIDs)
	}

	if len(v.AffectedPackages) != 1 {
		t.Fatalf("expected 1 affected package, got %d", len(v.AffectedPackages))
	}

	ap := v.AffectedPackages[0]
	if ap.Ecosystem != "npm" {
		t.Errorf("expected ecosystem npm, got %s", ap.Ecosystem)
	}
	if ap.PackageName != "lodash" {
		t.Errorf("expected package lodash, got %s", ap.PackageName)
	}
	if ap.VersionRange != ">= 0, < 4.17.21" {
		t.Errorf("unexpected version range: %s", ap.VersionRange)
	}
	if ap.FixedVersion != "4.17.21" {
		t.Errorf("expected fixed version 4.17.21, got %s", ap.FixedVersion)
	}

	if len(v.References) != 2 {
		t.Errorf("expected 2 references, got %d", len(v.References))
	}
}

func TestParseGitHubAdvisory_NoCVE(t *testing.T) {
	data := `{
		"ghsaId": "GHSA-test-1234",
		"cveId": "",
		"summary": "Test",
		"description": "Test desc",
		"severity": "MODERATE",
		"vulnerabilities": {"nodes": []},
		"references": [],
		"publishedAt": "2024-01-01T00:00:00Z",
		"updatedAt": "2024-01-01T00:00:00Z"
	}`

	results, err := ParseGitHubAdvisory([]byte(data))
	if err != nil {
		t.Fatalf("ParseGitHubAdvisory failed: %v", err)
	}

	// Should fall back to GHSA ID
	if results[0].CVEID != "GHSA-test-1234" {
		t.Errorf("expected GHSA ID fallback, got %s", results[0].CVEID)
	}

	// Should map severity to approximate score
	if results[0].CVSSv31Score != 5.5 {
		t.Errorf("expected severity-mapped score 5.5, got %f", results[0].CVSSv31Score)
	}
}

func TestParseGitHubAdvisory_InvalidJSON(t *testing.T) {
	_, err := ParseGitHubAdvisory([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
