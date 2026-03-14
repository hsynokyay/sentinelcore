package ingest

import (
	"testing"
)

const osvTestFixture = `{
  "id": "GHSA-jfh8-c2jp-5v3q",
  "summary": "Remote code execution in lodash",
  "details": "Versions of lodash prior to 4.17.21 are vulnerable to prototype pollution.",
  "aliases": ["CVE-2021-23337"],
  "severity": [
    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}
  ],
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "lodash"},
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {"introduced": "0"},
            {"fixed": "4.17.21"}
          ]
        }
      ]
    }
  ],
  "published": "2021-02-19T00:00:00Z",
  "modified": "2021-08-10T00:00:00Z",
  "references": [
    {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
    {"type": "WEB", "url": "https://github.com/lodash/lodash/pull/5116"}
  ]
}`

func TestParseOSV_Lodash(t *testing.T) {
	results, err := ParseOSV([]byte(osvTestFixture))
	if err != nil {
		t.Fatalf("ParseOSV failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	v := results[0]

	// Should use CVE alias
	if v.CVEID != "CVE-2021-23337" {
		t.Errorf("expected CVE-2021-23337, got %s", v.CVEID)
	}

	if v.Source != "osv" {
		t.Errorf("expected source osv, got %s", v.Source)
	}

	if v.Title != "Remote code execution in lodash" {
		t.Errorf("unexpected title: %s", v.Title)
	}

	if v.CVSSv31Vector != "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("unexpected CVSS vector: %s", v.CVSSv31Vector)
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

func TestParseOSV_NoAlias(t *testing.T) {
	data := `{
		"id": "GHSA-test-1234-abcd",
		"summary": "Test vulnerability",
		"details": "Test details",
		"aliases": [],
		"severity": [],
		"affected": [],
		"published": "2024-01-01T00:00:00Z",
		"modified": "2024-01-01T00:00:00Z"
	}`

	results, err := ParseOSV([]byte(data))
	if err != nil {
		t.Fatalf("ParseOSV failed: %v", err)
	}

	if results[0].CVEID != "GHSA-test-1234-abcd" {
		t.Errorf("expected GHSA ID as CVE ID when no alias, got %s", results[0].CVEID)
	}
}

func TestParseOSV_InvalidJSON(t *testing.T) {
	_, err := ParseOSV([]byte(`{invalid`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
