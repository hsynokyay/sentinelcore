package ingest

import (
	"testing"
)

const nvdTestFixture = `{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [
          {
            "lang": "en",
            "value": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseScore": 10.0,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
              }
            }
          ]
        },
        "weaknesses": [
          {
            "description": [
              {"lang": "en", "value": "CWE-502"},
              {"lang": "en", "value": "CWE-400"}
            ]
          }
        ],
        "references": [
          {"url": "https://logging.apache.org/log4j/2.x/security.html", "tags": []},
          {"url": "https://example.com/exploit", "tags": ["Exploit"]}
        ],
        "published": "2021-12-10T10:15:00.000",
        "lastModified": "2023-04-03T20:15:00.000"
      }
    },
    {
      "cve": {
        "id": "CVE-2022-22965",
        "descriptions": [
          {
            "lang": "en",
            "value": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseScore": 9.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
              }
            }
          ]
        },
        "weaknesses": [
          {
            "description": [
              {"lang": "en", "value": "CWE-94"}
            ]
          }
        ],
        "references": [
          {"url": "https://spring.io/security/cve-2022-22965", "tags": []}
        ],
        "published": "2022-04-01T00:00:00.000",
        "lastModified": "2022-05-15T00:00:00.000"
      }
    }
  ]
}`

func TestParseNVD_Log4Shell(t *testing.T) {
	results, err := ParseNVD([]byte(nvdTestFixture))
	if err != nil {
		t.Fatalf("ParseNVD failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify Log4Shell entry
	log4j := results[0]

	if log4j.CVEID != "CVE-2021-44228" {
		t.Errorf("expected CVE ID CVE-2021-44228, got %s", log4j.CVEID)
	}

	if log4j.Source != "nvd" {
		t.Errorf("expected source nvd, got %s", log4j.Source)
	}

	if log4j.CVSSv31Score != 10.0 {
		t.Errorf("expected CVSS score 10.0, got %f", log4j.CVSSv31Score)
	}

	if log4j.CVSSv31Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" {
		t.Errorf("unexpected CVSS vector: %s", log4j.CVSSv31Vector)
	}

	if len(log4j.CWEIDs) != 2 {
		t.Fatalf("expected 2 CWE IDs, got %d", len(log4j.CWEIDs))
	}
	if log4j.CWEIDs[0] != 502 {
		t.Errorf("expected CWE-502, got CWE-%d", log4j.CWEIDs[0])
	}
	if log4j.CWEIDs[1] != 400 {
		t.Errorf("expected CWE-400, got CWE-%d", log4j.CWEIDs[1])
	}

	if !log4j.ExploitAvailable {
		t.Error("expected ExploitAvailable to be true")
	}

	if log4j.PublishedAt != "2021-12-10T10:15:00.000" {
		t.Errorf("unexpected published date: %s", log4j.PublishedAt)
	}

	if len(log4j.References) != 2 {
		t.Errorf("expected 2 references, got %d", len(log4j.References))
	}

	// Verify Spring4Shell entry
	spring := results[1]
	if spring.CVEID != "CVE-2022-22965" {
		t.Errorf("expected CVE-2022-22965, got %s", spring.CVEID)
	}
	if spring.CVSSv31Score != 9.8 {
		t.Errorf("expected CVSS 9.8, got %f", spring.CVSSv31Score)
	}
}

func TestParseNVD_EmptyFeed(t *testing.T) {
	results, err := ParseNVD([]byte(`{"vulnerabilities": []}`))
	if err != nil {
		t.Fatalf("ParseNVD failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestParseNVD_InvalidJSON(t *testing.T) {
	_, err := ParseNVD([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
